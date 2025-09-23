// Package main implements a session-based file processing plugin for the host connector.
//
// The session plugin provides intelligent grouping and batch processing of files based on their
// directory structure. It creates isolated sessions for files located in specific subdirectories,
// enabling organized scanning workflows and consolidated reporting.
//
// Key Features:
//   - Automatic session creation based on configurable directory depth
//   - Thread-safe tracking of file scanning progress within sessions
//   - Automatic session closure with configurable delay after completion
//   - Consolidated report generation for each session
//   - Optional cleanup of processed files
//
// Session Creation:
// Sessions are automatically created when files are detected in subdirectories at the configured
// depth level. For example, with depth=2 and root="/tmp/samples":
//   - "/tmp/samples/user_a/batch1/file1.txt" -> session "user_a/batch1"
//   - "/tmp/samples/user_b/upload/file2.txt" -> session "user_b/upload"
//
// Session Lifecycle:
//  1. Session starts when the first file is added to a qualifying directory
//  2. Files are tracked as they move through the scanning pipeline
//  3. Session remains active while files are pending or recently completed
//  4. After all files complete and the delay period expires, session closes
//  5. Final report is generated and files are optionally cleaned up
//
// This design enables batch processing scenarios where related files should be
// processed together and reported as a unit, such as user uploads or timed batches.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/report"
	"gopkg.in/yaml.v3"
)

// SessionPlugin implements the plugins.Plugin interface to provide session-based file processing.
//
// The plugin monitors file scanning events and groups files into sessions based on their
// directory structure. Each session represents a batch of related files that should be
// processed and reported together.
//
// Thread Safety:
// All public methods are thread-safe and can be called concurrently from multiple goroutines.
// Internal state is protected by read-write mutexes to ensure data consistency.
//
// Background Processing:
// The plugin runs a background goroutine (sessionMonitor) that periodically checks for
// sessions ready to be closed and performs cleanup operations.
type SessionPlugin struct {
	config   Config              // Plugin configuration loaded from YAML
	sessions map[string]*Session // Active sessions mapped by session ID
	mutex    sync.RWMutex        // Protects the sessions map
	hcc      plugins.HCContext   // Host connector context for callbacks
	logger   *slog.Logger        // Logger instance from host connector
	ctx      context.Context     // Context for background operations
	cancel   context.CancelFunc  // Cancellation function for graceful shutdown
}

// Config defines the configuration parameters for the session plugin.
//
// These settings control how sessions are created, managed, and cleaned up.
// Configuration can be loaded from YAML files or use built-in defaults.
//
// Example YAML configuration:
//
//	depth: 2
//	delay: 30s
//	remove_inputs: true
//	root_folder: "/tmp/samples"
type Config struct {
	// Depth specifies how many directory levels under RootFolder define a session.
	// For example, with depth=2 and root="/tmp/samples":
	//   - "/tmp/samples/user_a/batch1/file.txt" creates session "user_a/batch1"
	//   - "/tmp/samples/user_a/file.txt" is ignored (insufficient depth)
	Depth int `yaml:"depth" desc:"number of subdirectory levels that define a session"`

	// Delay is the minimum time to wait after a session becomes inactive before closing it.
	// A session is considered inactive when all its files have been processed.
	// This prevents premature closure if new files arrive shortly after the last file completes.
	Delay time.Duration `yaml:"delay" desc:"delay before closing inactive sessions"`

	// RemoveInputs determines whether to delete processed files when closing a session.
	// When true, all files tracked by the session will be deleted from the filesystem.
	// When false, files remain in place after session closure.
	RemoveInputs bool `yaml:"remove_inputs" desc:"remove input files after session completion"`

	// RootFolder is the base directory path to monitor for session creation.
	// Only files within subdirectories of this path will be considered for sessions.
	// The path should be absolute for reliable operation.
	RootFolder string `yaml:"root_folder" desc:"root folder to monitor for sessions"`
}

// Session represents an active scanning session for files in a specific subdirectory.
//
// A session tracks the lifecycle of related files from initial detection through
// scan completion and report generation. Sessions provide isolation between
// different batches or users, ensuring that files are processed and reported
// in logical groups.
//
// State Management:
// Sessions maintain both pending files (not yet completed) and completed reports.
// The session is considered ready for closure when all pending files have been
// processed and the configured delay period has elapsed.
//
// Concurrency:
// Session methods are thread-safe and can be called concurrently. Internal
// state is protected by a read-write mutex.
type Session struct {
	ID               string                // Unique identifier derived from directory path
	Path             string                // Full filesystem path to the session directory
	StartTime        time.Time             // Timestamp when the session was first created
	LastActivity     time.Time             // Timestamp of the most recent file or scan activity
	PendingFiles     map[string]*FileEntry // Files currently being tracked, keyed by file path
	CompletedReports []report.Report       // All completed scan reports for this session
	mutex            sync.RWMutex          // Protects concurrent access to session state
}

// FileEntry tracks the state and metadata of individual files within a session.
//
// Each file entry represents one file's journey through the scanning pipeline,
// from initial detection to scan completion. The entry maintains timing
// information and error state to provide comprehensive tracking.
//
// Lifecycle:
//  1. Created when a file is first detected (Completed = false)
//  2. Updated when scanning completes (Completed = true, Error set if applicable)
//  3. Remains in session until session closure for reporting purposes
type FileEntry struct {
	FilePath  string    // Full path to the file being tracked
	SHA256    string    // SHA256 hash of the file content for identification
	StartTime time.Time // When this file was first added to the session
	Completed bool      // Whether scanning has completed for this file
	Error     error     // Any error that occurred during scanning (nil if successful)
}

var (
	// Compile-time interface compliance check
	_ plugins.Plugin = &SessionPlugin{}

	// HCPlugin is the exported plugin instance that the host connector will load.
	// This variable must be named exactly "HCPlugin" as specified by the plugin
	// loading mechanism. It provides the entry point for the session plugin functionality.
	HCPlugin SessionPlugin
)

// Close implements the plugins.Plugin interface for graceful shutdown.
//
// This method performs the following cleanup operations:
//  1. Cancels the background session monitoring goroutine
//  2. Waits briefly for ongoing operations to complete
//  3. Returns without forcing closure of active sessions
//
// Active sessions are not forcibly closed during shutdown to avoid data loss.
// The background monitor will stop checking for session closures, but existing
// sessions will remain in memory until the process terminates.
//
// Parameters:
//   - ctx: Context for controlling shutdown timeout (currently not used for early termination)
//
// Returns:
//   - Always returns nil as the shutdown process cannot fail
func (p *SessionPlugin) Close(ctx context.Context) error {
	if p.cancel != nil {
		p.cancel()
	}

	// Wait a bit for cleanup to complete
	select {
	case <-time.After(1 * time.Second):
	case <-ctx.Done():
	}

	return nil
}

// Init implements the plugins.Plugin interface for plugin initialization.
//
// This method sets up the session plugin with the provided configuration and
// registers the necessary event callbacks with the host connector. It performs
// the following initialization steps:
//
//  1. Loads configuration from file or uses defaults
//  2. Initializes internal data structures
//  3. Registers event callbacks for file scanning lifecycle
//  4. Starts the background session monitoring goroutine
//
// Configuration Loading:
// If configPath is provided, the method attempts to load YAML configuration
// from that file. If the path is empty or the file cannot be read, default
// configuration values are used instead.
//
// Event Registration:
// The plugin registers for three key events:
//   - OnStartScanFile: Called when a file begins scanning
//   - OnFileScanned: Called when file scanning completes
//   - OnReport: Called when a scan report is generated
//
// Background Processing:
// A monitoring goroutine is started to periodically check for sessions
// that are ready to be closed and to perform cleanup operations.
//
// Parameters:
//   - configPath: Path to YAML configuration file (empty string uses defaults)
//   - hcc: Host connector context for registering callbacks
//
// Returns:
//   - error: Non-nil if configuration loading fails or initialization encounters errors
func (p *SessionPlugin) Init(configPath string, hcc plugins.HCContext) error {
	// Load configuration
	config := Config{
		Depth:        2,                // Default depth
		Delay:        30 * time.Second, // Default delay
		RemoveInputs: true,             // Default remove inputs
		RootFolder:   "/tmp/samples",   // Default root folder
	}

	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// Initialize plugin
	p.config = config
	p.sessions = make(map[string]*Session)
	p.hcc = hcc
	p.logger = hcc.GetLogger()
	p.ctx, p.cancel = context.WithCancel(context.Background())

	// Register callbacks
	hcc.RegisterOnStartScanFile(p.OnStartScanFile)
	hcc.RegisterOnFileScanned(p.OnFileScanned)
	hcc.RegisterOnReport(p.OnReport)

	// Start background session monitor
	go p.sessionMonitor()

	p.logger.Info("Session plugin initialized",
		"depth", config.Depth,
		"delay", config.Delay,
		"root_folder", config.RootFolder)

	return nil
}

// OnStartScanFile implements the plugins.OnStartScanFile callback interface.
//
// This method is called by the host connector when a file begins the scanning process.
// It determines whether the file belongs to a session based on its path and the
// configured directory depth, and if so, adds it to the appropriate session.
//
// Session Determination:
// Files are evaluated based on their path relative to the configured root folder.
// Only files in subdirectories at the configured depth level will be included
// in sessions. Files outside the root folder or at insufficient depth are ignored.
//
// Session Management:
// If the file qualifies for session processing:
//  1. The session ID is extracted from the file path
//  2. An existing session is retrieved or a new one is created
//  3. The file is added to the session's pending files list
//
// Parameters:
//   - file: Full filesystem path to the file being scanned
//   - sha256: SHA256 hash of the file content
//
// Returns:
//   - *gdetect.Result: Always returns nil (no scan result override)
func (p *SessionPlugin) OnStartScanFile(file string, sha256 string) *gdetect.Result {
	sessionID := p.getSessionID(file)
	if sessionID == "" {
		// File is not within a session directory
		return nil
	}

	session := p.getOrCreateSession(sessionID, file)
	if session != nil {
		session.addFile(file, sha256)
		p.logger.Debug("File added to session",
			"file_path", file,
			"session_id", sessionID,
			"sha256", sha256)
	}

	return nil
}

// OnFileScanned implements the plugins.OnFileScanned callback interface.
//
// This method is called by the host connector when file scanning completes,
// whether successfully or with errors. It updates the corresponding file
// entry in the session to mark it as completed and record any errors.
//
// Processing Flow:
//  1. Determines the session ID from the file path
//  2. Locates the existing session (if any)
//  3. Marks the file as completed in the session's pending files
//  4. Records any error that occurred during scanning
//  5. Updates the session's last activity timestamp
//
// Error Handling:
// Both successful scans and failed scans are recorded. The error parameter
// captures any issues that occurred during the scanning process, allowing
// the session to maintain a complete record of all file processing attempts.
//
// Parameters:
//   - file: Full filesystem path to the file that was scanned
//   - sha256: SHA256 hash of the file content
//   - result: Scan result from the detection engine (currently unused)
//   - err: Any error that occurred during scanning (nil if successful)
func (p *SessionPlugin) OnFileScanned(file string, sha256 string, result gdetect.Result, err error) {
	sessionID := p.getSessionID(file)
	if sessionID == "" {
		return
	}

	session := p.getSession(sessionID)
	if session != nil {
		session.markFileCompleted(file, err)
		if err != nil {
			p.logger.Warn("File scan completed with error",
				"file_path", file,
				"session_id", sessionID,
				"error", err)
		} else {
			p.logger.Debug("File scan completed successfully",
				"file_path", file,
				"session_id", sessionID)
		}
	}
}

// OnReport implements the plugins.OnReport callback interface.
//
// This method is called by the host connector when a scan report is generated
// for a file. It adds the report to the appropriate session's collection of
// completed reports, which will be used for final session reporting.
//
// Report Aggregation:
// Reports are collected per session to enable consolidated reporting when
// the session closes. This allows users to receive a single comprehensive
// report covering all files processed in a session rather than individual
// file reports.
//
// Processing Flow:
//  1. Determines the session ID from the report's file name
//  2. Locates the existing session (if any)
//  3. Adds the report to the session's completed reports collection
//  4. Updates the session's last activity timestamp
//
// Report Usage:
// The collected reports are used when the session closes to generate a
// consolidated session report through the host connector's report generation
// system. Individual reports remain available for detailed analysis.
//
// Parameters:
//   - rep: Pointer to the scan report containing results and metadata
func (p *SessionPlugin) OnReport(rep *report.Report) {
	sessionID := p.getSessionID(rep.FileName)
	if sessionID == "" {
		return
	}

	session := p.getSession(sessionID)
	if session != nil {
		session.addReport(*rep)
		p.logger.Debug("Report added to session",
			"file_name", rep.FileName,
			"session_id", sessionID,
			"malicious", rep.Malicious,
			"sha256", rep.Sha256)
	}
}

// getSessionID extracts the session ID from a file path based on the configured depth
func (p *SessionPlugin) getSessionID(filePath string) string {
	if !strings.HasPrefix(filePath, p.config.RootFolder) {
		return ""
	}

	relPath, err := filepath.Rel(p.config.RootFolder, filePath)
	if err != nil {
		return ""
	}

	parts := strings.Split(relPath, string(filepath.Separator))
	// Remove the filename (last part) to get only directory parts
	if len(parts) <= p.config.Depth {
		return ""
	}

	// Build session ID from the first 'depth' directory parts (excluding filename)
	sessionParts := parts[:p.config.Depth]
	return strings.Join(sessionParts, "/")
}

// getOrCreateSession retrieves an existing session or creates a new one
func (p *SessionPlugin) getOrCreateSession(sessionID, _ string) *Session {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	session, exists := p.sessions[sessionID]
	if !exists {
		sessionPath := filepath.Join(p.config.RootFolder, sessionID)
		session = &Session{
			ID:               sessionID,
			Path:             sessionPath,
			StartTime:        time.Now(),
			LastActivity:     time.Now(),
			PendingFiles:     make(map[string]*FileEntry),
			CompletedReports: make([]report.Report, 0),
		}
		p.sessions[sessionID] = session
		p.logger.Info("New session created",
			"session_id", sessionID,
			"session_path", sessionPath,
			"start_time", session.StartTime)
	}

	return session
}

// getSession retrieves an existing session
func (p *SessionPlugin) getSession(sessionID string) *Session {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.sessions[sessionID]
}

// addFile adds a file to the session's pending list
func (s *Session) addFile(filePath, sha256 string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.PendingFiles[filePath] = &FileEntry{
		FilePath:  filePath,
		SHA256:    sha256,
		StartTime: time.Now(),
		Completed: false,
	}
	s.LastActivity = time.Now()
}

// markFileCompleted marks a file as completed and moves it from pending to completed
func (s *Session) markFileCompleted(filePath string, err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if entry, exists := s.PendingFiles[filePath]; exists {
		entry.Completed = true
		entry.Error = err
		s.LastActivity = time.Now()
	}
}

// addReport adds a completed report to the session
func (s *Session) addReport(rep report.Report) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.CompletedReports = append(s.CompletedReports, rep)
	s.LastActivity = time.Now()
}

// isReadyForClosure checks if a session is ready to be closed
func (s *Session) isReadyForClosure(delay time.Duration) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Check if all files are completed
	for _, file := range s.PendingFiles {
		if !file.Completed {
			return false
		}
	}

	// Check if enough time has passed since last activity
	return time.Since(s.LastActivity) >= delay
}

// sessionMonitor runs in the background to monitor and close inactive sessions
func (p *SessionPlugin) sessionMonitor() {
	ticker := time.NewTicker(5 * time.Second) // Check every 5 seconds
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.checkAndCloseSessions()
		}
	}
}

// checkAndCloseSessions checks all sessions and closes those that are ready
func (p *SessionPlugin) checkAndCloseSessions() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for sessionID, session := range p.sessions {
		if session.isReadyForClosure(p.config.Delay) {
			p.closeSession(sessionID, session)
			delete(p.sessions, sessionID)
		}
	}
}

// closeSession closes a session by generating a report and cleaning up files
func (p *SessionPlugin) closeSession(sessionID string, session *Session) {
	p.logger.Info("Closing session",
		"session_id", sessionID,
		"completed_reports", len(session.CompletedReports),
		"pending_files", len(session.PendingFiles),
		"duration", time.Since(session.StartTime))

	// Generate session report
	if len(session.CompletedReports) > 0 {
		p.generateSessionReport(session)
	}

	// Clean up files if configured
	if p.config.RemoveInputs {
		p.cleanupSessionFiles(session)
	}
}

// generateSessionReport generates a final report for the session
func (p *SessionPlugin) generateSessionReport(session *Session) {
	if p.hcc == nil {
		return
	}

	reportContext := report.ScanContext{
		ScanID: fmt.Sprintf("session-%s-%d", session.ID, session.StartTime.Unix()),
		Start:  session.StartTime,
		End:    time.Now(),
	}

	reader, err := p.hcc.GenerateReport(reportContext, session.CompletedReports)
	if err != nil {
		p.logger.Error("Failed to generate session report",
			"session_id", session.ID,
			"error", err)
		return
	}

	// Save report to session directory
	reportPath := filepath.Join(session.Path, fmt.Sprintf("session-report-%d.pdf", time.Now().Unix()))
	if err := p.saveReport(reader, reportPath); err != nil {
		p.logger.Error("Failed to save session report",
			"session_id", session.ID,
			"report_path", reportPath,
			"error", err)
	} else {
		p.logger.Info("Session report saved",
			"session_id", session.ID,
			"report_path", reportPath)
	}
}

// saveReport saves a report reader to a file
func (p *SessionPlugin) saveReport(reader io.Reader, filePath string) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return err
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, reader)
	return err
}

// cleanupSessionFiles removes files from the session directory
func (p *SessionPlugin) cleanupSessionFiles(session *Session) {
	session.mutex.RLock()
	defer session.mutex.RUnlock()

	for filePath := range session.PendingFiles {
		if err := os.Remove(filePath); err != nil {
			p.logger.Warn("Failed to remove session file",
				"file_path", filePath,
				"session_id", session.ID,
				"error", err)
		} else {
			p.logger.Debug("Removed session file",
				"file_path", filePath,
				"session_id", session.ID)
		}
	}

	// Try to remove the session directory if it's empty
	if err := os.Remove(session.Path); err != nil {
		p.logger.Debug("Failed to remove session directory",
			"session_path", session.Path,
			"session_id", session.ID,
			"error", err)
	} else {
		p.logger.Debug("Removed session directory",
			"session_path", session.Path,
			"session_id", session.ID)
	}
}

func main() {}
