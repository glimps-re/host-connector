// Package main implements a session-based file grouping and reporting plugin.
//
// Groups files by directory structure, tracks their processing, and generates
// consolidated reports per session with optional file cleanup.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

var (
	logger        = slog.New(slog.DiscardHandler)
	consoleLogger = slog.New(slog.DiscardHandler)
)

// SessionPlugin groups files into sessions based on directory structure.
type SessionPlugin struct {
	config   Config
	sessions map[string]*Session
	mutex    sync.RWMutex
	hcc      plugins.HCContext
	stop     chan struct{}
	started  bool
}

// Config defines session behavior and directory monitoring settings.
type Config struct {
	Depth      int           `mapstructure:"depth"`
	Delay      time.Duration `mapstructure:"delay"`
	RootFolder string        `mapstructure:"root_folder"`
	Exports    []string      `mapstructure:"exports"`
}

// Session tracks files and reports for a specific directory.
type Session struct {
	ID               string
	RefPath          string
	Paths            []string
	StartTime        time.Time
	LastActivity     time.Time
	TrackedFiles     map[string]*FileEntry
	CompletedReports []datamodel.Report
	mutex            sync.RWMutex
}

// FileEntry tracks individual file scanning state within a session.
type FileEntry struct {
	FilePath  string
	SHA256    string
	StartTime time.Time
	Completed bool
}

var (
	_ plugins.Plugin = &SessionPlugin{}

	// HCPlugin is the exported plugin instance.
	HCPlugin SessionPlugin
)

const (
	sessionIDLogKey      = "session_id"
	sessionRefPathLogKey = "ref_path"
	filepathLogKey       = "file_path"
)

func (p *SessionPlugin) GetDefaultConfig() (config any) {
	config = &Config{
		Depth: 1,
		Delay: 15 * time.Minute,
	}
	return
}

// Init initializes the plugin, registers callbacks, and starts session monitoring.
func (p *SessionPlugin) Init(rawConfig any, hcc plugins.HCContext) error {
	config, ok := rawConfig.(*Config)
	if !ok {
		return fmt.Errorf("bad config passed to session plugin: %v", config)
	}

	p.config = *config
	p.sessions = make(map[string]*Session)
	p.hcc = hcc
	p.stop = make(chan struct{})
	logger = hcc.GetLogger().With(slog.String("plugin", "session"))
	consoleLogger = hcc.GetConsoleLogger()

	hcc.RegisterOnStartScanFile(p.OnStartScanFile)
	hcc.RegisterWithWaitForOptions(p.WaitForOptions)
	hcc.RegisterOnFileScanned(p.OnFileScanned)
	hcc.RegisterOnReport(p.OnReport)

	go p.sessionMonitor()

	logger.Info("plugin initialized",
		slog.Int("depth", config.Depth),
		slog.String("delay", config.Delay.String()),
		slog.String("root_folder", config.RootFolder),
	)
	consoleLogger.Info(fmt.Sprintf("session plugin initialized, depth: %d, delay: %s, root_folder: %s",
		config.Depth, config.Delay.String(), config.RootFolder))
	p.started = true
	return nil
}

// Close stops session monitoring and waits briefly for cleanup.
func (p *SessionPlugin) Close(ctx context.Context) error {
	if !p.started {
		return nil
	}
	close(p.stop)
	select {
	case <-time.After(1 * time.Second):
	case <-ctx.Done():
	}
	p.started = false
	return nil
}

// OnStartScanFile adds files to their appropriate sessions based on directory path.
func (p *SessionPlugin) OnStartScanFile(file string, sha256 string) {
	session, created := p.getSession(file, true)
	if session != nil {
		logger.Debug("start scan", slog.String("rep filename", file))
		session.addFile(file, sha256)
		logger.Debug("file added to session",
			slog.String(filepathLogKey, file),
			slog.String(sessionRefPathLogKey, session.RefPath),
			slog.String(sessionIDLogKey, session.ID),
			slog.String("sha256", sha256),
		)
		if created {
			consoleLogger.Info(fmt.Sprintf("session %s:%s started", session.RefPath, session.ID))
		}
	}
}

func (p *SessionPlugin) WaitForOptions(opts *gdetect.WaitForOptions, location string) {
	session, _ := p.getSession(location, false)
	if session == nil {
		return
	}
	opts.Tags = append(opts.Tags, "session:"+session.RefPath+":"+session.ID)
}

// OnFileScanned marks files as completed in their sessions.
func (p *SessionPlugin) OnFileScanned(file string, sha256 string, result datamodel.Result) (newResult *datamodel.Result) {
	session, _ := p.getSession(file, false)
	if session == nil {
		return
	}

	session.markFileCompleted(file)
	if result.Error != nil {
		logger.Warn("file scan completed with error",
			slog.String(filepathLogKey, file),
			slog.String(sessionRefPathLogKey, session.RefPath),
			slog.String(sessionIDLogKey, session.ID),
			slog.Any("error", result.Error.Error()),
		)
		return
	}
	logger.Debug("file scan completed successfully",
		slog.String(filepathLogKey, file),
		slog.String(sessionRefPathLogKey, session.RefPath),
		slog.String(sessionIDLogKey, session.ID),
	)
	return
}

// OnReport adds scan reports to their sessions for consolidated reporting.
func (p *SessionPlugin) OnReport(rep *datamodel.Report) {
	session, _ := p.getSession(rep.Filename, false)
	if session == nil {
		return
	}

	session.addReport(*rep)
	logger.Debug("report added to session",
		slog.String(filepathLogKey, rep.Filename),
		slog.String(sessionRefPathLogKey, session.RefPath),
		slog.String(sessionIDLogKey, session.ID),
		slog.Bool("malicious", rep.Malicious),
		slog.String("sha256", rep.SHA256),
	)
	consoleLogger.Debug(fmt.Sprintf("add report for %s to session %s:%s (malicious: %v)", rep.Filename, session.RefPath, session.ID, rep.Malicious))
}

func (p *SessionPlugin) getSession(filePath string, ensure bool) (session *Session, created bool) {
	if !strings.HasPrefix(filePath, p.config.RootFolder) {
		return
	}

	relPath, err := filepath.Rel(p.config.RootFolder, filePath)
	if err != nil {
		return
	}

	parts := strings.Split(relPath, string(filepath.Separator))
	// Remove the filename (last part) to get only directory parts
	if len(parts) <= p.config.Depth {
		return
	}

	// Build session ID from the first 'depth' directory parts (excluding filename)
	sessionParts := parts[:p.config.Depth]
	refPath := strings.Join(sessionParts, "/")

	p.mutex.Lock()
	defer p.mutex.Unlock()
	session, exists := p.sessions[refPath]
	switch {
	case exists:
		return
	case ensure:
		created = true
		sessionPaths := make([]string, 0, len(p.config.Exports))
		for _, v := range p.config.Exports {
			sessionPaths = append(sessionPaths, filepath.Join(v, refPath))
		}

		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return
		}
		session = &Session{
			ID:               hex.EncodeToString(b),
			RefPath:          refPath,
			Paths:            sessionPaths,
			StartTime:        time.Now(),
			LastActivity:     time.Now(),
			TrackedFiles:     make(map[string]*FileEntry),
			CompletedReports: make([]datamodel.Report, 0),
		}
		p.sessions[refPath] = session
		logger.Info("new session created",
			slog.String(sessionRefPathLogKey, refPath),
			slog.String("export_paths", strings.Join(sessionPaths, ",")),
			slog.String("start_time", session.StartTime.Format(time.RFC3339)),
		)
	default:
		return
	}
	return
}

func (s *Session) addFile(filePath, sha256 string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.TrackedFiles[filePath] = &FileEntry{
		FilePath:  filePath,
		SHA256:    sha256,
		StartTime: time.Now(),
		Completed: false,
	}
	s.LastActivity = time.Now()
}

func (s *Session) markFileCompleted(filePath string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if entry, exists := s.TrackedFiles[filePath]; exists {
		entry.Completed = true
		s.LastActivity = time.Now()
	}
}

func (s *Session) addReport(rep datamodel.Report) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.CompletedReports = append(s.CompletedReports, rep)
	s.LastActivity = time.Now()
}

func (s *Session) isReadyForClosure(delay time.Duration) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, file := range s.TrackedFiles {
		if !file.Completed {
			return false
		}
	}

	return time.Since(s.LastActivity) >= delay
}

func (p *SessionPlugin) sessionMonitor() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			p.checkAndCloseSessions()
		}
	}
}

func (p *SessionPlugin) checkAndCloseSessions() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for refPath, session := range p.sessions {
		if session.isReadyForClosure(p.config.Delay) {
			p.closeSession(refPath, session)
			delete(p.sessions, refPath)
		}
	}
}

func (p *SessionPlugin) closeSession(refPath string, session *Session) {
	session.mutex.RLock()
	hasReports := len(session.CompletedReports) > 0
	session.mutex.RUnlock()

	logger.Info("closing session",
		slog.String(sessionRefPathLogKey, refPath),
		slog.Int("completed_reports", len(session.CompletedReports)),
		slog.Int("tracked_files", len(session.TrackedFiles)),
		slog.String("duration", time.Since(session.StartTime).String()))

	consoleLogger.Info(fmt.Sprintf("closing session %s (completed reports: %d, duration: %s)", refPath, len(session.CompletedReports), time.Since(session.StartTime).String()))

	if hasReports {
		p.generateSessionReport(session)
	}
}

func (p *SessionPlugin) generateSessionReport(session *Session) {
	if p.hcc == nil {
		return
	}

	reportContext := datamodel.ScanContext{
		ScanID: fmt.Sprintf("session-%s-%s-%d", session.RefPath, session.ID, session.StartTime.Unix()),
		Start:  session.StartTime,
		End:    time.Now(),
	}

	reader, err := p.hcc.GenerateReport(reportContext, session.CompletedReports)
	if err != nil {
		logger.Error("failed to generate session report",
			slog.String(sessionRefPathLogKey, session.RefPath),
			slog.String(sessionIDLogKey, session.ID),
			slog.String("error", err.Error()))
		return
	}
	reportPaths := make([]string, 0, len(session.Paths))
	for _, path := range session.Paths {
		reportPaths = append(reportPaths, filepath.Join(path, fmt.Sprintf("session-report-%d.pdf", time.Now().Unix())))
	}
	if err := p.saveReport(reader, reportPaths...); err != nil {
		logger.Error("failed to save session report",
			slog.String(sessionRefPathLogKey, session.RefPath),
			slog.String(sessionIDLogKey, session.ID),
			slog.String("report_paths", strings.Join(reportPaths, ",")),
			slog.String("error", err.Error()),
		)
		return
	}
	logger.Info("session report saved",
		slog.String(sessionRefPathLogKey, session.RefPath),
		slog.String(sessionIDLogKey, session.ID),
		slog.String("report_paths", strings.Join(reportPaths, ",")),
	)
}

func (p *SessionPlugin) saveReport(reader io.Reader, filePaths ...string) (err error) {
	if len(filePaths) == 0 {
		return
	}
	files := make([]io.Writer, 0, len(filePaths))
	for _, path := range filePaths {
		cleanPath := filepath.Clean(path)
		if e := os.MkdirAll(filepath.Dir(cleanPath), 0o750); e != nil {
			consoleLogger.Error(fmt.Sprintf("failed to create session rapport at %s, error: %s", cleanPath, e.Error()))
			logger.Error("failed to create folder for session report", slog.String("folder", filepath.Dir(cleanPath)), slog.String("error", e.Error()))
			continue
		}
		file, createErr := os.Create(path)
		if createErr != nil {
			consoleLogger.Error(fmt.Sprintf("failed to create session rapport at %s, error: %s", cleanPath, createErr.Error()))
			logger.Error("failed to create folder for session report", slog.String("folder", filepath.Dir(cleanPath)), slog.String("error", createErr.Error()))
			continue
		}
		defer func(f *os.File) {
			if e := file.Close(); e != nil {
				logger.Warn("failed to close report file",
					slog.String(filepathLogKey, f.Name()),
					slog.String("error", e.Error()),
				)
			}
		}(file)
		files = append(files, file)
	}
	mw := io.MultiWriter(files...)
	_, err = io.Copy(mw, reader)
	if err != nil {
		return
	}
	return
}

func main() {}
