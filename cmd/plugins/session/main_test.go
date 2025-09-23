package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/report"
)

// mockHCContext is a mock implementation of plugins.HCContext for testing
type mockHCContext struct {
	onStartScanFile    plugins.OnStartScanFile
	onFileScanned      plugins.OnFileScanned
	onReport           plugins.OnReport
	generateReportFunc plugins.GenerateReport
	logger             *slog.Logger
}

func newMockHCContext() *mockHCContext {
	return &mockHCContext{
		logger: slog.Default(),
	}
}

func (m *mockHCContext) SetXTractFile(f plugins.XtractFileFunc)            {}
func (m *mockHCContext) RegisterOnStartScanFile(f plugins.OnStartScanFile) { m.onStartScanFile = f }
func (m *mockHCContext) RegisterOnFileScanned(f plugins.OnFileScanned)     { m.onFileScanned = f }
func (m *mockHCContext) RegisterOnReport(f plugins.OnReport)               { m.onReport = f }
func (m *mockHCContext) RegisterGenerateReport(f plugins.GenerateReport)   { m.generateReportFunc = f }
func (m *mockHCContext) GetLogger() *slog.Logger                           { return m.logger }
func (m *mockHCContext) GenerateReport(reportContext report.ScanContext, reports []report.Report) (io.Reader, error) {
	if m.generateReportFunc != nil {
		return m.generateReportFunc(reportContext, reports)
	}
	return strings.NewReader("mock report content"), nil
}

func TestSessionPlugin_Init(t *testing.T) {
	tests := []struct {
		name        string
		configPath  string
		wantErr     bool
		expectDepth int
	}{
		{
			name:        "init with default config",
			configPath:  "",
			wantErr:     false,
			expectDepth: 2,
		},
		{
			name:       "init with invalid config path",
			configPath: "/invalid/path/config.yml",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &SessionPlugin{}
			mockContext := newMockHCContext()

			err := plugin.Init(tt.configPath, mockContext)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionPlugin.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if plugin.config.Depth != tt.expectDepth {
					t.Errorf("SessionPlugin.Init() depth = %v, want %v", plugin.config.Depth, tt.expectDepth)
				}
				if plugin.sessions == nil {
					t.Error("SessionPlugin.Init() sessions map should be initialized")
				}
				if mockContext.onStartScanFile == nil {
					t.Error("SessionPlugin.Init() should register OnStartScanFile callback")
				}
				if mockContext.onFileScanned == nil {
					t.Error("SessionPlugin.Init() should register OnFileScanned callback")
				}
				if mockContext.onReport == nil {
					t.Error("SessionPlugin.Init() should register OnReport callback")
				}
			}

			// Clean up
			if plugin.cancel != nil {
				plugin.cancel()
			}
		})
	}
}

func TestSessionPlugin_Close(t *testing.T) {
	plugin := &SessionPlugin{}
	mockContext := newMockHCContext()

	// Initialize plugin
	err := plugin.Init("", mockContext)
	if err != nil {
		t.Fatalf("Failed to initialize plugin: %v", err)
	}

	// Test close
	err = plugin.Close(context.Background())
	if err != nil {
		t.Errorf("SessionPlugin.Close() error = %v, want nil", err)
	}
}

func TestSessionPlugin_getSessionID(t *testing.T) {
	plugin := &SessionPlugin{
		config: Config{
			RootFolder: "/tmp/samples",
			Depth:      2,
		},
	}

	tests := []struct {
		name     string
		filePath string
		want     string
	}{
		{
			name:     "valid session path depth 2",
			filePath: "/tmp/samples/user_a/subdir/file.txt",
			want:     "user_a/subdir",
		},
		{
			name:     "insufficient depth - only 2 parts",
			filePath: "/tmp/samples/user_a/file.txt",
			want:     "",
		},
		{
			name:     "file outside root folder",
			filePath: "/other/path/file.txt",
			want:     "",
		},
		{
			name:     "file directly in root folder",
			filePath: "/tmp/samples/file.txt",
			want:     "",
		},
		{
			name:     "insufficient depth",
			filePath: "/tmp/samples/user_a",
			want:     "",
		},
	}

	// Test with depth 1
	plugin.config.Depth = 1
	if got := plugin.getSessionID("/tmp/samples/user_a/file.txt"); got != "user_a" {
		t.Errorf("getSessionID() with depth 1 = %v, want user_a", got)
	}

	// Test with depth 2
	plugin.config.Depth = 2
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := plugin.getSessionID(tt.filePath)
			if got != tt.want {
				t.Errorf("SessionPlugin.getSessionID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSessionPlugin_SessionManagement(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "session_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Logf("Warning: failed to remove temp dir %s: %v", tmpDir, err)
		}
	}()

	plugin := &SessionPlugin{
		config: Config{
			RootFolder: tmpDir,
			Depth:      2,
			Delay:      100 * time.Millisecond,
		},
		sessions: make(map[string]*Session),
		logger:   slog.Default(),
	}

	// Test creating session
	sessionID := "user_a/subdir"
	filePath := filepath.Join(tmpDir, "user_a/subdir/test.txt")

	session := plugin.getOrCreateSession(sessionID, filePath)
	if session == nil {
		t.Fatal("getOrCreateSession should return a session")
	}

	if session.ID != sessionID {
		t.Errorf("Session ID = %v, want %v", session.ID, sessionID)
	}

	// Test adding file to session
	session.addFile(filePath, "sha256hash")

	if len(session.PendingFiles) != 1 {
		t.Errorf("PendingFiles length = %v, want 1", len(session.PendingFiles))
	}

	fileEntry, exists := session.PendingFiles[filePath]
	if !exists {
		t.Error("File should exist in PendingFiles")
	}

	if fileEntry.SHA256 != "sha256hash" {
		t.Errorf("File SHA256 = %v, want sha256hash", fileEntry.SHA256)
	}

	// Test marking file completed
	session.markFileCompleted(filePath, nil)

	if !fileEntry.Completed {
		t.Error("File should be marked as completed")
	}

	// Test adding report
	rep := report.Report{
		FileName:  filePath,
		Sha256:    "sha256hash",
		Malicious: false,
	}
	session.addReport(rep)

	if len(session.CompletedReports) != 1 {
		t.Errorf("CompletedReports length = %v, want 1", len(session.CompletedReports))
	}

	// Test session ready for closure
	time.Sleep(150 * time.Millisecond) // Wait longer than delay
	if !session.isReadyForClosure(plugin.config.Delay) {
		t.Error("Session should be ready for closure")
	}
}

func TestSessionPlugin_OnStartScanFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "session_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Logf("Warning: failed to remove temp dir %s: %v", tmpDir, err)
		}
	}()

	plugin := &SessionPlugin{
		config: Config{
			RootFolder: tmpDir,
			Depth:      2,
		},
		sessions: make(map[string]*Session),
		logger:   slog.Default(),
	}

	tests := []struct {
		name           string
		filePath       string
		expectSession  bool
		expectedSessID string
	}{
		{
			name:           "valid session file",
			filePath:       filepath.Join(tmpDir, "user_a/subdir/test.txt"),
			expectSession:  true,
			expectedSessID: "user_a/subdir",
		},
		{
			name:          "file outside session",
			filePath:      "/other/path/test.txt",
			expectSession: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.OnStartScanFile(tt.filePath, "sha256hash")

			// Should always return nil (no override)
			if result != nil {
				t.Errorf("OnStartScanFile should return nil, got %v", result)
			}

			if tt.expectSession {
				session := plugin.getSession(tt.expectedSessID)
				if session == nil {
					t.Error("Session should be created")
				} else {
					if _, exists := session.PendingFiles[tt.filePath]; !exists {
						t.Error("File should be added to session")
					}
				}
			}
		})
	}
}

func TestSessionPlugin_OnFileScanned(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "session_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Logf("Warning: failed to remove temp dir %s: %v", tmpDir, err)
		}
	}()

	plugin := &SessionPlugin{
		config: Config{
			RootFolder: tmpDir,
			Depth:      2,
		},
		sessions: make(map[string]*Session),
		logger:   slog.Default(),
	}

	filePath := filepath.Join(tmpDir, "user_a/subdir/test.txt")
	sessionID := "user_a/subdir"

	// First add the file to a session
	plugin.OnStartScanFile(filePath, "sha256hash")

	// Test OnFileScanned
	plugin.OnFileScanned(filePath, "sha256hash", gdetect.Result{}, nil)

	session := plugin.getSession(sessionID)
	if session == nil {
		t.Fatal("Session should exist")
	}

	fileEntry := session.PendingFiles[filePath]
	if fileEntry == nil {
		t.Fatal("File entry should exist")
	}

	if !fileEntry.Completed {
		t.Error("File should be marked as completed")
	}
}

func TestSessionPlugin_OnReport(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "session_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Logf("Warning: failed to remove temp dir %s: %v", tmpDir, err)
		}
	}()

	plugin := &SessionPlugin{
		config: Config{
			RootFolder: tmpDir,
			Depth:      2,
		},
		sessions: make(map[string]*Session),
		logger:   slog.Default(),
	}

	filePath := filepath.Join(tmpDir, "user_a/subdir/test.txt")
	sessionID := "user_a/subdir"

	// First add the file to a session
	plugin.OnStartScanFile(filePath, "sha256hash")

	// Test OnReport
	rep := &report.Report{
		FileName:  filePath,
		Sha256:    "sha256hash",
		Malicious: false,
	}
	plugin.OnReport(rep)

	session := plugin.getSession(sessionID)
	if session == nil {
		t.Fatal("Session should exist")
	}

	if len(session.CompletedReports) != 1 {
		t.Errorf("CompletedReports length = %v, want 1", len(session.CompletedReports))
	}

	if session.CompletedReports[0].FileName != filePath {
		t.Errorf("Report filename = %v, want %v", session.CompletedReports[0].FileName, filePath)
	}
}

func TestSessionPlugin_IntegrationWorkflow(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "session_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Logf("Warning: failed to remove temp dir %s: %v", tmpDir, err)
		}
	}()

	plugin := &SessionPlugin{}
	mockContext := newMockHCContext()

	// Override config for testing
	config := Config{
		RootFolder:   tmpDir,
		Depth:        2,
		Delay:        50 * time.Millisecond,
		RemoveInputs: false, // Don't remove files in test
	}

	// Initialize manually with test config
	plugin.config = config
	plugin.sessions = make(map[string]*Session)
	plugin.hcc = mockContext
	plugin.logger = mockContext.GetLogger()
	plugin.ctx, plugin.cancel = context.WithCancel(context.Background())
	defer plugin.cancel()

	mockContext.RegisterOnStartScanFile(plugin.OnStartScanFile)
	mockContext.RegisterOnFileScanned(plugin.OnFileScanned)
	mockContext.RegisterOnReport(plugin.OnReport)

	// Create test files
	userDir := filepath.Join(tmpDir, "user_a", "batch1")
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		t.Fatalf("Failed to create user dir: %v", err)
	}

	file1 := filepath.Join(userDir, "test1.txt")
	file2 := filepath.Join(userDir, "test2.txt")

	if err := os.WriteFile(file1, []byte("test content 1"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	if err := os.WriteFile(file2, []byte("test content 2"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Simulate scanning workflow
	// 1. Start scanning files
	plugin.OnStartScanFile(file1, "hash1")
	plugin.OnStartScanFile(file2, "hash2")

	// Verify session was created
	sessionID := "user_a/batch1"
	session := plugin.getSession(sessionID)
	if session == nil {
		t.Fatal("Session should be created")
	}

	if len(session.PendingFiles) != 2 {
		t.Errorf("Should have 2 pending files, got %d", len(session.PendingFiles))
	}

	// 2. Complete scanning
	plugin.OnFileScanned(file1, "hash1", gdetect.Result{}, nil)
	plugin.OnFileScanned(file2, "hash2", gdetect.Result{}, nil)

	// 3. Generate reports
	plugin.OnReport(&report.Report{
		FileName:  file1,
		Sha256:    "hash1",
		Malicious: false,
	})
	plugin.OnReport(&report.Report{
		FileName:  file2,
		Sha256:    "hash2",
		Malicious: true,
		Malware:   []string{"Test.Malware"},
	})

	// Verify reports were added
	if len(session.CompletedReports) != 2 {
		t.Errorf("Should have 2 completed reports, got %d", len(session.CompletedReports))
	}

	// 4. Wait for session to be ready for closure
	time.Sleep(100 * time.Millisecond)

	if !session.isReadyForClosure(plugin.config.Delay) {
		t.Error("Session should be ready for closure")
	}

	// Verify all files are completed
	for _, fileEntry := range session.PendingFiles {
		if !fileEntry.Completed {
			t.Error("All files should be completed")
		}
	}
}

func TestSessionPlugin_Interface(t *testing.T) {
	// Test that SessionPlugin implements the Plugin interface
	var _ plugins.Plugin = &SessionPlugin{}
}
