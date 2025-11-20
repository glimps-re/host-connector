package main

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
	"github.com/google/go-cmp/cmp"
)

func TestSessionPlugin_Init(t *testing.T) {
	tests := []struct {
		name       string
		config     any
		wantConfig Config
		wantErr    bool
	}{
		{
			name: "init config",
			config: &Config{
				Depth:        2,
				Delay:        time.Second,
				RemoveInputs: true,
				RootFolder:   "/tmp",
			},
			wantErr: false,
			wantConfig: Config{
				Depth:        2,
				Delay:        time.Second,
				RemoveInputs: true,
				RootFolder:   "/tmp",
			},
		},
		{
			name:    "bad config struct",
			config:  struct{}{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &SessionPlugin{}
			mockContext := mock.NewMockHCContext()
			err := plugin.Init(tt.config, mockContext)
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionPlugin.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if diff := cmp.Diff(plugin.config, tt.wantConfig); diff != "" {
					t.Errorf("SessionPlugin.Init() config diff(got-want)=%s", diff)
				}
				if plugin.sessions == nil {
					t.Error("SessionPlugin.Init() sessions map should be initialized")
				}
				if mockContext.OnStartScanFile == nil {
					t.Error("SessionPlugin.Init() should register OnStartScanFile callback")
				}
				if mockContext.OnFileScanned == nil {
					t.Error("SessionPlugin.Init() should register OnFileScanned callback")
				}
				if mockContext.OnReport == nil {
					t.Error("SessionPlugin.Init() should register OnReport callback")
				}
			}
		})
	}
}

func TestSessionPlugin_Close(t *testing.T) {
	plugin := &SessionPlugin{}
	mockContext := mock.NewMockHCContext()

	// Initialize plugin
	err := plugin.Init(plugin.GetDefaultConfig(), mockContext)
	if err != nil {
		t.Fatalf("Failed to initialize plugin: %v", err)
	}

	// Test close
	err = plugin.Close(context.Background())
	if err != nil {
		t.Errorf("SessionPlugin.Close() error = %v, want nil", err)
	}
}

func TestSessionPlugin_SessionManagement(t *testing.T) {
	// Create temporary directory for testing
	tmpDir := t.TempDir()
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
	}

	// Test creating session
	sessionID := "user_a/subdir"
	filePath := filepath.Join(tmpDir, "user_a/subdir/test.txt")

	session, created := plugin.getSession(filePath, true)
	if session == nil {
		t.Fatal("getOrCreateSession should return a session")
		return
	}

	if !created {
		t.Fatal("getOrCreateSession should create a session")
		return
	}

	if session.ID != sessionID {
		t.Errorf("Session ID = %v, want %v", session.ID, sessionID)
	}

	// Test adding file to session
	session.addFile(filePath, "sha256hash")

	if len(session.TrackedFiles) != 1 {
		t.Errorf("PendingFiles length = %v, want 1", len(session.TrackedFiles))
	}

	fileEntry, exists := session.TrackedFiles[filePath]
	if !exists {
		t.Error("File should exist in PendingFiles")
	}

	if fileEntry.SHA256 != "sha256hash" {
		t.Errorf("File SHA256 = %v, want sha256hash", fileEntry.SHA256)
	}

	// Test marking file completed
	session.markFileCompleted(filePath)

	if !fileEntry.Completed {
		t.Error("File should be marked as completed")
	}

	// Test adding report
	rep := datamodel.Report{
		Filename:  filePath,
		SHA256:    "sha256hash",
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
	tmpDir := t.TempDir()
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
			plugin.OnStartScanFile(tt.filePath, "sha256hash")

			if tt.expectSession {
				session, _ := plugin.getSession(tt.filePath, false)
				if session == nil {
					t.Error("Session should be created")
				} else {
					if session.ID != tt.expectedSessID {
						t.Errorf("want session ID %s, got %s", tt.expectedSessID, session.ID)
					}
					if _, exists := session.TrackedFiles[tt.filePath]; !exists {
						t.Error("File should be added to session")
					}
				}
			}
		})
	}
}

func TestSessionPlugin_OnFileScanned(t *testing.T) {
	tmpDir := t.TempDir()
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
	}

	filePath := filepath.Join(tmpDir, "user_a/subdir/test.txt")

	// First add the file to a session
	plugin.OnStartScanFile(filePath, "sha256hash")

	// Test OnFileScanned
	plugin.OnFileScanned(filePath, "sha256hash", datamodel.Result{})

	session, _ := plugin.getSession(filePath, false)
	if session == nil {
		t.Fatal("Session should exist")
		return
	}

	fileEntry := session.TrackedFiles[filePath]
	if fileEntry == nil {
		t.Fatal("File entry should exist")
		return
	}

	if !fileEntry.Completed {
		t.Error("File should be marked as completed")
	}
}

func TestSessionPlugin_OnReport(t *testing.T) {
	tmpDir := t.TempDir()
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
	}

	filePath := filepath.Join(tmpDir, "user_a/subdir/test.txt")

	// First add the file to a session
	plugin.OnStartScanFile(filePath, "sha256hash")

	// Test OnReport
	rep := &datamodel.Report{
		Filename:  filePath,
		SHA256:    "sha256hash",
		Malicious: false,
	}
	plugin.OnReport(rep)

	session, _ := plugin.getSession(filePath, false)
	if session == nil {
		t.Fatal("session should exist")
		return
	}

	if len(session.CompletedReports) != 1 {
		t.Errorf("CompletedReports length = %v, want 1", len(session.CompletedReports))
	}

	if session.CompletedReports[0].Filename != filePath {
		t.Errorf("Report filename = %v, want %v", session.CompletedReports[0].Filename, filePath)
	}
}

func TestSessionPlugin_IntegrationWorkflow(t *testing.T) {
	tmpDir := t.TempDir()
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Logf("Warning: failed to remove temp dir %s: %v", tmpDir, err)
		}
	}()

	plugin := &SessionPlugin{}
	mockContext := mock.NewMockHCContext()

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
	plugin.stop = make(chan struct{})

	mockContext.RegisterOnStartScanFile(plugin.OnStartScanFile)
	mockContext.RegisterOnFileScanned(plugin.OnFileScanned)
	mockContext.RegisterOnReport(plugin.OnReport)

	// Create test files
	userDir := filepath.Join(tmpDir, "user_a", "batch1")
	if err := os.MkdirAll(userDir, 0o750); err != nil {
		t.Fatalf("Failed to create user dir: %v", err)
	}

	file1 := filepath.Join(userDir, "test1.txt")
	file2 := filepath.Join(userDir, "test2.txt")

	if err := os.WriteFile(file1, []byte("test content 1"), 0o600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	if err := os.WriteFile(file2, []byte("test content 2"), 0o600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Simulate scanning workflow
	// 1. Start scanning files
	plugin.OnStartScanFile(file1, "hash1")
	plugin.OnStartScanFile(file2, "hash2")

	// Verify session was created
	session, _ := plugin.getSession(file1, false)
	if session == nil {
		t.Fatal("Session should be created")
		return
	}

	if len(session.TrackedFiles) != 2 {
		t.Errorf("Should have 2 pending files, got %d", len(session.TrackedFiles))
	}

	// 2. Complete scanning
	plugin.OnFileScanned(file1, "hash1", datamodel.Result{})
	plugin.OnFileScanned(file2, "hash2", datamodel.Result{})

	// 3. Generate reports
	plugin.OnReport(&datamodel.Report{
		Filename:  file1,
		SHA256:    "hash1",
		Malicious: false,
	})
	plugin.OnReport(&datamodel.Report{
		Filename:  file2,
		SHA256:    "hash2",
		Malicious: true,
		Malwares:  []string{"Test.Malware"},
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
	for _, fileEntry := range session.TrackedFiles {
		if !fileEntry.Completed {
			t.Error("All files should be completed")
		}
	}
}

func TestSessionPlugin_Interface(t *testing.T) {
	// Test that SessionPlugin implements the Plugin interface
	var _ plugins.Plugin = &SessionPlugin{}
}

func TestSessionPlugin_getSession(t *testing.T) {
	type fields struct {
		storedSessions map[string]*Session
		config         *Config
	}
	tests := []struct {
		name   string // description of this test case
		fields fields

		// Named input parameters for target function.
		filePath    string
		ensure      bool
		wantSession bool
		wantID      string
	}{
		{
			name: "ok insufficient depth",
			fields: fields{
				config: &Config{
					RootFolder: "/root/folder/",
					Depth:      4,
					Delay:      time.Second,
				},
			},
			filePath:    "/root/folder/user_a/file2",
			ensure:      true,
			wantSession: false,
		},
		{
			name: "ok different root",
			fields: fields{
				config: &Config{
					RootFolder: "/root/other_folder/",
					Depth:      2,
					Delay:      time.Second,
				},
			},
			filePath:    "/root/folder/user_a/file2",
			ensure:      true,
			wantSession: false,
		},
		{
			name: "ok different root 2",
			fields: fields{
				config: &Config{
					RootFolder: "/root/folder/",
					Depth:      2,
					Delay:      time.Second,
				},
			},
			filePath:    "/root/folder_2/user_a/file2",
			ensure:      true,
			wantSession: false,
		},
		{
			name: "ok create",
			fields: fields{
				config: &Config{
					RootFolder: "/root/folder/",
					Depth:      1,
					Delay:      time.Second,
				},
			},
			filePath:    "/root/folder/user_a/file2",
			ensure:      true,
			wantSession: true,
			wantID:      "user_a",
		},
		{
			name: "ok no session",
			fields: fields{
				config: &Config{
					RootFolder: "/root/folder/",
					Depth:      1,
					Delay:      time.Second,
				},
			},
			filePath:    "/root/folder/user_a/file2",
			ensure:      false,
			wantSession: false,
		},
		{
			name: "ok present session",
			fields: fields{
				config: &Config{
					RootFolder: "/root/folder/",
					Depth:      1,
					Delay:      time.Second,
				},
				storedSessions: map[string]*Session{
					"user_a": {
						ID: "user_a",
					},
				},
			},
			filePath:    "/root/folder/user_a/file2",
			ensure:      false,
			wantSession: true,
			wantID:      "user_a",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &SessionPlugin{}
			mockContext := mock.NewMockHCContext()
			err := plugin.Init(tt.fields.config, mockContext)
			if err != nil {
				t.Fatalf("could not init plugin")
			}
			maps.Copy(plugin.sessions, tt.fields.storedSessions)

			got, _ := plugin.getSession(tt.filePath, tt.ensure)
			if tt.wantSession != (got != nil) {
				t.Errorf("getSession() want session = %v, got=%v", tt.wantSession, got)
			}
			if got == nil {
				return
			}
			if got.ID != tt.wantID {
				t.Errorf("getSession() want session ID %s, got %s", tt.wantID, got.ID)
			}
		})
	}
}
