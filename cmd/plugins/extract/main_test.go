package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/report"
	"golift.io/xtractr"
)

// mockHCContext is a mock implementation of plugins.HCContext for testing
type mockHCContext struct {
	onStartScanFile    plugins.OnStartScanFile
	onFileScanned      plugins.OnFileScanned
	onReport           plugins.OnReport
	generateReportFunc plugins.GenerateReport
	xtractFileFunc     plugins.XtractFileFunc
	logger             *slog.Logger
}

func newMockHCContext() *mockHCContext {
	return &mockHCContext{
		logger: slog.Default(),
	}
}

func (m *mockHCContext) SetXTractFile(f plugins.XtractFileFunc)            { m.xtractFileFunc = f }
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

func TestSevenZipExtractPlugin_Init(t *testing.T) {
	tests := []struct {
		name       string
		configPath string
		wantErr    bool
	}{
		{
			name:       "init with empty config path (use defaults)",
			configPath: "",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &SevenZipExtractPlugin{}
			mockContext := newMockHCContext()

			err := plugin.Init(tt.configPath, mockContext)
			if (err != nil) != tt.wantErr {
				t.Errorf("SevenZipExtractPlugin.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if plugin.logger == nil {
					t.Error("SevenZipExtractPlugin.Init() logger should be set")
				}
				if plugin.sze == nil {
					t.Error("SevenZipExtractPlugin.Init() sze should be initialized")
				}
				if mockContext.xtractFileFunc == nil {
					t.Error("SevenZipExtractPlugin.Init() should register XtractFile callback")
				}
				if plugin.pathToRemove == nil {
					t.Error("SevenZipExtractPlugin.Init() pathToRemove should be initialized")
				}
			}
		})
	}
}

func TestSevenZipExtractPlugin_Close(t *testing.T) {
	plugin := &SevenZipExtractPlugin{}
	mockContext := newMockHCContext()

	// Initialize plugin
	err := plugin.Init("", mockContext)
	if err != nil {
		t.Fatalf("Failed to initialize plugin: %v", err)
	}

	// Add some fake paths to cleanup list
	tmpDir, err := os.MkdirTemp("", "extract_test_cleanup")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	plugin.pathToRemove = append(plugin.pathToRemove, tmpDir)

	// Test close
	err = plugin.Close(context.Background())
	if err != nil {
		t.Errorf("SevenZipExtractPlugin.Close() error = %v, want nil", err)
	}

	// Verify cleanup happened
	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		t.Error("SevenZipExtractPlugin.Close() should have removed temporary directories")
	}
}

func TestSevenZipExtractPlugin_get7zzs(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "get 7zzs binary",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &SevenZipExtractPlugin{
				pathToRemove: []string{},
				logger:       slog.Default(),
			}

			path, err := plugin.get7zzs()
			if (err != nil) != tt.wantErr {
				t.Errorf("SevenZipExtractPlugin.get7zzs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if path == "" {
					t.Error("SevenZipExtractPlugin.get7zzs() should return a valid path")
				}

				// Check if path exists
				if _, err := os.Stat(path); os.IsNotExist(err) {
					t.Errorf("SevenZipExtractPlugin.get7zzs() returned non-existent path: %s", path)
				}

				// If it's a temporary file, it should be tracked for cleanup
				// Check if the returned path is in system PATH or in pathToRemove
				isInPath := false
				for _, pathToRemove := range plugin.pathToRemove {
					if pathToRemove == path {
						isInPath = true
						break
					}
				}

				// Check if it's a system binary
				if !strings.Contains(path, os.TempDir()) && !isInPath {
					// It's likely a system binary, which is fine
					t.Logf("Using system 7zzs binary at: %s", path)
				} else if !isInPath {
					t.Error("Temporary 7zzs binary should be tracked for cleanup")
				}

				// Clean up if temporary file was created
				for _, pathToRemove := range plugin.pathToRemove {
					os.RemoveAll(pathToRemove)
				}
			}
		})
	}
}

func TestSevenZipExtractPlugin_XtractFile(t *testing.T) {
	// Create a simple test archive
	tmpDir, err := os.MkdirTemp("", "extract_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test file to archive
	testFile := filepath.Join(tmpDir, "test.txt")
	testContent := "Hello, World!"
	if err := os.WriteFile(testFile, []byte(testContent), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Since we can't easily create a real archive without 7-zip installed,
	// we'll test the method structure and error handling
	tests := []struct {
		name         string
		setupArchive func() string
		wantErr      bool
		expectFiles  bool
	}{
		{
			name: "extract non-existent file",
			setupArchive: func() string {
				return "/non/existent/archive.zip"
			},
			wantErr:     true,
			expectFiles: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &SevenZipExtractPlugin{}
			mockContext := newMockHCContext()

			// Initialize plugin
			err := plugin.Init("", mockContext)
			if err != nil {
				t.Fatalf("Failed to initialize plugin: %v", err)
			}
			defer plugin.Close(context.Background())

			archivePath := tt.setupArchive()
			xFile := &xtractr.XFile{
				FilePath: archivePath,
			}

			size, files, volumes, err := plugin.XtractFile(xFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("SevenZipExtractPlugin.XtractFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.expectFiles && len(files) == 0 {
				t.Error("SevenZipExtractPlugin.XtractFile() should return extracted files")
			}

			// For successful extractions, verify return values make sense
			if !tt.wantErr {
				if size < 0 {
					t.Errorf("SevenZipExtractPlugin.XtractFile() size = %v, want >= 0", size)
				}
				if files == nil {
					t.Error("SevenZipExtractPlugin.XtractFile() files should not be nil")
				}
				if volumes == nil {
					t.Error("SevenZipExtractPlugin.XtractFile() volumes should not be nil")
				}
			}
		})
	}
}

func TestSevenZipExtractPlugin_Integration(t *testing.T) {
	plugin := &SevenZipExtractPlugin{}
	mockContext := newMockHCContext()

	// Test initialization
	err := plugin.Init("", mockContext)
	if err != nil {
		t.Fatalf("SevenZipExtractPlugin.Init() error = %v", err)
	}

	// Verify callback was registered
	if mockContext.xtractFileFunc == nil {
		t.Fatal("XtractFile callback should be registered")
	}

	// Verify plugin state
	if plugin.logger == nil {
		t.Error("Plugin logger should be initialized")
	}
	if plugin.sze == nil {
		t.Error("Plugin extraction engine should be initialized")
	}

	// Test close
	err = plugin.Close(context.Background())
	if err != nil {
		t.Errorf("SevenZipExtractPlugin.Close() error = %v", err)
	}
}

func TestSevenZipExtractPlugin_Interface(t *testing.T) {
	// Test that SevenZipExtractPlugin implements the Plugin interface
	var _ plugins.Plugin = &SevenZipExtractPlugin{}
}

func TestSevenZipExtractPlugin_DefaultConfig(t *testing.T) {
	plugin := &SevenZipExtractPlugin{}
	mockContext := newMockHCContext()

	// Initialize with empty config path to test defaults
	err := plugin.Init("", mockContext)
	if err != nil {
		t.Fatalf("SevenZipExtractPlugin.Init() with defaults error = %v", err)
	}
	defer plugin.Close(context.Background())

	// Verify that the extraction engine was created with defaults
	if plugin.sze == nil {
		t.Error("Extraction engine should be initialized with default config")
	}

	// Verify default configuration values through behavior
	// The specific values are tested indirectly through the extraction engine
	if plugin.sze.config.MaxFileSize != 1024*1024 {
		t.Errorf("Default MaxFileSize = %v, want %v", plugin.sze.config.MaxFileSize, 1024*1024)
	}
	if plugin.sze.config.MaxExtractedElements != 1000 {
		t.Errorf("Default MaxExtractedElements = %v, want %v", plugin.sze.config.MaxExtractedElements, 1000)
	}
	if len(plugin.sze.config.DefaultPasswords) != 1 || plugin.sze.config.DefaultPasswords[0] != "infected" {
		t.Errorf("Default passwords = %v, want [\"infected\"]", plugin.sze.config.DefaultPasswords)
	}
}

func TestSevenZipExtractPlugin_BinaryManagement(t *testing.T) {
	plugin := &SevenZipExtractPlugin{
		pathToRemove: []string{},
		logger:       slog.Default(),
	}

	// Test binary location/deployment
	binaryPath, err := plugin.get7zzs()
	if err != nil {
		t.Fatalf("Failed to get 7zzs binary: %v", err)
	}

	// Verify binary exists and is executable
	info, err := os.Stat(binaryPath)
	if err != nil {
		t.Fatalf("7zzs binary not found at %s: %v", binaryPath, err)
	}

	// Check permissions (should be executable)
	mode := info.Mode()
	if mode&0o111 == 0 {
		t.Error("7zzs binary should be executable")
	}

	// Clean up any temporary files
	for _, path := range plugin.pathToRemove {
		os.RemoveAll(path)
	}
}
