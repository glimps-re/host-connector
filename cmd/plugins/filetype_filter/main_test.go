package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/report"
	"github.com/vimeo/go-magic/magic"
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

func TestFTFilterPlugin_Init(t *testing.T) {
	tests := []struct {
		name         string
		configPath   string
		configData   string
		wantErr      bool
		expectConfig bool
	}{
		{
			name:         "init with empty config path",
			configPath:   "",
			wantErr:      false,
			expectConfig: false,
		},
		{
			name:       "init with invalid config path",
			configPath: "/invalid/path/config.yml",
			wantErr:    true,
		},
		{
			name:       "init with valid config",
			configPath: "test_config.yml",
			configData: `forbidden_types:
  - application/x-executable
  - application/x-msdos-program
skipped_types:
  - text/plain
  - image/jpeg`,
			wantErr:      false,
			expectConfig: true,
		},
		{
			name:       "init with invalid yaml",
			configPath: "invalid_config.yml",
			configData: `invalid: yaml: content:
  - not properly formatted`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &FTFilterPlugin{}
			mockContext := newMockHCContext()

			// Create temporary config file if needed
			var configPath string
			if tt.configPath != "" && tt.configData != "" {
				tmpDir, err := os.MkdirTemp("", "ftfilter_test")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}
				defer func() {
				if err := os.RemoveAll(tmpDir); err != nil {
					t.Logf("Warning: failed to remove temp dir %s: %v", tmpDir, err)
				}
			}()

				configPath = filepath.Join(tmpDir, tt.configPath)
				if err := os.WriteFile(configPath, []byte(tt.configData), 0o644); err != nil {
					t.Fatalf("Failed to write config file: %v", err)
				}
			} else {
				configPath = tt.configPath
			}

			err := plugin.Init(configPath, mockContext)
			if (err != nil) != tt.wantErr {
				t.Errorf("FTFilterPlugin.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if plugin.logger == nil {
					t.Error("FTFilterPlugin.Init() logger should be set")
				}
				if mockContext.onStartScanFile == nil && tt.expectConfig {
					t.Error("FTFilterPlugin.Init() should register OnStartScanFile callback when config is provided")
				}

				if tt.expectConfig {
					if plugin.ForbiddenTypes == nil {
						t.Error("FTFilterPlugin.Init() ForbiddenTypes should be initialized")
					}
					if plugin.SkippedTypes == nil {
						t.Error("FTFilterPlugin.Init() SkippedTypes should be initialized")
					}

					// Check specific configuration
					if len(plugin.ForbiddenTypes) != 2 {
						t.Errorf("FTFilterPlugin.Init() expected 2 forbidden types, got %d", len(plugin.ForbiddenTypes))
					}
					if len(plugin.SkippedTypes) != 2 {
						t.Errorf("FTFilterPlugin.Init() expected 2 skipped types, got %d", len(plugin.SkippedTypes))
					}

					if _, exists := plugin.ForbiddenTypes["application/x-executable"]; !exists {
						t.Error("FTFilterPlugin.Init() should contain application/x-executable in forbidden types")
					}
					if _, exists := plugin.SkippedTypes["text/plain"]; !exists {
						t.Error("FTFilterPlugin.Init() should contain text/plain in skipped types")
					}
				}
			}
		})
	}
}

func TestFTFilterPlugin_Close(t *testing.T) {
	plugin := &FTFilterPlugin{}
	err := plugin.Close(context.Background())
	if err != nil {
		t.Errorf("FTFilterPlugin.Close() error = %v, want nil", err)
	}
}

func TestFTFilterPlugin_OnStartScanFile(t *testing.T) {
	// Initialize magic library
	if err := magic.AddMagicDir(magic.GetDefaultDir()); err != nil {
		t.Fatalf("Failed to initialize magic library: %v", err)
	}

	// Create temporary test files with different content types
	tmpDir, err := os.MkdirTemp("", "ftfilter_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Logf("Warning: failed to remove temp dir %s: %v", tmpDir, err)
		}
	}()

	// Create a text file
	textFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(textFile, []byte("Hello, World!"), 0o644); err != nil {
		t.Fatalf("Failed to create text file: %v", err)
	}

	// Create a binary file (simulate executable with proper ELF header)
	binaryFile := filepath.Join(tmpDir, "test.bin")
	// Complete ELF header for x86_64
	binaryContent := []byte{
		0x7f, 0x45, 0x4c, 0x46, // ELF magic
		0x02,                                           // 64-bit
		0x01,                                           // little endian
		0x01,                                           // ELF version
		0x00,                                           // System V ABI
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding
		0x02, 0x00, // executable file type
		0x3e, 0x00, // x86_64 machine type
	}
	// Pad to minimum size to be recognized as ELF
	for len(binaryContent) < 64 {
		binaryContent = append(binaryContent, 0x00)
	}
	if err := os.WriteFile(binaryFile, binaryContent, 0o755); err != nil {
		t.Fatalf("Failed to create binary file: %v", err)
	}

	tests := []struct {
		name           string
		plugin         *FTFilterPlugin
		filePath       string
		sha256         string
		expectedResult *gdetect.Result
		expectNil      bool
	}{
		{
			name: "file with forbidden type",
			plugin: func() *FTFilterPlugin {
				// Dynamically determine the MIME type detected by magic
				actualMime := magic.MimeFromFile(binaryFile)
				t.Logf("Binary file MIME type detected as: %s", actualMime)
				return &FTFilterPlugin{
					ForbiddenTypes: map[string]struct{}{
						actualMime: {},
					},
					SkippedTypes: map[string]struct{}{},
					logger:       slog.Default(),
				}
			}(),
			filePath: binaryFile,
			sha256:   "test_sha256",
			expectedResult: &gdetect.Result{
				Malware:  true,
				SHA256:   "test_sha256",
				Score:    1000,
				Malwares: []string{"forbidden_files"},
			},
		},
		{
			name: "file with skipped type",
			plugin: &FTFilterPlugin{
				ForbiddenTypes: map[string]struct{}{},
				SkippedTypes: map[string]struct{}{
					"text/plain": {},
				},
				logger: slog.Default(),
			},
			filePath: textFile,
			sha256:   "test_sha256",
			expectedResult: &gdetect.Result{
				Malware: false,
				SHA256:  "test_sha256",
				Score:   -500,
			},
		},
		{
			name: "file with no configured type",
			plugin: &FTFilterPlugin{
				ForbiddenTypes: map[string]struct{}{},
				SkippedTypes:   map[string]struct{}{},
				logger:         slog.Default(),
			},
			filePath:  textFile,
			sha256:    "test_sha256",
			expectNil: true,
		},
		{
			name: "file not in forbidden or skipped lists",
			plugin: &FTFilterPlugin{
				ForbiddenTypes: map[string]struct{}{
					"application/pdf": {},
				},
				SkippedTypes: map[string]struct{}{
					"image/jpeg": {},
				},
				logger: slog.Default(),
			},
			filePath:  textFile,
			sha256:    "test_sha256",
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.plugin.OnStartScanFile(tt.filePath, tt.sha256)

			if tt.expectNil {
				if result != nil {
					t.Errorf("FTFilterPlugin.OnStartScanFile() = %v, want nil", result)
				}
				return
			}

			if result == nil {
				t.Fatal("FTFilterPlugin.OnStartScanFile() returned nil, expected result")
			}

			if result.Malware != tt.expectedResult.Malware {
				t.Errorf("FTFilterPlugin.OnStartScanFile() Malware = %v, want %v", result.Malware, tt.expectedResult.Malware)
			}
			if result.SHA256 != tt.expectedResult.SHA256 {
				t.Errorf("FTFilterPlugin.OnStartScanFile() SHA256 = %v, want %v", result.SHA256, tt.expectedResult.SHA256)
			}
			if result.Score != tt.expectedResult.Score {
				t.Errorf("FTFilterPlugin.OnStartScanFile() Score = %v, want %v", result.Score, tt.expectedResult.Score)
			}
			if tt.expectedResult.Malware && len(result.Malwares) != len(tt.expectedResult.Malwares) {
				t.Errorf("FTFilterPlugin.OnStartScanFile() Malwares length = %v, want %v", len(result.Malwares), len(tt.expectedResult.Malwares))
			}
			if tt.expectedResult.Malware && len(result.Malwares) > 0 && result.Malwares[0] != tt.expectedResult.Malwares[0] {
				t.Errorf("FTFilterPlugin.OnStartScanFile() Malwares[0] = %v, want %v", result.Malwares[0], tt.expectedResult.Malwares[0])
			}
		})
	}
}

func TestFTFilterPlugin_OnStartScanFile_NonExistentFile(t *testing.T) {
	plugin := &FTFilterPlugin{
		ForbiddenTypes: map[string]struct{}{
			"application/x-executable": {},
		},
		SkippedTypes: map[string]struct{}{},
		logger:       slog.Default(),
	}

	// Test with non-existent file
	result := plugin.OnStartScanFile("/non/existent/file.txt", "test_sha256")

	// Should return nil for non-existent files (magic library handles this gracefully)
	if result != nil {
		t.Errorf("FTFilterPlugin.OnStartScanFile() with non-existent file = %v, want nil", result)
	}
}

func TestFTFilterPlugin_Integration(t *testing.T) {
	// Create temporary config file
	tmpDir, err := os.MkdirTemp("", "ftfilter_integration_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Logf("Warning: failed to remove temp dir %s: %v", tmpDir, err)
		}
	}()

	configContent := `forbidden_types:
  - application/x-executable
skipped_types:
  - text/plain`

	configPath := filepath.Join(tmpDir, "config.yml")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Create test files
	textFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(textFile, []byte("Hello, World!"), 0o644); err != nil {
		t.Fatalf("Failed to create text file: %v", err)
	}

	plugin := &FTFilterPlugin{}
	mockContext := newMockHCContext()

	// Test initialization
	err = plugin.Init(configPath, mockContext)
	if err != nil {
		t.Fatalf("FTFilterPlugin.Init() error = %v", err)
	}

	// Test that callback was registered
	if mockContext.onStartScanFile == nil {
		t.Fatal("OnStartScanFile callback should be registered")
	}

	// Test the callback functionality
	result := mockContext.onStartScanFile(textFile, "test_sha256")
	if result == nil {
		t.Fatal("Expected result for text file, got nil")
	}

	if result.Malware != false {
		t.Errorf("Expected text file to be marked as safe, got malware = %v", result.Malware)
	}
	if result.Score != -500 {
		t.Errorf("Expected score -500 for skipped file, got %d", result.Score)
	}

	// Test close
	err = plugin.Close(context.Background())
	if err != nil {
		t.Errorf("FTFilterPlugin.Close() error = %v", err)
	}
}

func TestFTFilterPlugin_Interface(t *testing.T) {
	// Test that FTFilterPlugin implements the Plugin interface
	var _ plugins.Plugin = &FTFilterPlugin{}
}
