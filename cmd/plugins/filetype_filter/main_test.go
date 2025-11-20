package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/vimeo/go-magic/magic"
)

func TestFTFilterPlugin_Init(t *testing.T) {
	tests := []struct {
		name       string
		config     any
		wantErr    bool
		wantConfig Config
	}{
		{
			name:    "init with empty config path",
			config:  &Config{},
			wantErr: false,
		},
		{
			name:    "init with invalid config",
			config:  struct{}{},
			wantErr: true,
		},
		{
			name: "init with valid config",
			config: &Config{
				ForbiddenTypes: []string{
					"application/x-executable",
					"application/x-msdos-program",
				},
				SkippedTypes: []string{
					"text/plain",
					"image/jpeg",
				},
			},
			wantErr: false,
			wantConfig: Config{
				ForbiddenTypes: []string{
					"application/x-executable",
					"application/x-msdos-program",
				},
				SkippedTypes: []string{
					"text/plain",
					"image/jpeg",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &FTFilterPlugin{}
			mockContext := mock.NewMockHCContext()

			err := plugin.Init(tt.config, mockContext)
			if (err != nil) != tt.wantErr {
				t.Errorf("FTFilterPlugin.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if mockContext.OnScanFile == nil {
					t.Error("FTFilterPlugin.Init() should register OnScanFile callback when config is provided")
				}

				forbidden := make([]string, 0, len(plugin.ForbiddenTypes))
				skipped := make([]string, 0, len(plugin.SkippedTypes))

				for k := range plugin.ForbiddenTypes {
					forbidden = append(forbidden, k)
				}

				for k := range plugin.SkippedTypes {
					skipped = append(skipped, k)
				}
				less := func(a, b string) bool { return a < b }
				if diff := cmp.Diff(forbidden, tt.wantConfig.ForbiddenTypes, cmpopts.SortSlices(less), cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("FTFilterPlugin.Init() forbidden types diff(got-want)=%s", diff)
				}
				if diff := cmp.Diff(skipped, tt.wantConfig.SkippedTypes, cmpopts.SortSlices(less), cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("FTFilterPlugin.Init() skipped types diff(got-want)=%s", diff)
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
	tmpDir := t.TempDir()
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Logf("Warning: failed to remove temp dir %s: %v", tmpDir, err)
		}
	}()

	// Create a text file
	textFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(textFile, []byte("Hello, World!"), 0o600); err != nil {
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
	if err := os.WriteFile(binaryFile, binaryContent, 0o600); err != nil {
		t.Fatalf("Failed to create binary file: %v", err)
	}

	tests := []struct {
		name           string
		plugin         *FTFilterPlugin
		filename       string
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
			},
			filePath:  textFile,
			sha256:    "test_sha256",
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.plugin.OnScanFile(tt.filename, tt.filePath, tt.sha256, false)

			if tt.expectNil {
				if result != nil {
					t.Errorf("FTFilterPlugin.OnStartScanFile() = %v, want nil", result)
				}
				return
			}

			if result == nil {
				t.Fatal("FTFilterPlugin.OnStartScanFile() returned nil, expected result")
				return
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
	}

	// Test with non-existent file
	result := plugin.OnScanFile("file.txt", "/non/existent/file.txt", "test_sha256", false)

	// Should return nil for non-existent files (magic library handles this gracefully)
	if result != nil {
		t.Errorf("FTFilterPlugin.OnStartScanFile() with non-existent file = %v, want nil", result)
	}
}

func TestFTFilterPlugin_Integration(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Logf("Warning: failed to remove temp dir %s: %v", tmpDir, err)
		}
	}()

	config := &Config{
		ForbiddenTypes: []string{
			"application/x-executable",
		},
		SkippedTypes: []string{
			"text/plain",
		},
	}

	// Create test files
	textFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(textFile, []byte("Hello, World!"), 0o600); err != nil {
		t.Fatalf("Failed to create text file: %v", err)
	}

	plugin := &FTFilterPlugin{}
	mockContext := mock.NewMockHCContext()

	// Test initialization
	err := plugin.Init(config, mockContext)
	if err != nil {
		t.Fatalf("FTFilterPlugin.Init() error = %v", err)
	}

	// Test that callback was registered
	if mockContext.OnScanFile == nil {
		t.Fatal("OnScanFile callback should be registered")
	}

	// Test the callback functionality
	result := mockContext.OnScanFile("file.txt", textFile, "test_sha256", false)
	if result == nil {
		t.Fatal("Expected result for text file, got nil")
		return
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
