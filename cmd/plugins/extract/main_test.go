package main

import (
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

func TestSevenZipExtractPlugin_Init(t *testing.T) {
	tests := []struct {
		name    string
		config  any
		wantErr bool
	}{
		{
			name: "ok",
			config: &Config{
				DefaultPasswords: []string{"infected"},
			},
			wantErr: false,
		},
		{
			name:    "error bad config",
			config:  struct{}{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &SevenZipExtractPlugin{}
			mockContext := newMockContext(t)

			err := plugin.Init(tt.config, mockContext)
			if (err != nil) != tt.wantErr {
				t.Errorf("SevenZipExtractPlugin.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if plugin.sze == nil {
					t.Error("SevenZipExtractPlugin.Init() sze should be initialized")
				}
				if mockContext.ExtractFile == nil {
					t.Error("SevenZipExtractPlugin.Init() should register XtractFile callback")
				}
			}
		})
	}
}

func TestSevenZipExtractPlugin_Close(t *testing.T) {
	plugin := &SevenZipExtractPlugin{}
	mockContext := newMockContext(t)

	config := plugin.GetDefaultConfig()

	// Initialize plugin
	err := plugin.Init(config, mockContext)
	if err != nil {
		t.Fatalf("Failed to initialize plugin: %v", err)
	}

	// Test close
	err = plugin.Close(t.Context())
	if err != nil {
		t.Errorf("SevenZipExtractPlugin.Close() error = %v, want nil", err)
	}
}

func TestSevenZipExtractPlugin_ExtractFile(t *testing.T) {
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
			mockContext := newMockContext(t)

			// Initialize plugin
			err := plugin.Init(plugin.GetDefaultConfig(), mockContext)
			if err != nil {
				t.Fatalf("Failed to initialize plugin: %v", err)
			}
			defer func() {
				if err := plugin.Close(t.Context()); err != nil {
					t.Logf("Warning: failed to close plugin: %v", err)
				}
			}()

			archivePath := tt.setupArchive()
			outputDir := t.TempDir()

			extraction, err := plugin.ExtractFile(archivePath, outputDir, plugins.ExtractLimits{})
			size, files := extraction.Size, extraction.Files
			if (err != nil) != tt.wantErr {
				t.Errorf("SevenZipExtractPlugin.XtractFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.expectFiles && len(files) == 0 {
				t.Error("SevenZipExtractPlugin.XtractFile() should return extracted files")
			}

			// For successful extractions, verify return values make sense
			if !tt.wantErr {
				if tt.expectFiles && size == 0 {
					t.Errorf("SevenZipExtractPlugin.XtractFile() size = %v, want > 0", size)
				}
				if files == nil {
					t.Error("SevenZipExtractPlugin.XtractFile() files should not be nil")
				}
			}
		})
	}
}

func TestSevenZipExtractPlugin_Integration(t *testing.T) {
	plugin := &SevenZipExtractPlugin{}
	mockContext := newMockContext(t)

	// Test initialization
	err := plugin.Init(plugin.GetDefaultConfig(), mockContext)
	if err != nil {
		t.Fatalf("SevenZipExtractPlugin.Init() error = %v", err)
	}

	// Verify callback was registered
	if mockContext.ExtractFile == nil {
		t.Fatal("XtractFile callback should be registered")
	}

	if plugin.sze == nil {
		t.Error("Plugin extraction engine should be initialized")
	}

	// Test close
	err = plugin.Close(t.Context())
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
	mockContext := newMockContext(t)

	// Initialize with empty config path to test defaults
	err := plugin.Init(plugin.GetDefaultConfig(), mockContext)
	if err != nil {
		t.Fatalf("SevenZipExtractPlugin.Init() with defaults error = %v", err)
	}
	defer func() {
		if err := plugin.Close(t.Context()); err != nil {
			t.Logf("Warning: failed to close plugin: %v", err)
		}
	}()

	// Verify that the extraction engine was created with defaults
	if plugin.sze == nil {
		t.Error("Extraction engine should be initialized with default config")
	}

	if len(plugin.sze.config.DefaultPasswords) != 1 || plugin.sze.config.DefaultPasswords[0] != "infected" {
		t.Errorf("Default passwords = %v, want [\"infected\"]", plugin.sze.config.DefaultPasswords)
	}
}

// newMockContext is a mock whose work directory is a private folder.
func newMockContext(t *testing.T) *mock.MockHCContext {
	t.Helper()
	hcc := mock.NewMockHCContext()
	hcc.WorkDir = t.TempDir()
	return hcc
}

// stubProve replaces the test of the binary for the tests that use a binary
// that is not a real 7-Zip.
func stubProve(t *testing.T) {
	t.Helper()
	prev := proveBinary
	t.Cleanup(func() { proveBinary = prev })
	proveBinary = func(*sevenZipExtract, string) error { return nil }
}
