package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/alecthomas/units"
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
				MaxFileSize:           defaultMaxSize,               // 500MB limit per file
				MaxExtractedFiles:     defaultMaxFileExtracted,      // Max 1000 files per archive
				MaxTotalExtractedSize: defaultMaxTotalExtractedSize, // 3GB limit total
				DefaultPasswords:      []string{"infected"},
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
			mockContext := mock.NewMockHCContext()

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
				// if plugin.pathToRemove == nil {
				// 	t.Error("SevenZipExtractPlugin.Init() pathToRemove should be initialized")
				// }
			}
		})
	}
}

func TestSevenZipExtractPlugin_Close(t *testing.T) {
	plugin := &SevenZipExtractPlugin{}
	mockContext := mock.NewMockHCContext()

	config := plugin.GetDefaultConfig()

	// Initialize plugin
	err := plugin.Init(config, mockContext)
	if err != nil {
		t.Fatalf("Failed to initialize plugin: %v", err)
	}

	// Test close
	err = plugin.Close(context.Background())
	if err != nil {
		t.Errorf("SevenZipExtractPlugin.Close() error = %v, want nil", err)
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
				// pathToRemove: []string{},
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

				// Check if it's a system binary
				if !strings.Contains(path, os.TempDir()) && !isInPath {
					t.Logf("Using system 7zzs binary at: %s", path)
				}
			}
		})
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
			mockContext := mock.NewMockHCContext()

			// Initialize plugin
			err := plugin.Init(plugin.GetDefaultConfig(), mockContext)
			if err != nil {
				t.Fatalf("Failed to initialize plugin: %v", err)
			}
			defer func() {
				if err := plugin.Close(context.Background()); err != nil {
					t.Logf("Warning: failed to close plugin: %v", err)
				}
			}()

			archivePath := tt.setupArchive()
			outputDir := t.TempDir()

			size, files, volumes, err := plugin.ExtractFile(archivePath, outputDir)
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
	mockContext := mock.NewMockHCContext()

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
	mockContext := mock.NewMockHCContext()

	// Initialize with empty config path to test defaults
	err := plugin.Init(plugin.GetDefaultConfig(), mockContext)
	if err != nil {
		t.Fatalf("SevenZipExtractPlugin.Init() with defaults error = %v", err)
	}
	defer func() {
		if err := plugin.Close(context.Background()); err != nil {
			t.Logf("Warning: failed to close plugin: %v", err)
		}
	}()

	// Verify that the extraction engine was created with defaults
	if plugin.sze == nil {
		t.Error("Extraction engine should be initialized with default config")
	}

	// Verify default configuration values through behavior
	// The specific values are tested indirectly through the extraction engine
	expectedMaxSize, err := units.ParseStrictBytes(defaultMaxSize)
	if err != nil {
		t.Fatalf("Failed to parse defaultMaxSize: %v", err)
	}
	if plugin.sze.config.MaxFileSize != int(expectedMaxSize) {
		t.Errorf("Default MaxFileSize = %v, want %v", plugin.sze.config.MaxFileSize, int(expectedMaxSize))
	}
	if plugin.sze.config.MaxExtractedFiles != defaultMaxFileExtracted {
		t.Errorf("Default MaxExtractedElements = %v, want %v", plugin.sze.config.MaxExtractedFiles, defaultMaxFileExtracted)
	}
	if len(plugin.sze.config.DefaultPasswords) != 1 || plugin.sze.config.DefaultPasswords[0] != "infected" {
		t.Errorf("Default passwords = %v, want [\"infected\"]", plugin.sze.config.DefaultPasswords)
	}
}

func TestSevenZipExtractPlugin_BinaryManagement(t *testing.T) {
	plugin := &SevenZipExtractPlugin{
		// pathToRemove: []string{},
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
	// for _, path := range plugin.pathToRemove {
	// 	if err := os.RemoveAll(path); err != nil {
	// 		t.Logf("Warning: failed to remove temporary path %s: %v", path, err)
	// 	}
	// }
}
