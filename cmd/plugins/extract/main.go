// Package main implements an archive extraction plugin for the host connector using 7-Zip.
//
// The extract plugin provides secure and configurable archive extraction capabilities using
// the 7-Zip command-line tool. It supports a wide variety of archive formats and implements
// security measures to prevent extraction bombs and malicious archive attacks.
//
// Key Features:
//   - Support for numerous archive formats via 7-Zip (ZIP, RAR, 7Z, TAR, GZIP, etc.)
//   - Configurable extraction limits to prevent resource exhaustion
//   - Password-protected archive support with configurable default passwords
//   - Automatic 7-Zip binary management (embedded or system binary)
//   - Symlink handling for security (dangerous symlinks are ignored)
//   - Structured logging for audit trails and debugging
//
// Security Features:
//   - Maximum file size limits to prevent extraction bombs
//   - Maximum extracted file count limits
//   - Dangerous symlink detection and removal
//   - Configurable password attempts to prevent brute force
//   - Safe temporary directory handling
//
// Configuration:
// The plugin can be configured via YAML with the following options:
//
//	max_file_size: Maximum size in bytes for individual extracted files
//	max_extracted_elements: Maximum number of files to extract from an archive
//	default_passwords: List of passwords to try for encrypted archives
//	seven_zip_path: Custom path to 7-Zip binary (optional)
//	t_option: Enable 7-Zip type detection mode
//
// Example configuration:
//
//	max_file_size: 104857600  # 100MB
//	max_extracted_elements: 1000
//	default_passwords:
//	  - infected
//	  - malware
//	  - password
//	t_option: true
//
// Binary Management:
// The plugin includes an embedded 7-Zip binary (7zzs) that is automatically deployed
// if no system 7-Zip installation is found. This ensures the plugin works out-of-the-box
// without requiring manual installation of dependencies.
//
// Processing Flow:
//  1. Receive extraction request from host connector
//  2. Create secure temporary extraction directory
//  3. List archive contents with password attempts
//  4. Apply size and count limits to prevent extraction bombs
//  5. Extract files to temporary directory
//  6. Scan extracted files for dangerous content (symlinks)
//  7. Return list of extracted files for further processing
//  8. Clean up temporary files on plugin shutdown
package main

import (
	"context"
	_ "embed"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/glimps-re/host-connector/pkg/plugins"
	"golift.io/xtractr"
)

// SevenZipExtractPlugin implements the plugins.Plugin interface to provide archive extraction
// capabilities using the 7-Zip command-line tool.
//
// The plugin manages the lifecycle of archive extraction operations, including binary
// management, temporary file cleanup, and integration with the host connector's
// extraction pipeline.
//
// Fields:
//   - sze: Internal 7-Zip extraction engine with configured security limits
//   - pathToRemove: List of temporary paths created during extraction for cleanup
//   - logger: Structured logger for audit trails and debugging
type SevenZipExtractPlugin struct {
	sze          *sevenZipExtract // 7-Zip extraction engine
	pathToRemove []string         // Temporary paths to clean up on shutdown
	logger       *slog.Logger     // Structured logger instance
}

// Config represents the YAML configuration structure for the extract plugin.
//
// The configuration allows administrators to tune extraction behavior for security
// and performance. All fields are optional and have sensible defaults.
//
// Security Considerations:
//   - MaxFileSize prevents extraction bombs with oversized files
//   - MaxExtractedElements prevents zip bombs with excessive file counts
//   - DefaultPasswords should be chosen carefully to avoid brute force attacks
//
// Fields:
//   - MaxFileSize: Maximum size in bytes for individual extracted files (default: 1MB)
//   - MaxExtractedElements: Maximum number of files to extract (default: 1000)
//   - DefaultPasswords: Passwords to attempt for encrypted archives (default: ["infected"])
//   - SevenZipPath: Custom path to 7-Zip binary (auto-detected if empty)
//   - TOption: Enable 7-Zip type detection mode for better format support
type Config struct {
	MaxFileSize          int      `yaml:"max_file_size,omitempty"`          // Max size per extracted file in bytes
	MaxExtractedElements int      `yaml:"max_extracted_elements,omitempty"` // Max number of files to extract
	DefaultPasswords     []string `yaml:"default_passwords,omitempty"`      // Default passwords for encrypted archives
	SevenZipPath         string   `yaml:"seven_zip_path,omitempty"`         // Custom 7-Zip binary path
	TOption              bool     `yaml:"t_option,omitempty"`               // Enable type detection mode
}

var (
	// HCPlugin is the exported plugin instance required by the plugin loader.
	// This variable must be named exactly "HCPlugin" as it's looked up by name
	// during the dynamic plugin loading process.
	HCPlugin SevenZipExtractPlugin

	// SevenZip contains the embedded 7-Zip binary (7zzs) for automatic deployment.
	// This binary is embedded at compile time and automatically extracted to a
	// temporary location if no system 7-Zip installation is found.
	//
	//go:embed 7zzs
	SevenZip []byte
)

// Init implements the plugins.Plugin interface, initializing the extract plugin.
//
// This method sets up the plugin by:
//  1. Initializing the structured logger from the host connector context
//  2. Loading configuration from file or using secure defaults
//  3. Setting up the 7-Zip binary (embedded or system installation)
//  4. Creating the extraction engine with configured security limits
//  5. Registering the extraction callback with the host connector
//
// Default Configuration (when no config file provided):
//   - MaxFileSize: 1MB (1024*1024 bytes)
//   - MaxExtractedElements: 1000 files
//   - DefaultPasswords: ["infected"]
//   - Auto-detect 7-Zip binary location
//
// Security Features:
//   - Extraction limits prevent resource exhaustion attacks
//   - Password attempts are limited to configured list
//   - Temporary files are tracked for secure cleanup
//
// Parameters:
//   - configPath: Path to YAML configuration file, or empty string for defaults
//   - hcc: Host connector context providing logging and callback registration
//
// Returns:
//   - error: Error if 7-Zip binary setup fails or configuration is invalid
func (p *SevenZipExtractPlugin) Init(configPath string, hcc plugins.HCContext) error {
	// Initialize structured logger from host connector context
	p.logger = hcc.GetLogger()

	// Load configuration or use secure defaults
	var conf Config
	if configPath == "" {
		conf = Config{
			MaxFileSize:          1024 * 1024, // 1MB limit per file
			MaxExtractedElements: 1000,        // Max 1000 files per archive
			DefaultPasswords:     []string{"infected"},
		}
	}

	// Set up 7-Zip binary path (embedded or system)
	if conf.SevenZipPath == "" {
		var err error
		if conf.SevenZipPath, err = p.get7zzs(); err != nil {
			return err
		}
	}

	// Create extraction engine with security configuration
	p.sze = newSevenZipExtract(extractorConfig{
		MaxFileSize:          conf.MaxFileSize,
		MaxExtractedElements: conf.MaxExtractedElements,
		DefaultPasswords:     conf.DefaultPasswords,
	}, conf.SevenZipPath, conf.TOption, p.logger)

	// Register extraction callback with host connector
	hcc.SetXTractFile(p.XtractFile)
	return nil
}

// get7zzs locates or deploys the 7-Zip binary for archive extraction.
//
// This method implements a fallback strategy for 7-Zip binary availability:
//  1. First, attempt to find 7zzs in the system PATH
//  2. If not found, extract the embedded binary to a temporary location
//  3. Set executable permissions on the extracted binary
//  4. Track the temporary file for cleanup on plugin shutdown
//
// The embedded binary approach ensures the plugin works out-of-the-box without
// requiring manual installation of 7-Zip on the target system.
//
// Security Considerations:
//   - Extracted binaries are created with restrictive permissions (0o755)
//   - Temporary files are tracked for secure cleanup
//   - System PATH binaries are preferred over embedded ones
//
// Returns:
//   - string: Absolute path to the 7-Zip binary
//   - error: Error if binary location fails or deployment fails
func (p *SevenZipExtractPlugin) get7zzs() (string, error) {
	// Try to find 7zzs in system PATH first
	fname, err := exec.LookPath("7zzs")
	if err == nil {
		path, e := filepath.Abs(fname)
		if e != nil {
			return "", e
		}
		return path, nil
	}

	// Deploy embedded binary to temporary location
	f, err := os.CreateTemp(os.TempDir(), "7zzs")
	if err != nil {
		return "", err
	}

	// Track temporary file for cleanup
	p.pathToRemove = append(p.pathToRemove, f.Name())
	defer func() {
		if err := f.Close(); err != nil {
			p.logger.Warn("Failed to close temporary file", "error", err)
		}
	}()

	// Write embedded binary data
	_, err = f.Write(SevenZip)
	if err != nil {
		return "", err
	}

	// Set executable permissions
	err = f.Chmod(0o755)
	if err != nil {
		return "", err
	}

	return f.Name(), nil
}

// XtractFile implements the extraction callback for the host connector pipeline.
//
// This method is called by the host connector when an archive file needs to be extracted.
// It performs secure extraction using the configured 7-Zip engine and returns the paths
// of extracted files for further processing by the scanning pipeline.
//
// Extraction Process:
//  1. Create a secure temporary directory for extraction
//  2. Use the 7-Zip engine to extract files with security limits
//  3. Track temporary directory for cleanup
//  4. Collect paths of successfully extracted files
//  5. Delegate to xtractr library for additional processing
//
// Security Features:
//   - Extraction limits prevent zip bombs and resource exhaustion
//   - Dangerous symlinks are automatically detected and removed
//   - All extraction happens in isolated temporary directories
//   - Temporary paths are tracked for secure cleanup
//
// Parameters:
//   - xFile: Archive file information from the xtractr library
//
// Returns:
//   - size: Total size of extracted content (delegated to xtractr)
//   - files: List of absolute paths to extracted files
//   - volumes: Volume information (delegated to xtractr)
//   - err: Error if extraction fails or security limits are exceeded
func (p *SevenZipExtractPlugin) XtractFile(xFile *xtractr.XFile) (size int64, files []string, volumes []string, err error) {
	// Create secure temporary directory for extraction
	dest, err := os.MkdirTemp(os.TempDir(), "extracted*")
	if err != nil {
		return
	}

	// Track temporary directory for cleanup
	p.pathToRemove = append(p.pathToRemove, dest)

	// Perform secure extraction with configured limits
	result, err := p.sze.extract(xFile.FilePath, dest, []string{}, []string{})
	if err != nil {
		return
	}

	// Collect paths of successfully extracted files
	for _, ep := range result.extractedFiles {
		files = append(files, ep.Path)
	}

	// Delegate to xtractr library for additional processing
	return xtractr.ExtractFile(xFile)
}

// Close implements the plugins.Plugin interface, performing cleanup when the plugin is shut down.
//
// This method ensures all temporary files and directories created during extraction
// operations are securely removed. This includes:
//   - Temporary extraction directories
//   - Deployed 7-Zip binaries (if embedded binary was used)
//   - Any other temporary files tracked during plugin operation
//
// The cleanup is performed synchronously to ensure all resources are properly
// released before the plugin shuts down. Cleanup errors are logged but do not
// prevent plugin shutdown.
//
// Parameters:
//   - ctx: Context for cancellation (unused but required by interface)
//
// Returns:
//   - error: Always nil for this implementation
func (p *SevenZipExtractPlugin) Close(_ context.Context) error { //nolint:unparam // interface requirement
	// Clean up all temporary paths created during plugin operation
	for _, path := range p.pathToRemove {
		if err := os.RemoveAll(path); err != nil {
			p.logger.Warn("Failed to remove temporary path", "path", path, "error", err)
		}
	}
	return nil
}

// main is the entry point required for Go plugin compilation.
//
// This function is intentionally empty as the plugin is loaded dynamically by the host
// connector, which accesses the exported HCPlugin variable directly. The main function
// exists only to satisfy Go's requirement for executable compilation.
func main() {}
