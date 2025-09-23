// Package main implements a MIME type-based file filtering plugin for the host connector.
//
// The filetype filter plugin provides automated file classification and filtering based on MIME types
// detected through libmagic. It enables security policies by allowing administrators to define
// forbidden file types that should be immediately flagged as malicious, or skipped file types
// that should be marked as safe without further analysis.
//
// Key Features:
//   - Real-time MIME type detection using libmagic
//   - Configurable forbidden file types (marked as malicious)
//   - Configurable skipped file types (marked as safe)
//   - Immediate file classification before expensive analysis
//   - Structured logging for audit trails
//
// Configuration:
// The plugin is configured via YAML with two optional lists:
//
//	forbidden_types: MIME types to immediately flag as malicious
//	skipped_types: MIME types to mark as safe and skip analysis
//
// Example configuration:
//
//	forbidden_types:
//	  - application/x-executable
//	  - application/x-msdos-program
//	  - application/x-msdownload
//	skipped_types:
//	  - text/plain
//	  - image/jpeg
//	  - image/png
//
// Processing Logic:
//  1. For each file, detect MIME type using libmagic
//  2. If MIME type is in forbidden_types: return malicious result with score 1000
//  3. If MIME type is in skipped_types: return safe result with score -500
//  4. Otherwise: return nil to allow normal processing pipeline
//
// This design enables efficient early filtering to reduce processing load on expensive
// analysis tools while enforcing organizational security policies.
package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/vimeo/go-magic/magic"
	"gopkg.in/yaml.v3"
)

// FTFilterPlugin implements the plugins.Plugin interface to provide MIME type-based file filtering.
//
// The plugin maintains two sets of MIME types: forbidden types that should be immediately
// flagged as malicious, and skipped types that should be marked as safe. Files with MIME
// types not in either set are allowed to proceed through the normal processing pipeline.
//
// Fields:
//   - ForbiddenTypes: Set of MIME types to immediately flag as malicious
//   - SkippedTypes: Set of MIME types to mark as safe and skip further analysis
//   - logger: Structured logger for audit trails and debugging
type FTFilterPlugin struct {
	ForbiddenTypes map[string]struct{} // MIME types to flag as malicious
	SkippedTypes   map[string]struct{} // MIME types to mark as safe
	logger         *slog.Logger        // Structured logger instance
}

// Config represents the YAML configuration structure for the filetype filter plugin.
//
// The configuration allows administrators to define lists of MIME types that should
// receive special handling during the scanning process. Both lists are optional.
//
// Fields:
//   - ForbiddenTypes: MIME types that should be immediately flagged as malicious
//   - SkippedTypes: MIME types that should be marked as safe without analysis
type Config struct {
	ForbiddenTypes []string `yaml:"forbidden_types,omitempty"` // MIME types to flag as malicious
	SkippedTypes   []string `yaml:"skipped_types,omitempty"`   // MIME types to mark as safe
}

var (
	// Compile-time check to ensure FTFilterPlugin implements plugins.Plugin interface
	_ plugins.Plugin = &FTFilterPlugin{}

	// HCPlugin is the exported plugin instance required by the plugin loader.
	// This variable must be named exactly "HCPlugin" as it's looked up by name
	// during the dynamic plugin loading process.
	HCPlugin FTFilterPlugin
)

// Close implements the plugins.Plugin interface, performing cleanup when the plugin is shut down.
//
// For the filetype filter plugin, no cleanup is required as it doesn't maintain
// persistent resources or background processes. This method always returns nil.
//
// Parameters:
//   - ctx: Context for cancellation (unused)
//
// Returns:
//   - error: Always nil for this plugin
func (p *FTFilterPlugin) Close(context.Context) error {
	return nil
}

// Init implements the plugins.Plugin interface, initializing the filetype filter plugin.
//
// This method sets up the plugin by:
//  1. Initializing the libmagic library for MIME type detection
//  2. Loading and parsing the YAML configuration file (if provided)
//  3. Building internal lookup tables for forbidden and skipped MIME types
//  4. Registering the OnStartScanFile callback with the host connector
//
// If no configuration file is provided (empty configPath), the plugin will be disabled
// and will not filter any files. The plugin requires libmagic to be available on the system.
//
// Configuration File Format:
//
//	forbidden_types:
//	  - application/x-executable
//	  - application/x-msdos-program
//	skipped_types:
//	  - text/plain
//	  - image/jpeg
//
// Parameters:
//   - configPath: Path to YAML configuration file, or empty string to disable filtering
//   - hcc: Host connector context providing logging and callback registration
//
// Returns:
//   - error: Error if libmagic initialization fails or config file is invalid
func (p *FTFilterPlugin) Init(configPath string, hcc plugins.HCContext) error {
	// Initialize structured logger from host connector context
	p.logger = hcc.GetLogger()

	// Initialize libmagic library for MIME type detection
	if err := magic.AddMagicDir(magic.GetDefaultDir()); err != nil {
		return err
	}

	// Handle case where no configuration is provided - plugin remains inactive
	if configPath == "" {
		p.logger.Warn("[FTFilter]no configuration provided, plugin will be disabled")
		return nil
	}

	// Load and parse YAML configuration file
	f, err := os.Open(filepath.Clean(configPath))
	if err != nil {
		return err
	}
	defer f.Close()

	var conf Config
	if err = yaml.NewDecoder(f).Decode(&conf); err != nil {
		return err
	}

	// Initialize lookup tables for O(1) MIME type checking
	p.ForbiddenTypes = make(map[string]struct{}, len(conf.ForbiddenTypes))
	p.SkippedTypes = make(map[string]struct{}, len(conf.SkippedTypes))

	// Populate forbidden MIME types lookup table
	for _, mime := range conf.ForbiddenTypes {
		p.ForbiddenTypes[mime] = struct{}{}
	}

	// Populate skipped MIME types lookup table
	for _, mime := range conf.SkippedTypes {
		p.SkippedTypes[mime] = struct{}{}
	}

	// Register callback to intercept file scanning events
	hcc.RegisterOnStartScanFile(p.OnStartScanFile)
	return nil
}

// OnStartScanFile implements the file scanning callback for MIME type-based filtering.
//
// This method is called by the host connector before each file begins scanning. It performs
// real-time MIME type detection using libmagic and immediately classifies files based on
// the configured forbidden and skipped type lists.
//
// Processing Logic:
//  1. Detect the file's MIME type using libmagic
//  2. Check if MIME type is in forbidden list → return malicious result (score: 1000)
//  3. Check if MIME type is in skipped list → return safe result (score: -500)
//  4. Otherwise → return nil to allow normal pipeline processing
//
// The scoring system uses high absolute values to ensure clear classification:
//   - Forbidden files: +1000 (strongly malicious)
//   - Skipped files: -500 (strongly safe)
//
// Logging is performed at DEBUG level for all classifications to maintain audit trails
// without overwhelming normal log output.
//
// Parameters:
//   - file: Absolute path to the file being scanned
//   - sha256: SHA256 hash of the file content
//
// Returns:
//   - *gdetect.Result: Classification result if file matches configured types, nil otherwise
//   - Forbidden files: Malware=true, Score=1000, Malwares=["forbidden_files"]
//   - Skipped files: Malware=false, Score=-500
//   - Other files: nil (continue normal processing)
func (p *FTFilterPlugin) OnStartScanFile(file string, sha256 string) *gdetect.Result {
	// Detect MIME type using libmagic
	mime := magic.MimeFromFile(file)

	// Check if file type is forbidden - immediately flag as malicious
	if _, ok := p.ForbiddenTypes[mime]; ok {
		p.logger.Debug("[FTFilter]set file as malware",
			slog.String("file", file),
			slog.String("sha256", sha256),
			slog.String("mime", mime))
		return &gdetect.Result{
			Malware:  true,
			SHA256:   sha256,
			Score:    1000, // High positive score for forbidden files
			Malwares: []string{"forbidden_files"},
		}
	}

	// Check if file type should be skipped - mark as safe
	if _, ok := p.SkippedTypes[mime]; ok {
		p.logger.Debug("[FTFilter]set file as legit",
			slog.String("file", file),
			slog.String("sha256", sha256),
			slog.String("mime", mime))
		return &gdetect.Result{
			Malware: false,
			SHA256:  sha256,
			Score:   -500, // Negative score for safe files
		}
	}

	// File type not configured - allow normal processing pipeline
	return nil
}

// main is the entry point required for Go plugin compilation.
//
// This function is intentionally empty as the plugin is loaded dynamically by the host
// connector, which accesses the exported HCPlugin variable directly. The main function
// exists only to satisfy Go's requirement for executable compilation.
func main() {}
