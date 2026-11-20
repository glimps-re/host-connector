// Package main implements an archive extraction plugin using 7-Zip.
//
// Extracts archives with configurable limits to prevent extraction bombs.
// Supports password-protected archives and automatically removes dangerous symlinks.
package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/units"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

const (
	defaultMaxSize               = "500MB"
	defaultMaxFileExtracted      = 1000  // 1000 files extracted max
	defaultMaxTotalExtractedSize = "3GB" // max total size of extracted elements
)

// SevenZipExtractPlugin provides archive extraction via 7-Zip.
type SevenZipExtractPlugin struct {
	sze           *sevenZipExtract
	logger        *slog.Logger
	consoleLogger *slog.Logger
}

// Config defines extraction behavior and security limits.
type Config struct {
	MaxFileSize           string   `mapstructure:"max_file_size,omitempty"`            // Max size per extracted file (e.g., "100MB", "1GB")
	MaxExtractedFiles     int      `mapstructure:"max_extracted_files,omitempty"`      // Max number of files to extract
	MaxTotalExtractedSize string   `mapstructure:"max_total_extracted_size,omitempty"` // Max total size to extract from one archive (e.g., "500MB", "3GB"). Additional files are skipped if reached
	DefaultPasswords      []string `mapstructure:"default_passwords,omitempty"`        // Default passwords for encrypted archives
	SevenZipPath          string   `mapstructure:"seven_zip_path,omitempty"`
}

var (
	_ plugins.Plugin    = &SevenZipExtractPlugin{}
	_ plugins.Validator = &SevenZipExtractPlugin{}

	// HCPlugin is the exported plugin instance.
	HCPlugin SevenZipExtractPlugin

	// SevenZip is the embedded 7-Zip binary.
	//
	//go:embed 7zzs
	SevenZip []byte
)

func (p *SevenZipExtractPlugin) GetDefaultConfig() (config any) {
	config = &Config{
		MaxFileSize:           defaultMaxSize,
		MaxExtractedFiles:     defaultMaxFileExtracted,
		MaxTotalExtractedSize: defaultMaxTotalExtractedSize,
		DefaultPasswords:      []string{"infected"},
	}
	return
}

// Validate checks the configuration like Init does, without any effect: the
// sizes are parsed and a configured 7-Zip binary is checked and declared.
func (p *SevenZipExtractPlugin) Validate(rawConfig any, vc plugins.ValidationContext) error {
	config, ok := rawConfig.(*Config)
	if !ok {
		return errors.New("error bad config passed")
	}
	_, _, err := parseSizes(config)
	if err != nil {
		return err
	}
	return declareBinary(config, vc)
}

func parseSizes(config *Config) (maxFileSize, maxTotalExtractedSize int64, err error) {
	if maxFileSize, err = units.ParseStrictBytes(config.MaxFileSize); err != nil {
		return 0, 0, fmt.Errorf("could not parse max_file_size: %w", err)
	}
	if maxTotalExtractedSize, err = units.ParseStrictBytes(config.MaxTotalExtractedSize); err != nil {
		return 0, 0, fmt.Errorf("could not parse max_total_extracted_size: %w", err)
	}
	return maxFileSize, maxTotalExtractedSize, nil
}

// declareBinary declares the configured 7-Zip binary to the core, which checks
// it before anything runs it.
func declareBinary(config *Config, vc plugins.ValidationContext) error {
	if config.SevenZipPath == "" {
		return nil
	}
	if err := vc.DeclareExecutable(config.SevenZipPath); err != nil {
		return fmt.Errorf("seven_zip_path: %w", err)
	}
	return nil
}

// Init sets up the extraction engine and registers callbacks.
func (p *SevenZipExtractPlugin) Init(rawConfig any, hcc plugins.HCContext) (err error) {
	p.logger = hcc.GetLogger().With(slog.String("plugin", "7z"))
	p.consoleLogger = hcc.GetConsoleLogger()

	config, ok := rawConfig.(*Config)
	if !ok {
		return errors.New("error bad config passed")
	}

	maxFileSize, maxTotalExtractedSize, err := parseSizes(config)
	if err != nil {
		return
	}
	if err = declareBinary(config, hcc); err != nil {
		return
	}

	p.sze, err = newSevenZipExtract(extractorConfig{
		MaxFileSize:           maxFileSize,
		MaxExtractedFiles:     config.MaxExtractedFiles,
		MaxTotalExtractedSize: maxTotalExtractedSize,
		DefaultPasswords:      config.DefaultPasswords,
	}, config.SevenZipPath, p.logger)
	if err != nil {
		return
	}

	hcc.SetExtractFile(p.ExtractFile)
	p.logger.Info("plugin initialized",
		slog.String("max_file_size", config.MaxFileSize),
		slog.Int("max_extracted_files", config.MaxExtractedFiles),
		slog.String("max_total_extracted_size", config.MaxTotalExtractedSize),
		slog.String("default_passwords", strings.Join(config.DefaultPasswords, ", ")),
		slog.String("seven_zip_path", config.SevenZipPath),
	)
	p.consoleLogger.Info(fmt.Sprintf("extract plugin initialized, max_file_size: %s, max_extracted_elements: %d, max_total_extracted_size: %s, default_passwords: %s, seven_zip_path: %s",
		config.MaxFileSize, config.MaxExtractedFiles, config.MaxTotalExtractedSize, strings.Join(config.DefaultPasswords, ", "), config.SevenZipPath,
	))
	return
}

// ExtractFile extracts archive contents to outputDir within the strictest of
// the plugin's keys and limits. Every failure of 7z is classified: see the
// errors wrapped by the returned error.
func (p *SevenZipExtractPlugin) ExtractFile(archiveLocation, outputDir string, limits plugins.ExtractLimits) (extraction plugins.Extraction, err error) {
	p.consoleLogger.Debug(fmt.Sprintf("start extraction of %s with 7z", archiveLocation))

	ctx, cancel := context.WithTimeout(context.Background(), szExtractTimeout)
	defer cancel()
	result, err := p.sze.extract(ctx, archiveLocation, outputDir, nil, limits)
	if err != nil {
		if errors.Is(err, ErrInvalidPassword) {
			err = fmt.Errorf("%w: %w", plugins.ErrEncrypted, err)
		}
		return plugins.Extraction{}, err
	}

	for _, ep := range result.extractedFiles {
		extraction.Files = append(extraction.Files, ep.Path)
		if ep.Size > 0 {
			extraction.Size += uint64(ep.Size)
		}
	}
	extraction.Skipped = result.skipped.entries
	extraction.SkippedCount = result.skipped.count
	if len(result.anomalies) > 0 {
		p.logger.Error("extraction anomaly", slog.String("archive", sanitizeOutput(archiveLocation)), slog.String("anomalies", sanitizeOutput(strings.Join(result.anomalies, "; "))))
		extraction.Skipped = append([]datamodel.NotAnalyzedFile{{FileName: truncateName(filepath.Base(archiveLocation)), Reason: datamodel.NotAnalyzedExtractError}}, extraction.Skipped...)
		if len(extraction.Skipped) > datamodel.MaxListedSubfiles {
			extraction.Skipped = extraction.Skipped[:datamodel.MaxListedSubfiles]
		}
		extraction.SkippedCount++
	}
	return extraction, nil
}

// Close removes temporary 7-Zip binary if one was deployed.
func (p *SevenZipExtractPlugin) Close(_ context.Context) (err error) {
	if p.sze == nil || !p.sze.tmpSevenZip {
		return
	}
	p.sze.tmpSevenZip = false
	if err = os.Remove(p.sze.sevenZipPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return
	}
	return nil
}

func main() {}
