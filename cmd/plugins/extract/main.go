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
	"strings"

	"github.com/alecthomas/units"
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
	_ plugins.Plugin = &SevenZipExtractPlugin{}

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

// Init sets up the extraction engine and registers callbacks.
func (p *SevenZipExtractPlugin) Init(rawConfig any, hcc plugins.HCContext) (err error) {
	p.logger = hcc.GetLogger().With(slog.String("plugin", "7z"))
	p.consoleLogger = hcc.GetConsoleLogger()

	config, ok := rawConfig.(*Config)
	if !ok {
		return errors.New("error bad config passed")
	}

	maxFileSize, err := units.ParseStrictBytes(config.MaxFileSize)
	if err != nil {
		err = fmt.Errorf("could not parse max_file_size: %w", err)
		return
	}

	maxTotalExtractedSize, err := units.ParseStrictBytes(config.MaxTotalExtractedSize)
	if err != nil {
		err = fmt.Errorf("could not parse max_total_extracted_size: %w", err)
		return
	}

	p.sze, err = newSevenZipExtract(extractorConfig{
		MaxFileSize:           int(maxFileSize),
		MaxExtractedFiles:     config.MaxExtractedFiles,
		MaxTotalExtractedSize: int(maxTotalExtractedSize),
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

// ExtractFile extracts archive contents to outputDir with security limits.
func (p *SevenZipExtractPlugin) ExtractFile(archiveLocation, outputDir string) (size int64, files []string, volumes []string, err error) {
	p.consoleLogger.Debug(fmt.Sprintf("start extraction of %s with 7z", archiveLocation))

	result, err := p.sze.extract(archiveLocation, outputDir, []string{}, []string{})
	if err != nil {
		return
	}

	for _, ep := range result.extractedFiles {
		files = append(files, ep.Path)
		size += int64(ep.Size)
	}
	return
}

// Close removes temporary 7-Zip binary if one was deployed.
func (p *SevenZipExtractPlugin) Close(_ context.Context) (err error) {
	if !p.sze.tmpSevenZip {
		return
	}
	err = os.Remove(p.sze.sevenZipPath)
	if err != nil {
		return
	}
	return
}

func main() {}
