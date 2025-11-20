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
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

var (
	logger        = slog.New(slog.DiscardHandler)
	consoleLogger = slog.New(slog.DiscardHandler)
)

const (
	defaultMaxSize          = 500 * 1024 * 1024 // 500MB
	defaultMaxFileExtracted = 1000              // 1000 files extracted max
)

// SevenZipExtractPlugin provides archive extraction via 7-Zip.
type SevenZipExtractPlugin struct {
	sze *sevenZipExtract
}

// Config defines extraction behavior and security limits.
type Config struct {
	extractorConfig
	SevenZipPath string `mapstructure:"seven_zip_path,omitempty"`
	TOption      bool   `mapstructure:"t_option,omitempty"`
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
		extractorConfig: extractorConfig{
			MaxFileSize:          defaultMaxSize,
			MaxExtractedElements: defaultMaxFileExtracted,
			DefaultPasswords:     []string{"infected"},
		},
	}
	return
}

// Init sets up the extraction engine and registers callbacks.
func (p *SevenZipExtractPlugin) Init(rawConfig any, hcc plugins.HCContext) error {
	logger = hcc.GetLogger().With(slog.String("plugin", "7z"))
	consoleLogger = hcc.GetConsoleLogger()

	config, ok := rawConfig.(*Config)
	if !ok {
		return errors.New("error bad config passed")
	}

	if config.SevenZipPath == "" {
		szPath, err := p.get7zzs()
		if err != nil {
			return err
		}
		config.SevenZipPath = szPath
	}

	p.sze = newSevenZipExtract(extractorConfig{
		MaxFileSize:          config.MaxFileSize,
		MaxExtractedElements: config.MaxExtractedElements,
		DefaultPasswords:     config.DefaultPasswords,
	}, config.SevenZipPath, config.TOption)

	hcc.SetExtractFile(p.ExtractFile)
	logger.Info("plugin initialized",
		slog.Int("max_file_size", config.MaxFileSize),
		slog.Int("max_extracted_elements", config.MaxExtractedElements),
		slog.String("default_passwords", strings.Join(config.DefaultPasswords, ", ")),
		slog.String("seven_zip_path", config.SevenZipPath),
		slog.Bool("t_option", config.TOption),
	)
	return nil
}

// get7zzs locates 7zzs in PATH or deploys the embedded binary.
func (p *SevenZipExtractPlugin) get7zzs() (path string, err error) {
	fname, err := exec.LookPath("7zzs")
	if err == nil {
		path, err = filepath.Abs(fname)
		if err != nil {
			return
		}
		return
	}

	f, err := os.CreateTemp(os.TempDir(), "7zzs")
	if err != nil {
		return
	}
	defer func() {
		if e := f.Close(); e != nil {
			logger.Error("could not close created 7zzs temp file", slog.String("file", f.Name()), slog.String("error", e.Error()))
		}
	}()

	_, err = f.Write(SevenZip)
	if err != nil {
		return
	}

	err = f.Chmod(0o755)
	if err != nil {
		return
	}
	path = f.Name()
	return
}

// ExtractFile extracts archive contents to outputDir with security limits.
func (p *SevenZipExtractPlugin) ExtractFile(archiveLocation, outputDir string) (size int64, files []string, volumes []string, err error) {
	consoleLogger.Debug(fmt.Sprintf("start extraction of %s with 7z", archiveLocation))

	result, err := p.sze.extract(archiveLocation, outputDir, []string{}, []string{})
	if err != nil {
		return
	}

	for _, ep := range result.extractedFiles {
		files = append(files, ep.Path)
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
