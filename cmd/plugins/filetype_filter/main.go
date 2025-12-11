// Package main implements a MIME type-based file filtering plugin.
//
// Filters files based on MIME types detected via libmagic. Forbidden types are
// flagged as malicious, skipped types are marked as safe, others pass through.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/vimeo/go-magic/magic"
)

var (
	logger        = slog.New(slog.DiscardHandler)
	consoleLogger = slog.New(slog.DiscardHandler)
)

// FTFilterPlugin provides MIME type-based file filtering.
type FTFilterPlugin struct {
	ForbiddenTypes map[string]struct{} // MIME types to flag as malicious
	SkippedTypes   map[string]struct{} // MIME types to mark as safe
}

// Config defines MIME type filtering rules.
type Config struct {
	ForbiddenTypes []string `mapstructure:"forbidden_types,omitempty"`
	SkippedTypes   []string `mapstructure:"skipped_types,omitempty"`
}

var (
	_ plugins.Plugin = &FTFilterPlugin{}

	// HCPlugin is the exported plugin instance.
	HCPlugin FTFilterPlugin
)

func (p *FTFilterPlugin) GetDefaultConfig() (config any) {
	return new(Config)
}

// Init initializes the plugin with libmagic and configuration.
func (p *FTFilterPlugin) Init(rawConfig any, hcc plugins.HCContext) error {
	logger = hcc.GetLogger().With(slog.String("plugin", "filetype_filter"))
	consoleLogger = hcc.GetConsoleLogger()

	if addMagicErr := magic.AddMagicDir(magic.GetDefaultDir()); addMagicErr != nil {
		logger.Warn("could not add default magic dir", slog.String("dir", magic.GetDefaultDir()), slog.String("error", addMagicErr.Error()))
	}

	config, ok := rawConfig.(*Config)
	if !ok {
		return errors.New("invalid config passed")
	}

	p.ForbiddenTypes = make(map[string]struct{}, len(config.ForbiddenTypes))
	p.SkippedTypes = make(map[string]struct{}, len(config.SkippedTypes))

	for _, mime := range config.ForbiddenTypes {
		p.ForbiddenTypes[mime] = struct{}{}
	}

	for _, mime := range config.SkippedTypes {
		p.SkippedTypes[mime] = struct{}{}
	}

	hcc.RegisterOnScanFile(p.OnScanFile)

	logger.Info("plugin initialized",
		slog.String("forbidden_types", strings.Join(config.ForbiddenTypes, ", ")),
		slog.String("skipped_types", strings.Join(config.SkippedTypes, ", ")),
	)
	consoleLogger.Info(fmt.Sprintf("filetypefilter plugin initialized, forbidden_types: %s, skipped_types: %s",
		strings.Join(config.ForbiddenTypes, ", "), strings.Join(config.SkippedTypes, ", ")))
	return nil
}

// Close cleans up plugin resources (no-op for this plugin).
func (p *FTFilterPlugin) Close(context.Context) error {
	return nil
}

// OnScanFile filters files based on MIME type (forbidden=malicious, skipped=safe).
func (p *FTFilterPlugin) OnScanFile(filename string, location string, sha256 string, _ bool) (res *datamodel.Result) {
	fileInfo, err := os.Stat(location)
	if err != nil {
		return
	}
	mime := magic.MimeFromFile(location)
	if _, ok := p.ForbiddenTypes[mime]; ok {
		consoleLogger.Debug(fmt.Sprintf("filtered file based on its type (blacklist) file=%s, mime=%s", location, mime))
		logger.Debug("set file as malware",
			slog.String("file", location),
			slog.String("sha256", sha256),
			slog.String("mime", mime))
		return &datamodel.Result{
			Filename:       filename,
			FileType:       mime,
			Malware:        true,
			SHA256:         sha256,
			Score:          1000,
			Malwares:       []string{"forbidden_files"},
			MalwareReason:  datamodel.FilteredFileType,
			FilteredVolume: fileInfo.Size(),
			FileSize:       fileInfo.Size(),
		}
	}

	if _, ok := p.SkippedTypes[mime]; ok {
		consoleLogger.Debug(fmt.Sprintf("filtered file based on its type (whitelist) file=%s, mime=%s", location, mime))
		logger.Debug("set file as legit",
			slog.String("file", location),
			slog.String("sha256", sha256),
			slog.String("mime", mime))
		return &datamodel.Result{
			Filename:       filename,
			FileType:       mime,
			Malware:        false,
			SHA256:         sha256,
			Score:          -500,
			FilteredVolume: fileInfo.Size(),
			FileSize:       fileInfo.Size(),
		}
	}

	return nil
}

func main() {}
