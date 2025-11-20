// Package main implements a file size filter plugin.
//
// Marks files exceeding the configured size limit as malicious (excludes archives).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/alecthomas/units"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

var logger = slog.New(slog.DiscardHandler)

// Config defines the maximum file size limit.
type Config struct {
	MaxSize string `mapstructure:"max_size"`
}

var (
	_ plugins.Plugin = &FileSizePlugin{}

	// HCPlugin is the exported plugin instance.
	HCPlugin FileSizePlugin
)

// FileSizePlugin filters files based on size.
type FileSizePlugin struct {
	MaxSize int64
}

// Close cleans up plugin resources (no-op for this plugin).
func (p *FileSizePlugin) Close(ctx context.Context) (err error) {
	return
}

// GetDefaultConfig returns the default configuration (100MB limit).
func (p *FileSizePlugin) GetDefaultConfig() (config any) {
	return &Config{
		MaxSize: "100MB",
	}
}

// Init parses configuration and registers callbacks.
func (p *FileSizePlugin) Init(rawConfig any, hcc plugins.HCContext) (err error) {
	logger = logger.With(slog.String("plugin", "FileSize"))
	config, ok := rawConfig.(*Config)
	if !ok {
		return errors.New("invalid config passed")
	}

	maxFileSize, err := units.ParseStrictBytes(config.MaxSize)
	if err != nil {
		err = fmt.Errorf("could not parse max_size: %w", err)
		return
	}

	p.MaxSize = maxFileSize
	hcc.RegisterOnScanFile(p.OnScanFile)
	logger.Info("plugin initialized", slog.Int("max_size", int(p.MaxSize)))
	return
}

// OnScanFile marks files exceeding MaxSize as malicious (excludes archives).
func (p *FileSizePlugin) OnScanFile(filename string, location string, sha256 string, isArchive bool) (res *datamodel.Result) {
	if isArchive {
		return
	}
	fileInfo, err := os.Stat(location)
	if err != nil {
		return
	}
	if fileInfo.Size() > p.MaxSize {
		res = &datamodel.Result{
			Filename:       filename,
			Malware:        true,
			SHA256:         sha256,
			Score:          1000,
			MalwareReason:  datamodel.TooBig,
			FileSize:       fileInfo.Size(),
			FilteredVolume: fileInfo.Size(),
		}
	}
	return
}

func main() {}
