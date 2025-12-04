// Package main implements a plugin that marks files with analysis errors as malicious.
package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

var (
	logger        = slog.New(slog.DiscardHandler)
	consoleLogger = slog.New(slog.DiscardHandler)
)

// Config for the error filter plugin (currently no configuration needed).
type Config struct{}

var (
	_ plugins.Plugin = &ErrorFilterPlugin{}

	// HCPlugin is the exported plugin instance.
	HCPlugin ErrorFilterPlugin
)

// ErrorFilterPlugin mitigates files that encountered analysis errors.
type ErrorFilterPlugin struct{}

// Close cleans up plugin resources (no-op for this plugin).
func (p *ErrorFilterPlugin) Close(_ context.Context) (err error) {
	return
}

// GetDefaultConfig returns the default configuration.
func (p *ErrorFilterPlugin) GetDefaultConfig() (config any) {
	return &Config{}
}

// Init initializes the plugin and registers callbacks.
func (p *ErrorFilterPlugin) Init(_ any, hcc plugins.HCContext) (err error) {
	logger = hcc.GetLogger().With(slog.String("plugin", "error_filter"))
	consoleLogger = hcc.GetConsoleLogger()
	hcc.RegisterOnFileScanned(p.OnFileScanned)
	logger.Info("plugin initialized")
	consoleLogger.Info("error_filter plugin initialized")
	return
}

// OnFileScanned marks files with analysis errors as malicious.
func (p *ErrorFilterPlugin) OnFileScanned(file string, sha256 string, result datamodel.Result) (newResult *datamodel.Result) {
	if result.AnalysisError != "" {
		consoleLogger.Debug(fmt.Sprintf("analysis result for file %s contains error (%s), mitigate it", file, result.AnalysisError))
		result.Malware = true
		result.MalwareReason = datamodel.AnalysisError
		return &result
	}
	return
}

func main() {}
