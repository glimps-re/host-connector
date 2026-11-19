package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// PluginConfig describes one plugin to load. Plugins are loaded in slice order,
// which fixes the order of their callbacks.
type PluginConfig struct {
	// Name is the key of the plugin in the plugins file.
	Name   string         `yaml:"-"`
	File   string         `yaml:"file"`
	Config map[string]any `yaml:"config"`
}

var (
	errInvalidPlugin   = errors.New("invalid plugin")
	errDuplicatePlugin = errors.New("duplicate plugin name")
)

type namedFileScanned struct {
	plugin string
	fn     plugins.OnFileScanned
}

func checkPluginNames(pluginsConfig []PluginConfig) error {
	seen := make(map[string]struct{}, len(pluginsConfig))
	for _, pc := range pluginsConfig {
		if _, dup := seen[pc.Name]; dup {
			return fmt.Errorf("%w: %q", errDuplicatePlugin, pc.Name)
		}
		seen[pc.Name] = struct{}{}
	}
	return nil
}

func (c *Connector) SetExtractFile(f plugins.ExtractFile) {
	ExtractFile = f
}

func (c *Connector) onStartScanFile(filepath string, sha256 string) {
	for _, cb := range c.onStartScanFileCbs {
		cb(filepath, sha256)
	}
}

// onScanFile calls the OnScanFile callbacks in order. The first refusal (any
// non-nil result that is not a waiver) wins and stops the chain. A waiver is
// kept but later callbacks are still called, so a deny-list placed after an
// allow-list still applies. Without refusal, the first waiver is returned; nil
// means the file must be analyzed.
func (c *Connector) onScanFile(filename string, filepath string, sha256 string, isArchive bool) (waiver *datamodel.Result) {
	for _, cb := range c.onScanFileCbs {
		r := cb(filename, filepath, sha256, isArchive)
		if r == nil {
			continue
		}
		if !isWaiver(r) {
			return r
		}
		if waiver == nil {
			waiver = r
		}
	}
	return waiver
}

// isWaiver reports whether r only dispenses the file from analysis: not
// malicious, no error. Anything else is a refusal.
func isWaiver(r *datamodel.Result) bool {
	return !r.Malware && r.Error == nil && r.AnalysisError == ""
}

// onFileScanned calls every OnFileScanned callback in registration order, each
// one receiving the current result. It returns nil when no callback changed it.
// A callback may harden the result but never soften it: Error, Malware and
// AnalysisError set before the callback are restored.
func (c *Connector) onFileScanned(filepath string, sha256 string, result datamodel.Result) (newResult *datamodel.Result) {
	cur := result
	for _, cb := range c.onFileScannedCbs {
		res := cb.fn(filepath, sha256, cur)
		if res == nil {
			continue
		}
		next := *res
		if restoreHardened(cur, &next) {
			logger.Warn("plugin tried to soften a result, restored",
				slog.String("plugin", cb.plugin), slog.String("file", filepath))
		}
		cur = next
		newResult = &cur
	}
	return newResult
}

func restoreHardened(prev datamodel.Result, next *datamodel.Result) (restored bool) {
	if prev.Error != nil && next.Error == nil {
		next.Error = prev.Error
		restored = true
	}
	if prev.Malware && !next.Malware {
		next.Malware = true
		next.Malwares = prev.Malwares
		next.MalwareReason = prev.MalwareReason
		if next.Score < prev.Score {
			next.Score = prev.Score
		}
		restored = true
	}
	if prev.AnalysisError != "" && next.AnalysisError == "" {
		next.AnalysisError = prev.AnalysisError
		restored = true
	}
	return restored
}

func (c *Connector) withWaitForOptions(opts *gdetect.WaitForOptions, location string) {
	for _, f := range c.withWaitForOptionsFunc {
		f(opts, location)
	}
}

func (c *Connector) onReport(report *datamodel.Report) {
	for _, cb := range c.onReportCbs {
		cb(report)
	}
}

func (c *Connector) RegisterOnStartScanFile(f plugins.OnStartScanFile) {
	c.onStartScanFileCbs = append(c.onStartScanFileCbs, f)
}

func (c *Connector) RegisterOnFileScanned(f plugins.OnFileScanned) {
	c.onFileScannedCbs = append(c.onFileScannedCbs, namedFileScanned{plugin: c.loadingPlugin, fn: f})
}

// RegisterOnScanFile registers f. See onScanFile for how results combine: a
// refusal (malware or error) beats a waiver wherever the plugin sits in the file.
func (c *Connector) RegisterOnScanFile(f plugins.OnScanFile) {
	c.onScanFileCbs = append(c.onScanFileCbs, f)
}

func (c *Connector) RegisterWithWaitForOptions(f plugins.WithWaitForOptionsFunc) {
	c.withWaitForOptionsFunc = append(c.withWaitForOptionsFunc, f)
}

func (c *Connector) RegisterOnReport(f plugins.OnReport) {
	c.onReportCbs = append(c.onReportCbs, f)
}

func (c *Connector) RegisterGenerateReport(f plugins.GenerateReport) {
	c.generateReport = f
}

func (c *Connector) GenerateReport(ctx context.Context, reportContext datamodel.ScanContext, reports []datamodel.Report) (io.Reader, error) {
	return c.generateReport(ctx, reportContext, reports)
}
