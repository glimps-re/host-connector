package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"slices"

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
	errDuplicateFile   = errors.New("same plugin file declared twice")

	// errInconsistentPluginResult is a final outcome: a plugin result is
	// deterministic, retrying would extract the archive again for nothing.
	errInconsistentPluginResult = errors.New("inconsistent plugin result")
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

// checkPluginFiles refuses one plugin file declared under two names: its
// callbacks would be registered twice.
func checkPluginFiles(pluginsConfig []PluginConfig) error {
	var seen []os.FileInfo
	for _, pc := range pluginsConfig {
		fi, err := os.Stat(pc.File)
		if err != nil {
			logger.Debug("cannot stat plugin file", slog.String("plugin", pc.Name), slog.String("error", err.Error()))
			continue
		}
		for _, other := range seen {
			if os.SameFile(fi, other) {
				return fmt.Errorf("%w: plugin %q", errDuplicateFile, pc.Name)
			}
		}
		seen = append(seen, fi)
	}
	return nil
}

func (c *Connector) SetExtractFile(f plugins.ExtractFile) {
	c.register("ExtractFile", func(string) {
		ExtractFile = f
	})
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
// malicious, no error and no detection trace. Anything else is a refusal.
func isWaiver(r *datamodel.Result) bool {
	return !r.Malware && r.Error == nil && r.AnalysisError == "" &&
		r.MalwareReason == "" && len(r.Malwares) == 0 &&
		len(r.MaliciousSubfiles) == 0 && len(r.ErrorSubfiles) == 0
}

// refusal returns r, or a copy carrying errInconsistentPluginResult when r
// looks like a refusal (detection traces) without saying so: it must not pass
// for a clean file.
func refusal(pluginName, filepath string, r *datamodel.Result) *datamodel.Result {
	if r.Malware || r.Error != nil || r.AnalysisError != "" {
		return r
	}
	logger.Warn("inconsistent plugin result, file refused: it carries detection traces but no malware, error or analysis error",
		slog.String("plugin", pluginName), slog.String("file", filepath))
	out := cloneResult(*r)
	out.Error = errInconsistentPluginResult
	return &out
}

// cloneResult deep-copies the maps and slices of r, so that a plugin cannot
// modify a result owned by the core, nor keep a reference to it.
func cloneResult(r datamodel.Result) datamodel.Result {
	r.Malwares = slices.Clone(r.Malwares)
	r.ErrorSubfiles = maps.Clone(r.ErrorSubfiles)
	if r.MaliciousSubfiles != nil {
		sub := make(map[string]datamodel.Result, len(r.MaliciousSubfiles))
		for k, v := range r.MaliciousSubfiles {
			sub[k] = cloneResult(v)
		}
		r.MaliciousSubfiles = sub
	}
	return r
}

// onFileScanned calls every OnFileScanned callback in registration order, each
// one receiving a deep copy of the current result. It returns nil when no
// callback changed it. A callback may harden the result but never soften it:
// Error, Malware, AnalysisError, MalwareReason, Malwares, MaliciousSubfiles
// and ErrorSubfiles set before the callback are restored.
func (c *Connector) onFileScanned(filepath string, sha256 string, result datamodel.Result) (newResult *datamodel.Result) {
	cur := cloneResult(result)
	for _, cb := range c.onFileScannedCbs {
		res := cb.fn(filepath, sha256, cloneResult(cur))
		if res == nil {
			continue
		}
		next := cloneResult(*res)
		if restoreHardened(cur, &next) {
			logger.Warn("plugin tried to soften a result, restored",
				slog.String("plugin", cb.plugin), slog.String("file", filepath))
		}
		cur = next
		newResult = &cur
	}
	return newResult
}

// restoreHardened merges the detection state of prev back into next, so that a
// plugin can add to a result but not remove from it: entries of Malwares,
// MaliciousSubfiles (recursively) and ErrorSubfiles missing from next are
// restored, as are Error, Malware, AnalysisError and MalwareReason. It reports
// whether anything had to be restored.
func restoreHardened(prev datamodel.Result, next *datamodel.Result) (restored bool) {
	if prev.Error != nil && next.Error == nil {
		next.Error = prev.Error
		restored = true
	}
	if prev.Malware && !next.Malware {
		next.Malware = true
		restored = true
	}
	if next.Score < prev.Score {
		next.Score = prev.Score
		restored = true
	}
	if prev.AnalysisError != "" && next.AnalysisError == "" {
		next.AnalysisError = prev.AnalysisError
		restored = true
	}
	if prev.MalwareReason != "" && next.MalwareReason == "" {
		next.MalwareReason = prev.MalwareReason
		restored = true
	}
	for _, m := range prev.Malwares {
		if !slices.Contains(next.Malwares, m) {
			next.Malwares = append(next.Malwares, m)
			restored = true
		}
	}
	for name, prevSub := range prev.ErrorSubfiles {
		if _, ok := next.ErrorSubfiles[name]; !ok {
			if next.ErrorSubfiles == nil {
				next.ErrorSubfiles = make(map[string]string, len(prev.ErrorSubfiles))
			}
			next.ErrorSubfiles[name] = prevSub
			restored = true
		}
	}
	for name, prevSub := range prev.MaliciousSubfiles {
		nextSub, ok := next.MaliciousSubfiles[name]
		if !ok {
			if next.MaliciousSubfiles == nil {
				next.MaliciousSubfiles = make(map[string]datamodel.Result, len(prev.MaliciousSubfiles))
			}
			next.MaliciousSubfiles[name] = cloneResult(prevSub)
			restored = true
			continue
		}
		if restoreHardened(prevSub, &nextSub) {
			next.MaliciousSubfiles[name] = nextSub
			restored = true
		}
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

// register runs add under the plugin lock, unless loading is over (a Connector
// stays sealed once its plugins are loaded): later Register* and SetExtractFile calls are ignored with a warning, so the callback lists never change
// while files are processed. add receives the name of the plugin being loaded.
func (c *Connector) register(what string, add func(pluginName string)) {
	c.pluginsMu.Lock()
	defer c.pluginsMu.Unlock()
	if c.pluginsSealed {
		logger.Warn("plugin registration outside Init ignored", slog.String("callback", what), slog.String("plugin", c.loadingPlugin))
		return
	}
	add(c.loadingPlugin)
}

func (c *Connector) setLoading(pluginName string) {
	c.pluginsMu.Lock()
	defer c.pluginsMu.Unlock()
	c.loadingPlugin = pluginName
}

func (c *Connector) setSealed(sealed bool) {
	c.pluginsMu.Lock()
	defer c.pluginsMu.Unlock()
	c.pluginsSealed = sealed
}

func (c *Connector) RegisterOnStartScanFile(f plugins.OnStartScanFile) {
	c.register("OnStartScanFile", func(string) {
		c.onStartScanFileCbs = append(c.onStartScanFileCbs, f)
	})
}

func (c *Connector) RegisterOnFileScanned(f plugins.OnFileScanned) {
	c.register("OnFileScanned", func(pluginName string) {
		c.onFileScannedCbs = append(c.onFileScannedCbs, namedFileScanned{plugin: pluginName, fn: f})
	})
}

// RegisterOnScanFile registers f. See onScanFile for how results combine: a
// refusal (malware or error) beats a waiver wherever the plugin sits in the file.
// The result of f is copied once, before any test: the plugin keeps no
// reference into what the core processes.
func (c *Connector) RegisterOnScanFile(f plugins.OnScanFile) {
	c.register("OnScanFile", func(pluginName string) {
		c.onScanFileCbs = append(c.onScanFileCbs, func(filename, location, sha256 string, isArchive bool) *datamodel.Result {
			r := f(filename, location, sha256, isArchive)
			if r == nil {
				return nil
			}
			own := cloneResult(*r)
			if isWaiver(&own) {
				return &own
			}
			return refusal(pluginName, location, &own)
		})
	})
}

func (c *Connector) RegisterWithWaitForOptions(f plugins.WithWaitForOptionsFunc) {
	c.register("WithWaitForOptions", func(string) {
		c.withWaitForOptionsFunc = append(c.withWaitForOptionsFunc, f)
	})
}

func (c *Connector) RegisterOnReport(f plugins.OnReport) {
	c.register("OnReport", func(string) {
		c.onReportCbs = append(c.onReportCbs, f)
	})
}

func (c *Connector) RegisterGenerateReport(f plugins.GenerateReport) {
	c.register("GenerateReport", func(string) {
		c.generateReport = f
	})
}

func (c *Connector) GenerateReport(ctx context.Context, reportContext datamodel.ScanContext, reports []datamodel.Report) (io.Reader, error) {
	return c.generateReport(ctx, reportContext, reports)
}
