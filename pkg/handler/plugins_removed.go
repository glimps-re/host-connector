package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"

	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

// removedContext is what the messages about removed plugins say of the
// configuration that replaces them.
type removedContext struct {
	tooBig, analysisError string
	forbiddenPaths        int
	skippedPaths          int
}

func newRemovedContext(conf *config.Config) removedContext {
	return removedContext{
		tooBig:         conf.UnanalyzablePolicy.TooBig,
		analysisError:  conf.UnanalyzablePolicy.AnalysisError,
		forbiddenPaths: len(conf.FilepathFilter.ForbiddenPaths),
		skippedPaths:   len(conf.FilepathFilter.SkippedPaths),
	}
}

// removedPlugin is a plugin that is no longer shipped. Its entries in the plugins
// file are ignored and never carried over; an entry is never refused on its own (a
// plugin that is no longer shipped must not fail the start), while a file with
// nothing else is (errOnlyRemovedPlugins). Each entry is named in a warning and a
// console error, which say what to set instead and are resolved once the entries
// are gone. An entry is the one of the plugin by its name, or by the base name of
// its file: a plugin of anyone else whose file is called filepath.so (or one of the
// other names of files) is dropped too.
type removedPlugin struct {
	name string
	// files are the base names of the files of the plugin, besides name.
	files   []string
	event   events.ErrorEventType
	message func(dropped []scanner.PluginConfig, c removedContext) string
}

var removedPlugins = []removedPlugin{
	{
		name: "filesize_filter", files: []string{"filesize_filter.so", "filesize.so"},
		event: HostPluginRemovedFilesize, message: removedFilesizeMessage,
	},
	{
		name: "filepath_filter", files: []string{"filepath_filter.so", "filepath.so", "filepath_filter"},
		event: HostPluginRemovedFilepath, message: removedFilepathMessage,
	},
	{
		name: "error_filter", files: []string{"error_filter.so", "error_filter"},
		event: HostPluginRemovedError, message: removedErrorMessage,
	},
}

// matches tells whether a plugins file entry is the one of the plugin: by its name,
// or by the file it names.
func (r *removedPlugin) matches(pc scanner.PluginConfig) bool {
	if pc.Name == r.name {
		return true
	}
	return slices.Contains(r.files, filepath.Base(pc.File))
}

// removedEntries lists the entries of the plugin, in the order of the file.
func (r *removedPlugin) removedEntries(dropped []scanner.PluginConfig) []scanner.PluginConfig {
	var out []scanner.PluginConfig
	for _, pc := range dropped {
		if r.matches(pc) {
			out = append(out, pc)
		}
	}
	return out
}

func namedEntries(dropped []scanner.PluginConfig) string {
	entries := make([]string, min(len(dropped), maxReportedKeys))
	for i, pc := range dropped[:len(entries)] {
		entries[i] = quoteBounded(pc.Name, maxReportedNameLen) + " (file " + quoteBounded(pc.File, maxReportedFileLen) + ")"
	}
	return joinCounted(entries, len(dropped))
}

// removedFilesizeMessage names the entries, says that their configuration is not
// carried over and which policy governs oversized files now, so that nothing is
// switched on for the operator.
func removedFilesizeMessage(dropped []scanner.PluginConfig, c removedContext) string {
	policy := "unanalyzable_policy.too_big is " + effectiveTooBig(c.tooBig)
	if c.tooBig == scanner.PolicyMitigate {
		policy += ", which keeps oversized files quarantined"
	} else {
		policy += ": set it to mitigate to keep oversized files quarantined"
	}
	return "the filesize_filter plugin was removed and these entries of the plugins file are ignored: " + namedEntries(dropped) +
		"; their configuration (max_size) is not carried over, max_file_size and unanalyzable_policy.too_big apply instead (" + policy + ")"
}

// removedFilepathMessage says that the lists of the plugin no longer apply from the
// plugins file, and where they are set now. Nothing is carried over: a deny-list
// that is not in the main configuration does not apply, which the message says.
func removedFilepathMessage(dropped []scanner.PluginConfig, c removedContext) string {
	now := "the filepath_filter section of the configuration has no pattern, so no path is forbidden or skipped"
	if c.forbiddenPaths+c.skippedPaths > 0 {
		now = fmt.Sprintf("the filepath_filter section of the configuration has %d forbidden and %d skipped pattern(s)", c.forbiddenPaths, c.skippedPaths)
	}
	msg := "the filepath_filter plugin was removed and these entries of the plugins file are ignored: " + namedEntries(dropped) +
		"; their forbidden_paths and skipped_paths are not carried over and no longer apply: set them in the filepath_filter section of the configuration (forbidden_paths, skipped_paths) (" + now + ")"
	if lost := droppedDenyPatterns(dropped); lost > 0 && c.forbiddenPaths == 0 {
		msg = fmt.Sprintf("WARNING: the deny-list of the removed filepath_filter plugin (%d forbidden_paths pattern(s)) is NOT enforced: the main configuration has no forbidden_paths. ", lost) + msg
	}
	return msg
}

// droppedDenyPatterns counts the forbidden_paths patterns of the dropped entries.
func droppedDenyPatterns(dropped []scanner.PluginConfig) int {
	n := 0
	for _, pc := range dropped {
		switch list := pc.Config["forbidden_paths"].(type) {
		case []any:
			n += len(list)
		case []string:
			n += len(list)
		}
	}
	return n
}

// removedErrorMessage says what governs the files whose analysis fails now.
func removedErrorMessage(dropped []scanner.PluginConfig, c removedContext) string {
	policy := "unanalyzable_policy.analysis_error is " + effectiveAnalysisError(c.analysisError)
	if c.analysisError == scanner.PolicyMitigate {
		policy += ", which quarantines them as the plugin did"
	} else {
		policy += ": set it to mitigate to quarantine them as the plugin did"
	}
	return "the error_filter plugin was removed and these entries of the plugins file are ignored: " + namedEntries(dropped) +
		"; files whose analysis fails are handled by unanalyzable_policy.analysis_error now (" + policy + ")"
}

func effectiveTooBig(tooBig string) string {
	if tooBig == "" {
		return scanner.PolicyError + " (the default)"
	}
	return tooBig
}

func effectiveAnalysisError(policy string) string {
	if policy == "" {
		return scanner.PolicyError + " (the default: they stay in INPUT)"
	}
	return policy
}

// errOnlyRemovedPlugins refuses a plugins file that holds nothing but removed
// plugins: loading no plugin would silently drop every filter.
var errOnlyRemovedPlugins = errors.New("the plugins file only has removed plugins (" + removedNames() + "): remove the plugins file or add a plugin")

func removedNames() string {
	names := make([]string, len(removedPlugins))
	for i, r := range removedPlugins {
		names[i] = r.name
	}
	return strings.Join(names, ", ")
}

// dropRemovedPlugins takes the entries of removed plugins out of the list, before
// the plugins are validated and loaded: a plugin that is no longer shipped must
// not fail the start. It returns the entries it dropped.
func dropRemovedPlugins(configs []scanner.PluginConfig) (kept, dropped []scanner.PluginConfig) {
	kept = make([]scanner.PluginConfig, 0, len(configs))
	for _, pc := range configs {
		if isRemovedPlugin(pc) {
			dropped = append(dropped, pc)
			continue
		}
		kept = append(kept, pc)
	}
	return kept, dropped
}

func isRemovedPlugin(pc scanner.PluginConfig) bool {
	for i := range removedPlugins {
		if removedPlugins[i].matches(pc) {
			return true
		}
	}
	return false
}

// reportRemovedPlugins keeps the entries of the removed plugins visible: for each
// plugin, a warning in the log and a console error for as long as the plugins file
// has an entry of it, and a resolution once it has none.
func (h *Handler) reportRemovedPlugins(ctx context.Context, dropped []scanner.PluginConfig, c removedContext) {
	for i := range removedPlugins {
		r := &removedPlugins[i]
		entries := r.removedEntries(dropped)
		if len(entries) == 0 {
			if e := eventHandler.NotifyResolution(ctx, "no entry of the removed "+r.name+" plugin in the plugins file", r.event); e != nil {
				logger.Warn("could not push resolution event to connector manager", slog.String("error", e.Error()))
			}
			continue
		}
		msg := r.message(entries, c)
		logger.Warn(msg)
		scanner.ConsoleLogger.Warn(msg)
		if e := eventHandler.NotifyError(ctx, r.event, errors.New(msg)); e != nil {
			logger.Warn("could not push console error", slog.String("error", e.Error()))
		}
	}
}
