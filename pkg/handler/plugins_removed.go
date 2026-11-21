package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/glimps-re/host-connector/pkg/scanner"
)

// removedFilesizeWarning is what the entries of the removed plugin get: each one
// is named, its configuration is not carried over, and the message says which
// policy governs oversized files now, so that nothing is switched on for the
// operator.
func removedFilesizeWarning(dropped []scanner.PluginConfig, tooBig string) string {
	entries := make([]string, len(dropped))
	for i, pc := range dropped {
		entries[i] = fmt.Sprintf("%q (file %q)", pc.Name, pc.File)
	}
	policy := "unanalyzable_policy.too_big is " + effectiveTooBig(tooBig)
	if tooBig == scanner.PolicyMitigate {
		policy += ", which keeps oversized files quarantined"
	} else {
		policy += ": set it to mitigate to keep oversized files quarantined"
	}
	return "the filesize_filter plugin was removed and these entries of the plugins file are ignored: " + strings.Join(entries, ", ") +
		"; their configuration (max_size) is not carried over, max_file_size and unanalyzable_policy.too_big apply instead (" + policy + ")"
}

func effectiveTooBig(tooBig string) string {
	if tooBig == "" {
		return scanner.PolicyError + " (the default)"
	}
	return tooBig
}

// errOnlyRemovedPlugins refuses a plugins file that holds nothing but removed
// plugins: loading no plugin would silently drop every filter.
var errOnlyRemovedPlugins = errors.New("the plugins file only has the removed filesize_filter plugin: remove the plugins file or add a plugin")

// isRemovedFilesizeFilter tells whether a plugins file entry is the one of the
// removed plugin: by its name, or by the file it names.
func isRemovedFilesizeFilter(pc scanner.PluginConfig) bool {
	if pc.Name == "filesize_filter" {
		return true
	}
	switch filepath.Base(pc.File) {
	case "filesize_filter.so", "filesize.so":
		return true
	}
	return false
}

// dropRemovedPlugins takes the entries of removed plugins out of the list, before
// the plugins are validated and loaded: a plugin that is no longer shipped must
// not fail the start. It returns the entries it dropped.
func dropRemovedPlugins(configs []scanner.PluginConfig) (kept, dropped []scanner.PluginConfig) {
	kept = make([]scanner.PluginConfig, 0, len(configs))
	for _, pc := range configs {
		if isRemovedFilesizeFilter(pc) {
			dropped = append(dropped, pc)
			continue
		}
		kept = append(kept, pc)
	}
	return kept, dropped
}

// reportRemovedPlugins keeps the entries of a removed plugin visible: a warning in
// the log and a console error for as long as the plugins file has them.
func (h *Handler) reportRemovedPlugins(ctx context.Context, dropped []scanner.PluginConfig, tooBig string) {
	if len(dropped) == 0 {
		if e := eventHandler.NotifyResolution(ctx, "no entry of the removed filesize_filter plugin in the plugins file", HostPluginRemovedFilesize); e != nil {
			logger.Warn("could not push resolution event to connector manager", slog.String("error", e.Error()))
		}
		return
	}
	msg := removedFilesizeWarning(dropped, tooBig)
	logger.Warn(msg)
	scanner.ConsoleLogger.Warn(msg)
	if e := eventHandler.NotifyError(ctx, HostPluginRemovedFilesize, errors.New(msg)); e != nil {
		logger.Warn("could not push console error", slog.String("error", e.Error()))
	}
}
