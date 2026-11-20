package handler

import (
	"fmt"

	"github.com/glimps-re/host-connector/internal/pathutil"
	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

// checkDeclarations refuses what plugins declared when it conflicts with the
// configuration: an output directory that is, or is under, a monitored path
// (results would be scanned as deposits) or that overlaps the quarantine
// directory; an executable under a monitored path, under move.destination or
// under an output directory (users or plugins could replace it).
func checkDeclarations(conf *config.Config, d scanner.Declarations) error {
	for _, out := range d.OutputDirs {
		for _, watched := range conf.Paths {
			if pathutil.Same(out, watched) || pathutil.UnderResolved(watched, out) {
				return fmt.Errorf("output directory %q declared by a plugin is, or is under, the monitored path %q: its results would be scanned again; use a directory outside the monitored paths", out, watched)
			}
		}
		if conf.Actions.Quarantine {
			quarantineDir := conf.Quarantine.Location
			if quarantineDir == "" {
				quarantineDir = config.DefaultQuarantineLocation
			}
			if overlaps(quarantineDir, out) {
				return fmt.Errorf("output directory %q declared by a plugin overlaps the quarantine directory %q", out, quarantineDir)
			}
		}
		if dest := conf.Move.Destination; dest != "" && pathutil.UnderResolved(dest, out) {
			return fmt.Errorf("output directory %q declared by a plugin is under move.destination %q: results would be moved with the clean files", out, dest)
		}
	}
	for _, exe := range d.Executables {
		for _, watched := range conf.Paths {
			if pathutil.UnderResolved(watched, exe) {
				return fmt.Errorf("executable %q declared by a plugin is under the monitored path %q: a user could replace it; install it elsewhere", exe, watched)
			}
		}
		if dest := conf.Move.Destination; dest != "" && pathutil.UnderResolved(dest, exe) {
			return fmt.Errorf("executable %q declared by a plugin is under move.destination %q: a user could replace it; install it elsewhere", exe, dest)
		}
		for _, out := range d.OutputDirs {
			if pathutil.UnderResolved(out, exe) {
				return fmt.Errorf("executable %q declared by a plugin is under the output directory %q: it could be replaced by a result; install it elsewhere", exe, out)
			}
		}
	}
	return nil
}
