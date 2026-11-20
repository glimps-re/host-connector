package handler

import (
	"fmt"
	"os"

	"github.com/glimps-re/host-connector/internal/pathutil"
	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/quarantine"
)

// checkQuarantineLocation refuses a quarantine directory that other accounts
// could write to, or that overlaps a place users or plugins write to: restoring
// without a registry entry trusts that only the connector writes there. It runs
// at every application of the configuration and changes nothing.
func checkQuarantineLocation(conf *config.Config) error {
	if !conf.Actions.Quarantine {
		return nil
	}
	dir := conf.Quarantine.Location
	if dir == "" {
		dir = config.DefaultQuarantineLocation
	}
	if err := quarantine.CheckLocation(dir); err != nil {
		return err
	}

	workDir := conf.WorkDir
	if workDir == "" {
		workDir = os.TempDir()
	}
	for _, watched := range conf.Paths {
		if overlaps(dir, watched) {
			return overlapError(dir, "the monitored path", watched)
		}
	}
	if dest := conf.Move.Destination; dest != "" && overlaps(dir, dest) {
		return overlapError(dir, "move.destination", dest)
	}
	// The connector works in a private folder under workDir: a quarantine
	// directory under workDir is fine, one that is or contains it is not.
	if pathutil.Same(dir, workDir) || pathutil.UnderResolved(dir, workDir) {
		return overlapError(dir, "the work directory", workDir)
	}
	return nil
}

func overlapError(dir, what, path string) error {
	return fmt.Errorf("the quarantine directory %q is, is under, or contains %s %q: quarantine files must not be reachable by users or mixed with processed files; move the quarantine directory elsewhere", dir, what, path)
}

func overlaps(a, b string) bool {
	return pathutil.Same(a, b) || pathutil.UnderResolved(a, b) || pathutil.UnderResolved(b, a)
}
