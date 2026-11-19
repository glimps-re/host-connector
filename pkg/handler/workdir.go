package handler

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/glimps-re/host-connector/internal/pathutil"
	"github.com/glimps-re/host-connector/pkg/config"
)

// checkWorkDir refuses a work directory base that is, or lies under, a
// monitored path: the extraction directories would be watched (one inotify
// watch each, which can exhaust max_user_watches) and their files taken for
// user deposits. A move destination under a monitored path only warns: files
// written there would be scanned again.
func checkWorkDir(conf *config.Config) error {
	base := conf.WorkDir
	if base == "" {
		base = os.TempDir()
	}
	for _, watched := range conf.Paths {
		if pathutil.Same(base, watched) || pathutil.UnderResolved(watched, base) {
			return fmt.Errorf("work_dir %q is, or is under, the monitored path %q: set work_dir to a directory outside the monitored paths (the default is the system temporary directory)", base, watched)
		}
	}
	if dest := conf.Move.Destination; dest != "" {
		for _, watched := range conf.Paths {
			if pathutil.UnderResolved(watched, dest) {
				warnWorkDir(fmt.Sprintf("move.destination %q is under the monitored path %q: files written there would be scanned again", dest, watched))
			}
		}
	}
	return nil
}

func warnWorkDir(msg string) {
	logger.Warn(msg, slog.String("source", "work_dir"))
	consoleLogger.Warn(msg)
}
