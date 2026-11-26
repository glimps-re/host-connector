package handler

import (
	"github.com/glimps-re/host-connector/pkg/config"
)

// warnFollowSymlinks tells the operator that follow_symlinks switches off the
// symbolic link checks of the paths while files are moved, deleted or
// quarantined: a user could point a link at a file outside the monitored tree.
func warnFollowSymlinks(conf *config.Config) {
	if !conf.FollowSymlinks || len(conf.Paths) == 0 {
		return
	}
	if !conf.Actions.Move && !conf.Actions.Delete && !conf.Actions.Quarantine {
		return
	}
	warnConfig("follow_symlinks", "follow_symlinks is enabled with move, delete or quarantine actions: the symbolic link checks are off, a link in a monitored folder can make the connector act on files outside it")
}
