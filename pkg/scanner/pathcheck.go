package scanner

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/glimps-re/host-connector/internal/pathutil"
)

// containingRoot returns the shortest known root (monitored path, or scan
// argument) containing abs, or "". The shortest, not the longest: with nested
// roots, a link replacing the inner one must not be taken for a trusted root.
func (c *Connector) containingRoot(abs string) string {
	best := ""
	consider := func(root string) {
		if pathutil.Under(root, abs) && (best == "" || len(root) < len(best)) {
			best = root
		}
	}
	c.rootsOnce.Do(func() {
		for _, r := range c.config.Roots {
			if ra, err := filepath.Abs(r); err == nil {
				c.absRoots = append(c.absRoots, ra)
			}
		}
	})
	for _, ra := range c.absRoots {
		consider(ra)
	}
	c.scanRoots.Range(func(k, _ any) bool {
		if root, ok := k.(string); ok {
			consider(root)
		}
		return true
	})
	return best
}

// rootFor returns the root a path is checked from: the monitored path that
// contains it, else the argument of the scan it came from, else its own
// directory (only the file itself is then examined).
func (c *Connector) rootFor(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Dir(path)
	}
	if root := c.containingRoot(abs); root != "" {
		return root
	}
	return filepath.Dir(abs)
}

// noteScanRoot remembers input as the root of its scan when no known root
// contains it: the operator named it on the command line.
func (c *Connector) noteScanRoot(input string) {
	abs, err := filepath.Abs(input)
	if err != nil || c.containingRoot(abs) != "" {
		return
	}
	c.scanRoots.LoadOrStore(abs, struct{}{})
}

// checkPath refuses location when its path crosses a symbolic link below its
// root. follow_symlinks, chosen by the operator, disables the check.
func (c *Connector) checkPath(location string) error {
	if c.config.FollowSymlinks {
		return nil
	}
	abs, err := filepath.Abs(location)
	if err != nil {
		return err
	}
	return pathutil.CheckNoSymlink(c.rootFor(abs), abs)
}

// refusePath reports a refused path. A link is a possible hijack attempt; a
// file that vanished is not.
func refusePath(location string, err error) {
	if !errors.Is(err, pathutil.ErrSymlinkInPath) {
		logger.Debug("file left in place, its path cannot be checked", slog.String("file", location), slog.String(logErrorKey, err.Error()))
		return
	}
	logger.Warn("path refused, no action taken, file left in place", slog.String("file", location), slog.String(logErrorKey, err.Error()))
	ConsoleLogger.Warn(fmt.Sprintf("file %s refused, left in place: %s", location, err.Error()))
}
