package scanner

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/glimps-re/host-connector/internal/pathutil"
)

const (
	dirPrivate  fs.FileMode = 0o700
	dirUnlocked fs.FileMode = 0o750
)

const (
	workDirPrefix  = "gmhost-"
	workDirLock    = ".lock"
	extractDirName = "extract"
)

// workDir is the connector private directory: extraction output and plugin
// scratch files live there, never user deposits. It is guarded by a lock file
// so that the directory of a crashed process can be told from a live one.
type workDir struct {
	path     string
	resolved string
	lock     *os.File
}

// newWorkDir creates <base>/gmhost-<random> (mode 0o700), base defaulting to
// os.TempDir(). Orphans left by crashed processes next to it are purged.
func newWorkDir(base string) (*workDir, error) {
	if base == "" {
		base = os.TempDir()
	}
	base, err := filepath.Abs(base)
	if err != nil {
		return nil, fmt.Errorf("work dir base: %w", err)
	}
	if err = os.MkdirAll(base, 0o750); err != nil {
		return nil, fmt.Errorf("create work dir base: %w", err)
	}
	path, err := os.MkdirTemp(base, workDirPrefix)
	if err != nil {
		return nil, fmt.Errorf("create work dir: %w", err)
	}
	w := &workDir{path: path}
	// The purge only takes 0o700 directories: keeping it 0o750 until the lock
	// is held keeps a concurrent start from removing this one.
	if err = os.Chmod(path, dirUnlocked); err != nil {
		return nil, errors.Join(fmt.Errorf("prepare work dir: %w", err), os.RemoveAll(path))
	}
	lock, err := createWorkDirLock(filepath.Join(path, workDirLock))
	if err != nil {
		return nil, errors.Join(fmt.Errorf("lock work dir: %w", err), os.RemoveAll(path))
	}
	w.lock = lock
	if err = os.Chmod(path, dirPrivate); err != nil {
		return nil, errors.Join(fmt.Errorf("secure work dir: %w", err), w.close())
	}
	if err = os.Mkdir(filepath.Join(path, extractDirName), 0o700); err != nil {
		return nil, errors.Join(fmt.Errorf("create extract dir: %w", err), w.close())
	}
	w.resolved, err = filepath.EvalSymlinks(path)
	if err != nil {
		w.resolved = path
	}
	purgeOrphans(base, path)
	if inMemoryFS(path) {
		const msg = "the work directory is on a memory filesystem (tmpfs/ramfs): archive extractions use RAM, set work_dir to a local disk"
		logger.Warn(msg, slog.String("work_dir", path))
		ConsoleLogger.Warn(msg)
	}
	return w, nil
}

func (w *workDir) extractDir() string { return filepath.Join(w.path, extractDirName) }

func (w *workDir) close() error {
	if w == nil {
		return nil
	}
	var errs []error
	if w.lock != nil {
		errs = append(errs, w.lock.Close())
	}
	errs = append(errs, os.RemoveAll(w.path))
	return errors.Join(errs...)
}

// contains reports whether p is the work directory or lies under it, compared
// lexically (no filesystem access): it runs for every file of every rescan.
func (w *workDir) contains(p string) bool {
	abs, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	return pathutil.Under(w.path, abs) || pathutil.Under(w.resolved, abs)
}

// containsResolved is contains on the symlink-resolved path: for the places
// where a link may be followed.
func (w *workDir) containsResolved(p string) bool {
	return pathutil.UnderResolved(w.path, p) || pathutil.UnderResolved(w.resolved, p)
}

// IsInternalPath reports whether path is the connector work directory or lies
// under it, compared lexically. Such paths are never user deposits.
func (c *Connector) IsInternalPath(path string) bool {
	return c.work != nil && c.work.contains(path)
}

// GetWorkDir returns the connector private working directory. It never holds
// user deposits; plugins must ignore paths under it.
func (c *Connector) GetWorkDir() string {
	if c.work == nil {
		return ""
	}
	return c.work.path
}
