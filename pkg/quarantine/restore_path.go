package quarantine

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/glimps-re/host-connector/internal/pathutil"
)

// beforeRestoreMkdir runs between the symbolic link check of the destination
// directory and its creation; tests use it to swap a parent for a link.
var beforeRestoreMkdir = func() {}

// trustedLink decides which links may appear on a destination outside the
// monitored paths; tests replace it.
var trustedLink = pathutil.TrustedLink

// watchedRoot returns the shortest watched path containing p, or "": with
// nested roots, a link replacing the inner one would otherwise be taken for
// the trusted root itself.
func watchedRoot(watched []string, p string) string {
	best := ""
	for _, w := range watched {
		root, err := filepath.Abs(w)
		if err != nil {
			continue
		}
		if pathutil.Under(root, p) && (best == "" || len(root) < len(best)) {
			best = root
		}
	}
	return best
}

// openRestoreDir returns the destination directory opened as an os.Root, after
// making sure no link can redirect the restore.
//
// Below a watched path, no component may be a link; the missing directories are
// created one level at a time from that path, itself opened as a root, and the
// destination is opened from it. Outside the watched paths (the configuration
// changed since the quarantine) nothing is created, and every component from
// the filesystem root must be a real directory or a system link
// (pathutil.TrustedLink).
func openRestoreDir(watched []string, restoreDir string) (dir *os.Root, closeAll func(), err error) {
	root := watchedRoot(watched, restoreDir)
	if root == "" {
		return openOutsideWatched(restoreDir)
	}
	if err = checkRestoreTree(pathutil.CheckExistingNoSymlink(root, restoreDir)); err != nil {
		return
	}
	watchedRootDir, err := os.OpenRoot(root)
	if err != nil {
		return
	}
	closeRoot := func() { closeQuietly(watchedRootDir, "watched path") }
	rel, err := filepath.Rel(root, restoreDir)
	if err != nil {
		closeRoot()
		return
	}
	beforeRestoreMkdir()
	if err = createLevels(watchedRootDir, rel); err != nil {
		closeRoot()
		return
	}
	if err = checkRestoreTree(pathutil.CheckNoSymlink(root, restoreDir)); err != nil {
		closeRoot()
		return
	}
	pre, err := watchedRootDir.Lstat(rel)
	if err != nil {
		closeRoot()
		return
	}
	dir, err = watchedRootDir.OpenRoot(rel)
	if err != nil {
		closeRoot()
		return
	}
	closeAll = func() {
		closeQuietly(dir, "destination directory")
		closeRoot()
	}
	if err = sameDirectory(pre, dir); err != nil {
		closeAll()
		return nil, nil, err
	}
	return
}

// createLevels creates the missing directories of rel under root one level at a
// time, refusing a link or a file at any level: os.Root.MkdirAll would follow a
// relative link that stays inside the root.
func createLevels(root *os.Root, rel string) error {
	if rel == "." {
		return nil
	}
	cum := ""
	for part := range strings.SplitSeq(rel, string(filepath.Separator)) {
		cum = filepath.Join(cum, part)
		fi, err := root.Lstat(cum)
		switch {
		case err == nil:
			if pathutil.IsLinkLike(fi.Mode()) || !fi.IsDir() {
				return fmt.Errorf("%w: %q is not a plain directory", ErrRestoreDestinationUnsafe, cum)
			}
		case errors.Is(err, os.ErrNotExist):
			if err = root.Mkdir(cum, 0o750); err != nil {
				return fmt.Errorf("%w: %w", ErrRestoreDestinationUnsafe, err)
			}
		default:
			return err
		}
	}
	return nil
}

func openOutsideWatched(restoreDir string) (dir *os.Root, closeAll func(), err error) {
	logger.Warn("restore destination is outside the watched paths: its whole path is checked, nothing is created", slog.String("dir", restoreDir))
	if err = pathutil.CheckTrustedPath(restoreDir, trustedLink); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = fmt.Errorf("destination directory does not exist and is outside the watched paths, it is not created: %w", err)
		}
		return nil, nil, fmt.Errorf("%w: %w", ErrRestoreDestinationUnsafe, err)
	}
	pre, err := os.Stat(restoreDir)
	if err != nil {
		return
	}
	dir, err = os.OpenRoot(restoreDir)
	if err != nil {
		return
	}
	if err = sameDirectory(pre, dir); err != nil {
		closeQuietly(dir, "destination directory")
		return nil, nil, err
	}
	return dir, func() { closeQuietly(dir, "destination directory") }, nil
}

func checkRestoreTree(err error) error {
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRestoreDestinationUnsafe, err)
	}
	return nil
}

// sameDirectory refuses a destination that is not the directory seen before it
// was opened.
func sameDirectory(pre os.FileInfo, opened *os.Root) error {
	info, err := opened.Lstat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(pre, info) {
		return ErrRestoreDestinationUnsafe
	}
	return nil
}

func closeQuietly(r *os.Root, what string) {
	if err := r.Close(); err != nil {
		logger.Error("Restore cannot close "+what, slog.String("error", err.Error()))
	}
}
