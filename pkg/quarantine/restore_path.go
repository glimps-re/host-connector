package quarantine

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/glimps-re/host-connector/internal/pathutil"
	"github.com/glimps-re/host-connector/internal/safepath"
)

// restoreDirMode is the mode of the folders a restoration creates.
const restoreDirMode os.FileMode = 0o750

// beforeRestoreMkdir runs between the symbolic link check of the destination
// directory and its creation; tests use it to swap a parent for a link.
var beforeRestoreMkdir = func() {}

// beforeOpenOutside runs between the check of a destination outside the
// watched paths and its opening; tests use it to swap a folder for a link.
var beforeOpenOutside = func() {}

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
	rel, err := filepath.Rel(root, restoreDir)
	if err != nil {
		return nil, nil, err
	}
	beforeRestoreMkdir()
	if dir, err = safepath.OpenDir(root, rel, true, restoreDirMode); err != nil {
		return nil, nil, restoreOpenError(err)
	}
	return dir, func() { closeQuietly(dir, "destination directory") }, nil
}

// restoreOpenError makes a refusal to follow a link, or a folder that is not a
// plain directory, the error of an unsafe destination.
func restoreOpenError(err error) error {
	if errors.Is(err, safepath.ErrSymlink) || errors.Is(err, safepath.ErrBadPath) || errors.Is(err, safepath.ErrNotDir) {
		return fmt.Errorf("%w: %w", ErrRestoreDestinationUnsafe, err)
	}
	return err
}

func openOutsideWatched(restoreDir string) (dir *os.Root, closeAll func(), err error) {
	logger.Warn("restore destination is outside the watched paths: its whole path is checked, nothing is created", slog.String("dir", restoreDir))
	// The path is resolved once, by the walk that validates it (the trusted
	// system links are followed there), and that very path is opened without
	// following any link: a component turned into a link afterwards is refused.
	resolved, err := pathutil.ResolveTrustedPath(restoreDir, trustedLink)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = fmt.Errorf("destination directory does not exist and is outside the watched paths, it is not created: %w", err)
		}
		return nil, nil, fmt.Errorf("%w: %w", ErrRestoreDestinationUnsafe, err)
	}
	fsRoot := filepath.VolumeName(resolved) + string(filepath.Separator)
	rel, err := filepath.Rel(fsRoot, resolved)
	if err != nil {
		return nil, nil, err
	}
	beforeOpenOutside()
	if dir, err = safepath.OpenDir(fsRoot, rel, false, restoreDirMode); err != nil {
		return nil, nil, restoreOpenError(err)
	}
	return dir, func() { closeQuietly(dir, "destination directory") }, nil
}
