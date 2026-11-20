//go:build linux

package quarantine

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/glimps-re/host-connector/internal/safepath"
)

// linkFD makes dst a name of the file behind f: linkat on the descriptor, which
// links the inode that was verified whatever the name it was found under holds
// now. Replaced in tests.
var linkFD = func(f *os.File, dst string) error {
	linkMu.RLock()
	defer linkMu.RUnlock()
	return unix.Linkat(unix.AT_FDCWD, safepath.FDPath(f, 0), unix.AT_FDCWD, dst, unix.AT_SYMLINK_FOLLOW)
}

// errSharedInode stands for a file with more than one name: it is copied, not linked.
var errSharedInode = errors.New("the file has another name")

// linkCount is the number of names of the file behind f.
func linkCount(f *os.File) (uint64, error) {
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("no link count")
	}
	return widen(st.Nlink), nil
}

// widen converts the link count, whose type depends on the architecture.
func widen[T ~uint32 | ~uint64](v T) uint64 { return uint64(v) }

func hasOtherLinks(f *os.File) (bool, error) {
	n, err := linkCount(f)
	return n != 1, err
}

// linkRefused tells the errors of a file system that cannot, or will not, make
// the hard link: another device, links forbidden to this user (protected
// hardlinks), or not supported.
func linkRefused(err error) bool {
	return errors.Is(err, errSharedInode) || errors.Is(err, syscall.EXDEV) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EMLINK)
}

func moveSource(src MoveSource, dst, stagingDir string, next func(attempt int) (string, bool)) (final string, err error) {
	if src.File == nil || src.Remove == nil {
		return "", fmt.Errorf("%w: %s", ErrNoVerifiedSource, src.Path)
	}
	target, staged := dst, ""
	var copied fs.FileInfo
	defer func() {
		if staged != "" {
			if e := os.Remove(staged); e != nil && !errors.Is(e, fs.ErrNotExist) {
				logger.Error("move cannot remove the staged copy", slog.String("file", staged), slog.String("error", e.Error()))
			}
		}
	}()
	for attempt := 0; ; {
		var pubErr error
		if staged == "" {
			linkErr := error(nil)
			if shared, err := hasOtherLinks(src.File); err != nil {
				return "", err
			} else if shared {
				// Another name of the same inode (a hard link made by the
				// depositor): publishing the inode would let them rewrite what was
				// verified, so a private copy is published instead.
				linkErr = errSharedInode
			} else {
				linkErr = linkFD(src.File, target)
			}
			switch {
			case linkErr == nil:
				return target, removeThroughHandle(src, target)
			case errors.Is(linkErr, fs.ErrExist):
				pubErr = fmt.Errorf("%w: %s", ErrDestinationExists, target)
			case linkRefused(linkErr):
				// Copied from the descriptor into the transit directory, then
				// published by name: a private file of this process, not the source.
				if staged, copied, err = stageFromFD(src, stagingDir); err != nil {
					return "", err
				}
				continue
			default:
				return "", linkErr
			}
		} else {
			var renamed bool
			renamed, pubErr = publishNoReplace(staged, target)
			if pubErr == nil {
				if renamed {
					staged = ""
				}
				return target, finishStaged(src, target, copied)
			}
		}
		if !errors.Is(pubErr, ErrDestinationExists) {
			return "", pubErr
		}
		name, ok := next(attempt)
		if !ok {
			return "", pubErr
		}
		target = name
		attempt++
	}
}

// stageFromFD copies the verified file, read through a new descriptor on the
// same inode, into the transit directory. The copy fails if the file changed
// while it was read.
func stageFromFD(src MoveSource, stagingDir string) (string, fs.FileInfo, error) {
	in, err := safepath.Reopen(src.File)
	if err != nil {
		return "", nil, err
	}
	defer func() {
		if e := in.Close(); e != nil {
			logger.Error("move cannot close the source file", slog.String("file", src.Path), slog.String("error", e.Error()))
		}
	}()
	return stageFrom(in, src.Path, stagingDir, func(before fs.FileInfo) error {
		after, err := in.Stat()
		if err != nil || !unchanged(before, after) {
			return fmt.Errorf("%w: %s", ErrSourceChanged, src.Path)
		}
		return nil
	})
}

// finishStaged removes the source once its copy is published, unless the file
// changed since the copy was made: then the copy is taken back.
func finishStaged(src MoveSource, dst string, copied fs.FileInfo) error {
	now, err := src.File.Stat()
	if err != nil || !unchanged(copied, now) {
		return rollback(dst, fmt.Errorf("%w: %s", ErrSourceChanged, src.Path))
	}
	return removeAfterCopy(src, dst)
}

// removeThroughHandle removes the old name of a file published as a hard link
// through the verified handle. A name that no longer holds the verified file
// (it was renamed, replaced or removed) has nothing of ours to remove. Whatever
// the way the old name went, the destination must end as the only name of the
// inode: any other name, or a count that cannot be read, would let someone else
// rewrite the published file, so the destination is taken back.
func removeThroughHandle(src MoveSource, dst string) error {
	err := src.Remove()
	switch {
	case errors.Is(err, safepath.ErrChanged), errors.Is(err, fs.ErrNotExist):
		logger.Warn("the source name no longer holds the file that was moved, it is left alone", slog.String("file", src.Path))
	case err != nil:
		return rollback(dst, fmt.Errorf("could not remove %s after moving it: %w", src.Path, MarkRemovalRefused(err)))
	}
	if n, countErr := linkCount(src.File); countErr != nil || n != 1 {
		return rollback(dst, fmt.Errorf("%w: %s has another name since it was moved", ErrSourceChanged, src.Path))
	}
	return nil
}

// removeAfterCopy removes the old name of a file whose private copy was
// published. The copy is another inode: whatever happens to the source, the
// copy must stay (taking it back could destroy the only one left), so a name
// that remains is only reported.
func removeAfterCopy(src MoveSource, dst string) error {
	err := src.Remove()
	switch {
	case errors.Is(err, safepath.ErrChanged), errors.Is(err, fs.ErrNotExist):
		logger.Warn("the source name no longer holds the file that was copied, it is left alone", slog.String("file", src.Path))
		return nil
	case err != nil:
		return rollback(dst, fmt.Errorf("could not remove %s after moving it: %w", src.Path, MarkRemovalRefused(err)))
	}
	if n, countErr := linkCount(src.File); countErr != nil || n != 0 {
		logger.Warn("the source file still has a name after its copy was moved", slog.String("file", src.Path))
	}
	return nil
}
