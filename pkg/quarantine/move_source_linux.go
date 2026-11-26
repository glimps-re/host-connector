//go:build linux

package quarantine

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
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

func moveSource(ctx context.Context, src MoveSource, dst, stagingDir string, next func(attempt int) (string, bool)) (string, error) {
	if src.File == nil || src.Remove == nil {
		return "", fmt.Errorf("%w: %s", ErrNoVerifiedSource, src.Path)
	}
	return runPublication(&fdMove{ctx: ctx, src: src, stagingDir: stagingDir}, dst, next)
}

// fdMove publishes the verified descriptor: a hard link made from it, or, when
// the file system refuses links, a private copy.
type fdMove struct {
	ctx        context.Context
	src        MoveSource
	stagingDir string
	staged     string
	copied     fs.FileInfo
	linked     bool
}

func (m *fdMove) publish(target string) error {
	if m.staged != "" {
		_, err := publishNoReplace(m.staged, target)
		return err
	}
	var linkErr error
	if shared, err := hasOtherLinks(m.src.File); err != nil {
		return err
	} else if shared {
		// Another name of the same inode (a hard link made by the depositor):
		// publishing the inode would let them rewrite what was verified, so a
		// private copy is published instead.
		linkErr = errSharedInode
	} else {
		linkErr = linkFD(m.src.File, target)
	}
	switch {
	case linkErr == nil:
		m.linked = true
		return nil
	case errors.Is(linkErr, fs.ErrExist):
		return fmt.Errorf("%w: %s", ErrDestinationExists, target)
	case linkRefused(linkErr):
		var err error
		if m.staged, m.copied, err = stageFromFD(m.ctx, m.src, m.stagingDir); err != nil {
			return err
		}
		_, err = publishNoReplace(m.staged, target)
		return err
	default:
		return linkErr
	}
}

func (m *fdMove) finish(target string) error {
	if m.linked {
		return removeThroughHandle(m.src, target)
	}
	if err := syncDir(filepath.Dir(target)); err != nil {
		return rollback(target, fmt.Errorf("could not make %s durable: %w", target, err))
	}
	return finishStaged(m.src, target, m.copied)
}

func (m *fdMove) cleanup() { removeStaged(m.staged) }

// stageFromFD copies the verified file, read through a new descriptor on the
// same inode, into the transit directory. The copy must hash to the SHA256 the
// file was analyzed with: without one it is refused, as is a file rewritten
// since the analysis.
func stageFromFD(ctx context.Context, src MoveSource, stagingDir string) (string, fs.FileInfo, error) {
	want, err := parseSHA256(src.SHA256)
	if err != nil {
		return "", nil, err
	}
	in, err := safepath.Reopen(src.File)
	if err != nil {
		return "", nil, err
	}
	defer func() {
		if e := in.Close(); e != nil {
			logger.Error("move cannot close the source file", slog.String("file", src.Path), slog.String("error", e.Error()))
		}
	}()
	return stageVerified(ctx, in, stagingDir, want)
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
	removed, err := removeNamed(dst, src.Path, src.Remove)
	if err != nil || !removed {
		return err
	}
	if n, countErr := linkCount(src.File); countErr != nil || n != 0 {
		logger.Warn("the source file still has a name after its copy was moved", slog.String("file", src.Path))
	}
	return nil
}
