//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	// direntBuffer is the size of the one buffer the names of every folder are
	// read through.
	direntBuffer = 32 << 10
)

const cleanupSupported = true

// afterList is called once the names of a folder are read, before they are
// processed. Replaced in tests.
var afterList = func(path string) {}

// folderID identifies a folder whatever the path it is reached by.
type folderID struct{ dev, ino uint64 }

func idOf(st *unix.Stat_t) folderID { return folderID{st.Dev, st.Ino} }

// removeEmptyDirs removes the empty folders below the session folder root/rel,
// deepest first, and returns what it did. The session folder itself, symbolic
// links and the folder protect names (the work directory of the connector,
// recognized by device and inode read when the cleanup starts) are never removed
// nor entered; nothing outside the session folder is reached. A folder is
// removed only when its modification time, as it was before the cleanup touched
// what is in it, is at least olderThan old. It stops with the error of ctx when
// it ends, and with errTooDeep when part of the tree is deeper than
// maxCleanupDepth.
func removeEmptyDirs(ctx context.Context, root, rel string, olderThan time.Duration, protect string) (cleanupStats, error) {
	c := &cleaner{ctx: ctx, olderThan: olderThan, now: time.Now(), buf: make([]byte, direntBuffer)}
	if protect != "" {
		var pst unix.Stat_t
		switch err := unix.Stat(filepath.Clean(protect), &pst); {
		case err == nil:
			c.protect, c.protected = idOf(&pst), true
		case !errors.Is(err, unix.ENOENT):
			return c.stats, fmt.Errorf("cannot identify the work directory %s: %w", protect, err)
		}
	}
	fd, path, err := c.openSession(root, rel)
	if errors.Is(err, unix.ENOENT) {
		return c.stats, nil
	}
	if err != nil {
		return c.stats, err
	}
	err = c.walkSession(fd, path)
	closeFd(fd)
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && c.tooDeep {
		err = errTooDeep
	}
	return c.stats, err
}

// openSession opens the session folder root/rel without following any link
// below root. A folder that does not exist is reported with an error wrapping
// ENOENT; a part of rel that is ".." is refused.
func (c *cleaner) openSession(root, rel string) (fd int, path string, err error) {
	fd, err = unix.Open(filepath.Clean(root), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", fmt.Errorf("cannot open %s: %w", root, err)
	}
	path = filepath.Clean(root)
	for part := range strings.SplitSeq(filepath.ToSlash(filepath.Clean(rel)), "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			closeFd(fd)
			return -1, "", fmt.Errorf("the session folder %q leaves %s", rel, root)
		}
		next, oerr := unix.Openat(fd, part, dirFlags, 0)
		closeFd(fd)
		if oerr != nil {
			return -1, "", fmt.Errorf("the session folder %s is not a plain folder below %s: %w", rel, root, oerr)
		}
		fd, path = next, filepath.Join(path, part)
	}
	return fd, path, nil
}

// walkSession cleans the session folder open as fd, unless it is the protected
// folder.
func (c *cleaner) walkSession(fd int, path string) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("cannot identify the session folder %s: %w", path, err)
	}
	if c.isProtected(&st) {
		c.stats.kept++
		return nil
	}
	c.walk(fd, path, 0)
	return nil
}

func closeFd(fd int) {
	// Nothing to do about a failed close of a descriptor opened for reading.
	_ = unix.Close(fd)
}

type cleaner struct {
	ctx       context.Context
	olderThan time.Duration
	now       time.Time
	protect   folderID
	protected bool
	stats     cleanupStats
	tooDeep   bool
	buf       []byte
}

func (c *cleaner) isProtected(st *unix.Stat_t) bool {
	return c.protected && idOf(st) == c.protect
}

// walk processes the folder open as fd and tells whether nothing is left in it.
// Its names are read as the system gives them, about a thousand at a time, and
// each batch is processed before the next is read: a folder of any size is
// walked with a fixed amount of memory. The buffer is shared by all levels: the
// names are copied out of it, and each descriptor keeps its own read position.
func (c *cleaner) walk(fd int, path string, depth int) (empty bool) {
	empty = true
	first := true
	for {
		if c.ctx.Err() != nil {
			return false
		}
		n, err := unix.ReadDirent(fd, c.buf)
		if err != nil {
			c.stats.fail(fmt.Errorf("cannot list %s: %w", path, err))
			return false
		}
		if n <= 0 {
			return empty
		}
		_, _, names := unix.ParseDirent(c.buf[:n], -1, nil)
		if first {
			afterList(path)
			first = false
		}
		for _, name := range names {
			if c.ctx.Err() != nil {
				return false
			}
			var st unix.Stat_t
			if err = unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				if !errors.Is(err, unix.ENOENT) {
					c.stats.fail(fmt.Errorf("cannot inspect %s: %w", filepath.Join(path, name), err))
					empty = false
				}
				continue
			}
			if st.Mode&unix.S_IFMT != unix.S_IFDIR {
				empty = false
				continue
			}
			if depth+1 > maxCleanupDepth {
				c.tooDeep, empty = true, false
				continue
			}
			if !c.child(fd, name, filepath.Join(path, name), &st, depth+1) {
				empty = false
			}
		}
	}
}

// child processes the folder name of the folder open as fd, listed with st, and
// tells whether it is gone.
func (c *cleaner) child(fd int, name, path string, st *unix.Stat_t, depth int) bool {
	// O_NOFOLLOW, then the device and inode below: the folder opened must be the
	// one that was listed, not a link or a folder swapped in since.
	cfd, err := unix.Openat(fd, name, dirFlags, 0)
	switch {
	case err == nil:
	case errors.Is(err, unix.ENOENT):
		return true
	case errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR):
		c.stats.kept++
		return false
	default:
		c.stats.fail(fmt.Errorf("cannot open %s: %w", path, err))
		return false
	}
	var cst unix.Stat_t
	if err = unix.Fstat(cfd, &cst); err != nil {
		closeFd(cfd)
		c.stats.fail(fmt.Errorf("cannot inspect %s: %w", path, err))
		return false
	}
	if cst.Dev != st.Dev || cst.Ino != st.Ino || c.isProtected(&cst) {
		closeFd(cfd)
		c.stats.kept++
		return false
	}
	mtime := time.Unix(cst.Mtim.Unix())
	emptyNow := c.walk(cfd, path, depth)
	closeFd(cfd)
	if !emptyNow || c.now.Sub(mtime) < c.olderThan {
		c.stats.kept++
		return false
	}
	switch err = unix.Unlinkat(fd, name, unix.AT_REMOVEDIR); {
	case err == nil:
		c.stats.removed++
		return true
	case errors.Is(err, unix.ENOENT):
		return true
	case errors.Is(err, unix.ENOTEMPTY) || errors.Is(err, unix.EEXIST):
		c.stats.kept++
	default:
		c.stats.fail(fmt.Errorf("cannot remove %s: %w", path, err))
	}
	return false
}
