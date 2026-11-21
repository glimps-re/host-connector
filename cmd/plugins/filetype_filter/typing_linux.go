//go:build linux

package main

import (
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vimeo/go-magic/magic"
	"golang.org/x/sys/unix"
)

// typeFile gives the MIME type libmagic finds for the file at a path, and calls
// release when it no longer needs what the path names; a variable so
// that tests can replace it.
var typeFile func(path string, release func()) (string, error) = libmagicType

// databaseFiles is the list of libmagic databases, as go-magic loads them: the
// compiled files of its default directory, or none for the default of libmagic.
func databaseFiles() ([]string, error) {
	dir := magic.GetDefaultDir()
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".mgc" {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	return files, nil
}

// ownDescriptor tells whether location names a descriptor of this process through
// /proc, which is how the core hands over the file it has verified, and which.
func ownDescriptor(location string) (fd int, ok bool) {
	rest, found := strings.CutPrefix(location, "/proc/")
	if !found {
		return 0, false
	}
	who, rest, found := strings.Cut(rest, "/fd/")
	if !found || (who != "self" && who != strconv.Itoa(os.Getpid())) {
		return 0, false
	}
	n, err := strconv.ParseUint(rest, 10, 31)
	if err != nil || n > math.MaxInt32 || strconv.FormatUint(n, 10) != rest {
		return 0, false
	}
	return int(n), true
}

// isOwnDescriptor tells whether location names a descriptor of this process.
func isOwnDescriptor(location string) bool {
	_, ok := ownDescriptor(location)
	return ok
}

// closeDescriptor closes a descriptor this plugin owns; a failure is logged, there
// is nobody to return it to.
func closeDescriptor(fd int) {
	if err := unix.Close(fd); err != nil {
		slog.Warn("filetype_filter could not close a descriptor", slog.Int("fd", fd), slog.String("error", err.Error()))
	}
}

// typeOf types the whole file at location, and gives its size.
//
// The file the core hands over (/proc/self/fd/<N>, its verified descriptor) is
// typed by libmagic through that very name: libmagic opens the magic link, so it is
// the inode the core verified, with its own offset, and the core's descriptor is
// never moved. It is a reopen, so it checks the permissions again: a deposit made
// unreadable after the core opened it fails, and the caller refuses it.
//
// Any other path (a member of an archive, in a private folder) is opened without
// following a link or blocking, checked to be a regular file, and typed through the
// descriptor of that open file.
func typeOf(location string) (t typed, err error) {
	var fd int // the descriptor the file is typed through
	if own, ok := ownDescriptor(location); ok {
		info, statErr := os.Stat(location)
		if statErr != nil {
			return typed{}, statErr
		}
		if !info.Mode().IsRegular() {
			return typed{}, fmt.Errorf("%w: %s", errNotRegular, info.Mode().Type())
		}
		t.size = info.Size()
		fd = own
	} else {
		pre, lstatErr := os.Lstat(filepath.Clean(location))
		if lstatErr != nil {
			return typed{}, lstatErr
		}
		if pre.Mode()&os.ModeSymlink == 0 && !pre.Mode().IsRegular() {
			return typed{}, fmt.Errorf("%w: %s", errNotRegular, pre.Mode().Type())
		}
		opened, openErr := unix.Open(filepath.Clean(location), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return typed{}, openErr
		}
		defer closeDescriptor(opened)
		var st unix.Stat_t
		if err = unix.Fstat(opened, &st); err != nil {
			return typed{}, err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return typed{}, fmt.Errorf("%w: descriptor %d", errNotRegular, opened)
		}
		t.size = st.Size
		fd = opened
	}
	// The typing may end after this function has: it types a duplicate of the
	// descriptor, which it closes itself, so that the number it opens is never one
	// that was closed and given to something else in the meantime.
	pinned, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return typed{}, fmt.Errorf("could not duplicate the descriptor: %w", err)
	}
	mime, err := typeFile("/proc/self/fd/"+strconv.Itoa(pinned), func() { closeDescriptor(pinned) })
	if err != nil {
		return typed{}, fmt.Errorf("could not type the file: %w", err)
	}
	return withType(t, mime)
}
