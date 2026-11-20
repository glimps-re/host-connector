//go:build linux

package safepath

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// useOpenat2 is false in tests that exercise the fallback for kernels older
// than 5.6.
var useOpenat2 = true

// Open opens root/rel read-only and fails if any component below root is a
// symbolic link. root itself is trusted. The directory it was found in stays
// open, so that Remove acts on that directory even if its path is redirected.
func Open(root, rel string) (*File, error) {
	rel, err := cleanRel(rel)
	if err != nil {
		return nil, err
	}
	rootFd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: root, Err: err}
	}
	defer closeFd(rootFd)

	dirRel, name := filepath.Split(rel)
	parentFd, err := reopenDir(rootFd, dirRel)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: filepath.Join(root, dirRel), Err: mapErr(err)}
	}
	full := filepath.Join(root, rel)
	// O_NONBLOCK: opening a named pipe for reading would wait for a writer.
	fd, err := openBeneath(parentFd, name, unix.O_RDONLY|unix.O_NONBLOCK, unix.O_RDONLY|unix.O_NONBLOCK)
	if err != nil {
		closeFd(parentFd)
		return nil, &os.PathError{Op: "open", Path: full, Err: mapErr(err)}
	}
	if err = requireRegular(fd); err != nil {
		closeFd(fd)
		closeFd(parentFd)
		return nil, &os.PathError{Op: "open", Path: full, Err: err}
	}
	return &File{
		f:      os.NewFile(uintptr(fd), full),
		parent: os.NewFile(uintptr(parentFd), filepath.Dir(full)),
		name:   name,
		path:   full,
	}, nil
}

// requireRegular refuses a descriptor that is not a regular file, and clears
// the non-blocking flag it was opened with (it has no effect on a regular file,
// but callers read it as a plain file).
func requireRegular(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return ErrNotRegular
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags&^unix.O_NONBLOCK)
	return err
}

// reopenDir opens dirRel below dirFd as a directory; "" gives a new handle on
// dirFd itself.
func reopenDir(dirFd int, dirRel string) (int, error) {
	dirRel = filepath.Clean(dirRel)
	if dirRel == "." {
		return unix.Openat(dirFd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	}
	return openBeneath(dirFd, dirRel, unix.O_RDONLY|unix.O_DIRECTORY, unix.O_RDONLY|unix.O_DIRECTORY)
}

// openBeneath opens rel below dirFd without following a link: openat2 where
// the kernel has it, a walk with O_NOFOLLOW otherwise.
//
// The flags are given twice, as the int of openat and the uint64 of openat2:
// they are constants of the caller, so no conversion is needed.
func openBeneath(dirFd int, rel string, flags int, howFlags uint64) (int, error) {
	if useOpenat2 {
		how := &unix.OpenHow{
			Flags:   howFlags | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS,
		}
		fd, err := unix.Openat2(dirFd, rel, how)
		if !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EPERM) {
			return fd, err
		}
		// Kernel older than 5.6, or a filter that refuses the call.
	}
	return walkNoFollow(dirFd, rel, flags)
}

// walkNoFollow opens rel one component at a time with O_NOFOLLOW.
func walkNoFollow(dirFd int, rel string, flags int) (int, error) {
	parts := strings.Split(rel, string(filepath.Separator))
	cur, err := unix.Openat(dirFd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for i, part := range parts {
		f := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if i == len(parts)-1 {
			f = flags | unix.O_NOFOLLOW | unix.O_CLOEXEC
		}
		next, err := unix.Openat(cur, part, f, 0)
		if errors.Is(err, unix.ENOTDIR) && isLink(cur, part) {
			// O_DIRECTORY|O_NOFOLLOW reports a link as "not a directory".
			err = unix.ELOOP
		}
		closeFd(cur)
		if err != nil {
			return -1, err
		}
		cur = next
	}
	return cur, nil
}

// isLink tells whether name in the directory dirFd is a symbolic link.
func isLink(dirFd int, name string) bool {
	var st unix.Stat_t
	return unix.Fstatat(dirFd, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK
}

// mapErr names a symbolic link in the error: openat2 and O_NOFOLLOW report it as
// ELOOP (or ENOTDIR for a link opened as a directory).
func mapErr(err error) error {
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) {
		return fmt.Errorf("%w: %w", ErrSymlink, err)
	}
	return err
}

func closeFd(fd int) {
	if err := unix.Close(fd); err != nil {
		slog.Warn("cannot close a descriptor", slog.String("error", err.Error()))
	}
}

// Remove deletes the file by name in the directory it was opened in, only if
// that name still is the inode that was opened (same device and inode): a file
// replaced by another, or a name turned into a link, is not deleted. The check
// and the removal are two system calls: the window is the one of any
// unlink-by-name, and it is in a directory that cannot have been redirected.
func (f *File) Remove() error {
	var opened, current unix.Stat_t
	if err := unix.Fstat(int(f.f.Fd()), &opened); err != nil {
		return &os.PathError{Op: "remove", Path: f.path, Err: err}
	}
	parentFd := int(f.parent.Fd())
	if err := unix.Fstatat(parentFd, f.name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return &os.PathError{Op: "remove", Path: f.path, Err: err}
	}
	if current.Ino != opened.Ino || current.Dev != opened.Dev {
		return &os.PathError{Op: "remove", Path: f.path, Err: ErrChanged}
	}
	if err := unix.Unlinkat(parentFd, f.name, 0); err != nil {
		return &os.PathError{Op: "remove", Path: f.path, Err: err}
	}
	return nil
}

// Close closes the file and its directory.
func (f *File) Close() error {
	f.once.Do(func() { f.closeErr = errors.Join(f.f.Close(), f.parent.Close()) })
	return f.closeErr
}
