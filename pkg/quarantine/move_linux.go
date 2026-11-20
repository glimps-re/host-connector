//go:build linux

package quarantine

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// renameNoReplaceAtomicOS renames with RENAME_NOREPLACE: the kernel refuses an
// existing destination. handled is false when the system or the file system
// does not support it.
func renameNoReplaceAtomicOS(src, dst string) (handled bool, err error) {
	err = unix.Renameat2(unix.AT_FDCWD, src, unix.AT_FDCWD, dst, unix.RENAME_NOREPLACE)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.ENOSYS), errors.Is(err, syscall.ENOTSUP):
		return false, nil
	case errors.Is(err, syscall.EEXIST):
		return true, os.ErrExist
	default:
		return true, &os.LinkError{Op: "rename", Old: src, New: dst, Err: err}
	}
}

func ownedByCurrentUser(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}
