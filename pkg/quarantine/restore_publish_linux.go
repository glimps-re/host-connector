//go:build linux

package quarantine

import (
	"errors"
	"io/fs"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// rootRenameNoReplaceOS renames oldname to newname inside root with
// RENAME_NOREPLACE, through the descriptor of the directory: the kernel refuses
// an existing destination, whoever wrote it. handled is false only when the
// system or the file system does not support it: any other failure, the opening
// of the directory included, is the error of the publication.
func rootRenameNoReplaceOS(root *os.Root, oldname, newname string) (handled bool, err error) {
	dir, err := root.Open(".")
	if err != nil {
		return true, err
	}
	defer closeQuietly(dir, "restore directory")
	fd := int(dir.Fd())
	err = unix.Renameat2(fd, oldname, fd, newname, unix.RENAME_NOREPLACE)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.ENOSYS), errors.Is(err, syscall.ENOTSUP):
		return false, nil
	case errors.Is(err, syscall.EEXIST):
		return true, fs.ErrExist
	default:
		return true, &os.LinkError{Op: "rename", Old: oldname, New: newname, Err: err}
	}
}
