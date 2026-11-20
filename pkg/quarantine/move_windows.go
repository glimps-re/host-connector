//go:build windows

package quarantine

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// renameNoReplaceAtomicOS uses MoveFileEx without MOVEFILE_REPLACE_EXISTING: the
// system refuses an existing destination.
func renameNoReplaceAtomicOS(src, dst string) (handled bool, err error) {
	from, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return true, err
	}
	to, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return true, err
	}
	err = windows.MoveFileEx(from, to, 0)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, windows.ERROR_ALREADY_EXISTS), errors.Is(err, windows.ERROR_FILE_EXISTS):
		return true, os.ErrExist
	default:
		return true, &os.LinkError{Op: "rename", Old: src, New: dst, Err: err}
	}
}

// ownedByCurrentUser cannot tell portably: the directory is created by this
// process in a folder the operator chose.
func ownedByCurrentUser(os.FileInfo) bool { return true }
