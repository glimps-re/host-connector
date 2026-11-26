//go:build !windows

package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// openRegular opens path for reading without ever blocking on it, and refuses
// anything but a regular file. Links are not followed unless followLinks.
func openRegular(path string, followLinks bool) (*os.File, error) {
	flags := syscall.O_RDONLY | syscall.O_NONBLOCK
	if !followLinks {
		flags |= syscall.O_NOFOLLOW
	}
	f, err := os.OpenFile(filepath.Clean(path), flags, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		if e := f.Close(); e != nil {
			logger.Warn("could not close file correctly", "file", path, "error", e.Error())
		}
		return nil, fmt.Errorf("%w: %s", errNotRegular, path)
	}
	return f, nil
}
