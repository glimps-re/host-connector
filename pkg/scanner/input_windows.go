//go:build windows

package scanner

import (
	"fmt"
	"os"
	"path/filepath"
)

// openRegular opens path for reading and refuses anything but a regular file.
func openRegular(path string, _ bool) (*os.File, error) {
	f, err := os.Open(filepath.Clean(path))
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
