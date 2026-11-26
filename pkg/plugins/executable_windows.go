//go:build windows

package plugins

import (
	"fmt"
	"os"
	"path/filepath"
)

// CheckExecutable only checks that path is absolute and, links resolved, a
// regular file: ownership and permission checks are not implemented on
// Windows, where the ACLs of the directory apply.
func CheckExecutable(path string) (resolved string, warnings []string, err error) {
	if !filepath.IsAbs(path) {
		return "", nil, fmt.Errorf("%w: %s: the path is not absolute; give the absolute path of the binary", ErrUnsafeExecutable, path)
	}
	if resolved, err = filepath.EvalSymlinks(path); err != nil {
		return "", nil, fmt.Errorf("%w: %s: not found: %w; install the binary or fix the configured path", ErrUnsafeExecutable, path, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %s: %w; point to the binary itself", ErrUnsafeExecutable, resolved, err)
	}
	if !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("%w: %s: not a regular file; point to the binary itself", ErrUnsafeExecutable, resolved)
	}
	return resolved, nil, nil
}

// CheckPluginFile only checks that path is an absolute regular file.
func CheckPluginFile(path string) (warnings []string, err error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: %s: the path is not absolute; give the absolute path of the file", ErrUnsafeExecutable, path)
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		return nil, fmt.Errorf("%w: %s: %w; point to the file itself", ErrUnsafeExecutable, path, statErr)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s: not a regular file; point to the file itself", ErrUnsafeExecutable, path)
	}
	return nil, nil
}
