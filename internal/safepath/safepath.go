// Package safepath opens, reads and deletes files, and opens directories,
// without ever following a symbolic link below a given root, and acts on what
// was opened rather than on a name someone can redirect in the meantime.
package safepath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	// ErrSymlink is wrapped by the error of an open that met a symbolic link
	// (or an irregular entry) below the root.
	ErrSymlink = errors.New("a component of the path is a symbolic link")
	// ErrChanged is returned by Remove when the name no longer is the file that
	// was opened.
	ErrChanged = errors.New("the file is no longer the one that was opened")
	// ErrNotRegular is returned by Open for anything that is not a regular
	// file: a named pipe would block every reader for ever.
	ErrNotRegular = errors.New("not a regular file")
	// ErrNotDir is returned by OpenDir for a component that is not a directory.
	ErrNotDir = errors.New("not a directory")
	// ErrBadPath is returned for a relative path that is empty, absolute or
	// leaves the root.
	ErrBadPath = errors.New("not a path below the root")
)

// OS returns the opened file. It stays owned by the File: Close closes it.
func (f *File) OS() *os.File { return f.f }

// cleanRel validates rel: relative, inside the root, naming something.
func cleanRel(rel string) (string, error) {
	rel = filepath.Clean(rel)
	if rel == "." || rel == "" || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q", ErrBadPath, rel)
	}
	return rel, nil
}
