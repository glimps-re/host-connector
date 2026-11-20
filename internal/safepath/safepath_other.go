//go:build !linux

package safepath

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/glimps-re/host-connector/internal/pathutil"
)

// Open opens root/rel read-only after checking that no component below root is
// a symbolic link. Without openat2 the check and the open are two steps, and
// the window between them stays: a documented limit of these platforms.
func Open(root, rel string) (*File, error) {
	rel, err := cleanRel(rel)
	if err != nil {
		return nil, err
	}
	full := filepath.Join(root, rel)
	if err = pathutil.CheckNoSymlink(root, full); err != nil {
		return nil, &os.PathError{Op: "open", Path: full, Err: errors.Join(ErrSymlink, err)}
	}
	// A named pipe must not be opened: it would wait for a writer. The check
	// and the open are two steps here, like the one on links.
	pre, err := os.Lstat(full)
	if err != nil {
		return nil, err
	}
	if !pre.Mode().IsRegular() {
		return nil, &os.PathError{Op: "open", Path: full, Err: ErrNotRegular}
	}
	f, err := os.Open(full)
	if err != nil {
		return nil, err
	}
	if info, statErr := f.Stat(); statErr != nil || !info.Mode().IsRegular() {
		if closeErr := f.Close(); closeErr != nil {
			return nil, closeErr
		}
		return nil, &os.PathError{Op: "open", Path: full, Err: ErrNotRegular}
	}
	return &File{f: f, name: filepath.Base(full), path: full}, nil
}

// Remove deletes the file by name if it still is the file that was opened. The
// file is closed first: Windows refuses to delete a file that is open without
// the share-delete right. The File is no longer readable afterwards.
func (f *File) Remove() error {
	opened, err := f.f.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(f.path)
	if err != nil {
		return err
	}
	if !os.SameFile(opened, current) {
		return &os.PathError{Op: "remove", Path: f.path, Err: ErrChanged}
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Remove(f.path)
}

// Close closes the file; it has no effect on a file Remove already closed.
func (f *File) Close() error {
	f.once.Do(func() { f.closeErr = f.f.Close() })
	return f.closeErr
}
