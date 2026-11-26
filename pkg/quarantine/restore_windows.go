//go:build windows

package quarantine

import (
	"os"
	"strings"
)

// restoreFileInfo applies the mode and modification time carried by locked
// to f (the already-open temp file, named name inside root). Chmod is
// applied through f's descriptor rather than by path through root, removing
// the symlink-swap race os.Root's path-based operations are documented to
// have; Chtimes has no descriptor-based equivalent in the standard library
// and remains root-scoped by name (accepted, narrow residual risk). Windows
// never calls os.Chown: the historical code always did, which fails
// unconditionally on this platform and only produced a spurious error log
// line on every restore.
func restoreFileInfo(root *os.Root, f *os.File, name string, locked LockedFile) (err error) {
	if err = f.Chmod(locked.Mode); err != nil {
		return
	}
	// AccessTime is intentionally absent from LockedFile (see its
	// documentation): atime is set equal to mtime.
	err = root.Chtimes(name, locked.ModTime, locked.ModTime)
	return
}

// isRestorePathAllowed rejects UNC paths (\\server\share\...) and device
// paths (\\.\..., \\?\...), which filepath.IsAbs treats as absolute but
// which must never be accepted as a quarantine restore destination.
func isRestorePathAllowed(path string) bool {
	return !strings.HasPrefix(path, `\\`)
}
