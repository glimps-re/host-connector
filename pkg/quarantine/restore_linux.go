//go:build linux

package quarantine

import (
	"log/slog"
	"os"
)

// restoreFileInfo applies the mode, ownership and modification time carried
// by locked to f (the already-open temp file, named name inside root).
// Chmod/Chown are applied through f's file descriptor (fchmod/fchown)
// rather than by path through root: os.Root's own documentation notes its
// path-based Chmod/Chown/Chtimes "are vulnerable to a race condition" if the
// name is swapped for a symlink mid-operation, and f is already the exact,
// already-open file we created - using its descriptor removes that race for
// the two operations that support it. Chtimes has no descriptor-based
// equivalent in the standard library, so it remains root-scoped by name;
// this is accepted, narrow residual risk (documented upstream), not an
// oversight.
//
// Ownership is restored via Chown on a best-effort basis: an unprivileged
// process (a dedicated account, or most test environments) cannot chown to an
// arbitrary uid/gid. A Chown failure is only logged; a Chtimes failure is an
// error.
func restoreFileInfo(root *os.Root, f *os.File, name string, locked LockedFile) (err error) {
	if err = f.Chmod(locked.Mode); err != nil {
		return
	}
	if chownErr := f.Chown(locked.UID, locked.GID); chownErr != nil {
		logger.Error("error chown file", slog.String("name", name), slog.String("error", chownErr.Error()))
	}
	// AccessTime is intentionally absent from LockedFile (see its
	// documentation): atime is set equal to mtime.
	err = root.Chtimes(name, locked.ModTime, locked.ModTime)
	return
}

// isRestorePathAllowed reports whether path is an acceptable restore
// destination. On Linux there is no UNC/device-path notion equivalent to
// Windows, so any absolute, cleaned path is allowed; the remaining checks
// (absolute, cleaned, matches the registry entry) are performed by the
// caller.
func isRestorePathAllowed(path string) bool {
	return true
}
