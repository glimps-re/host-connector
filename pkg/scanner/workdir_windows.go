//go:build windows

package scanner

import (
	"os"
	"path/filepath"
)

func inMemoryFS(string) bool { return false }

func createWorkDirLock(path string) (*os.File, error) {
	return os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
}

// purgeOrphans does nothing on Windows: no portable way to tell a live
// process from a crashed one.
func purgeOrphans(string, string) {}
