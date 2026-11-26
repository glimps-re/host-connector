//go:build windows

package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileIdentity_windowsReducesToSizeAndModificationTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, []byte("aaaa"), 0o600); err != nil {
		t.Fatal(err)
	}
	id := idOf(t, path)
	if id.Dev != 0 || id.Ino != 0 || !id.ChangeTime.IsZero() {
		t.Errorf("identity = %+v, want no device, inode or change time", id)
	}
}
