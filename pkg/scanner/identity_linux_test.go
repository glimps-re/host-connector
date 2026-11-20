//go:build linux

package scanner

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileIdentity_linuxChangesWithEveryWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, []byte("aaaa"), 0o600); err != nil {
		t.Fatal(err)
	}
	mtime := idOf(t, path).ModTime
	tests := []struct {
		name   string
		change func(t *testing.T)
	}{
		{"same size, modification time restored", func(t *testing.T) {
			time.Sleep(20 * time.Millisecond)
			if err := os.WriteFile(path, []byte("bbbb"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, time.Time{}, mtime); err != nil {
				t.Fatal(err)
			}
		}},
		{"replaced by rename with the same size and time", func(t *testing.T) {
			other := path + ".new"
			if err := os.WriteFile(other, []byte("aaaa"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(other, time.Time{}, mtime); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(other, path); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte("aaaa"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, time.Time{}, mtime); err != nil {
				t.Fatal(err)
			}
			before := idOf(t, path)
			tt.change(t)
			if before.Equal(idOf(t, path)) {
				t.Error("the identity must change")
			}
			if before.Dev == 0 || before.Ino == 0 || before.ChangeTime.IsZero() {
				t.Errorf("Linux must provide the device, the inode and the change time: %+v", before)
			}
		})
	}
}
