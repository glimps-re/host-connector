//go:build linux

package scanner

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const (
	dirGroupRead fs.FileMode = 0o750
)

func mkOrphan(t *testing.T, base, name string, wide, withLock bool) string {
	t.Helper()
	dir := filepath.Join(base, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if withLock {
		if err := os.WriteFile(filepath.Join(dir, workDirLock), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if wide {
		if err := os.Chmod(dir, dirGroupRead); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})
	return dir
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func TestPurgeOrphans(t *testing.T) {
	base := t.TempDir()
	orphan := mkOrphan(t, base, "gmhost-orphan", false, true)
	userDir := mkOrphan(t, base, "gmhost-equipe", false, false)
	wideMode := mkOrphan(t, base, "gmhost-wide", true, true)
	notOurs := mkOrphan(t, base, "other-orphan", false, true)
	locked := mkOrphan(t, base, "gmhost-locked", false, true)

	target := mkOrphan(t, t.TempDir(), "gmhost-target", false, true)
	link := filepath.Join(base, "gmhost-x")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	notDir := filepath.Join(base, "gmhost-file")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := os.Open(filepath.Clean(filepath.Join(locked, workDirLock)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lock.Close(); err != nil {
			t.Logf("close lock: %v", err)
		}
	})
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	lockLink := mkOrphan(t, base, "gmhost-locklink", false, false)
	if err := os.Symlink(filepath.Join(target, workDirLock), filepath.Join(lockLink, workDirLock)); err != nil {
		t.Fatal(err)
	}

	w, err := newWorkDir(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := w.close(); err != nil {
			t.Errorf("close() error = %v", err)
		}
	})

	if exists(orphan) {
		t.Error("a real orphan must be removed")
	}
	for name, p := range map[string]string{
		"user folder without .lock": userDir, "mode 0755": wideMode, "not gmhost-*": notOurs,
		"locked by a live process": locked, "symlink to an orphan": link, "target of the symlink": target,
		"regular file": notDir, ".lock that is a symlink": lockLink, "own directory": w.path,
	} {
		if !exists(p) {
			t.Errorf("%s was removed: %s", name, p)
		}
	}
}

func TestInMemoryFS(t *testing.T) {
	prev := statfsType
	t.Cleanup(func() { statfsType = prev })
	for typ, want := range map[uint32]bool{tmpfsMagic: true, ramfsMagic: true, 0xEF53: false} {
		statfsType = func(string) (uint32, error) { return typ, nil }
		if got := inMemoryFS("/x"); got != want {
			t.Errorf("inMemoryFS(type %#x) = %t, want %t", typ, got, want)
		}
	}
}

func TestNewWorkDir_warnsOnMemoryFS(t *testing.T) {
	prev := statfsType
	t.Cleanup(func() { statfsType = prev })
	statfsType = func(string) (uint32, error) { return tmpfsMagic, nil }
	buf := captureLogs(t)
	w, err := newWorkDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := w.close(); err != nil {
			t.Errorf("close() error = %v", err)
		}
	})
	if out := buf.String(); !strings.Contains(out, "memory filesystem") || !strings.Contains(out, `"level":"WARN"`) {
		t.Errorf("log = %q, want a Warn about the memory filesystem", out)
	}
}
