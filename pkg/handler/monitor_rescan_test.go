package handler

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/quarantine"
)

func TestMonitor_walkRootUnreadableDirIsPartial(t *testing.T) {
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("permission denied cannot be triggered as root or on windows")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	writeTestFile(t, filepath.Join(locked, "hidden.txt"))
	writeTestFile(t, filepath.Join(root, "ok", "f.txt"))
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(locked, ownerRWX); err != nil {
			t.Errorf("could not restore permissions: %v", err)
		}
	})
	m := newTestMonitor(t, 0, func(string) error { return nil })
	unreadable, _ := m.walkRoot(root, maxUnreadableDirs)
	if _, ok := m.table.Get(filepath.Join(root, "ok", "f.txt")); !ok {
		t.Errorf("sibling file not tracked")
	}
	if _, ok := m.table.Get(filepath.Join(locked, "hidden.txt")); ok {
		t.Error("file of unreadable dir must not be tracked")
	}
	if len(unreadable) != 1 || unreadable[0] != locked {
		t.Errorf("unreadable = %v, want only %s: the folder, not the root", unreadable, locked)
	}
}

func TestMonitor_rescanPurgesTheGoneAndKeepsWhatAnUnreadableFolderHides(t *testing.T) {
	complete := t.TempDir()
	writeTestFile(t, filepath.Join(complete, "live.txt"))
	missing := filepath.Join(t.TempDir(), "missing")

	staleComplete := filepath.Join(complete, "gone.txt")
	underMissing := filepath.Join(missing, "sub", "f.txt")
	siblingPrefix := missing + "-other/f.txt"

	m := newTestMonitor(t, 0, func(string) error { return nil })
	now := time.Now()
	for _, p := range []string{staleComplete, underMissing, siblingPrefix} {
		m.table.Track(p, fileStamp{size: 1}, now, now.Add(time.Hour))
	}
	m.paths.Store(complete, struct{}{})
	m.paths.Store(missing, struct{}{})
	m.rescan()

	if _, ok := m.table.Get(staleComplete); ok {
		t.Error("a stale entry on a fully walked root must be purged")
	}
	if _, ok := m.table.Get(siblingPrefix); ok {
		t.Error("an entry outside any root must be purged")
	}
	if _, ok := m.table.Get(underMissing); !ok {
		t.Error("an entry under a root that could not be walked must be kept")
	}
	if _, ok := m.table.Get(filepath.Join(complete, "live.txt")); !ok {
		t.Error("the live file must be tracked")
	}
}

func TestMonitor_ignoresRestoreTemporaryFiles(t *testing.T) {
	root := t.TempDir()
	tmpName := quarantine.TempPrefix + "victim.bin-0123456789abcdef"
	writeTestFile(t, filepath.Join(root, tmpName))
	writeTestFile(t, filepath.Join(root, "sub", tmpName))
	writeTestFile(t, filepath.Join(root, "regular.bin"))

	var mu sync.Mutex
	got := map[string]struct{}{}
	m := newTestMonitor(t, 5*time.Millisecond, func(path string) error {
		mu.Lock()
		defer mu.Unlock()
		got[path] = struct{}{}
		return nil
	})
	m.Start()
	if err := m.Add(root); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	created := filepath.Join(root, "created.bin")
	writeTestFile(t, created)
	writeTestFile(t, filepath.Join(root, quarantine.TempPrefix+"event.bin-1"))

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		_, a := got[filepath.Join(root, "regular.bin")]
		_, b := got[created]
		mu.Unlock()
		if a && b {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	for p := range got {
		if quarantine.IsTempFile(p) {
			t.Errorf("temporary file %q reached the callback", p)
		}
	}
	if len(got) != 2 {
		t.Errorf("callbacks = %v, want regular.bin and created.bin only", got)
	}
}

func TestMonitor_walkRootCapsTheUnreadableList(t *testing.T) {
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("permission denied cannot be triggered as root or on windows")
	}
	root := t.TempDir()
	for i := range 10 {
		dir := filepath.Join(root, fmt.Sprintf("locked%d", i))
		writeTestFile(t, filepath.Join(dir, "hidden.txt"))
		if err := os.Chmod(dir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Chmod(dir, ownerRWX); err != nil {
				t.Errorf("could not restore permissions: %v", err)
			}
		})
	}
	m := newTestMonitor(t, 0, func(string) error { return nil })
	got, overflow := m.walkRoot(root, 3)
	if len(got) != 3 || !overflow {
		t.Errorf("walkRoot() = %d folders, overflow %v; want 3 and true", len(got), overflow)
	}
	got, overflow = m.walkRoot(root, 10)
	if len(got) != 10 || overflow {
		t.Errorf("walkRoot() = %d folders, overflow %v; want 10 and false", len(got), overflow)
	}
}
