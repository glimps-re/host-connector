package handler

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
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
	go func() {
		for {
			select {
			case <-m.filesToScan:
			case <-m.done:
				return
			}
		}
	}()
	seen := map[string]struct{}{}
	if !m.walkRoot(root, seen) {
		t.Error("walkRoot() = false, want true (partial)")
	}
	if _, ok := seen[filepath.Join(root, "ok", "f.txt")]; !ok {
		t.Errorf("sibling file not seen: %v", seen)
	}
	if _, ok := seen[filepath.Join(locked, "hidden.txt")]; ok {
		t.Error("file of unreadable dir must not be seen")
	}
}

func TestMonitor_periodicalScanPurgeSkippedOnPartialRoot(t *testing.T) {
	complete := t.TempDir()
	writeTestFile(t, filepath.Join(complete, "live.txt"))
	missing := filepath.Join(t.TempDir(), "missing")

	staleComplete := filepath.Join(complete, "gone.txt")
	underMissing := filepath.Join(missing, "sub", "f.txt")
	siblingPrefix := missing + "-other/f.txt"

	m := newTestMonitor(t, 5*time.Millisecond, func(string) error { return nil })
	m.states.Store(staleComplete, fileState{size: 1})
	m.states.Store(underMissing, fileState{size: 1})
	m.states.Store(siblingPrefix, fileState{size: 1})
	m.paths.Store(complete, struct{}{})
	m.paths.Store(missing, struct{}{})
	m.Start()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := m.states.Load(staleComplete); !ok {
			if _, ok := m.states.Load(siblingPrefix); ok {
				t.Fatal("state outside any root must be purged")
			}
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, ok := m.states.Load(staleComplete); ok {
		t.Fatal("stale state on a fully walked root must be purged")
	}
	time.Sleep(50 * time.Millisecond)
	if _, ok := m.states.Load(underMissing); !ok {
		t.Error("state under a partially walked root must be kept")
	}
}
