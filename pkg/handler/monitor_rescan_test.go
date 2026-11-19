package handler

import (
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
