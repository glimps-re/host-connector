package handler

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

func TestMonitor_walkQueueIsDeduplicated(t *testing.T) {
	m := newBareMonitor(t, func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{})
	for range 1000 {
		m.preScanPath("/in/a/b/c")
	}
	if got := len(m.walkPending); got != 1 {
		t.Errorf("pending walks = %d after 1000 requests for one folder, want 1", got)
	}
	m.preScanPath("/in/a")
	if _, ok := m.walkPending["/in/a"]; !ok {
		t.Fatal("the parent must be queued")
	}
	m.preScanPath("/in/a/b")
	m.preScanPath("/in/a/b/c/d")
	m.preScanPath("/in/a/x/y/z")
	if _, ok := m.walkPending["/in/a/b"]; ok {
		t.Error("a folder below a queued one must not be queued: the walk of its parent covers it")
	}
	if len(m.walkPending) != 1 {
		t.Errorf("pending = %v, want only the parent: its walk covers the folders below it", m.walkPending)
	}
	if root, ok := m.nextWalk(); !ok || root != "/in/a" || len(m.walkPending) != 0 {
		t.Errorf("nextWalk() = %q, %t with %d left", root, ok, len(m.walkPending))
	}
	m.preScanPath("/in/ab")
	m.preScanPath("/in/a")
	if len(m.walkPending) != 2 {
		t.Errorf("pending = %v, want /in/ab and /in/a apart: a prefix of names is not a parent", m.walkPending)
	}
}

func TestMonitor_mkdirOfADeepTreeDoesNotSpawnAWalkPerLevel(t *testing.T) {
	root := t.TempDir()
	m, seen := newIdentityMonitor(t, Config{ModDelay: 10_000_000})
	m.Start()
	if err := m.Add(root); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()
	deep := root
	for range 40 {
		deep = filepath.Join(deep, "d")
	}
	writeTestFile(t, filepath.Join(deep, "f.bin"))
	waitFor(t, "the file of the deep tree", func() bool { return len(seen()) == 1 })
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Errorf("goroutines went from %d to %d: the walks must share one consumer", before, after)
	}
}

// With links followed, a link to a folder under a monitored path must not lead
// the walk out of it.
func TestMonitor_linkToAFolderIsNeverWalked(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeTestFile(t, filepath.Join(outside, "secret.bin"))
	writeTestFile(t, filepath.Join(root, "own.bin"))
	for name, target := range map[string]string{"out": outside, "up": filepath.Dir(root), "loop": root} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	var mu sync.Mutex
	got := map[string]bool{}
	m, err := NewMonitor(func(path string, _ scanner.FileIdentity) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		got[path] = true
		return true, nil
	}, Config{FollowSymlinks: true, PreScan: true, ModDelay: sdk.Duration(5 * time.Millisecond), DisableWatcher: true, Period: sdk.Duration(30 * time.Millisecond)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := m.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	m.Start()
	if err = m.Add(root); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the own file", func() bool { mu.Lock(); defer mu.Unlock(); return got[filepath.Join(root, "own.bin")] })
	time.Sleep(150 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	for path := range got {
		if filepath.Base(path) != "own.bin" {
			t.Errorf("%s reached the callback through a link to a folder", path)
		}
	}
	if n := runtime.NumGoroutine(); n > 100 {
		t.Errorf("%d goroutines: a link loop must not be walked", n)
	}
}
