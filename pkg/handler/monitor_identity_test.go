package handler

import (
	"maps"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

type seenFile struct {
	at time.Time
	id scanner.FileIdentity
}

func newIdentityMonitor(t *testing.T, cfg Config) (*Monitor, func() map[string]seenFile) {
	t.Helper()
	var mu sync.Mutex
	seen := map[string]seenFile{}
	m, err := NewMonitor(func(path string, id scanner.FileIdentity) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		seen[path] = seenFile{at: time.Now(), id: id}
		return true, nil
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := m.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	return m, func() map[string]seenFile {
		mu.Lock()
		defer mu.Unlock()
		out := make(map[string]seenFile, len(seen))
		maps.Copy(out, seen)
		return out
	}
}

func TestMonitor_preScanWaitsForStabilityAndPassesTheValidatedIdentity(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "sub", "upload.bin")
	writeTestFile(t, file)
	const delay = 300 * time.Millisecond
	m, seen := newIdentityMonitor(t, Config{PreScan: true, ModDelay: sdk.Duration(delay), DisableWatcher: true, Period: sdk.Duration(time.Hour)})
	m.Start()
	start := time.Now()
	if err := m.Add(root); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the file to be handed over", func() bool { return len(seen()) == 1 })
	got := seen()[file]
	// The delay is checked on the time of the hand-over: a pause before looking
	// would only prove that the machine was slow.
	if got.at.Sub(start) < delay {
		t.Errorf("handed over after %v, want at least %v", got.at.Sub(start), delay)
	}
	info, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	if !got.id.Equal(scanner.IdentityOf(info)) {
		t.Errorf("identity = %+v, want the validated one %+v", got.id, scanner.IdentityOf(info))
	}
	if _, folder := seen()[filepath.Join(root, "sub")]; folder {
		t.Error("a folder must never reach the callback")
	}
}

func TestMonitor_writeResumedBeforeTheDelayPostponesTheFile(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "upload.bin")
	writeTestFile(t, file)
	const delay = 500 * time.Millisecond
	m, seen := newIdentityMonitor(t, Config{PreScan: true, ModDelay: sdk.Duration(delay), DisableWatcher: true, Period: sdk.Duration(20 * time.Millisecond)})
	m.Start()
	if err := m.Add(root); err != nil {
		t.Fatal(err)
	}
	var first trackedFile
	waitFor(t, "the file to be tracked", func() bool {
		var ok bool
		first, ok = m.table.Get(file)
		return ok
	})
	// The change is judged through the table, not through naps: a rescan that sees
	// it must give the file a whole new delay, counted from the write.
	wrote := time.Now()
	f, err := os.OpenFile(filepath.Clean(file), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteString(" more"); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	want := scanner.IdentityOf(info)
	var postponed trackedFile
	waitFor(t, "the changed file to be tracked with its new identity", func() bool {
		var ok bool
		postponed, ok = m.table.Get(file)
		return ok && postponed.stamp.Equal(want)
	})
	if postponed.deadline.Before(wrote.Add(delay)) || !postponed.deadline.After(first.deadline) {
		t.Errorf("the changed file waits until %v, want at least %v (the write plus the delay) and after the first deadline %v",
			postponed.deadline, wrote.Add(delay), first.deadline)
	}
	waitFor(t, "the file to be handed over", func() bool { return len(seen()) == 1 })
	got := seen()[file]
	if !got.id.Equal(want) {
		t.Errorf("handed over with %+v, want its new identity %+v", got.id, want)
	}
	if got.at.Before(wrote.Add(delay)) {
		t.Errorf("handed over %v after the write, want at least %v: the write restarted the delay", got.at.Sub(wrote), delay)
	}
}

func TestMonitor_folderEventWalksItsFiles(t *testing.T) {
	root := t.TempDir()
	m, seen := newIdentityMonitor(t, Config{ModDelay: sdk.Duration(10 * time.Millisecond)})
	m.Start()
	if err := m.Add(root); err != nil {
		t.Fatal(err)
	}
	staging := t.TempDir()
	file := filepath.Join(staging, "tree", "deep", "f.bin")
	writeTestFile(t, file)
	if err := os.Rename(filepath.Join(staging, "tree"), filepath.Join(root, "tree")); err != nil {
		t.Skipf("cannot move across file systems: %v", err)
	}
	want := filepath.Join(root, "tree", "deep", "f.bin")
	waitFor(t, "the files of the moved folder", func() bool { _, ok := seen()[want]; return ok })
}

func TestMonitor_refusedFileIsForgotten(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "a.bin"))
	calls := 0
	var mu sync.Mutex
	m, err := NewMonitor(func(string, scanner.FileIdentity) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return false, nil
	}, Config{PreScan: true, ModDelay: sdk.Duration(5 * time.Millisecond), DisableWatcher: true, Period: sdk.Duration(time.Hour)})
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
	waitFor(t, "the callback", func() bool { mu.Lock(); defer mu.Unlock(); return calls == 1 })
	waitFor(t, "the entry to be released", func() bool { return m.table.Len() == 0 })
}
