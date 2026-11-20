package handler

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/scanner"
)

// pendingWalksPeak samples the number of folders waiting to be walked.
func pendingWalksPeak(m *Monitor) (stop func() int) {
	var peak atomic.Int64
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			m.walkMu.Lock()
			n := int64(len(m.walkPending))
			m.walkMu.Unlock()
			if n > peak.Load() {
				peak.Store(n)
			}
			select {
			case <-done:
				return
			case <-time.After(200 * time.Microsecond):
			}
		}
	})
	return func() int {
		close(done)
		wg.Wait()
		return int(peak.Load())
	}
}

func TestT10_mkdirOfTwoHundredLevelsAskForBoundedWalks(t *testing.T) {
	root := t.TempDir()
	m, seen := newIdentityMonitor(t, Config{ModDelay: 10_000_000, PreScan: true})
	m.Start()
	if err := m.Add(root); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()
	stop := pendingWalksPeak(m)
	var maxGoroutines atomic.Int64
	sampling := make(chan struct{})
	var sampler sync.WaitGroup
	sampler.Go(func() {
		for {
			if n := int64(runtime.NumGoroutine()); n > maxGoroutines.Load() {
				maxGoroutines.Store(n)
			}
			select {
			case <-sampling:
				return
			case <-time.After(time.Millisecond):
			}
		}
	})
	deep := root
	for range 200 {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(deep, "f.bin"))
	waitFor(t, "the file at the bottom of 200 levels", func() bool { return len(seen()) == 1 })
	close(sampling)
	sampler.Wait()
	if peak := stop(); peak > 2 {
		t.Errorf("%d folders waited to be walked at once, want at most 2 (one in progress, one pending) for one mkdir -p", peak)
	}
	if got := maxGoroutines.Load(); got > int64(before)+4 {
		t.Errorf("goroutines peaked at %d from %d: walks must share one consumer", got, before)
	}
}

func TestT10_manyEventsOnTheSameFolderAreOneWalk(t *testing.T) {
	m := newBareMonitor(t, func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{})
	before := runtime.NumGoroutine()
	stop := pendingWalksPeak(m)
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			for range 200 {
				m.preScanPath("/in/team/alice")
			}
		})
	}
	wg.Wait()
	if peak := stop(); peak > 1 {
		t.Errorf("%d walks pending for one folder after 12800 events, want 1", peak)
	}
	m.walkMu.Lock()
	n := len(m.walkPending)
	m.walkMu.Unlock()
	if n > 1 {
		t.Errorf("pending = %d, want at most 1", n)
	}
	if got := runtime.NumGoroutine(); got > before+2 {
		t.Errorf("goroutines went from %d to %d after 12800 events", before, got)
	}
}

func TestT10_siblingFoldersAreNotMergedIntoOne(t *testing.T) {
	m := newBareMonitor(t, func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{})
	for i := range 50 {
		m.preScanPath(fmt.Sprintf("/in/u%02d", i))
	}
	m.walkMu.Lock()
	n := len(m.walkPending)
	m.walkMu.Unlock()
	if n < 1 || n > 50 {
		t.Errorf("pending = %d, want between 1 and 50 independent folders", n)
	}
}
