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

// Serial: it counts the goroutines of the process.
func TestMonitor_mkdirOfTwoHundredLevelsAskForBoundedWalks(t *testing.T) {
	tests := []struct {
		name   string
		levels int
	}{
		{name: "200 levels", levels: 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			for range tt.levels {
				deep = filepath.Join(deep, "d")
			}
			if err := os.MkdirAll(deep, 0o700); err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, filepath.Join(deep, "f.bin"))
			waitFor(t, "the file at the bottom of the levels", func() bool { return len(seen()) == 1 })
			close(sampling)
			sampler.Wait()
			if peak := stop(); peak > 2 {
				t.Errorf("%d folders waited to be walked at once, want at most 2 (one in progress, one pending) for one mkdir -p", peak)
			}
			if got := maxGoroutines.Load(); got > int64(before)+4 {
				t.Errorf("goroutines peaked at %d from %d: walks must share one consumer", got, before)
			}
		})
	}
}

// Serial: it counts the goroutines of the process.
func TestMonitor_manyEventsOnTheSameFolderAreOneWalk(t *testing.T) {
	tests := []struct {
		name            string
		folder          string
		senders, events int
	}{
		{name: "64 senders of 200 events", folder: "/in/team/alice", senders: 64, events: 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newBareMonitor(t, func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{})
			before := runtime.NumGoroutine()
			stop := pendingWalksPeak(m)
			var wg sync.WaitGroup
			for range tt.senders {
				wg.Go(func() {
					for range tt.events {
						m.preScanPath(tt.folder)
					}
				})
			}
			wg.Wait()
			if peak := stop(); peak > 1 {
				t.Errorf("%d walks pending for one folder after %d events, want 1", peak, tt.senders*tt.events)
			}
			m.walkMu.Lock()
			n := len(m.walkPending)
			m.walkMu.Unlock()
			if n > 1 {
				t.Errorf("pending = %d, want at most 1", n)
			}
			if got := runtime.NumGoroutine(); got > before+2 {
				t.Errorf("goroutines went from %d to %d after %d events", before, got, tt.senders*tt.events)
			}
		})
	}
}

func TestMonitor_siblingFoldersAreNotMergedIntoOne(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		folders int
	}{
		{name: "50 sibling folders", folders: 50},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newBareMonitor(t, func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{})
			for i := range tt.folders {
				m.preScanPath(fmt.Sprintf("/in/u%02d", i))
			}
			m.walkMu.Lock()
			n := len(m.walkPending)
			m.walkMu.Unlock()
			if n < 1 || n > tt.folders {
				t.Errorf("pending = %d, want between 1 and %d independent folders", n, tt.folders)
			}
		})
	}
}
