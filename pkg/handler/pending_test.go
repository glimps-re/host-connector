package handler

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

func TestFileTable_pendingFollowsEveryTransition(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	tab := newFileTable(1<<30, 25, nil, []string{"/in"})
	const tom, jerry = "/in/tom", "/in/jerry"
	a, b, c := "/in/tom/a", "/in/tom/b", "/in/tom/c"
	id := func(n int64) scanner.FileIdentity { return scanner.FileIdentity{Size: n} }

	steps := []struct {
		name string
		do   func()
		tom  int
	}{
		{"nothing tracked", func() {}, 0},
		{"first file waits for its delay", func() { tab.Track(a, id(1), now, now.Add(time.Second)) }, 1},
		{"second file", func() { tab.Track(b, id(2), now, now.Add(2*time.Second)) }, 2},
		{"another owner is not counted", func() { tab.Track("/in/jerry/x", id(1), now, now.Add(time.Hour)) }, 2},
		{"handed to the pipeline: still pending", func() {
			if p, _, ok := tab.PopDue(now.Add(1500 * time.Millisecond)); !ok || p != a {
				t.Fatalf("PopDue() = %q, %v, want %q", p, ok, a)
			}
		}, 2},
		{"forgotten while waiting", func() { tab.Forget(b) }, 1},
		{"a third file", func() { tab.Track(c, id(3), now, now.Add(time.Hour)) }, 2},
		{"a submitted file ends in a retry: no longer pending", func() {
			tab.Done(a, now.Add(time.Hour), 1)
		}, 1},
		{"forgotten", func() { tab.Forget(c) }, 0},
	}
	for _, s := range steps {
		s.do()
		if got := tab.Pending(tom); got != s.tom {
			t.Errorf("%s: Pending(tom) = %d, want %d", s.name, got, s.tom)
		}
	}
	if got := tab.Pending(jerry); got != 1 {
		t.Errorf("Pending(jerry) = %d, want 1", got)
	}
	if got := tab.Pending("/in/nobody"); got != 0 {
		t.Errorf("Pending(unknown owner) = %d, want 0", got)
	}
}

func TestFileTable_pendingFinalOutcomeAndEvictionStopCounting(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	tab := newFileTable(1<<30, 25, nil, []string{"/in"})
	tab.Track("/in/tom/a", scanner.FileIdentity{Size: 1}, now, now)
	p, _, ok := tab.PopDue(now)
	if !ok || tab.Pending("/in/tom") != 1 {
		t.Fatalf("submitted file: ok %v, pending %d", ok, tab.Pending("/in/tom"))
	}
	tab.Done(p, time.Time{}, 0)
	if got := tab.Pending("/in/tom"); got != 0 {
		t.Errorf("a file that ended is still pending: %d", got)
	}
}

func TestMonitor_pendingFilesTakesTheFolderOfTheOwner(t *testing.T) {
	m, err := NewMonitor(func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{
		Period:  sdk.Duration(time.Hour),
		Owners:  []scanner.OwnerRule{{Root: "/in", Depth: 1}},
		Watched: []string{"/in"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := m.Close(); e != nil {
			t.Error(e)
		}
	})
	now := time.Now()
	if !m.table.Track("/in/tom/sub/a", scanner.FileIdentity{Size: 1}, now, now.Add(time.Hour)) {
		t.Fatal("Track refused")
	}
	if got := m.PendingFiles("/in/tom"); got != 1 {
		t.Errorf("PendingFiles(folder of the owner) = %d, want 1", got)
	}
	if got := m.PendingFiles("/in/tom/"); got != 1 {
		t.Errorf("PendingFiles(folder of the owner, trailing separator) = %d, want 1", got)
	}
	for _, other := range []string{"/in", "/in/tom/sub", "/in/tom/sub/a", "/in/jerry", "/elsewhere/tom"} {
		if got := m.PendingFiles(other); got != 0 {
			t.Errorf("PendingFiles(%q) = %d, want 0: only the folder of an owner counts", other, got)
		}
	}
}

// A file evicted from the table under pressure is no longer pending: the
// session of its owner is not held by what the table forgot.
func TestFileTable_pendingDropsWhatPressureEvicts(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	limit := int64(3)*(int64(len("/in/tom/f0"))+fileOverhead) + ownerOverhead + int64(len("/in/tom"))
	tab := newFileTable(limit, 25, nil, []string{"/in"})
	for i := range 10 {
		tab.Track(fmt.Sprintf("/in/tom/f%d", i), scanner.FileIdentity{Size: int64(i)}, now, now.Add(time.Hour))
	}
	got := tab.Pending("/in/tom")
	if got != tab.Len() || got >= 10 {
		t.Errorf("Pending = %d with %d entries kept of 10: eviction must lower it to what is kept", got, tab.Len())
	}
}

// T20a: a file handed to the pipeline that changes before a worker takes it
// does not stay pending: once its outcome comes, the folder of its owner counts
// nothing pending, so the session of the owner is not held.
func TestMonitor_aPendingFileThatChangesBeforeBeingTakenIsNoLongerPending(t *testing.T) {
	tests := []struct {
		name   string
		change func(t *testing.T, p string)
	}{
		{"deleted", func(t *testing.T, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
		}},
		{"rewritten", func(t *testing.T, p string) {
			if err := os.WriteFile(p, []byte("tom rewritten content"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"replaced by a link", func(t *testing.T, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(filepath.Dir(p), "1.txt"), p); err != nil {
				t.Fatal(err)
			}
		}},
		{"emptied", func(t *testing.T, p string) {
			if err := os.Truncate(p, 0); err != nil {
				t.Fatal(err)
			}
		}},
		{"deleted then recreated", func(t *testing.T, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("tom recreated"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tom := filepath.Join(dir, "tom")
			if err := os.MkdirAll(tom, 0o750); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(tom, "2.txt")
			if err := os.WriteFile(p, []byte("tom second"), 0o600); err != nil {
				t.Fatal(err)
			}
			// The first submission of p waits for a worker until the test hands its
			// outcome back; every other submission ends at once.
			held := make(chan scanner.FileOutcome, 1)
			var once sync.Once
			var m *Monitor
			m, err := NewMonitor(func(path string, id scanner.FileIdentity) (bool, error) {
				o := scanner.FileOutcome{Location: path, Identity: id, Kind: scanner.OutcomeFinal}
				first := false
				if path == p {
					once.Do(func() { first = true })
				}
				if first {
					held <- o
					return true, nil
				}
				go m.FileDone(o)
				return true, nil
			}, Config{
				DisableWatcher: true,
				Period:         sdk.Duration(15 * time.Millisecond),
				ModDelay:       sdk.Duration(5 * time.Millisecond),
				Owners:         []scanner.OwnerRule{{Root: dir, Depth: 1}},
				Watched:        []string{dir},
				PreScan:        true,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if e := m.Close(); e != nil {
					t.Error(e)
				}
			})
			m.Start()
			if err = m.Add(dir); err != nil {
				t.Fatal(err)
			}
			var o scanner.FileOutcome
			select {
			case o = <-held:
			case <-time.After(5 * time.Second):
				t.Fatal("the file was never submitted")
			}
			if got := m.PendingFiles(tom); got != 1 {
				t.Fatalf("PendingFiles(tom) = %d while the file waits for a worker, want 1", got)
			}
			tt.change(t, p)
			m.FileDone(o)
			waitFor(t, "nothing pending under tom", func() bool { return m.PendingFiles(tom) == 0 })
		})
	}
}
