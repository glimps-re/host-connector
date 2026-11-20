package handler

import (
	"fmt"
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
