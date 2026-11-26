package handler

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

// Serial: it counts the goroutines of the process.
func TestMonitor_oneTimerWhateverTheNumberOfWaitingFiles(t *testing.T) {
	tests := []struct {
		name  string
		files int
	}{
		{name: "100000 waiting files", files: 100_000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewMonitor(func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{ModDelay: sdk.Duration(time.Hour), MaxTrackedBytes: 1 << 40})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if e := m.Close(); e != nil {
					t.Errorf("Close() error = %v", e)
				}
			})
			m.Start()
			now := time.Now()
			m.table.Track("/in/u/first", scanner.FileIdentity{Size: 1}, now, now.Add(time.Hour))
			time.Sleep(50 * time.Millisecond)
			withOne := runtime.NumGoroutine()
			for n := range tt.files {
				m.table.Track(fmt.Sprintf("/in/u%d/f%d", n%20, n), scanner.FileIdentity{Size: 1}, now, now.Add(time.Hour))
			}
			select {
			case m.wake <- struct{}{}:
			default:
			}
			time.Sleep(50 * time.Millisecond)
			if got := runtime.NumGoroutine(); got > withOne {
				t.Errorf("goroutines = %d with %d waiting files, %d with one: the monitor must keep a single timer", got, tt.files, withOne)
			}
		})
	}
}

func TestMonitor_ownersDeclaredByPluginsReachTheTableViaTheConnector(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		depth int
		paths []string
		want  map[string]bool
	}{
		{
			name:  "owners two levels below the watched path",
			depth: 2,
			paths: []string{"/in/eq1/alice/a", "/in/eq1/alice/b", "/in/eq1/bob/a", "/in/eq2/carol/a", "/in/eq1/team.txt"},
			want:  map[string]bool{"/in/eq1/alice": true, "/in/eq1/bob": true, "/in/eq2/carol": true, "/in/eq1": true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &scanner.Connector{}
			if err := conn.SetTrackingOwners("/in", tt.depth); err != nil {
				t.Fatal(err)
			}
			m, err := NewMonitor(func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{
				ModDelay: sdk.Duration(time.Hour),
				Owners:   conn.TrackingOwners(),
				Watched:  []string{"/in"},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if e := m.Close(); e != nil {
					t.Errorf("Close() error = %v", e)
				}
			})
			now := time.Now()
			for _, p := range tt.paths {
				m.table.Track(p, scanner.FileIdentity{Size: 1}, now, now.Add(time.Hour))
			}
			m.table.mu.Lock()
			owners := make([]string, 0, len(m.table.owners))
			for name := range m.table.owners {
				owners = append(owners, name)
			}
			m.table.mu.Unlock()
			if len(owners) != len(tt.want) {
				t.Fatalf("owners = %v, want %v", owners, tt.want)
			}
			for _, o := range owners {
				if !tt.want[o] {
					t.Errorf("unexpected owner %q: the declared depth must drive the grouping", o)
				}
			}
		})
	}
}

// TestFileTable_endRescanNeverBlocksTheOthersForLong checks the 50 ms
// bound on the lock held by the purge of a big table. Serial: it measures
// durations.
func TestFileTable_endRescanNeverBlocksTheOthersForLong(t *testing.T) {
	if testing.Short() {
		t.Skip("200000 entries, a few seconds")
	}
	const entries = 100_000
	const bound = 50 * time.Millisecond
	tests := []struct {
		name       string
		unreadable []string
	}{
		{name: "no unreadable folder", unreadable: nil},
		{name: "1024 unreadable folders", unreadable: ctUnreadableDirs(1024)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tab := newFileTable(1<<40, 25, nil, []string{"/in"})
			now := time.Now()
			for n := range entries {
				tab.Track(fmt.Sprintf("/in/u%d/d%d/f%d", n%1000, n%97, n), scanner.FileIdentity{Size: 1}, now, now.Add(time.Hour))
			}
			tab.BeginRescan()
			done := make(chan struct{})
			go func() {
				defer close(done)
				tab.EndRescan(tt.unreadable, false)
			}()
			// A lock held for the whole purge shows as thousands of slow probes
			// and one probe of many seconds. A loaded test machine only adds a few
			// scheduling outliers, which the 2 % tolerance and the 1 s ceiling
			// absorb.
			var worst time.Duration
			var probes, slow int
			probe := func(f func()) {
				start := time.Now()
				f()
				d := time.Since(start)
				worst = max(worst, d)
				probes++
				if d > bound {
					slow++
				}
			}
			for n := 0; ; n++ {
				select {
				case <-done:
					if worst > 20*bound || slow*50 > probes {
						t.Errorf("during EndRescan %d of %d operations took more than %v, worst %v: the purge must hold the lock for short batches", slow, probes, bound, worst)
					}
					return
				default:
				}
				path := fmt.Sprintf("/in/probe%d/f%d", n%10, n)
				probe(func() { tab.Track(path, scanner.FileIdentity{Size: 1}, now, now.Add(time.Hour)) })
				probe(func() { tab.Forget(path) })
				probe(func() { tab.Done(path, time.Time{}, 1) })
			}
		})
	}
}

func ctUnreadableDirs(n int) []string {
	dirs := make([]string, n)
	for i := range dirs {
		dirs[i] = fmt.Sprintf("/in/u%d/d%d", i%1000, i%97)
	}
	return dirs
}

func newBareMonitor(t *testing.T, cb OnNewFileFunc, cfg Config) *Monitor {
	t.Helper()
	m, err := NewMonitor(cb, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := m.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	return m
}

func TestMonitor_processDue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		file     string
		accepted bool
		err      error
		// closeFirst closes the monitor before the files are due.
		closeFirst bool
		// wantForgotten checks that the entry is gone, wantNotCalled that the
		// callback never ran.
		wantForgotten, wantNotCalled bool
	}{
		{name: "a failing callback does not keep the entry", file: "failing.txt", err: os.ErrPermission, wantForgotten: true},
		{name: "a closed monitor stops handing files over", file: "late.txt", accepted: true, closeFirst: true, wantNotCalled: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			m := newBareMonitor(t, func(string, scanner.FileIdentity) (bool, error) { called = true; return tt.accepted, tt.err }, Config{ModDelay: sdk.Duration(time.Millisecond)})
			p := filepath.Join(t.TempDir(), tt.file)
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(p)
			if err != nil {
				t.Fatal(err)
			}
			old := time.Now().Add(-time.Second)
			m.table.Track(p, scanner.IdentityOf(info), old, old)
			if tt.closeFirst {
				if err := m.Close(); err != nil {
					t.Fatal(err)
				}
			}
			m.processDue()
			if _, ok := m.table.Get(p); tt.wantForgotten && ok {
				t.Error("the entry must be forgotten after the callback, whatever its result")
			}
			if tt.wantNotCalled && called {
				t.Error("a closed monitor must not call the callback")
			}
		})
	}
}

// Serial: recordEvents replaces the event handler of the package.
func TestMonitor_pressureResolutionsAreSentOnce(t *testing.T) {
	tests := []struct {
		name     string
		rescans  int
		resolved []events.ErrorEventType
	}{
		{name: "two rescans without pressure after the table is full", rescans: 2, resolved: []events.ErrorEventType{HostMonitorPressure, HostMonitorTableFull}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := recordEvents(t)
			const delay = time.Hour
			entry := int64(len(ctPath("aaa", 0))) + fileOverhead
			limit := 10*entry + int64(len("/in/aaa")) + ownerOverhead
			m := newBareMonitor(t, func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{ModDelay: sdk.Duration(delay), MaxTrackedBytes: limit, Watched: []string{"/in"}})
			now := time.Now()
			for n := range 10 {
				m.table.Track(ctPath("aaa", n), scanner.FileIdentity{Size: 1}, now, now.Add(delay-time.Duration(10-n)*time.Minute))
			}
			for range 6 {
				p, _, ok := m.table.PopDue(now.Add(delay))
				if !ok {
					t.Fatal("expected a due entry")
				}
				m.table.Done(p, time.Time{}, 1)
			}
			for n := range 3 {
				m.table.Track(ctPath("aaa", 100+n), scanner.FileIdentity{Size: 1}, now, now.Add(delay))
			}
			if m.table.Track(ctPath("aaa", 200), scanner.FileIdentity{Size: 1}, now, now.Add(delay)) {
				t.Fatal("the largest owner with waiting entries must be refused")
			}
			m.reportPressure()
			for range tt.rescans {
				m.reportPressure()
			}
			for _, typ := range tt.resolved {
				if got := len(rec.find("resolution", typ)); got != 1 {
					t.Errorf("%s resolutions = %d after %d rescans without pressure, want 1: a resolution is sent once, not at every rescan", typ, got, tt.rescans)
				}
			}
		})
	}
}

func TestMonitor_walkRootCapsTheUnreadableFolders(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("permission denied cannot be triggered as root")
	}
	tests := []struct {
		name   string
		locked int
	}{
		{name: "120 unreadable folders", locked: 120},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for i := range tt.locked {
				d := filepath.Join(root, fmt.Sprintf("locked%03d", i))
				if err := os.Mkdir(d, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(d, 0o000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Chmod(d, ownerRWX); err != nil {
						t.Errorf("could not restore %s: %v", d, err)
					}
				})
			}
			m := newBareMonitor(t, func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{ModDelay: sdk.Duration(time.Hour)})
			dirs, over := m.walkRoot(root, 50)
			if len(dirs) != 50 || !over {
				t.Errorf("walkRoot(room 50) = %d folders, overflow %t, want the slice capped at 50 and overflow", len(dirs), over)
			}
			dirs, over = m.walkRoot(root, 1024)
			if len(dirs) != tt.locked || over {
				t.Errorf("walkRoot(room 1024) = %d folders, overflow %t, want all %d and no overflow", len(dirs), over, tt.locked)
			}
		})
	}
}

func TestFileTable_overflowProtectsEveryFileForTenRescansOnly(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		path    string
		rescans int
	}{
		{name: "one file, ten overflowing rescans", path: "/in/u/a.bin", rescans: 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCTTable(40)
			c.Track(tt.path, scanner.FileIdentity{Size: 1}, c.now, c.now.Add(time.Hour))
			for rescan := 1; rescan <= tt.rescans; rescan++ {
				c.BeginRescan()
				c.EndRescan(nil, true)
				if _, ok := c.Get(tt.path); !ok {
					t.Fatalf("file purged at overflowing rescan %d, want it protected", rescan)
				}
			}
			c.BeginRescan()
			c.EndRescan(nil, true)
			if _, ok := c.Get(tt.path); ok {
				t.Errorf("an overflow must not protect a file for more than %d consecutive rescans", tt.rescans)
			}
		})
	}
}

func TestFileTable_pressureReportCountsEveryRefusedFile(t *testing.T) {
	t.Parallel()
	const delay = time.Hour
	tests := []struct {
		name   string
		owners int
	}{
		{name: "100000 owners refused by a table of submitted files", owners: 100_000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCTTable(30)
			for n := 0; c.track("aaa", n, delay); n++ {
			}
			for {
				if _, _, ok := c.PopDue(c.now.Add(2 * delay)); !ok {
					break
				}
			}
			c.TakePressure()
			refused := 0
			for n := range tt.owners {
				if !c.Track(fmt.Sprintf("/in/user%06d/f", n), scanner.FileIdentity{Size: 1}, c.now, c.now.Add(delay)) {
					refused++
				}
			}
			if refused != tt.owners {
				t.Fatalf("refused = %d, want %d: nothing is evictable when everything is submitted", refused, tt.owners)
			}
			if rep := c.TakePressure(); rep.Refused != tt.owners {
				t.Errorf("Refused = %d, want the exact total %d", rep.Refused, tt.owners)
			}
		})
	}
}

// Serial: t.Chdir.
func TestMonitor_relativeWatchedPathKeepsUsersApart(t *testing.T) {
	tests := []struct {
		name  string
		files []string
		want  int
	}{
		{name: "alice and bob below in", files: []string{"in/alice/a.txt", "in/alice/sub/b.txt", "in/bob/c.txt"}, want: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)
			for _, p := range tt.files {
				if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			m := newBareMonitor(t, func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{ModDelay: sdk.Duration(time.Hour), DisableWatcher: true, Period: sdk.Duration(time.Hour), Watched: []string{"in"}})
			if err := m.Add("in"); err != nil {
				t.Fatal(err)
			}
			m.rescan()
			m.table.mu.Lock()
			defer m.table.mu.Unlock()
			if len(m.table.owners) != tt.want {
				names := make([]string, 0, len(m.table.owners))
				for n := range m.table.owners {
					names = append(names, n)
				}
				t.Errorf("owners = %v, want one per user folder (alice, bob) with a relative watched path", names)
			}
		})
	}
}

// TestFileTable_countedCostMatchesTheRealHeap compares the counted bytes
// with what the runtime really allocates for the entries. Serial: it measures
// the heap of the process.
func TestFileTable_countedCostMatchesTheRealHeap(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a few hundred thousand entries")
	}
	tests := []struct {
		name    string
		entries int
	}{
		{name: "200000 entries", entries: 200_000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := make([]string, tt.entries)
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			for i := range paths {
				paths[i] = fmt.Sprintf("/data/input/user%03d/project/sub/file-%08d.bin", i%500, i)
			}
			tab := newFileTable(1<<40, 25, nil, []string{"/data/input"})
			now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
			for _, p := range paths {
				tab.Track(p, scanner.FileIdentity{Size: 1, ModTime: now, ChangeTime: now}, now, now.Add(time.Hour))
			}
			runtime.GC()
			runtime.ReadMemStats(&after)
			// The slice of paths belongs to the test, not to the table.
			realBytes := float64(after.HeapAlloc-before.HeapAlloc) - float64(tt.entries*16)
			counted := float64(tab.Used())
			if realBytes < counted*0.9 || realBytes > counted*1.1 {
				t.Errorf("real heap %.0f B for %d entries, counted %.0f B: outside ±10%%", realBytes, tt.entries, counted)
			}
			runtime.KeepAlive(tab)
			runtime.KeepAlive(paths)
		})
	}
}
