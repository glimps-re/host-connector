package handler

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

func TestMonitorT09_oneTimerWhateverTheNumberOfWaitingFiles(t *testing.T) {
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
	for n := range 100_000 {
		m.table.Track(fmt.Sprintf("/in/u%d/f%d", n%20, n), scanner.FileIdentity{Size: 1}, now, now.Add(time.Hour))
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
	time.Sleep(50 * time.Millisecond)
	if got := runtime.NumGoroutine(); got > withOne {
		t.Errorf("goroutines = %d with 100000 waiting files, %d with one: the monitor must keep a single timer", got, withOne)
	}
}

func TestMonitorT09_ownersDeclaredByPluginsReachTheTable(t *testing.T) {
	conn := &scanner.Connector{}
	if err := conn.SetTrackingOwners("/in", 2); err != nil {
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
	for _, p := range []string{"/in/eq1/alice/a", "/in/eq1/alice/b", "/in/eq1/bob/a", "/in/eq2/carol/a", "/in/eq1/team.txt"} {
		m.table.Track(p, scanner.FileIdentity{Size: 1}, now, now.Add(time.Hour))
	}
	m.table.mu.Lock()
	owners := make([]string, 0, len(m.table.owners))
	for name := range m.table.owners {
		owners = append(owners, name)
	}
	m.table.mu.Unlock()
	want := map[string]bool{"/in/eq1/alice": true, "/in/eq1/bob": true, "/in/eq2/carol": true, "/in/eq1": true}
	if len(owners) != len(want) {
		t.Fatalf("owners = %v, want %v", owners, want)
	}
	for _, o := range owners {
		if !want[o] {
			t.Errorf("unexpected owner %q: the declared depth must drive the grouping", o)
		}
	}
}

func TestMonitorT09_pressureEventInEventOnlyModeIsRateLimited(t *testing.T) {
	rec := recordEvents(t)
	dir := t.TempDir()
	paths := make([]string, 40)
	for i := range paths {
		paths[i] = filepath.Join(dir, fmt.Sprintf("f%03d.txt", i))
		if err := os.WriteFile(paths[i], []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entry := int64(len(paths[0])) + fileOverhead
	limit := 10*entry + int64(len(dir)) + ownerOverhead
	m, err := NewMonitor(func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{
		ModDelay:        sdk.Duration(time.Hour),
		MaxTrackedBytes: limit,
		Watched:         []string{dir},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := m.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	if m.period != 0 {
		t.Fatal("the test needs the event-only mode")
	}
	for _, p := range paths {
		m.discover(p, true)
	}
	first := rec.find("error", HostMonitorPressure)
	if len(first) != 1 {
		t.Fatalf("pressure events after a burst of refusals = %d, want 1 (rate limited)", len(first))
	}
	for _, p := range paths[:5] {
		m.table.Forget(p)
	}
	for _, p := range paths {
		m.discover(p, true)
	}
	if got := len(rec.find("error", HostMonitorPressure)); got != 1 {
		t.Errorf("pressure events within the minute = %d, want still 1", got)
	}
	m.repMu.Lock()
	m.lastReport = time.Now().Add(-2 * minReportInterval)
	m.repMu.Unlock()
	m.table.Forget(paths[10])
	m.table.Forget(paths[11])
	for _, p := range paths {
		m.discover(p, true)
	}
	if got := len(rec.find("error", HostMonitorPressure)); got != 2 {
		t.Errorf("pressure events after the interval = %d, want a second one", got)
	}
}

// TestFileTableT09_endRescanNeverBlocksTheOthersForLong checks the 50 ms
// bound on the lock held by the purge of a big table.
func TestFileTableT09_endRescanNeverBlocksTheOthersForLong(t *testing.T) {
	if testing.Short() {
		t.Skip("200000 entries, a few seconds")
	}
	const entries = 100_000
	const bound = 50 * time.Millisecond
	tab := newFileTable(1<<40, 25, nil, []string{"/in"})
	now := time.Now()
	for n := range entries {
		tab.Track(fmt.Sprintf("/in/u%d/d%d/f%d", n%1000, n%97, n), scanner.FileIdentity{Size: 1}, now, now.Add(time.Hour))
	}
	for _, unreadable := range [][]string{nil, ctUnreadableDirs(1024)} {
		tab.BeginRescan()
		done := make(chan struct{})
		go func() {
			defer close(done)
			tab.EndRescan(unreadable, false)
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
				goto next
			default:
			}
			path := fmt.Sprintf("/in/probe%d/f%d", n%10, n)
			probe(func() { tab.Track(path, scanner.FileIdentity{Size: 1}, now, now.Add(time.Hour)) })
			probe(func() { tab.Forget(path) })
			probe(func() { tab.Done(path, time.Time{}, 1) })
		}
	next:
		for n := range entries {
			tab.Track(fmt.Sprintf("/in/u%d/d%d/f%d", n%1000, n%97, n), scanner.FileIdentity{Size: 1}, now, now.Add(time.Hour))
		}
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

func TestMonitorT09_processDue(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Run("a file changed while waiting waits again, then is handed over once", func(t *testing.T) {
		const delay = time.Hour
		type handed struct {
			path  string
			stamp scanner.FileIdentity
		}
		var mu sync.Mutex
		var got []handed
		m := newBareMonitor(t, func(p string, stamp scanner.FileIdentity) (bool, error) {
			mu.Lock()
			got = append(got, handed{p, stamp})
			mu.Unlock()
			return true, nil
		}, Config{ModDelay: sdk.Duration(delay)})
		p := write("changing.txt", "v1")
		info, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-time.Second)
		m.table.Track(p, scanner.IdentityOf(info), old, old)
		write("changing.txt", "version two")
		current, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		want := scanner.IdentityOf(current)
		m.processDue()
		mu.Lock()
		first := len(got)
		mu.Unlock()
		if first != 0 {
			t.Fatalf("the callback ran for a file that changed while waiting: %v", got)
		}
		tracked, ok := m.table.Get(p)
		if !ok {
			t.Fatal("the changed file must be tracked again")
		}
		if !tracked.stamp.Equal(want) {
			t.Errorf("tracked with %+v, want its new identity %+v", tracked.stamp, want)
		}
		if until := time.Until(tracked.deadline); until <= delay/2 || until > delay {
			t.Errorf("tracked again for %v, want a whole new delay of %v", until, delay)
		}
		// A one-hour delay cannot elapse in a test: the end of the wait is put in the
		// table, as the clock would have.
		m.table.Forget(p)
		m.table.Track(p, want, old, old)
		m.processDue()
		mu.Lock()
		defer mu.Unlock()
		if len(got) != 1 || got[0].path != p {
			t.Fatalf("callback calls = %v, want exactly one for %s", got, p)
		}
		if !got[0].stamp.Equal(want) {
			t.Errorf("handed over with %+v, want its current identity %+v", got[0].stamp, want)
		}
	})
	t.Run("a vanished file is forgotten without callback", func(t *testing.T) {
		called := false
		m := newBareMonitor(t, func(string, scanner.FileIdentity) (bool, error) { called = true; return true, nil }, Config{ModDelay: sdk.Duration(time.Millisecond)})
		gone := filepath.Join(dir, "gone.txt")
		old := time.Now().Add(-time.Second)
		m.table.Track(gone, scanner.FileIdentity{Size: 1}, old, old)
		m.processDue()
		if called {
			t.Error("the callback ran for a missing file")
		}
		if _, ok := m.table.Get(gone); ok {
			t.Error("a missing file must be forgotten")
		}
	})
	t.Run("a failing callback does not keep the entry", func(t *testing.T) {
		m := newBareMonitor(t, func(string, scanner.FileIdentity) (bool, error) { return false, os.ErrPermission }, Config{ModDelay: sdk.Duration(time.Millisecond)})
		p := write("failing.txt", "x")
		info, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-time.Second)
		m.table.Track(p, scanner.IdentityOf(info), old, old)
		m.processDue()
		if _, ok := m.table.Get(p); ok {
			t.Error("the entry must be forgotten after the callback, whatever its result")
		}
	})
	t.Run("a closed monitor stops handing files over", func(t *testing.T) {
		called := false
		m := newBareMonitor(t, func(string, scanner.FileIdentity) (bool, error) { called = true; return true, nil }, Config{ModDelay: sdk.Duration(time.Millisecond)})
		p := write("late.txt", "x")
		info, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-time.Second)
		m.table.Track(p, scanner.IdentityOf(info), old, old)
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
		m.processDue()
		if called {
			t.Error("a closed monitor must not call the callback")
		}
	})
}

func TestMonitorT09_pressureEventsAreRaisedThenResolved(t *testing.T) {
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
	if got := len(rec.find("error", HostMonitorPressure)); got != 1 {
		t.Errorf("pressure events = %d, want 1", got)
	}
	if got := len(rec.find("error", HostMonitorTableFull)); got != 1 {
		t.Errorf("table-full events = %d, want 1: the owner's done files fill more than half of the table", got)
	}
	m.reportPressure()
	if len(rec.find("resolution", HostMonitorPressure)) != 1 || len(rec.find("resolution", HostMonitorTableFull)) != 1 {
		t.Errorf("events = %+v, want both resolved by the first rescan without pressure", rec.records)
	}
	m.reportPressure()
	if len(rec.find("resolution", HostMonitorPressure)) != 1 {
		t.Error("a resolution must be sent once, not at every rescan")
	}
}

func TestMonitorT09_walkRootCapsTheUnreadableFolders(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission denied cannot be triggered as root")
	}
	root := t.TempDir()
	const locked = 120
	for i := range locked {
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
	if err := os.WriteFile(filepath.Join(root, "ok.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := newBareMonitor(t, func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{ModDelay: sdk.Duration(time.Hour)})
	dirs, over := m.walkRoot(root, 50)
	if len(dirs) != 50 || !over {
		t.Errorf("walkRoot(room 50) = %d folders, overflow %t, want the slice capped at 50 and overflow", len(dirs), over)
	}
	dirs, over = m.walkRoot(root, 1024)
	if len(dirs) != locked || over {
		t.Errorf("walkRoot(room 1024) = %d folders, overflow %t, want all %d and no overflow", len(dirs), over, locked)
	}
	if _, ok := m.table.Get(filepath.Join(root, "ok.txt")); !ok {
		t.Error("the readable file must be tracked despite the unreadable folders")
	}
}

func TestFileTableT09_overflowProtectsEveryFileForTenRescansOnly(t *testing.T) {
	c := newCTTable(40)
	p := "/in/u/a.bin"
	c.Track(p, scanner.FileIdentity{Size: 1}, c.now, c.now.Add(time.Hour))
	for rescan := 1; rescan <= 10; rescan++ {
		c.BeginRescan()
		c.EndRescan(nil, true)
		if _, ok := c.Get(p); !ok {
			t.Fatalf("file purged at overflowing rescan %d, want it protected", rescan)
		}
	}
	c.BeginRescan()
	c.EndRescan(nil, true)
	if _, ok := c.Get(p); ok {
		t.Error("an overflow must not protect a file for more than 10 consecutive rescans")
	}
}

func TestFileTableT09_pressureReportNamesAtMost32Owners(t *testing.T) {
	const delay = time.Hour
	c := newCTTable(30)
	for n := 0; c.track("aaa", n, delay); n++ {
	}
	for {
		if _, _, ok := c.PopDue(c.now.Add(2 * delay)); !ok {
			break
		}
	}
	c.TakePressure()
	const owners = 100_000
	refused := 0
	for n := range owners {
		if !c.Track(fmt.Sprintf("/in/user%06d/f", n), scanner.FileIdentity{Size: 1}, c.now, c.now.Add(delay)) {
			refused++
		}
	}
	if refused != owners {
		t.Fatalf("refused = %d, want %d: nothing is evictable when everything is submitted", refused, owners)
	}
	rep := c.TakePressure()
	if rep.Refused != owners {
		t.Errorf("Refused = %d, want the exact total %d", rep.Refused, owners)
	}
	if len(rep.Owners) > maxPressureOwners {
		t.Errorf("the report names %d owners, want at most %d", len(rep.Owners), maxPressureOwners)
	}
	if msg := describePressure(rep); len(msg) > 16<<10 {
		t.Errorf("the pressure message is %d bytes: it must not grow with the number of owners", len(msg))
	}
}

func TestMonitorT09_pressureEndIsRaisedInEventOnlyMode(t *testing.T) {
	rec := recordEvents(t)
	dir := t.TempDir()
	paths := make([]string, 30)
	for i := range paths {
		paths[i] = filepath.Join(dir, fmt.Sprintf("f%03d.txt", i))
		if err := os.WriteFile(paths[i], []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	limit := 10*fileCost(paths[0]) + ownerCost(dir)
	m := newBareMonitor(t, func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{ModDelay: sdk.Duration(time.Hour), MaxTrackedBytes: limit, Watched: []string{dir}})
	for _, p := range paths {
		m.discover(p, true)
	}
	if len(rec.find("error", HostMonitorPressure)) != 1 {
		t.Fatal("the pressure must be raised at once")
	}
	// The refusals that came after the first report are reported at the next
	// opportunity; the end of the pressure follows once a minute passes without
	// any new one.
	for _, p := range paths {
		m.table.Forget(p)
	}
	aged := func() {
		m.repMu.Lock()
		m.lastReport = time.Now().Add(-2 * minReportInterval)
		m.repMu.Unlock()
	}
	m.discover(paths[0], true)
	if len(rec.find("resolution", HostMonitorPressure)) != 0 {
		t.Error("the end of the pressure must not be raised before a minute passed")
	}
	aged()
	m.discover(paths[1], true)
	aged()
	m.discover(paths[2], true)
	if got := len(rec.find("resolution", HostMonitorPressure)); got != 1 {
		t.Errorf("resolutions = %d, want 1 once a minute passed without any new pressure", got)
	}
	aged()
	m.discover(paths[3], true)
	if got := len(rec.find("resolution", HostMonitorPressure)); got != 1 {
		t.Errorf("resolutions = %d, want it sent once", got)
	}
}

func TestMonitorT09_relativeWatchedPathKeepsUsersApart(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	for _, p := range []string{"in/alice/a.txt", "in/alice/sub/b.txt", "in/bob/c.txt"} {
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
	if len(m.table.owners) != 2 {
		names := make([]string, 0, len(m.table.owners))
		for n := range m.table.owners {
			names = append(names, n)
		}
		t.Errorf("owners = %v, want one per user folder (alice, bob) with a relative watched path", names)
	}
}

// TestFileTableT09_countedCostMatchesTheRealHeap compares the counted bytes
// with what the runtime really allocates for the entries.
func TestFileTableT09_countedCostMatchesTheRealHeap(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a few hundred thousand entries")
	}
	const entries = 200_000
	paths := make([]string, entries)
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
	realBytes := float64(after.HeapAlloc-before.HeapAlloc) - float64(entries*16)
	counted := float64(tab.Used())
	if realBytes < counted*0.9 || realBytes > counted*1.1 {
		t.Errorf("real heap %.0f B for %d entries, counted %.0f B: outside ±10%%", realBytes, entries, counted)
	}
	runtime.KeepAlive(tab)
	runtime.KeepAlive(paths)
}
