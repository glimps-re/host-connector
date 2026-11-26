package handler

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

// outcomeMonitor builds a monitor whose callback accepts every file and reports
// outcome(path, attempt) for it, like the pipeline would.
type outcomeMonitor struct {
	*Monitor
	mu    sync.Mutex
	calls map[string][]time.Time
}

func newOutcomeMonitor(t *testing.T, cfg Config, outcome func(path string, attempt int) scanner.FileOutcome) *outcomeMonitor {
	t.Helper()
	om := &outcomeMonitor{calls: map[string][]time.Time{}}
	m, err := NewMonitor(func(path string, id scanner.FileIdentity) (bool, error) {
		om.mu.Lock()
		om.calls[path] = append(om.calls[path], time.Now())
		attempt := len(om.calls[path])
		om.mu.Unlock()
		o := outcome(path, attempt)
		o.Location = path
		if o.Identity == (scanner.FileIdentity{}) {
			o.Identity = id
		}
		om.FileDone(o)
		return true, nil
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	om.Monitor = m
	t.Cleanup(func() {
		if e := m.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	return om
}

func (om *outcomeMonitor) count(path string) int {
	om.mu.Lock()
	defer om.mu.Unlock()
	return len(om.calls[path])
}

func final(string, int) scanner.FileOutcome {
	return scanner.FileOutcome{Kind: scanner.OutcomeFinal}
}

func retry(string, int) scanner.FileOutcome {
	return scanner.FileOutcome{Kind: scanner.OutcomeRetry}
}

func resource(string, int) scanner.FileOutcome {
	return scanner.FileOutcome{Kind: scanner.OutcomeResource}
}

func TestMonitor_unchangedProcessedFileIsNotSubmittedAgain(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "stays.bin")
	writeTestFile(t, file)
	om := newOutcomeMonitor(t, Config{ModDelay: sdk.Duration(time.Millisecond), DisableWatcher: true, Period: sdk.Duration(10 * time.Millisecond)}, final)
	om.Start()
	if err := om.Add(root); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first submission", func() bool { return om.count(file) == 1 })
	time.Sleep(200 * time.Millisecond) // about twenty rescans
	if n := om.count(file); n != 1 {
		t.Errorf("submitted %d times in 20 rescans, want once: a file left in INPUT is not processed again", n)
	}
}

func TestMonitor_modifiedProcessedFileIsProcessedAgain(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "f.bin")
	writeTestFile(t, file)
	om := newOutcomeMonitor(t, Config{ModDelay: sdk.Duration(5 * time.Millisecond), DisableWatcher: true, Period: sdk.Duration(10 * time.Millisecond)}, final)
	om.Start()
	if err := om.Add(root); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first submission", func() bool { return om.count(file) == 1 })
	time.Sleep(30 * time.Millisecond)
	if err := os.WriteFile(file, []byte("another content"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the second submission after the modification", func() bool { return om.count(file) == 2 })
}

func TestMonitor_transientFailuresAreRetriedWithBackoffAndGiveUpAtTheCap(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "f.bin")
	writeTestFile(t, file)
	const period = 4 * time.Millisecond
	om := newOutcomeMonitor(t, Config{ModDelay: sdk.Duration(time.Millisecond), DisableWatcher: true, Period: sdk.Duration(period)}, retry)
	om.Start()
	if err := om.Add(root); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the eight attempts", func() bool { return om.count(file) >= maxAttempts })
	time.Sleep(600 * time.Millisecond) // longer than the largest delay: nothing more must come
	om.mu.Lock()
	times := append([]time.Time(nil), om.calls[file]...)
	om.mu.Unlock()
	if len(times) != maxAttempts {
		t.Fatalf("submitted %d times, want exactly %d then final", len(times), maxAttempts)
	}
	for i := 1; i < len(times); i++ {
		// failure i (1-based) waits base×2^i, shifted by at most 20 %
		want := time.Duration(float64(period<<min(i, maxBackoff)) * 0.8)
		if got := times[i].Sub(times[i-1]); got < want {
			t.Errorf("attempt %d came %v after the previous one, want at least %v: the backoff was not respected", i+1, got, want)
		}
	}
}

func TestMonitor_resourceFailuresNeverGiveUp(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "f.bin")
	writeTestFile(t, file)
	om := newOutcomeMonitor(t, Config{ModDelay: sdk.Duration(time.Millisecond), DisableWatcher: true, Period: sdk.Duration(2 * time.Millisecond)}, resource)
	om.Start()
	if err := om.Add(root); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "more attempts than the cap", func() bool { return om.count(file) >= maxAttempts+4 })
}

func TestMonitor_fileModifiedWhileSubmittedIsReopenedEvenWithoutRescan(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "f.bin")
	writeTestFile(t, file)
	var first atomic.Bool
	// the file is modified while the pipeline works on it, then it reports a final outcome
	om := newOutcomeMonitor(t, Config{ModDelay: sdk.Duration(20 * time.Millisecond)}, func(path string, attempt int) scanner.FileOutcome {
		if first.CompareAndSwap(false, true) {
			time.Sleep(10 * time.Millisecond)
			f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				t.Error(err)
				return scanner.FileOutcome{Kind: scanner.OutcomeFinal}
			}
			if _, err = f.WriteString(" more"); err != nil {
				t.Error(err)
			}
			if err = f.Close(); err != nil {
				t.Error(err)
			}
		}
		return scanner.FileOutcome{Kind: scanner.OutcomeFinal}
	})
	om.Start() // period 0: no rescan will ever come
	// The folder is not watched: no event can report the modification, only the
	// comparison of the identities when the outcome arrives can.
	om.discover(file, true)
	waitFor(t, "the file to be submitted again", func() bool { return om.count(file) >= 2 })
}

func TestMonitor_fiveThousandPermanentFailuresAreProcessedOnce(t *testing.T) {
	root := t.TempDir()
	const n = 5000
	for i := range n {
		writeTestFile(t, filepath.Join(root, fmt.Sprintf("d%d", i%50), fmt.Sprintf("f%d.bin", i)))
	}
	var total atomic.Int64
	om := newOutcomeMonitor(t, Config{ModDelay: sdk.Duration(time.Millisecond), DisableWatcher: true, Period: sdk.Duration(20 * time.Millisecond)}, func(string, int) scanner.FileOutcome {
		total.Add(1)
		return scanner.FileOutcome{Kind: scanner.OutcomeFinal} // ENAMETOOLONG, ENOTDIR...: permanent, final
	})
	om.Start()
	if err := om.Add(root); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "all the files", func() bool { return total.Load() >= n })
	time.Sleep(300 * time.Millisecond) // several more rescans
	if got := total.Load(); got != n {
		t.Errorf("%d submissions for %d files, want exactly one each", got, n)
	}
}

func TestMonitor_concurrentFileDoneNeverDeadlocks(t *testing.T) {
	root := t.TempDir()
	const n = 200
	paths := make([]string, n)
	for i := range n {
		paths[i] = filepath.Join(root, fmt.Sprintf("f%d.bin", i))
		writeTestFile(t, paths[i])
	}
	var accepted sync.Map
	m, err := NewMonitor(func(path string, id scanner.FileIdentity) (bool, error) {
		accepted.Store(path, id)
		return true, nil
	}, Config{ModDelay: sdk.Duration(time.Millisecond), DisableWatcher: true, Period: sdk.Duration(5 * time.Millisecond)})
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
	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for w := range 8 {
			wg.Go(func() {
				for round := range 50 {
					for i := w; i < n; i += 8 {
						if v, ok := accepted.Load(paths[i]); ok {
							id, _ := v.(scanner.FileIdentity)
							m.FileDone(scanner.FileOutcome{Location: paths[i], Identity: id, Kind: kindOf(round)})
						}
					}
				}
			})
		}
		wg.Wait()
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("FileDone calls and the rescans deadlocked")
	}
}

func TestFileTable_retryBackoffIsSpreadByJitter(t *testing.T) {
	m, err := NewMonitor(func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{DisableWatcher: true, Period: sdk.Duration(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	now := time.Unix(1000, 0)
	retryAts := map[time.Time]struct{}{}
	for i := range 1000 {
		p := fmt.Sprintf("/in/u/f%d", i)
		m.table.Track(p, scanner.FileIdentity{}, now, now)
		m.table.PopDue(now)
		m.table.Finish(p, finishArgs{Retry: true, Now: now, Base: time.Minute, Jitter: m.jitter(p)})
		f, _ := m.table.Get(p)
		retryAts[f.retryAt] = struct{}{}
		if d := f.retryAt.Sub(now); d < time.Duration(float64(2*time.Minute)*0.8) || d > time.Duration(float64(2*time.Minute)*1.2) {
			t.Fatalf("retry after %v, want 2 minutes ±20%%", d)
		}
	}
	if len(retryAts) < 500 {
		t.Errorf("%d distinct retry times for 1000 simultaneous failures, want them spread", len(retryAts))
	}
}

func BenchmarkRescanUnchanged(b *testing.B) {
	m, err := NewMonitor(func(string, scanner.FileIdentity) (bool, error) {
		b.Fatal("an unchanged file must not be submitted")
		return false, nil
	}, Config{DisableWatcher: true, Period: sdk.Duration(time.Hour), Watched: []string{"/in"}})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = m.Close() })
	m.stat = func(string) (os.FileInfo, error) { return fakeInfo{}, nil }
	now := time.Unix(1000, 0)
	const n = 100_000
	paths := make([]string, n)
	for i := range paths {
		paths[i] = fmt.Sprintf("/in/u%d/f%d", i%100, i)
		m.table.Track(paths[i], scanner.IdentityOf(fakeInfo{}), now, now)
	}
	for range n {
		p, _, ok := m.table.PopDue(now)
		if !ok {
			b.Fatal("no entry due")
		}
		m.table.Finish(p, finishArgs{Now: now, Base: time.Minute})
	}
	b.ReportAllocs()
	for b.Loop() {
		m.table.BeginRescan()
		for _, p := range paths {
			m.discover(p, false)
		}
		m.table.EndRescan(nil, false)
	}
	if m.table.Len() != n {
		b.Fatalf("tracked = %d, want %d: processed entries must survive a rescan", m.table.Len(), n)
	}
}

// A full table must not starve the files of its largest owner: while another
// depositor brings a file at every rescan, and the pipeline moves the files it
// processes out of INPUT, every file of the large owner is submitted, the last
// one included.
func TestMonitor_fullTableDoesNotStarveTheLastFileOfTheLargestOwner(t *testing.T) {
	root := t.TempDir()
	const big = 30
	want := map[string]bool{}
	for i := range big {
		p := filepath.Join(root, "big", fmt.Sprintf("f%02d.bin", i))
		writeTestFile(t, p)
		want[p] = false
	}
	var mu sync.Mutex
	om := newOutcomeMonitor(t, Config{
		MaxTrackedBytes: 4000, // a handful of entries
		ModDelay:        sdk.Duration(time.Millisecond),
		DisableWatcher:  true,
		Period:          sdk.Duration(10 * time.Millisecond),
		Watched:         []string{root},
	}, func(path string, _ int) scanner.FileOutcome {
		mu.Lock()
		if _, ok := want[path]; ok {
			want[path] = true
		}
		mu.Unlock()
		// the pipeline moves the file out of INPUT
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
		return scanner.FileOutcome{Kind: scanner.OutcomeFinal}
	})
	om.Start()
	if err := om.Add(root); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
				writeTestFile(t, filepath.Join(root, "small", fmt.Sprintf("s%d.bin", i)))
			}
		}
	})
	defer func() {
		close(stop)
		wg.Wait()
	}()
	waitFor(t, "every file of the largest owner", func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, done := range want {
			if !done {
				return false
			}
		}
		return true
	})
}

// With processed files that stay in INPUT, the table fills with them: the
// operator is told.
func TestMonitor_tableFullOfFilesLeftInInputRaisesAnEvent(t *testing.T) {
	rec := recordEvents(t)
	root := t.TempDir()
	for i := range 30 {
		writeTestFile(t, filepath.Join(root, "alice", fmt.Sprintf("f%02d.bin", i)))
	}
	om := newOutcomeMonitor(t, Config{
		MaxTrackedBytes: 4000,
		ModDelay:        sdk.Duration(time.Millisecond),
		DisableWatcher:  true,
		Period:          sdk.Duration(10 * time.Millisecond),
		Watched:         []string{root},
	}, final)
	om.Start()
	if err := om.Add(root); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the table-full event", func() bool {
		return len(rec.find("error", HostMonitorTableFull)) > 0
	})
}

// Without a rescan period nothing comes back to a file by itself: a failure is
// retried at the first event on the file once its delay is over.
func TestFileTable_withoutRescanAFailureComesBackAtTheFirstEventAfterItsDelay(t *testing.T) {
	now := time.Unix(1000, 0)
	tab := newTestTable(1<<20, 25)
	p := tp("u", 1)
	stamp := scanner.FileIdentity{Size: 1}
	tab.Track(p, stamp, now, now)
	tab.PopDue(now)
	tab.Finish(p, finishArgs{Retry: true, Now: now, Base: time.Minute, Submitted: stamp, Current: stamp})
	f, _ := tab.Get(p)
	if f.phase != phaseDone || f.retryAt.IsZero() {
		t.Fatalf("state = %+v, want a failure waiting for its retry", f)
	}
	tab.Track(p, stamp, now.Add(10*time.Second), now.Add(10*time.Second))
	if f, _ = tab.Get(p); f.phase != phaseDone {
		t.Errorf("phase = %d after an event before the retry delay, want it left alone", f.phase)
	}
	tab.Track(p, stamp, now.Add(10*time.Minute), now.Add(10*time.Minute))
	if f, _ = tab.Get(p); f.phase != phaseWaiting {
		t.Errorf("phase = %d after an event past the retry delay, want it waiting again", f.phase)
	}
	if f.attempts != 1 {
		t.Errorf("attempts = %d, want the failure kept: a retry is not a new file", f.attempts)
	}
}

// An event received while a file is processed must not be lost when its outcome
// comes: the file changed, it waits for stability again.
func TestFileTable_changeSeenWhileSubmittedIsNotLostAtTheOutcome(t *testing.T) {
	now := time.Unix(1000, 0)
	tab := newTestTable(1<<20, 25)
	p := tp("u", 1)
	before, after := scanner.FileIdentity{Size: 1}, scanner.FileIdentity{Size: 2}
	tab.Track(p, before, now, now)
	tab.PopDue(now)
	tab.Track(p, after, now, now) // the write arrives after the outcome's stat, before Finish
	_, reopened := tab.Finish(p, finishArgs{Now: now, Submitted: before, Current: before, Deadline: now.Add(time.Second)})
	if !reopened {
		t.Fatal("the entry must be reopened: the file changed under its processing")
	}
	if f, _ := tab.Get(p); f.phase != phaseWaiting || !f.stamp.Equal(after) {
		t.Errorf("entry = %+v, want it waiting with the newest stamp", f)
	}
}

func TestFileTable_failureCountersAndBackoffNeverWrapOrOverflow(t *testing.T) {
	now := time.Unix(1000, 0)
	tab := newTestTable(1<<20, 25)
	p := tp("u", 1)
	stamp := scanner.FileIdentity{Size: 1}
	tab.Track(p, stamp, now, now)
	for range 600 {
		tab.PopDue(now.Add(3000 * time.Hour))
		tab.Finish(p, finishArgs{Retry: true, Resource: true, Now: now, Base: 1 << 62, Submitted: stamp, Current: stamp})
		f, _ := tab.Get(p)
		if f.resource == 0 {
			t.Fatal("the count of resource failures wrapped around to zero")
		}
		if d := f.retryAt.Sub(now); d <= 0 || d > time.Duration(float64(retryCeiling)*1.21) {
			t.Fatalf("retry after %v, want a delay within (0, 1h+20%%]: the backoff overflowed", d)
		}
		tab.Touch(p, now.Add(2000*time.Hour)) // reopen for the next round
	}
}

// An action that fails after altering the file (a link then an unlink moves the
// change time) must not loop at the speed of the stability delay.
func TestMonitor_anActionThatAltersTheFileBeforeFailingIsCountedNotReopened(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "f.bin")
	writeTestFile(t, file)
	om := newOutcomeMonitor(t, Config{ModDelay: sdk.Duration(time.Millisecond), DisableWatcher: true, Period: sdk.Duration(2 * time.Millisecond)}, func(path string, _ int) scanner.FileOutcome {
		// moves the change time, like a link then an unlink does
		if err := os.Chmod(path, 0o400); err != nil {
			t.Error(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Error(err)
		}
		// the pipeline reports the state its own action left the file in
		info, err := os.Lstat(path)
		if err != nil {
			t.Error(err)
			return scanner.FileOutcome{Kind: scanner.OutcomeRetry}
		}
		return scanner.FileOutcome{Kind: scanner.OutcomeRetry, Identity: scanner.IdentityOf(info)}
	})
	om.Start()
	if err := om.Add(root); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first attempts", func() bool { return om.count(file) >= 2 })
	time.Sleep(1500 * time.Millisecond)
	if n := om.count(file); n > maxAttempts {
		t.Errorf("submitted %d times, want at most %d: a failing action that alters the file must not loop", n, maxAttempts)
	}
}

// A file refused without failure (empty, a link) is not asked again at every
// rescan.
func TestMonitor_aRefusedFileIsNotSubmittedAgainUntilItChanges(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "refused.bin")
	writeTestFile(t, file)
	var calls atomic.Int64
	m, err := NewMonitor(func(string, scanner.FileIdentity) (bool, error) {
		calls.Add(1)
		return false, fmt.Errorf("%w: empty file", scanner.ErrRefused)
	}, Config{ModDelay: sdk.Duration(time.Millisecond), DisableWatcher: true, Period: sdk.Duration(5 * time.Millisecond)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	m.Start()
	if err = m.Add(root); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first submission", func() bool { return calls.Load() == 1 })
	time.Sleep(200 * time.Millisecond) // about forty rescans
	if n := calls.Load(); n != 1 {
		t.Errorf("submitted %d times in forty rescans, want once", n)
	}
	if err = os.WriteFile(file, []byte("now it has more content"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the file to be submitted again after it changed", func() bool { return calls.Load() >= 2 })
}

// kindOf alternates a failure and a final outcome.
func kindOf(round int) scanner.OutcomeKind {
	if round%2 == 0 {
		return scanner.OutcomeRetry
	}
	return scanner.OutcomeFinal
}

// A user who rewrites a file during every analysis: the first two reopenings
// are immediate, then they are spaced, up to once an hour, and the file is never
// abandoned.
func TestFileTable_aFileRewrittenDuringEveryAnalysisIsReopenedWithGrowingDelays(t *testing.T) {
	now := time.Unix(1000, 0)
	tab := newTestTable(1<<20, 25)
	p := tp("u", 1)
	const base = time.Minute
	stamp := scanner.FileIdentity{Size: 1}
	tab.Track(p, stamp, now, now)
	waits := make([]time.Duration, 0, 20)
	for i := range 20 {
		tab.PopDue(now.Add(1000 * time.Hour))
		next := scanner.FileIdentity{Size: int64(i) + 2}
		_, reopened := tab.Finish(p, finishArgs{Now: now, Base: base, Submitted: stamp, Current: next, Deadline: now.Add(time.Second)})
		if !reopened {
			t.Fatalf("cycle %d: a rewritten file must be reopened, never given up", i)
		}
		f, _ := tab.Get(p)
		waits = append(waits, f.deadline.Sub(now))
		stamp = next
	}
	if waits[0] != time.Second || waits[1] != time.Second {
		t.Errorf("first reopenings wait %v and %v, want the stability delay (1s)", waits[0], waits[1])
	}
	if waits[2] != 2*base || waits[3] != 4*base || waits[4] != 8*base {
		t.Errorf("next waits = %v, %v, %v; want base × 2^(n-2) = %v, %v, %v", waits[2], waits[3], waits[4], 2*base, 4*base, 8*base)
	}
	if last := waits[len(waits)-1]; last != retryCeiling {
		t.Errorf("last wait = %v, want the ceiling of one hour", last)
	}
	// an outcome that finds the file unchanged ends the series
	f, _ := tab.Get(p)
	_ = f
	tab.PopDue(now.Add(5000 * time.Hour))
	tab.Finish(p, finishArgs{Now: now, Base: base, Submitted: stamp, Current: stamp})
	if f, _ = tab.Get(p); f.reopens != 0 || f.phase != phaseDone {
		t.Errorf("entry = %+v, want the series of reopenings ended by an unchanged outcome", f)
	}
}

// Characterization of a documented limit: an entry waiting for a retry that is
// evicted under pressure is found again with its counters at zero.
func TestFileTable_evictedRetryEntryForgetsItsFailures(t *testing.T) {
	now := time.Unix(1000, 0)
	tab := newTestTable(1<<20, 25)
	p := tp("u", 1)
	stamp := scanner.FileIdentity{Size: 1}
	tab.Track(p, stamp, now, now)
	tab.PopDue(now)
	tab.Finish(p, finishArgs{Retry: true, Now: now, Base: time.Minute, Submitted: stamp, Current: stamp})
	if f, _ := tab.Get(p); f.attempts != 1 {
		t.Fatalf("attempts = %d, want 1", f.attempts)
	}
	tab.mu.Lock()
	tab.evict(tab.files[p], "someone else", tab.files[p].owner)
	tab.mu.Unlock()
	if _, ok := tab.Get(p); ok {
		t.Fatal("the entry must be gone")
	}
	tab.Track(p, stamp, now, now)
	if f, _ := tab.Get(p); f.attempts != 0 {
		t.Errorf("attempts = %d after eviction and rediscovery, want 0 (documented: the cap can be exceeded under pressure)", f.attempts)
	}
}
