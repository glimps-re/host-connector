//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type removals struct {
	mu    sync.Mutex
	calls []string
}

func (r *removals) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func recordRemoveDirs(t *testing.T, f *retentionFixture, fn func(ctx context.Context) (cleanupStats, error)) *removals {
	t.Helper()
	r := &removals{}
	f.p.removeDirs = func(ctx context.Context, root, rel string, _ time.Duration, _ string) (cleanupStats, error) {
		r.mu.Lock()
		r.calls = append(r.calls, filepath.Join(root, rel))
		r.mu.Unlock()
		if fn != nil {
			return fn(ctx)
		}
		return cleanupStats{}, nil
	}
	return r
}

func TestSession_emptyFoldersAreRemovedAfterTheReportIsWritten(t *testing.T) {
	f := newRetention(t, Config{RemoveEmptyDirs: true, CleanupTimeout: time.Minute})
	f.hcc.GenerateReportFunc = workingGenerator
	var ran, reportWritten atomic.Bool
	calls := recordRemoveDirs(t, f, func(context.Context) (cleanupStats, error) {
		reportWritten.Store(len(f.reports(t)) > 0)
		ran.Store(true)
		return cleanupStats{}, nil
	})
	f.ready("tom")
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions(f.p.baseCtx())
	waitFor(t, 5*time.Second, ran.Load)
	if got := calls.list(); got[0] != filepath.Join(f.root, "tom") {
		t.Errorf("cleanups = %v, want one on the session folder", got)
	}
	if !reportWritten.Load() {
		t.Error("the empty folders were removed before the report was written")
	}
}

func TestSession_theOptionOffMakesNoRemovalCall(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = workingGenerator
	calls := recordRemoveDirs(t, f, nil)
	f.ready("tom")
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions(f.p.baseCtx())
	if got := calls.list(); len(got) != 0 {
		t.Errorf("cleanups = %v, want none with remove_empty_dirs off", got)
	}
}

func TestSession_aReportThatIsLostLeavesTheFoldersAlone(t *testing.T) {
	f := newRetention(t, Config{RemoveEmptyDirs: true, CleanupTimeout: time.Minute, ReportRetries: 0})
	f.hcc.GenerateReportFunc = workingGenerator
	if err := os.WriteFile(filepath.Join(f.export, "tom"), []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := recordRemoveDirs(t, f, nil)
	f.ready("tom")
	f.ready("ann")
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions(f.p.baseCtx())
	waitFor(t, 5*time.Second, func() bool { return len(calls.list()) > 0 })
	if got := calls.list(); len(got) != 1 || got[0] != filepath.Join(f.root, "ann") {
		t.Errorf("cleanups = %v, want only the session whose report was written", got)
	}
}

// A cleanup that never ends must not hold back the reports of the sessions that
// follow, whichever way they are written.
func TestSession_aStuckCleanupNeverHoldsBackAReport(t *testing.T) {
	stuck := func(ctx context.Context) (cleanupStats, error) {
		<-ctx.Done()
		return cleanupStats{}, ctx.Err()
	}
	for name, write := range map[string]func(f *retentionFixture, sessions []*closingSession){
		"relieve": func(f *retentionFixture, sessions []*closingSession) {
			f.p.relieve(t.Context(), sessions)
		},
		"closeAllSessions": func(f *retentionFixture, _ []*closingSession) {
			f.p.cancelRun()
			f.p.closeAllSessions(t.Context(), t.Context())
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRetention(t, Config{RemoveEmptyDirs: true, CleanupTimeout: time.Hour})
			f.hcc.GenerateReportFunc = workingGenerator
			calls := recordRemoveDirs(t, f, stuck)
			f.ready("tom")
			f.ready("ann")
			sessions := make([]*closingSession, 0, 2)
			for _, user := range []string{"tom", "ann"} {
				s := f.session(user)
				s.closeSession()
				sessions = append(sessions, newClosing(s))
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				write(f, sessions)
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the reports were held back by a cleanup")
			}
			if got := len(f.reports(t)); got != 2 {
				t.Errorf("%d reports written, want 2", got)
			}
			if name == "closeAllSessions" {
				if got := calls.list(); len(got) != 0 {
					t.Errorf("cleanups = %v: none may start once the plugin is stopping", got)
				}
			}
		})
	}
}

func TestSession_aFullQueueDropsTheCleanupAndKeepsTheReport(t *testing.T) {
	f := newRetention(t, Config{RemoveEmptyDirs: true, CleanupTimeout: time.Hour})
	release := make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	recordRemoveDirs(t, f, func(ctx context.Context) (cleanupStats, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return cleanupStats{}, nil
	})
	t.Cleanup(free)
	for i := range 2*maxCleanupQueue + 2 {
		f.p.queueCleanup(string(rune('a' + i%26)))
	}
	if !f.p.cleanupDropped.Load() {
		t.Error("a full queue must drop and say so")
	}
	if !strings.Contains(f.logs.String(), "too many sessions wait") {
		t.Errorf("no warning in the log:\n%s", f.logs.String())
	}
	free()
	waitFor(t, 5*time.Second, func() bool { return !f.p.cleanupDropped.Load() })
}

// Close does not wait for a removal that ignores its cancellation.
func TestSession_closeDoesNotWaitForAHungCleanup(t *testing.T) {
	f := newRetention(t, Config{RemoveEmptyDirs: true, CleanupTimeout: time.Hour})
	f.p.started = true
	close(f.p.done)
	hung, release := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(release) })
	var once sync.Once
	f.p.removeDirs = func(context.Context, string, string, time.Duration, string) (cleanupStats, error) {
		once.Do(func() { close(hung) })
		<-release
		return cleanupStats{}, nil
	}
	f.p.queueCleanup("tom")
	<-hung
	start := time.Now()
	if err := f.p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took < cleanupStopWait || took > cleanupStopWait+3*time.Second {
		t.Errorf("Close took %s, want about %s", took, cleanupStopWait)
	}
	if !strings.Contains(f.logs.String(), "still running at stop") {
		t.Errorf("no warning in the log:\n%s", f.logs.String())
	}
}

func TestSession_theCleanupLogsOneLineWithTheFailuresAndTheDepth(t *testing.T) {
	for name, tt := range map[string]struct {
		stats cleanupStats
		err   error
		want  string
	}{
		"failures": {cleanupStats{removed: 1, failed: 2, firstErr: errors.New("cannot remove x: permission denied")}, nil, "permission denied"},
		"too deep": {cleanupStats{kept: 1}, errTooDeep, "incomplete"},
		"stopped":  {cleanupStats{}, context.DeadlineExceeded, "stopped"},
		"all fine": {cleanupStats{removed: 3}, nil, "empty folders removed"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRetention(t, Config{RemoveEmptyDirs: true, CleanupTimeout: time.Minute})
			recordRemoveDirs(t, f, func(context.Context) (cleanupStats, error) { return tt.stats, tt.err })
			f.p.cleanup(f.p.baseCtx(), "tom")
			if got := f.logs.String(); strings.Count(got, "\n") != 1 || !strings.Contains(got, tt.want) {
				t.Errorf("log = %q, want one line with %q", got, tt.want)
			}
		})
	}
}

func TestSession_theRealCleanupKeepsTheRootTheSessionFolderAndWhatIsRecentOrFull(t *testing.T) {
	f := newRetention(t, Config{RemoveEmptyDirs: true, CleanupTimeout: time.Minute, Delay: time.Minute})
	f.hcc.GenerateReportFunc = workingGenerator
	session := filepath.Join(f.root, "tom")
	old := filepath.Join(session, "old", "empty")
	recent := filepath.Join(session, "recent")
	mkdirs(t, old, recent)
	age(t, old, time.Hour)
	age(t, filepath.Join(session, "old"), time.Hour)
	f.ready("tom")
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions(f.p.baseCtx())
	waitFor(t, 5*time.Second, func() bool { return !exists(old) })
	if exists(old) || exists(filepath.Join(session, "old")) {
		t.Error("an old empty folder was left")
	}
	if !exists(recent) || !exists(session) || !exists(f.root) {
		t.Error("a recent folder, the session folder or the root was removed")
	}
}

func TestCheckConfig_aCleanupWithoutABudgetIsRefused(t *testing.T) {
	good := Config{Depth: 1, Delay: time.Minute, RootFolder: t.TempDir(), ReportTimeout: time.Minute, MaxDuration: 24 * time.Hour, MaxSpoolSize: "1GiB", InflightTimeout: time.Hour, RemoveEmptyDirs: true, CleanupTimeout: time.Minute}
	if err := checkConfig(&good, newMockHCC(t), true); err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.CleanupTimeout = 0
	if err := checkConfig(&bad, newMockHCC(t), true); err == nil || !strings.Contains(err.Error(), "cleanup_timeout") {
		t.Errorf("error = %v, want cleanup_timeout refused", err)
	}
	bad.RemoveEmptyDirs = false
	if err := checkConfig(&bad, newMockHCC(t), true); err != nil {
		t.Errorf("error = %v: the budget does not matter when the option is off", err)
	}
}

func TestGetDefaultConfig_removesEmptyFoldersByDefault(t *testing.T) {
	c, ok := new(SessionPlugin).GetDefaultConfig().(*Config)
	if !ok || !c.RemoveEmptyDirs || c.CleanupTimeout != 2*time.Minute {
		t.Errorf("default config = %+v, want remove_empty_dirs true and cleanup_timeout 2m", c)
	}
}

func TestSession_theWorkDirBelowASessionStaysWhenRootFolderIsSpelledThroughALink(t *testing.T) {
	f := newRetention(t, Config{RemoveEmptyDirs: true, CleanupTimeout: time.Minute, Delay: time.Minute})
	f.hcc.GenerateReportFunc = workingGenerator
	session := filepath.Join(f.root, "tom")
	work := filepath.Join(session, ".work")
	extract := filepath.Join(work, "extract")
	old := filepath.Join(session, "old")
	mkdirs(t, extract, old)
	for _, p := range []string{extract, work, old} {
		age(t, p, time.Hour)
	}
	f.ready("tom")
	link := filepath.Join(t.TempDir(), "in")
	if err := os.Symlink(f.root, link); err != nil {
		t.Fatal(err)
	}
	f.p.config.RootFolder, f.p.workDir = link, work
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions(f.p.baseCtx())
	waitFor(t, 5*time.Second, func() bool { return !exists(old) })
	if !exists(extract) || !exists(work) {
		t.Error("the work directory, or what is in it, was removed")
	}
}
