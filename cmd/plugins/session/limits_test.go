//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

func (f *retentionFixture) deposit(user, name string) string {
	file := f.file(user, name)
	f.p.OnStartScanFile(file, "h")
	f.p.OnFileScanned(file, "h", datamodel.Result{})
	f.p.OnReport(&datamodel.Report{Filename: file, SHA256: "h"})
	return file
}

func (f *retentionFixture) spoolFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(f.p.workDir, datamodel.SessionSpoolDir, "*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestSession_maxDurationClosesASessionThatIsNeverIdle(t *testing.T) {
	f := newRetention(t, Config{Delay: time.Hour, MaxDuration: 2 * time.Hour})
	f.hcc.GenerateReportFunc = workingGenerator
	f.deposit("tom", "a")
	first := f.session("tom")
	for i := range 3 {
		f.clock.advance(59 * time.Minute)
		f.p.checkAndCloseSessions(f.p.baseCtx())
		if i < 1 && f.session("tom") != first {
			t.Fatalf("closed after %d minutes, max_duration is 2h", 59*(i+1))
		}
		f.deposit("tom", "b"+string(rune('a'+i)))
	}
	if len(f.reports(t)) != 1 {
		t.Fatalf("reports = %v, want the one of the session closed by max_duration", f.reports(t))
	}
	next := f.session("tom")
	if next == nil || next == first {
		t.Fatal("the deposit after the forced close must open a new session")
	}
	if !strings.Contains(f.logs.String(), string(forceDuration)) {
		t.Errorf("the forced close is not logged: %s", f.logs.String())
	}
	if got := sessionReports(t, next); len(got) != 1 {
		t.Errorf("new session holds %d reports, want only the last deposit", len(got))
	}
}

func TestSession_maxSpoolSizeClosesTheSessionAtOnce(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = workingGenerator
	f.p.maxSpool = 600
	f.deposit("tom", "a")
	first := f.session("tom")
	for i := 0; first == f.session("tom") && i < 50; i++ {
		f.deposit("tom", "f"+string(rune('a'+i%26))+strings.Repeat("x", i))
	}
	if f.session("tom") == first {
		t.Fatal("the session still takes reports past max_spool_size")
	}
	if len(f.p.closing) != 1 || f.p.closing[0].session != first {
		t.Fatalf("closing = %d sessions, want the full one", len(f.p.closing))
	}
	if !strings.Contains(f.logs.String(), string(forceSpoolSize)) {
		t.Errorf("the forced close is not logged: %s", f.logs.String())
	}
	f.deposit("tom", "z")
	if n := len(sessionReports(t, f.session("tom"))); n != 1 {
		t.Errorf("the new session holds %d reports, want 1", n)
	}
	f.p.checkAndCloseSessions(f.p.baseCtx())
	if len(f.reports(t)) != 1 || len(f.p.closing) != 0 {
		t.Errorf("reports = %v, closing = %d: the full session must be reported at the next check", f.reports(t), len(f.p.closing))
	}
}

func TestSession_aSpoolThatCannotBeWrittenClosesTheSessionAndLosesNothing(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("no /dev/full")
	}
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = workingGenerator
	f.deposit("tom", "first")
	broken := f.session("tom")
	broken.mutex.Lock()
	broken.spool.path = "/dev/full"
	broken.mutex.Unlock()

	big := strings.Repeat("p", spoolFlushSize)
	file := f.file("tom", "big")
	f.p.OnStartScanFile(file, "h")
	f.p.OnFileScanned(file, "h", datamodel.Result{})
	f.p.OnReport(&datamodel.Report{Filename: file, SHA256: big})

	if f.session("tom") == broken {
		t.Fatal("a session whose spool fails must be closed at once")
	}
	if f.events(spoolEvent) != 1 {
		t.Fatalf("%s raised %d times, want once", spoolEvent, f.events(spoolEvent))
	}
	if len(f.p.closing) != 1 {
		t.Fatalf("closing = %d, want the broken session", len(f.p.closing))
	}

	f.deposit("tom", "next")
	if f.session("tom") == nil || f.session("tom") == broken {
		t.Fatal("the next deposit must open a new session")
	}
	f.mu.Lock()
	resolved := append([]string(nil), f.resolved...)
	f.mu.Unlock()
	if len(resolved) != 1 || resolved[0] != spoolEvent {
		t.Errorf("resolved = %v, want %s once the next write succeeded", resolved, spoolEvent)
	}
}

func TestSession_aBrokenSpoolStillGivesItsReport(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("no /dev/full")
	}
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = workingGenerator
	f.deposit("tom", "first")
	broken := f.session("tom")
	realPath := broken.spool.path
	broken.mutex.Lock()
	broken.spool.path = "/dev/full"
	broken.mutex.Unlock()
	file := f.file("tom", "big")
	f.p.OnStartScanFile(file, "h")
	f.p.OnReport(&datamodel.Report{Filename: file, SHA256: strings.Repeat("p", spoolFlushSize)})
	if f.session("tom") == broken {
		t.Fatal("the broken session must be closed")
	}
	broken.mutex.Lock()
	broken.spool.path = realPath
	broken.mutex.Unlock()

	got := sessionReports(t, broken)
	if len(got) != 2 {
		t.Fatalf("the report of the broken session holds %d reports, want the 2 it received", len(got))
	}
	f.p.checkAndCloseSessions(f.p.baseCtx())
	if len(f.reports(t)) != 1 {
		t.Errorf("reports = %v, want the broken session reported with what it holds", f.reports(t))
	}
}

func TestSession_errorsOverTheMemoryBudgetGoToTheSpool(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = workingGenerator
	f.p.errBudget.limit = 2500
	failed := func(name string) {
		file := f.file("tom", name)
		f.p.OnStartScanFile(file, "h")
		f.p.OnReport(&datamodel.Report{Filename: file, SHA256: "h", Error: "boom"})
		f.p.OnFileScanned(file, "h", datamodel.Result{})
	}
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		failed(n)
	}
	s := f.session("tom")
	s.mutex.RLock()
	held, spooled := len(s.pending), 0
	if s.spool != nil {
		spooled = s.spool.count
	}
	s.mutex.RUnlock()
	if held == 0 || spooled == 0 || held+spooled != 5 {
		t.Fatalf("held %d in memory and %d in the spool, want both used and 5 in all", held, spooled)
	}
	if got := f.p.errBudget.used.Load(); got > 2500 {
		t.Errorf("budget used = %d, over its limit", got)
	}
	if n := strings.Count(f.logs.String(), "the memory kept for reports in error is spent"); n != 1 {
		t.Errorf("the spill is logged %d times, want once: %s", n, f.logs.String())
	}
	if n := len(sessionReports(t, s)); n != 5 {
		t.Errorf("reports = %d, want 5", n)
	}
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions(f.p.baseCtx())
	if f.p.errBudget.used.Load() != 0 {
		t.Errorf("budget used = %d after the report, want 0", f.p.errBudget.used.Load())
	}
}

func TestSession_aLaterSuccessReplacesTheErrorHeldInMemory(t *testing.T) {
	f := newRetention(t, Config{})
	file := f.file("tom", "a")
	f.p.OnStartScanFile(file, "h")
	f.p.OnReport(&datamodel.Report{Filename: file, SHA256: "h", Error: "boom"})
	f.p.OnReport(&datamodel.Report{Filename: file, SHA256: "h", Error: "boom again"})
	s := f.session("tom")
	if got := sessionReports(t, s); len(got) != 1 || got[0].Error != "boom again" {
		t.Fatalf("reports = %+v, want the latest error alone", got)
	}
	f.p.OnReport(&datamodel.Report{Filename: file, SHA256: "h"})
	if got := sessionReports(t, s); len(got) != 1 || got[0].Error != "" {
		t.Fatalf("reports = %+v, want the success alone", got)
	}
	if f.p.errBudget.used.Load() != 0 {
		t.Errorf("budget used = %d, want 0 once the error is replaced", f.p.errBudget.used.Load())
	}
}

func TestSession_aReportedSessionFreesItsSpoolAndItsBudget(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = workingGenerator
	f.deposit("tom", "a")
	file := f.file("tom", "bad")
	f.p.OnStartScanFile(file, "h")
	f.p.OnReport(&datamodel.Report{Filename: file, SHA256: "h", Error: "boom"})
	f.p.OnFileScanned(file, "h", datamodel.Result{})
	if len(f.spoolFiles(t)) != 1 || f.p.errBudget.used.Load() == 0 {
		t.Fatalf("spools = %v, budget = %d: want one spool and a budget in use", f.spoolFiles(t), f.p.errBudget.used.Load())
	}
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions(f.p.baseCtx())
	if len(f.reports(t)) != 1 {
		t.Fatalf("reports = %v, want 1", f.reports(t))
	}
	if left := f.spoolFiles(t); len(left) != 0 {
		t.Errorf("spools left after the report: %v", left)
	}
	if f.p.errBudget.used.Load() != 0 {
		t.Errorf("budget = %d after the report, want 0", f.p.errBudget.used.Load())
	}
	if !f.p.knownError(file, "h") {
		t.Error("the failed file must stay known after its session was reported")
	}
}

func TestSession_aLostSessionFreesItsSpool(t *testing.T) {
	f, _, cs := attemptFixture(t)
	if len(f.spoolFiles(t)) != 1 {
		t.Fatalf("spools = %v, want one", f.spoolFiles(t))
	}
	f.p.logLost(cs, context.Canceled)
	if left := f.spoolFiles(t); len(left) != 0 {
		t.Errorf("spools left for a lost report: %v", left)
	}
	if err := cs.session.release(); err != nil {
		t.Errorf("a second release must be harmless: %v", err)
	}
}

func TestSession_rawCopyWhenTheSpoolCannotBeDecoded(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = workingGenerator
	f.deposit("tom", "a")
	f.deposit("tom", "b")
	s := f.session("tom")
	s.mutex.Lock()
	if err := s.spool.flush(); err != nil {
		t.Fatal(err)
	}
	garbage := strings.Repeat("x", int(s.spool.durable-1)) + "\n"
	path := s.spool.path
	s.mutex.Unlock()
	if err := os.WriteFile(path, []byte(garbage), 0o600); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions(f.p.baseCtx())
	got := f.reports(t)
	if len(got) != 1 || filepath.Ext(got[0]) != ".jsonl" {
		t.Fatalf("reports = %v, want the raw copy of the spool", got)
	}
	if !strings.HasPrefix(filepath.Base(got[0]), datamodel.SessionReportPrefix) {
		t.Errorf("raw copy %q lacks the reserved report prefix", got[0])
	}
	if f.events(lostEvent) != 0 {
		t.Error("a raw copy is not a loss")
	}
}

func TestSession_rawCopyHoldsTheSpoolThenTheErrorsInMemory(t *testing.T) {
	f := newRetention(t, Config{})
	f.deposit("tom", "ok")
	file := f.file("tom", "bad")
	f.p.OnStartScanFile(file, "h")
	f.p.OnReport(&datamodel.Report{Filename: file, SHA256: "h", Error: "boom"})
	s := f.session("tom")
	var out strings.Builder
	if err := s.copyRaw(t.Context(), &out); err != nil {
		t.Fatal(err)
	}
	got, err := collect(t, readLines(t.Context(), strings.NewReader(out.String())))
	if err != nil || len(got) != 2 || got[0].Error != "" || got[1].Error != "boom" {
		t.Fatalf("raw = %q (%v), want the spool line then the error held in memory", out.String(), err)
	}
}

func TestCheckConfig_spoolKeys(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{name: "defaults", mutate: func(*Config) {}},
		{name: "zero duration", mutate: func(c *Config) { c.MaxDuration = 0 }, wantErr: "max_duration"},
		{name: "negative duration", mutate: func(c *Config) { c.MaxDuration = -time.Hour }, wantErr: "max_duration"},
		{name: "empty size", mutate: func(c *Config) { c.MaxSpoolSize = "" }, wantErr: "max_spool_size"},
		{name: "not a size", mutate: func(c *Config) { c.MaxSpoolSize = "lots" }, wantErr: "max_spool_size"},
		{name: "negative size", mutate: func(c *Config) { c.MaxSpoolSize = "-5MiB" }, wantErr: "max_spool_size"},
		{name: "under 1MiB", mutate: func(c *Config) { c.MaxSpoolSize = "1000KiB" }, wantErr: "at least 1MiB"},
		{name: "exactly 1MiB", mutate: func(c *Config) { c.MaxSpoolSize = "1MiB" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := new(SessionPlugin).GetDefaultConfig().(*Config)
			cfg.RootFolder = t.TempDir()
			tt.mutate(cfg)
			err := new(SessionPlugin).Validate(cfg, newMockHCC(t))
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestSessionPlugin_InitRefusesABadSpoolSize(t *testing.T) {
	cfg := new(SessionPlugin).GetDefaultConfig().(*Config)
	cfg.RootFolder = t.TempDir()
	cfg.MaxSpoolSize = "1KiB"
	if err := new(SessionPlugin).Init(cfg, newMockHCC(t)); err == nil {
		t.Error("Init must refuse max_spool_size under 1MiB")
	}
}

func TestSessionPlugin_refusesAConnectorWithoutAWorkDir(t *testing.T) {
	cfg := new(SessionPlugin).GetDefaultConfig().(*Config)
	cfg.RootFolder = t.TempDir()
	hcc := mock.NewMockHCContext()
	if err := new(SessionPlugin).Validate(cfg, hcc); err == nil || !strings.Contains(err.Error(), "work directory") {
		t.Errorf("Validate error = %v, want a refusal for the missing work directory", err)
	}
	if err := new(SessionPlugin).Init(cfg, hcc); err == nil || !strings.Contains(err.Error(), "work directory") {
		t.Errorf("Init error = %v, want a refusal for the missing work directory", err)
	}
}

func TestSession_whenTheJSONReportFailsTheSpoolIsCopiedAndNothingIsLost(t *testing.T) {
	f, _, cs := attemptFixture(t)
	var closes atomic.Int32
	prev := closeReportFile
	t.Cleanup(func() { closeReportFile = prev })
	closeReportFile = func(file *os.File) error {
		if closes.Add(1) == 1 {
			return errors.Join(file.Close(), errors.New("disk full"))
		}
		return file.Close()
	}
	if !f.p.attempt(t.Context(), cs) {
		t.Fatal("the session must be done")
	}
	got := f.reports(t)
	if len(got) != 1 || filepath.Ext(got[0]) != datamodel.SessionSpoolExt {
		t.Fatalf("reports = %v, want one raw copy of the spool", got)
	}
	if f.events(lostEvent) != 0 || f.events(fallbackEvent) != 1 {
		t.Errorf("lost events = %d, fallback events = %d, want 0 and 1", f.events(lostEvent), f.events(fallbackEvent))
	}
}

func TestSession_aBacklogGetsTheRawCopyToo(t *testing.T) {
	f, _, cs := attemptFixture(t)
	var closes atomic.Int32
	prev := closeReportFile
	t.Cleanup(func() { closeReportFile = prev })
	closeReportFile = func(file *os.File) error {
		if closes.Add(1) == 1 {
			return errors.Join(file.Close(), errors.New("disk full"))
		}
		return file.Close()
	}
	f.p.relieve(t.Context(), []*closingSession{cs})
	if got := f.reports(t); len(got) != 1 || filepath.Ext(got[0]) != datamodel.SessionSpoolExt {
		t.Fatalf("reports = %v, want one raw copy of the spool", got)
	}
	if f.events(lostEvent) != 0 {
		t.Error("a raw copy is not a loss")
	}
}

func TestSession_aSuccessHeldAfterASpoolFailureIsNotRememberedAsAnError(t *testing.T) {
	f := newRetention(t, Config{})
	s := testSession(t, "tom", time.Unix(1_700_000_000, 0), nil)
	s.pending["ok"] = pendingReport{report: datamodel.Report{Filename: "ok", SHA256: "h1"}}
	s.pending["bad"] = pendingReport{report: datamodel.Report{Filename: "bad", SHA256: "h2", Error: "boom"}}
	s.pending["moved"] = pendingReport{report: datamodel.Report{Filename: "moved", SHA256: "h3", Error: "boom", MovedTo: "/out/x"}}
	f.p.rememberErrors(s)
	if f.p.knownError("ok", "h1") {
		t.Error("a success must not become a known error: the same file dropped again would open no session")
	}
	if f.p.knownError("moved", "h3") {
		t.Error("a file that left INPUT is not retried")
	}
	if !f.p.knownError("bad", "h2") {
		t.Error("a failed file still in INPUT must be known")
	}
}

func TestSession_aProbeNeedsARealWriteToResolve(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("no /dev/full")
	}
	s := testSession(t, "tom", time.Unix(1_700_000_000, 0), nil)
	s.closed = false
	if _, st := s.addReport(datamodel.Report{Filename: "a"}, false); st.works {
		t.Error("a line that only reached the buffer proves nothing: the spool must not be healthy yet")
	}
	s.spool.path = "/dev/full"
	_, st := s.addReport(datamodel.Report{Filename: "b"}, true)
	if st.works || st.forced != forceSpoolError || st.spoolErr == nil {
		t.Errorf("status = %+v: a probe on a full disk must fail the session", st)
	}
	s2 := testSession(t, "tom", time.Unix(1_700_000_000, 0), nil)
	s2.closed = false
	if _, st = s2.addReport(datamodel.Report{Filename: "a"}, true); !st.works || st.forced != "" {
		t.Errorf("status = %+v: a probe that reaches the disk must resolve", st)
	}
}

func TestSession_anOversizeReportIsHeldBound(t *testing.T) {
	s := testSession(t, "tom", time.Unix(1_700_000_000, 0), nil)
	s.closed = false
	r := datamodel.Report{Filename: "x", Error: "boom"}
	for i := range 6000 {
		r.NotAnalyzedExtractedFiles = append(r.NotAnalyzedExtractedFiles, datamodel.NotAnalyzedFile{FileName: strings.Repeat("n", 900) + strconv.Itoa(i)})
	}
	if ok, _ := s.addReport(r, false); !ok {
		t.Fatal("refused")
	}
	held := s.pending["x"]
	if len(held.report.NotAnalyzedExtractedFiles) >= len(r.NotAnalyzedExtractedFiles) {
		t.Error("the report held in memory must be the bound one that the budget counted")
	}
	if held.size <= 0 || held.size > datamodel.MaxReportSize+1 {
		t.Errorf("size = %d, want the size of the bound line", held.size)
	}
}

func TestSession_anEncodingFailureKeepsTheReportAndDoesNotCloseTheSession(t *testing.T) {
	s := testSession(t, "tom", time.Unix(1_700_000_000, 0), nil)
	s.closed = false
	s.mutex.Lock()
	s.keepError(datamodel.Report{Filename: "x", Error: "e"}, nil, errors.New("cannot encode"))
	st := s.statusLocked(false)
	s.mutex.Unlock()
	if st.encodeErr == nil || st.forced != "" || st.spoolErr != nil {
		t.Errorf("status = %+v, want the encoding error alone", st)
	}
	if _, ok := s.pending["x"]; !ok {
		t.Error("the report must be kept as it came")
	}
	s.mutex.Lock()
	again := s.statusLocked(false)
	s.mutex.Unlock()
	if again.encodeErr != nil {
		t.Error("the encoding error must be reported once")
	}
}

func TestSession_aSpoolFailureIsRaisedWhoeverClosedTheSession(t *testing.T) {
	f := newRetention(t, Config{})
	f.deposit("tom", "a")
	s := f.session("tom")
	f.p.mutex.Lock()
	delete(f.p.sessions, "tom")
	f.p.mutex.Unlock()
	f.p.afterWrite(s, sessionStatus{forced: forceSpoolError, spoolErr: errors.New("disk full")})
	if f.events(spoolEvent) != 1 {
		t.Errorf("%s raised %d times, want once even though the monitor took the session", spoolEvent, f.events(spoolEvent))
	}
}

func TestSession_forceCloseRacingTheStopLosesNoSession(t *testing.T) {
	for range 20 {
		f := newRetention(t, Config{})
		f.hcc.GenerateReportFunc = workingGenerator
		const n = 8
		sessions := make([]*Session, 0, n)
		for i := range n {
			f.deposit("u"+strconv.Itoa(i), "a")
			sessions = append(sessions, f.session("u"+strconv.Itoa(i)))
		}
		var wg sync.WaitGroup
		for _, s := range sessions {
			wg.Go(func() { f.p.forceClose(s) })
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		f.p.closeAllSessions(ctx, ctx)
		wg.Wait()
		cancel()
		f.p.closeMu.Lock()
		queued := len(f.p.closing)
		f.p.closeMu.Unlock()
		if queued != 0 {
			t.Fatalf("%d sessions queued after the stop took the list: nobody would write them", queued)
		}
		if got := len(f.reports(t)); got != n {
			t.Fatalf("reports = %d, want %d: a session was lost or written twice", got, n)
		}
		if strings.Contains(f.logs.String(), "is lost") {
			t.Fatalf("a session was named lost: %s", f.logs.String())
		}
	}
}

func TestSession_aBacklogCutByTheStopIsGivenBackNotLost(t *testing.T) {
	f, _, cs := attemptFixture(t)
	cut, cancel := context.WithCancel(t.Context())
	cancel()
	left := f.p.relieve(cut, []*closingSession{cs})
	if len(left) != 1 || left[0] != cs {
		t.Fatalf("left = %d sessions, want the one the stop cut", len(left))
	}
	if strings.Contains(f.logs.String(), "is lost") || f.events(lostEvent) != 0 {
		t.Errorf("a session cut by the stop is named lost: %s", f.logs.String())
	}
	if len(f.spoolFiles(t)) != 1 {
		t.Error("the spool of a session cut by the stop must stay: Close writes the report")
	}
	if err := f.p.writeFallback(t.Context(), cs); err != nil {
		t.Fatalf("Close could not write the report: %v", err)
	}
}

func TestSession_aProbeWithNothingBufferedProvesNothing(t *testing.T) {
	s := testSession(t, "tom", time.Unix(1_700_000_000, 0), nil)
	s.closed = false
	if _, st := s.addReport(datamodel.Report{Filename: "a"}, false); st.works {
		t.Fatal("not healthy before a write to disk")
	}
	s.mutex.Lock()
	if err := s.spool.flush(); err != nil {
		t.Fatal(err)
	}
	st := s.statusLocked(true)
	s.mutex.Unlock()
	if st.works {
		t.Error("an empty buffer writes nothing to the disk: it must not resolve the event")
	}
}

func TestSession_aFlushOnTheWayMakesTheSpoolHealthy(t *testing.T) {
	s := testSession(t, "tom", time.Unix(1_700_000_000, 0), nil)
	s.closed = false
	pad := strings.Repeat("p", spoolFlushSize)
	if _, st := s.addReport(datamodel.Report{Filename: "a", SHA256: pad}, false); !st.works {
		t.Error("a write that went to the disk proves the disk works")
	}
}

func TestSession_theBudgetChargesTheMemoryOfEachHeldReport(t *testing.T) {
	budget := &errorBudget{limit: 10_000}
	s := newBenchSession(t, budget, 0)
	for i := range 100 {
		okAdd(s, datamodel.Report{Filename: strconv.Itoa(i), Error: "e"})
	}
	if held := len(s.pending); held == 0 || int64(held)*pendingOverhead > budget.limit {
		t.Errorf("%d reports held for a budget of %d: each must be charged its overhead of %d", held, budget.limit, pendingOverhead)
	}
	if budget.used.Load() > budget.limit {
		t.Errorf("budget used = %d, over its limit", budget.used.Load())
	}
	if err := s.release(); err != nil || budget.used.Load() != 0 {
		t.Errorf("release: %v, budget used = %d, want 0", err, budget.used.Load())
	}
}

func TestSession_noSessionIsCreatedOnceTheStopTookTheOthers(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = workingGenerator
	f.deposit("tom", "a")
	f.p.closeAllSessions(t.Context(), t.Context())
	file := f.file("ann", "late")
	f.p.OnStartScanFile(file, "h")
	f.p.OnReport(&datamodel.Report{Filename: file, SHA256: "h"})
	if f.session("ann") != nil {
		t.Error("a session created after the stop would never be reported")
	}
	if !strings.Contains(f.logs.String(), "after the stop") || !strings.Contains(f.logs.String(), file) {
		t.Errorf("the file that arrived late must be named in a warning: %s", f.logs.String())
	}
}

func TestSession_aFlushedSpoolThatFailsLaterIsNoLongerHealthy(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("no /dev/full")
	}
	s := testSession(t, "tom", time.Unix(1_700_000_000, 0), nil)
	s.closed = false
	pad := strings.Repeat("p", spoolFlushSize)
	if _, st := s.addReport(datamodel.Report{Filename: "a", SHA256: pad}, false); !st.works {
		t.Fatal("a flush to disk makes the spool healthy")
	}
	s.spool.path = "/dev/full"
	if _, st := s.addReport(datamodel.Report{Filename: "b"}, true); st.works {
		t.Errorf("status = %+v: a spool that has lines buffered, or whose disk failed, must not resolve the event", st)
	}
}

func TestSession_aSessionCreatedDuringTheStopIsRefusedOrReported(t *testing.T) {
	for range 20 {
		f := newRetention(t, Config{})
		f.hcc.GenerateReportFunc = workingGenerator
		const n = 8
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				file := f.file("u"+strconv.Itoa(i), "a")
				f.p.OnStartScanFile(file, "h")
				f.p.OnReport(&datamodel.Report{Filename: file, SHA256: "h"})
			})
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		f.p.closeAllSessions(ctx, ctx)
		wg.Wait()
		cancel()
		f.p.mutex.RLock()
		left := len(f.p.sessions)
		f.p.mutex.RUnlock()
		if left != 0 {
			t.Fatalf("%d sessions left open after the stop: nobody would report them", left)
		}
		for i := range n {
			user := "u" + strconv.Itoa(i)
			reported := len(filesIn(t, filepath.Join(f.export, user))) > 0
			refused := strings.Contains(f.logs.String(), "after the stop took the sessions") && strings.Contains(f.logs.String(), f.file(user, "a"))
			if !reported && !refused {
				t.Fatalf("%s: neither reported nor refused with a warning", user)
			}
		}
	}
}

// Once the spool failed, nothing more is written to it: the next reports are held
// in memory, and the report of the session reads back what the spool kept, then
// what was held.
func TestSession_aSpoolThatFailedIsNotWrittenToAgain(t *testing.T) {
	s := testSession(t, "tom", time.Unix(1_700_000_000, 0), nil)
	s.closed = false
	okAdd(s, datamodel.Report{Filename: "before"})
	s.mutex.Lock()
	size := s.spool.size()
	s.spoolErr = errors.New("disk full")
	s.mutex.Unlock()

	for _, name := range []string{"after1", "after2"} {
		if ok, st := s.addReport(datamodel.Report{Filename: name}, false); !ok || st.forced != forceSpoolError || st.spoolErr == nil {
			t.Fatalf("addReport(%s) = %v, %+v, want it taken, with the session to be closed for its spool", name, ok, st)
		}
	}
	s.mutex.RLock()
	held, spoolSize, spoolCount := len(s.pending), s.spool.size(), s.spool.count
	s.mutex.RUnlock()
	if held != 2 {
		t.Errorf("%d reports held in memory, want the 2 that came after the failure", held)
	}
	if spoolSize != size || spoolCount != 1 {
		t.Errorf("spool = %d bytes, %d lines, want it untouched at %d bytes, 1 line", spoolSize, spoolCount, size)
	}
	s.closeSession()
	reports := sessionReports(t, s)
	got := make([]string, 0, len(reports))
	for _, r := range reports {
		got = append(got, r.Filename)
	}
	if want := []string{"before", "after1", "after2"}; !slices.Equal(got, want) {
		t.Errorf("reports = %v, want %v: nothing lost, the spool first", got, want)
	}
}

// The same with a disk that really failed, then works again: the session stays
// broken, a new one is the way back.
func TestSession_aSpoolThatFailedStaysBrokenEvenWhenTheDiskIsBack(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("no /dev/full")
	}
	s := testSession(t, "tom", time.Unix(1_700_000_000, 0), nil)
	s.closed = false
	okAdd(s, datamodel.Report{Filename: "before"})
	onDisk := s.spool.path
	s.spool.path = "/dev/full"
	if _, st := s.addReport(datamodel.Report{Filename: "big", SHA256: strings.Repeat("p", spoolFlushSize)}, false); st.forced != forceSpoolError {
		t.Fatalf("status = %+v, want the spool failure", st)
	}
	s.spool.path = onDisk
	size := s.spool.size()
	if _, st := s.addReport(datamodel.Report{Filename: "later"}, false); st.forced != forceSpoolError {
		t.Errorf("status = %+v, want the session to stay broken", st)
	}
	if s.spool.size() != size {
		t.Error("the spool took a line after its failure")
	}
	if _, held := s.pending["later"]; !held {
		t.Error("the report after the failure must be held in memory")
	}
}
