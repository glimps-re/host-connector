package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
	"github.com/glimps-re/host-connector/pkg/quarantine"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type retentionFixture struct {
	p      *SessionPlugin
	hcc    *mock.MockHCContext
	clock  *clock
	logs   *syncBuffer
	root   string
	export string

	mu                     sync.Mutex
	errorsRaised, resolved []string
	written                []string
}

func newRetention(t *testing.T, cfg Config) *retentionFixture {
	t.Helper()
	f := &retentionFixture{clock: &clock{t: time.Unix(1_700_000_000, 0)}, logs: &syncBuffer{}, root: t.TempDir(), export: t.TempDir()}
	f.hcc = newMockHCC(t)
	f.hcc.NotifyErrorFunc = func(_ context.Context, key string, _ error) {
		f.mu.Lock()
		f.errorsRaised = append(f.errorsRaised, key)
		f.mu.Unlock()
	}
	f.hcc.NotifyResolutionFunc = func(_ context.Context, key, _ string) {
		f.mu.Lock()
		f.resolved = append(f.resolved, key)
		f.mu.Unlock()
	}
	f.hcc.NotifyReportWrittenFunc = func(_ context.Context, _, path, digest string) {
		f.mu.Lock()
		f.written = append(f.written, path+" "+digest)
		f.mu.Unlock()
	}
	cfg.RootFolder, cfg.Depth, cfg.Exports = f.root, 1, []string{f.export}
	if cfg.ReportTimeout == 0 {
		cfg.ReportTimeout = time.Minute
	}
	if cfg.InflightTimeout == 0 {
		cfg.InflightTimeout = 24 * time.Hour
	}
	if cfg.Delay == 0 {
		cfg.Delay = time.Minute
	}
	f.p = &SessionPlugin{config: cfg, sessions: map[string]*Session{}, known: map[string]string{}, hcc: f.hcc, now: f.clock.now}
	f.p.workDir = t.TempDir()
	f.p.stop, f.p.done, f.p.closed = make(chan struct{}), make(chan struct{}), make(chan struct{})
	f.p.runCtx, f.p.cancelRun = context.WithCancel(context.Background())
	t.Cleanup(f.p.cancelRun)
	f.p.logger = slog.New(slog.NewTextHandler(f.logs, nil))
	f.p.consoleLogger = slog.New(slog.DiscardHandler)
	f.p.startCleanup()
	return f
}

func (f *retentionFixture) file(user, name string) string { return filepath.Join(f.root, user, name) }

func (f *retentionFixture) session(user string) *Session {
	f.p.mutex.RLock()
	defer f.p.mutex.RUnlock()
	return f.p.sessions[user]
}

func (f *retentionFixture) reports(t *testing.T) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(f.export, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	return out
}

func TestSession_aFileWaitingForAWorkerHoldsTheSession(t *testing.T) {
	f := newRetention(t, Config{})
	var pending atomic.Int32
	pending.Store(2)
	var asked atomic.Value
	f.hcc.PendingFilesFunc = func(path string) int {
		asked.Store(path)
		return int(pending.Load())
	}
	a := f.file("tom", "a.txt")
	f.p.OnStartScanFile(a, "h1")
	f.p.OnFileScanned(a, "h1", datamodel.Result{})
	f.p.OnReport(&datamodel.Report{Filename: a, SHA256: "h1"})
	s := f.session("tom")
	activity := s.LastActivity

	f.clock.advance(10 * time.Minute)
	if f.p.readyForClosure(s) {
		t.Fatal("the session closed with files of its folder waiting")
	}
	if got := asked.Load(); got != filepath.Join(f.root, "tom") {
		t.Errorf("PendingFiles asked for %v, want the folder of the session", got)
	}
	if !s.LastActivity.Equal(activity) {
		t.Error("a file waiting must not refresh LastActivity")
	}
	pending.Store(0)
	if !f.p.readyForClosure(s) {
		t.Error("the session must close once nothing waits and the delay has passed")
	}
}

func TestSession_pendingFilesDoNotHoldASessionBeyondTheInflightTimeout(t *testing.T) {
	f := newRetention(t, Config{MaxDuration: 24 * time.Hour, MaxSpoolSize: "1GiB", InflightTimeout: time.Hour})
	f.hcc.PendingFilesFunc = func(string) int { return 3 }
	a := f.file("tom", "a.txt")
	f.p.OnStartScanFile(a, "h1")
	f.p.OnFileScanned(a, "h1", datamodel.Result{})
	s := f.session("tom")

	f.clock.advance(59 * time.Minute)
	if f.p.readyForClosure(s) {
		t.Fatal("closed before the inflight timeout with files waiting")
	}
	f.clock.advance(2 * time.Minute)
	if !f.p.readyForClosure(s) {
		t.Fatal("a session must be closed once idle for the inflight timeout")
	}
	if logs := f.logs.String(); !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "pending=3") {
		t.Errorf("logs = %s, want a Warn with the number of pending files", logs)
	}
}

func TestSession_aFileThatNeverEndsIsDroppedAfterTheInflightTimeout(t *testing.T) {
	f := newRetention(t, Config{MaxDuration: 24 * time.Hour, MaxSpoolSize: "1GiB", InflightTimeout: time.Hour})
	f.p.OnStartScanFile(f.file("tom", "a.txt"), "h1")
	s := f.session("tom")
	f.clock.advance(2 * time.Hour)
	if !f.p.readyForClosure(s) || len(s.InFlight) != 0 {
		t.Errorf("ready, in flight = %d: the stuck file must be dropped with a Warn", len(s.InFlight))
	}
	if !strings.Contains(f.logs.String(), "never ended") {
		t.Error("no Warn about the dropped file")
	}
}

func TestSession_closeNeverAsksForPendingFiles(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.PendingFilesFunc = func(string) int {
		t.Error("PendingFiles must not be called at stop")
		return 1
	}
	a := f.file("tom", "a.txt")
	f.p.OnStartScanFile(a, "h1")
	f.p.OnReport(&datamodel.Report{Filename: a, SHA256: "h1"})
	f.p.started = true
	close(f.p.done)
	if err := f.p.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := f.reports(t); len(got) != 1 {
		t.Errorf("reports = %v, want one report written at stop", got)
	}
	if !strings.Contains(f.logs.String(), "reports_written=1") {
		t.Errorf("logs = %s, want the summary", f.logs.String())
	}
}

func TestSession_aFileThatEndedInErrorAppearsOnceAndItsRetriesAreNoActivity(t *testing.T) {
	f := newRetention(t, Config{})
	a := f.file("tom", "big.zip")
	f.p.OnStartScanFile(a, "h1")
	f.p.OnFileScanned(a, "h1", datamodel.Result{Error: errors.New("extractor unavailable")})
	s := f.session("tom")
	activity := s.LastActivity
	for range 5 {
		f.clock.advance(time.Second)
		f.p.OnStartScanFile(a, "h1")
		f.p.OnFileScanned(a, "h1", datamodel.Result{Error: errors.New("extractor unavailable")})
	}
	if len(sessionReports(t, s)) != 1 || sessionReports(t, s)[0].Error == "" {
		t.Fatalf("reports = %+v, want one entry in error", sessionReports(t, s))
	}
	if !s.LastActivity.Equal(activity) {
		t.Error("retries of a failed file must not refresh LastActivity")
	}
	f.clock.advance(2 * time.Minute)
	if !f.p.readyForClosure(s) {
		t.Error("the session must close after the delay: the retries did not keep it open")
	}
}

func TestSession_retriesOfAFailedFileOpenNoSessionAfterTheClose(t *testing.T) {
	f := newRetention(t, Config{})
	a := f.file("tom", "big.zip")
	f.p.OnStartScanFile(a, "h1")
	f.p.OnFileScanned(a, "h1", datamodel.Result{Error: errors.New("extractor unavailable")})
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions(f.p.baseCtx())
	if f.session("tom") != nil || len(f.reports(t)) != 1 {
		t.Fatalf("session = %v, reports = %v, want the session closed with its report", f.session("tom"), f.reports(t))
	}
	for range 5 {
		f.p.OnStartScanFile(a, "h1")
		f.p.OnFileScanned(a, "h1", datamodel.Result{Error: errors.New("extractor unavailable")})
		f.p.OnReport(&datamodel.Report{Filename: a, SHA256: "h1", Error: "extractor unavailable"})
	}
	if f.session("tom") != nil {
		t.Fatal("a retry of a file already reported as failed reopened a session")
	}
	f.p.OnReport(&datamodel.Report{Filename: a, SHA256: "h1"})
	if f.session("tom") == nil {
		t.Error("a report is always attached: the session must be reopened for it")
	}
}

// The text the scanner puts in the report of a file whose move, quarantine or
// removal failed makes the file a failed one for the session: reported once, and
// a repeat of the failure opens no session once the first one is closed.
func TestSession_aFileWhoseActionFailedIsReportedOnceAndItsRepeatsOpenNoSession(t *testing.T) {
	const moveFailed = "the file could not be moved to the destination"
	f := newRetention(t, Config{})
	a := f.file("tom", "locked.bin")
	f.p.OnStartScanFile(a, "h1")
	f.p.OnFileScanned(a, "h1", datamodel.Result{})
	f.p.OnReport(&datamodel.Report{Filename: a, SHA256: "h1", Error: moveFailed})
	s := f.session("tom")
	if len(sessionReports(t, s)) != 1 || sessionReports(t, s)[0].Error != moveFailed {
		t.Fatalf("reports = %+v, want one entry in error", sessionReports(t, s))
	}
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions(f.p.baseCtx())
	if f.session("tom") != nil || len(f.reports(t)) != 1 {
		t.Fatalf("session = %v, reports = %v, want the session closed with its report", f.session("tom"), f.reports(t))
	}
	for range 3 {
		f.p.OnStartScanFile(a, "h1")
		f.p.OnFileScanned(a, "h1", datamodel.Result{})
		f.p.OnReport(&datamodel.Report{Filename: a, SHA256: "h1", Error: moveFailed})
	}
	if f.session("tom") != nil {
		t.Error("a repeat of a failed move reopened a session")
	}
	f.p.OnReport(&datamodel.Report{Filename: a, SHA256: "h1", MovedTo: "/out/locked.bin"})
	if f.session("tom") == nil {
		t.Error("the report of the move that finally worked must reach a session")
	}
}

// A file in error that is still in INPUT is retried, and its repeats open no
// session. A file whose disposition was done (quarantined, deleted or moved) has
// left INPUT: the same bytes dropped again are a new file, and get their session
// from the start, whatever error its first report carried (an analysis error that
// a filter quarantined, for instance).
func TestSession_aFileThatLeftInputGetsASessionWhenItsBytesAreDroppedAgain(t *testing.T) {
	const analysisFailed = "the file could not be analyzed"
	tests := []struct {
		name        string
		report      datamodel.Report
		wantSession bool
	}{
		{"quarantined after an analysis error", datamodel.Report{Error: analysisFailed, Action: datamodel.Quarantined, Malicious: true}, true},
		{"deleted after an error", datamodel.Report{Error: analysisFailed, Deleted: true}, true},
		{"moved after an error", datamodel.Report{Error: analysisFailed, MovedTo: "/out/f.bin"}, true},
		{"a quarantine that failed: still in INPUT, retried", datamodel.Report{Error: "the file could not be quarantined", Malicious: true}, false},
		{"a move that failed: still in INPUT, retried", datamodel.Report{Error: "the file could not be moved to the destination"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRetention(t, Config{})
			a := f.file("tom", "f.bin")
			rep := tt.report
			rep.Filename, rep.SHA256 = a, "h1"
			f.p.OnStartScanFile(a, "h1")
			f.p.OnFileScanned(a, "h1", datamodel.Result{})
			f.p.OnReport(&rep)
			f.clock.advance(2 * time.Minute)
			f.p.checkAndCloseSessions(f.p.baseCtx())
			if f.session("tom") != nil || len(f.reports(t)) != 1 {
				t.Fatalf("session = %v, reports = %v, want the first session closed with its report", f.session("tom"), f.reports(t))
			}
			f.p.OnStartScanFile(a, "h1")
			if got := f.session("tom") != nil; got != tt.wantSession {
				t.Fatalf("a session after the bytes were dropped again at start = %v, want %v", got, tt.wantSession)
			}
			again := rep
			f.p.OnFileScanned(a, "h1", datamodel.Result{})
			f.p.OnReport(&again)
			s := f.session("tom")
			if tt.wantSession {
				if s == nil || len(sessionReports(t, s)) != 1 {
					t.Fatalf("session = %+v, want the second report in a session of its own", s)
				}
				return
			}
			if s != nil {
				t.Errorf("the repeat of a failure of a file still in INPUT opened a session: %+v", s)
			}
		})
	}
}

func TestSession_aLateReportReopensASessionAndGetsItsOwnReport(t *testing.T) {
	f := newRetention(t, Config{})
	a := f.file("tom", "a.txt")
	f.p.OnStartScanFile(a, "h1")
	f.p.OnFileScanned(a, "h1", datamodel.Result{})
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions(f.p.baseCtx())
	f.p.OnReport(&datamodel.Report{Filename: a, SHA256: "h1"})
	s := f.session("tom")
	if s == nil || len(sessionReports(t, s)) != 1 {
		t.Fatalf("session = %+v, want one reopened with the report", s)
	}
	f.clock.advance(2 * time.Minute)
	f.clock.advance(time.Second)
	f.p.checkAndCloseSessions(f.p.baseCtx())
	f.p.checkAndCloseSessions(f.p.baseCtx())
	if f.session("tom") != nil {
		t.Error("the reopened session must close too")
	}
}

func failingThenWorking(failures int32, calls *atomic.Int32) plugins.GenerateReport {
	return func(ctx context.Context, _ datamodel.ScanContext, reports iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
		if calls.Add(1) <= failures {
			return plugins.GeneratedReport{}, errors.New("chrome crashed")
		}
		var b bytes.Buffer
		if err := datamodel.WriteReportsJSON(ctx, &b, reports); err != nil {
			return plugins.GeneratedReport{}, err
		}
		return plugins.GeneratedReport{Content: io.NopCloser(&b), Extension: ".pdf"}, nil
	}
}

func closeOne(t *testing.T, f *retentionFixture) {
	t.Helper()
	a := f.file("tom", "a.txt")
	f.p.OnStartScanFile(a, "h1")
	f.p.OnFileScanned(a, "h1", datamodel.Result{})
	f.p.OnReport(&datamodel.Report{Filename: a, SHA256: "h1"})
	f.clock.advance(2 * time.Minute)
}

func TestSession_aFailingGeneratorIsRetriedThenTheJSONFallbackIsWritten(t *testing.T) {
	f := newRetention(t, Config{ReportRetries: 2})
	var calls atomic.Int32
	f.hcc.GenerateReportFunc = failingThenWorking(100, &calls)
	closeOne(t, f)
	f.p.checkAndCloseSessions(f.p.baseCtx()) // attempt 1, session moves to closing
	f.p.checkAndCloseSessions(f.p.baseCtx()) // attempt 2
	if len(f.reports(t)) != 0 || len(f.errorsRaised) != 0 {
		t.Fatalf("reports = %v, events = %v: the fallback must wait for the retries", f.reports(t), f.errorsRaised)
	}
	f.p.checkAndCloseSessions(f.p.baseCtx()) // attempt 3 > retries: fallback
	reports := f.reports(t)
	if len(reports) != 1 || !strings.HasSuffix(reports[0], ".json") || !strings.HasPrefix(filepath.Base(reports[0]), datamodel.SessionReportPrefix) {
		t.Fatalf("reports = %v, want one JSON report under the reserved prefix", reports)
	}
	if len(f.errorsRaised) != 1 || f.errorsRaised[0] != fallbackEvent {
		t.Errorf("events = %v, want the fallback console error once", f.errorsRaised)
	}
	if len(f.p.closing) != 0 {
		t.Error("the session must leave the closing list")
	}
}

func TestSession_theFallbackEventIsResolvedByTheNextGoodReport(t *testing.T) {
	f := newRetention(t, Config{ReportRetries: 0})
	var calls atomic.Int32
	f.hcc.GenerateReportFunc = failingThenWorking(1, &calls)
	closeOne(t, f)
	f.p.checkAndCloseSessions(f.p.baseCtx())
	if len(f.errorsRaised) != 1 {
		t.Fatalf("events = %v", f.errorsRaised)
	}
	b := f.file("jerry", "b.txt")
	f.p.OnStartScanFile(b, "h2")
	f.p.OnFileScanned(b, "h2", datamodel.Result{})
	f.p.OnReport(&datamodel.Report{Filename: b, SHA256: "h2"})
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions(f.p.baseCtx())
	if len(f.resolved) != 1 || f.resolved[0] != fallbackEvent {
		t.Errorf("resolutions = %v, want the event resolved by the first good report", f.resolved)
	}
}

func TestSession_aSlowSessionDoesNotBlockTheNextOnesBeyondItsOwnTimeout(t *testing.T) {
	f := newRetention(t, Config{ReportTimeout: 50 * time.Millisecond, ReportRetries: 0})
	f.hcc.GenerateReportFunc = func(ctx context.Context, _ datamodel.ScanContext, _ iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
		<-ctx.Done()
		return plugins.GeneratedReport{}, ctx.Err()
	}
	closeOne(t, f)
	start := time.Now()
	f.p.checkAndCloseSessions(f.p.baseCtx())
	if time.Since(start) > 5*time.Second {
		t.Error("an attempt must be bounded by report_timeout")
	}
	if len(f.reports(t)) != 1 {
		t.Errorf("reports = %v, want the fallback report", f.reports(t))
	}
}

func TestSession_tooManyClosingSessionsGetTheirFallbackAtOnce(t *testing.T) {
	f := newRetention(t, Config{ReportRetries: 1000})
	var calls atomic.Int32
	f.hcc.GenerateReportFunc = failingThenWorking(1<<30, &calls)
	for i := range maxClosing + 6 {
		user := fmt.Sprintf("u%03d", i)
		a := f.file(user, "a.txt")
		f.p.OnStartScanFile(a, "h")
		f.p.OnFileScanned(a, "h", datamodel.Result{})
		f.p.OnReport(&datamodel.Report{Filename: a, SHA256: "h"})
	}
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions(f.p.baseCtx())
	if n := len(f.p.closing); n > maxClosing {
		t.Errorf("closing = %d, want at most %d", n, maxClosing)
	}
	if got := len(f.reports(t)); got < 6 {
		t.Errorf("fallback reports = %d, want the overflow written at once", got)
	}
}

func TestSession_closeWithAnExpiredContextStillWritesAFallbackReport(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = func(ctx context.Context, _ datamodel.ScanContext, _ iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
		<-ctx.Done()
		return plugins.GeneratedReport{}, ctx.Err()
	}
	for _, u := range []string{"tom", "jerry"} {
		a := f.file(u, "a.txt")
		f.p.OnStartScanFile(a, "h")
		f.p.OnReport(&datamodel.Report{Filename: a, SHA256: "h"})
	}
	f.p.started = true
	close(f.p.done)
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	if err := f.p.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.reports(t); len(got) != 2 {
		t.Fatalf("reports = %v, want a JSON report per open session", got)
	}
	if !strings.Contains(f.logs.String(), "sessions=2") || !strings.Contains(f.logs.String(), "reports_written=2") || !strings.Contains(f.logs.String(), "failures=0") {
		t.Errorf("logs = %s, want the exact summary", f.logs.String())
	}
}

func TestSession_aWrittenReportIsAnnouncedWithItsSHA256(t *testing.T) {
	f := newRetention(t, Config{})
	closeOne(t, f)
	f.p.checkAndCloseSessions(f.p.baseCtx())
	reports := f.reports(t)
	if len(reports) != 1 || len(f.written) != 1 {
		t.Fatalf("reports = %v, announced = %v", reports, f.written)
	}
	b, err := os.ReadFile(filepath.Clean(reports[0]))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if want := reports[0] + " " + hex.EncodeToString(sum[:]); f.written[0] != want {
		t.Errorf("announced %q, want %q", f.written[0], want)
	}
}

func TestSaveReport_neverTouchesAnExistingFinalName(t *testing.T) {
	boom := errors.New("ENOSPC")
	tests := map[string]func(w io.Writer) error{
		"generator fails": func(io.Writer) error { return boom },
		"fails mid stream": func(w io.Writer) error {
			_, _ = io.WriteString(w, "partial")
			return boom
		},
	}
	for name, produce := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRetention(t, Config{})
			dir := filepath.Join(f.export, "team")
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			final := filepath.Join(dir, "report-session-team-1.json")
			if err := os.WriteFile(final, []byte("the existing report"), 0o600); err != nil {
				t.Fatal(err)
			}
			if res := f.p.saveReport(produce, final); len(res) != 1 || !errors.Is(res[0].err, boom) {
				t.Fatalf("results = %+v, want %v", res, boom)
			}
			if b, _ := os.ReadFile(filepath.Clean(final)); string(b) != "the existing report" {
				t.Errorf("existing report = %q, want it intact", b)
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 1 {
				t.Errorf("files = %v, want no temporary file left", entries)
			}
		})
	}
}

func TestSaveReport_aNameAlreadyTakenIsAnAnomalyWrittenUnderAConflictName(t *testing.T) {
	f := newRetention(t, Config{})
	dir := filepath.Join(f.export, "team")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(dir, "report-session-team-1.json")
	if err := os.WriteFile(final, []byte("created outside the connector"), 0o600); err != nil {
		t.Fatal(err)
	}
	written := f.p.saveReport(writeString("the report"), final)
	if len(written) != 1 || written[0].err != nil {
		t.Fatalf("saveReport() = %+v", written)
	}
	if written[0].path == final || !strings.Contains(written[0].path, ".conflict-") {
		t.Errorf("written at %q, want a conflict name", written[0].path)
	}
	if b, _ := os.ReadFile(filepath.Clean(final)); string(b) != "created outside the connector" {
		t.Errorf("the file at the final name = %q, want it intact", b)
	}
	if !strings.Contains(f.logs.String(), "level=ERROR") {
		t.Error("an anomaly must be logged as an Error")
	}
}

func TestCreateReportTemp_hasTheModeOfAReportAndTheNameOfATemporaryFile(t *testing.T) {
	f, err := createReportTemp(filepath.Join(t.TempDir(), "new", "folder"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if !quarantine.IsTempFile(f.Name()) {
		t.Errorf("%s must carry the temporary prefix: it is never scanned nor moved", f.Name())
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != reportMode {
		t.Errorf("mode = %v, want %o: the mode of the report", info.Mode().Perm(), reportMode)
	}
}

func TestSession_aFileWaitingThatIsRefusedLetsTheSessionCloseAfterTheDelay(t *testing.T) {
	f := newRetention(t, Config{})
	var pending atomic.Int32
	pending.Store(1)
	f.hcc.PendingFilesFunc = func(string) int { return int(pending.Load()) }
	a := f.file("tom", "a.txt")
	f.p.OnStartScanFile(a, "h")
	f.p.OnReport(&datamodel.Report{Filename: a, SHA256: "h"})
	f.p.OnFileScanned(a, "h", datamodel.Result{})
	s := f.session("tom")
	f.clock.advance(2 * time.Minute)
	if f.p.readyForClosure(s) {
		t.Fatal("closed while a file waits")
	}
	pending.Store(0) // the waiting file was deleted, refused or evicted
	if !f.p.readyForClosure(s) {
		t.Error("the session must close once the waiting file is gone")
	}
}
