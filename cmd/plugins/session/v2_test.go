package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

func (f *retentionFixture) events(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, k := range f.errorsRaised {
		if k == key {
			n++
		}
	}
	return n
}

// ready makes a session of user with one scanned file and its report, idle for
// longer than the delay.
func (f *retentionFixture) ready(user string) {
	a := f.file(user, "a.txt")
	f.p.OnStartScanFile(a, "h")
	f.p.OnFileScanned(a, "h", datamodel.Result{})
	f.p.OnReport(&datamodel.Report{Filename: a, SHA256: "h"})
}

func workingGenerator(ctx context.Context, _ datamodel.ScanContext, reports iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
	var b bytes.Buffer
	if err := datamodel.WriteReportsJSON(ctx, &b, reports); err != nil {
		return plugins.GeneratedReport{}, err
	}
	return plugins.GeneratedReport{Content: io.NopCloser(&b), Extension: ".pdf"}, nil
}

func blockedGenerator(ctx context.Context, _ datamodel.ScanContext, _ iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
	<-ctx.Done()
	return plugins.GeneratedReport{}, ctx.Err()
}

func TestReportName_staysBelowTheLimitOfAFileNameAndKeepsLongNamesApart(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	short := reportName("tom", start)
	if short != datamodel.SessionReportPrefix+"tom-1700000000" {
		t.Errorf("reportName() = %q", short)
	}
	a := reportName(strings.Repeat("d", 250), start)
	b := reportName(strings.Repeat("d", 249)+"e", start)
	if len(a)+len(".json") > 255 || len(b)+len(".json") > 255 {
		t.Errorf("names of %d and %d bytes pass the limit of a file name", len(a), len(b))
	}
	if a == b {
		t.Error("two sessions whose names share their first 200 characters must not share their report name")
	}
	multibyte := reportName(strings.Repeat("é", 200), start)
	if !strings.HasSuffix(multibyte, "-1700000000") || len(multibyte) > maxReportBase {
		t.Errorf("reportName(multibyte) = %q (%d bytes)", multibyte, len(multibyte))
	}
	for _, r := range multibyte {
		if r == '�' {
			t.Errorf("a character was cut in %q", multibyte)
		}
	}
}

func TestSession_aVeryLongFolderNameStillGetsItsReport(t *testing.T) {
	f := newRetention(t, Config{ReportRetries: 0})
	f.hcc.GenerateReportFunc = workingGenerator
	f.ready(strings.Repeat("d", 250))
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions()
	if got := f.reports(t); len(got) != 1 || len(filepath.Base(got[0])) > 255 {
		t.Fatalf("reports = %v, want one with a name below 255 bytes", got)
	}
	if len(f.p.closing) != 0 {
		t.Error("the session must have left the closing list")
	}
}

// A report that cannot be written by any means is said, once, and given up: the
// session is not regenerated at every tick for ever.
func TestSession_aReportThatCannotBeWrittenIsLostLoudlyAndNotRetriedForEver(t *testing.T) {
	f := newRetention(t, Config{ReportRetries: 1})
	var calls atomic.Int32
	f.hcc.GenerateReportFunc = func(ctx context.Context, sc datamodel.ScanContext, r iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
		calls.Add(1)
		return workingGenerator(ctx, sc, r)
	}
	if err := os.WriteFile(filepath.Join(f.export, "tom"), []byte("a file where the folder of the reports must be"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.ready("tom")
	f.clock.advance(2 * time.Minute)
	for range 6 {
		f.p.checkAndCloseSessions()
	}
	if len(f.p.closing) != 0 {
		t.Errorf("closing = %d, want the lost session given up", len(f.p.closing))
	}
	if got := f.events(lostEvent); got != 1 {
		t.Errorf("lost events = %d, want exactly one, naming the session", got)
	}
	if n := calls.Load(); n > 2 {
		t.Errorf("the generator ran %d times: a lost report is not retried", n)
	}
}

// Close while the monitor is attempting a report: the attempt is cut, the
// session goes back to the closing list, and Close writes its report.
func TestSession_closeDuringAnAttemptOfTheMonitorLosesNoReport(t *testing.T) {
	f := newRetention(t, Config{ReportRetries: 5})
	f.hcc.GenerateReportFunc = blockedGenerator
	f.p.tickEvery = 5 * time.Millisecond
	for _, u := range []string{"tom", "jerry"} {
		f.ready(u)
	}
	f.clock.advance(2 * time.Minute)
	go f.p.sessionMonitor()
	waitFor(t, 5*time.Second, func() bool {
		f.p.closeMu.Lock()
		defer f.p.closeMu.Unlock()
		return len(f.p.closing) == 0 && f.sessionsLeft() == 0
	})
	f.p.started = true
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	if err := f.p.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.reports(t); len(got) != 2 {
		t.Errorf("reports = %v, want one per session: none was lost", got)
	}
	if f.events(lostEvent) != 0 {
		t.Error("a report was lost")
	}
}

func (f *retentionFixture) sessionsLeft() int {
	f.p.mutex.RLock()
	defer f.p.mutex.RUnlock()
	return len(f.p.sessions)
}

func TestSession_closeKeepsAReserveOfTheDeadlineForTheFallbacks(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = blockedGenerator
	for _, u := range []string{"tom", "jerry", "alice"} {
		f.ready(u)
	}
	f.p.started = true
	close(f.p.done)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	start := time.Now()
	if err := f.p.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) >= 4*time.Second {
		t.Errorf("Close took %v: the fallbacks must be written before the deadline", time.Since(start))
	}
	if got := f.reports(t); len(got) != 3 {
		t.Errorf("reports = %v, want a JSON fallback per session", got)
	}
}

func TestSession_closeWithAnExpiredDeadlineWritesTheFallbacksInASecond(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = blockedGenerator
	for _, u := range []string{"tom", "jerry", "alice"} {
		f.ready(u)
	}
	f.p.started = true
	close(f.p.done)
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Minute))
	defer cancel()
	start := time.Now()
	if err := f.p.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > expiredBound+500*time.Millisecond {
		t.Errorf("Close took %v with an expired deadline", time.Since(start))
	}
	if got := f.reports(t); len(got) != 3 {
		t.Errorf("reports = %v, want a JSON fallback per session", got)
	}
}

// report_timeout bounds the copy of the content too: a generator whose content
// never ends does not stop the monitor.
func TestSession_report_timeoutBoundsTheCopyOfABlockedContent(t *testing.T) {
	f := newRetention(t, Config{ReportTimeout: 150 * time.Millisecond, ReportRetries: 0})
	f.hcc.GenerateReportFunc = func(context.Context, datamodel.ScanContext, iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
		pr, _ := io.Pipe()
		return plugins.GeneratedReport{Content: pr, Extension: ".pdf"}, nil
	}
	f.ready("tom")
	f.clock.advance(2 * time.Minute)
	done := make(chan struct{})
	go func() {
		f.p.checkAndCloseSessions()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a blocked content stopped the monitor")
	}
	if got := f.reports(t); len(got) != 1 || !strings.HasSuffix(got[0], ".json") {
		t.Errorf("reports = %v, want the JSON fallback", got)
	}
}

func TestSession_aReportIsReadableByTheOthers(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = workingGenerator
	f.ready("tom")
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions()
	reports := f.reports(t)
	if len(reports) != 1 {
		t.Fatalf("reports = %v", reports)
	}
	info, err := os.Stat(reports[0])
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != reportMode {
		t.Errorf("mode = %o, want %o", info.Mode().Perm(), reportMode)
	}
}

// What comes after the report of a session was taken is for another session:
// nothing is added to a closed one.
func TestSession_aClosedSessionTakesNothingMoreAndTheCallbacksAskForAnother(t *testing.T) {
	f := newRetention(t, Config{})
	f.ready("tom")
	s := f.session("tom")
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions()
	if s.addReport(datamodel.Report{Filename: "x"}) || s.addFile("x", "h") || s.markFileCompleted("x") || s.addFileError("x", "h", "e") {
		t.Fatal("a closed session accepted something")
	}
	f.p.OnReport(&datamodel.Report{Filename: f.file("tom", "late.txt"), SHA256: "late"})
	n := f.session("tom")
	if n == nil || n == s || len(n.CompletedReports) != 1 {
		t.Fatalf("session = %+v, want a new one holding the late report", n)
	}
}

func TestSession_aFileThatFailsAfterItsSessionClosedAppearsInAnotherReport(t *testing.T) {
	f := newRetention(t, Config{})
	f.ready("tom")
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions()
	a := f.file("tom", "big.zip")
	f.p.OnFileScanned(a, "h9", datamodel.Result{Error: errors.New("extractor unavailable")})
	s := f.session("tom")
	if s == nil || len(s.CompletedReports) != 1 || s.CompletedReports[0].Filename != a {
		t.Fatalf("session = %+v, want one that holds the failed file", s)
	}
}

// One export that fails does not fail the other, is said with its own error,
// and the session keeps trying that one only.
func TestSession_aFailingExportIsSaidAndOnlyItIsRetried(t *testing.T) {
	f := newRetention(t, Config{ReportRetries: 3})
	second := t.TempDir()
	f.p.config.Exports = []string{f.export, second}
	var console syncBuffer
	f.p.consoleLogger = slog.New(slog.NewTextHandler(&console, nil))
	f.hcc.GenerateReportFunc = workingGenerator
	if err := os.WriteFile(filepath.Join(second, "tom"), []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.ready("tom")
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions()
	if got := filepath.Join(f.export, "tom"); len(filesIn(t, got)) != 1 {
		t.Fatalf("the first export holds %v, want one report", filesIn(t, got))
	}
	if !strings.Contains(console.String(), "level=ERROR") || !strings.Contains(console.String(), second) {
		t.Errorf("console = %s, want an Error naming the failing export", console.String())
	}
	if len(f.p.closing) != 1 {
		t.Fatalf("closing = %d, want the session kept for its missing export", len(f.p.closing))
	}
	if err := os.Remove(filepath.Join(second, "tom")); err != nil {
		t.Fatal(err)
	}
	f.p.checkAndCloseSessions()
	if len(filesIn(t, filepath.Join(second, "tom"))) != 1 || len(f.p.closing) != 0 {
		t.Errorf("second export = %v, closing = %d, want its report now", filesIn(t, filepath.Join(second, "tom")), len(f.p.closing))
	}
	if got := filesIn(t, filepath.Join(f.export, "tom")); len(got) != 1 {
		t.Errorf("the first export holds %v: it must not be written again under a conflict name", got)
	}
}

// A target whose file fails to write is recorded and the others still get the
// whole content.
func TestTargetWriter_aFailingTargetDoesNotFailTheOthers(t *testing.T) {
	dir := t.TempDir()
	bad, err := os.Create(filepath.Clean(filepath.Join(dir, "bad")))
	if err != nil {
		t.Fatal(err)
	}
	if err = bad.Close(); err != nil {
		t.Fatal(err)
	}
	good, err := os.Create(filepath.Clean(filepath.Join(dir, "good")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = good.Close() })
	badW, goodW := &targetWriter{f: bad}, &targetWriter{f: good}
	if _, err = io.Copy(io.MultiWriter(badW, goodW), strings.NewReader("the whole content")); err != nil {
		t.Fatalf("Copy() = %v: a failing target must not stop the copy", err)
	}
	if badW.err == nil || goodW.err != nil {
		t.Errorf("errors: bad %v, good %v", badW.err, goodW.err)
	}
	if b, _ := os.ReadFile(filepath.Clean(filepath.Join(dir, "good"))); string(b) != "the whole content" {
		t.Errorf("good = %q", b)
	}
}

// A healthy burst of sessions is not a backlog: every report is written through
// the generator, and the fallback event is not raised.
func TestSession_aHealthyBurstBeyondTheBoundIsNotAFallback(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = workingGenerator
	for i := range maxClosing + 6 {
		f.ready(fmt.Sprintf("u%03d", i))
	}
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions()
	got := f.reports(t)
	if len(got) != maxClosing+6 {
		t.Fatalf("reports = %d, want %d", len(got), maxClosing+6)
	}
	for _, g := range got {
		if strings.HasSuffix(g, ".json") {
			t.Fatalf("%s: a healthy session was written as JSON", g)
		}
	}
	if f.events(fallbackEvent) != 0 || f.events(backlogEvent) != 0 {
		t.Errorf("events: fallback %d, backlog %d, want none", f.events(fallbackEvent), f.events(backlogEvent))
	}
}

// Past the bound, after an attempt, the oldest are written as JSON: the event
// says backlog and does not put the generator on trial.
func TestSession_aBacklogIsRaisedAsSuchAndNotAsAFallback(t *testing.T) {
	f := newRetention(t, Config{ReportRetries: 1000})
	f.hcc.GenerateReportFunc = func(context.Context, datamodel.ScanContext, iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
		return plugins.GeneratedReport{}, errors.New("chrome crashed")
	}
	for i := range maxClosing + 6 {
		f.ready(fmt.Sprintf("u%03d", i))
	}
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions()
	if f.events(backlogEvent) != 1 || f.events(fallbackEvent) != 0 {
		t.Errorf("events: backlog %d, fallback %d, want 1 and 0", f.events(backlogEvent), f.events(fallbackEvent))
	}
	if got := len(f.reports(t)); got != 6 {
		t.Errorf("reports = %d, want the 6 oldest as JSON", got)
	}
	if len(f.p.closing) != maxClosing {
		t.Errorf("closing = %d, want %d", len(f.p.closing), maxClosing)
	}
}

func TestCheckConfig_refusesWhatWouldBeSilentlyReplaced(t *testing.T) {
	good := Config{Depth: 1, Delay: time.Minute, RootFolder: t.TempDir(), ReportTimeout: time.Minute, InflightTimeout: time.Hour, ReportRetries: 3}
	tests := []struct {
		name   string
		mutate func(c *Config)
		ok     bool
	}{
		{"valid", func(*Config) {}, true},
		{"report_retries 0 is allowed", func(c *Config) { c.ReportRetries = 0 }, true},
		{"report_timeout 0", func(c *Config) { c.ReportTimeout = 0 }, false},
		{"inflight_timeout 0", func(c *Config) { c.InflightTimeout = 0 }, false},
		{"report_retries -1", func(c *Config) { c.ReportRetries = -1 }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := good
			tt.mutate(&c)
			if err := checkConfig(&c, mock.NewMockHCContext(), true); (err == nil) != tt.ok {
				t.Errorf("checkConfig() error = %v, want ok = %v", err, tt.ok)
			}
		})
	}
	var logs syncBuffer
	hcc := mock.NewMockHCContext()
	hcc.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	c := good
	c.InflightTimeout = time.Second
	if err := checkConfig(&c, hcc, true); err != nil || !strings.Contains(logs.String(), "level=WARN") {
		t.Errorf("error = %v, logs = %s, want a Warn: inflight_timeout < delay disarms PendingFiles", err, logs.String())
	}
}

// A file named like a session report, deposited by a user, is a file like the
// others: it is attached to its session, shows in error when it is refused, and
// the real report of the session is written next to nothing of it.
func TestSession_aDepositNamedLikeAReportIsAFileLikeTheOthers(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = workingGenerator
	fake := f.file("tom", "report-session-tom-1700000000.pdf")
	f.p.OnStartScanFile(fake, "hf")
	f.p.OnFileScanned(fake, "hf", datamodel.Result{})
	f.p.OnReport(&datamodel.Report{Filename: fake, SHA256: "hf", Error: "file name reserved for session reports"})
	f.ready("tom")
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions()
	reports := f.reports(t)
	if len(reports) != 1 {
		t.Fatalf("reports = %v, want the one real report", reports)
	}
	b, err := os.ReadFile(filepath.Clean(reports[0]))
	if err != nil {
		t.Fatal(err)
	}
	var entries []datamodel.Report
	if err = json.Unmarshal(b, &entries); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Filename == fake && e.Error != "" {
			found = true
		}
	}
	if !found {
		t.Errorf("the deposit is not in the report as an error: %s", b)
	}
	if !strings.Contains(filepath.Base(reports[0]), ".pdf") || strings.Contains(reports[0], ".conflict-") {
		t.Errorf("report = %s, want the plain name", reports[0])
	}
}
