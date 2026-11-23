//go:build linux

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
	"strconv"
	"strings"
	"sync"
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
	f.p.checkAndCloseSessions(f.p.baseCtx())
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
		f.p.checkAndCloseSessions(f.p.baseCtx())
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
	go f.p.sessionMonitor(f.p.runCtx, f.p.stop, f.p.done, f.p.runGeneration())
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

func TestSession_closeWithAnExpiredDeadlineWritesTheFallbacksWithinTheGrace(t *testing.T) {
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
	if time.Since(start) > plugins.CloseGrace {
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
		f.p.checkAndCloseSessions(f.p.baseCtx())
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
	f.p.checkAndCloseSessions(f.p.baseCtx())
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
	f.p.checkAndCloseSessions(f.p.baseCtx())
	if okAdd(s, datamodel.Report{Filename: "x"}) || s.addFile("x", "h") || s.markFileCompleted("x") || addedError(s, "x", "h", "e") {
		t.Fatal("a closed session accepted something")
	}
	f.p.OnReport(&datamodel.Report{Filename: f.file("tom", "late.txt"), SHA256: "late"})
	n := f.session("tom")
	if n == nil || n == s || len(sessionReports(t, n)) != 1 {
		t.Fatalf("session = %+v, want a new one holding the late report", n)
	}
}

func TestSession_aFileThatFailsAfterItsSessionClosedAppearsInAnotherReport(t *testing.T) {
	f := newRetention(t, Config{})
	f.ready("tom")
	f.clock.advance(2 * time.Minute)
	f.p.checkAndCloseSessions(f.p.baseCtx())
	a := f.file("tom", "big.zip")
	f.p.OnFileScanned(a, "h9", datamodel.Result{Error: errors.New("extractor unavailable")})
	s := f.session("tom")
	if s == nil || len(sessionReports(t, s)) != 1 || sessionReports(t, s)[0].Filename != a {
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
	f.p.checkAndCloseSessions(f.p.baseCtx())
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
	f.p.checkAndCloseSessions(f.p.baseCtx())
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
	f.p.checkAndCloseSessions(f.p.baseCtx())
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
	f.p.checkAndCloseSessions(f.p.baseCtx())
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
	good := Config{Depth: 1, Delay: time.Minute, RootFolder: t.TempDir(), ReportTimeout: time.Minute, MaxDuration: 24 * time.Hour, MaxSpoolSize: "1GiB", InflightTimeout: time.Hour, ReportRetries: 3}
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
			if err := checkConfig(&c, newMockHCC(t), true); (err == nil) != tt.ok {
				t.Errorf("checkConfig() error = %v, want ok = %v", err, tt.ok)
			}
		})
	}
	var logs syncBuffer
	hcc := newMockHCC(t)
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
	f.p.checkAndCloseSessions(f.p.baseCtx())
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

func TestFallbackDeadline(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	span := plugins.CloseGrace - closeMargin
	tests := []struct {
		name     string
		deadline time.Time
		want     time.Time
	}{
		{"not expired", now.Add(5 * time.Second), now.Add(5*time.Second + span)},
		{"just ahead", now.Add(10 * time.Millisecond), now.Add(10*time.Millisecond + span)},
		{"expired", now.Add(-time.Minute), now.Add(fallbackFloor)},
		{"at the boundary of the floor", now.Add(fallbackFloor - span), now.Add(fallbackFloor)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fallbackDeadline(tt.deadline, now); !got.Equal(tt.want) {
				t.Errorf("fallbackDeadline = %v, want %v", got.Sub(now), tt.want.Sub(now))
			}
		})
	}
}

func TestFallbackConstants(t *testing.T) {
	if fallbackFloor >= plugins.CloseGrace-closeMargin {
		t.Errorf("floor %v is not under the grace %v less the margin %v", fallbackFloor, plugins.CloseGrace, closeMargin)
	}
	if lostEventBound >= plugins.CloseGrace {
		t.Errorf("lostEventBound %v is not under the grace %v", lostEventBound, plugins.CloseGrace)
	}
}

// lostIn tells whether the logs, in the text format of slog, say the report of
// the session is lost.
func lostIn(logs, id string) bool { return lostCount(logs, id) > 0 }

func lostCount(logs, id string) int {
	return strings.Count(logs, `session \"`+id+`\" is lost`)
}

// takeHeld makes the sessions of the fixture the batch of a monitor at work.
func takeHeld(f *retentionFixture) *heldBatch {
	f.p.mutex.Lock()
	ready := make([]*closingSession, 0, len(f.p.sessions))
	for id, session := range f.p.sessions {
		ready = append(ready, newClosing(session))
		delete(f.p.sessions, id)
	}
	f.p.mutex.Unlock()
	return f.p.takeBatch(f.p.runGeneration(), ready)
}

func TestSession_closeWithASlowMonitorStillWritesTheFallbacks(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = blockedGenerator
	f.ready("tom")
	f.p.started = true
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	f.p.onMonitorWait = func() {
		time.Sleep(200 * time.Millisecond)
		close(f.p.done)
	}
	start := time.Now()
	if err := f.p.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 2*time.Second+plugins.CloseGrace {
		t.Errorf("Close took %v, more than the deadline and the grace", took)
	}
	if strings.Contains(f.logs.String(), "did not end in time") {
		t.Errorf("the monitor ended in time: %s", f.logs.String())
	}
	if got := f.reports(t); len(got) != 1 {
		t.Errorf("reports = %v, want a JSON fallback", got)
	}
}

func TestSession_closeWithAMonitorThatNeverReturnsLosesItsSessionsByName(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = blockedGenerator
	f.ready("tom")
	f.ready("jerry")
	held := takeHeld(f)
	f.ready("alice")
	f.p.started = true
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := f.p.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 300*time.Millisecond+plugins.CloseGrace {
		t.Errorf("Close took %v, more than the deadline and the grace", took)
	}
	logs := f.logs.String()
	for _, id := range []string{"tom", "jerry"} {
		if !lostIn(logs, id) {
			t.Errorf("%s is not named as lost: %s", id, logs)
		}
	}
	if !strings.Contains(logs, "did not end in time") || !strings.Contains(logs, "failures=2") || !strings.Contains(logs, "sessions=3") {
		t.Errorf("no warning or summary with the held sessions: %s", logs)
	}
	if got := f.reports(t); len(got) != 1 {
		t.Errorf("reports = %v, want the one session the monitor did not hold", got)
	}
	if n := f.events(lostEvent); n != 1 {
		t.Errorf("lost events = %d, want one for all", n)
	}
	if n := f.p.putBack(t.Context(), held, held.sessions); n != 0 {
		t.Errorf("a late monitor parked %d sessions", n)
	}
	if lostCount(f.logs.String(), "tom") != 1 {
		t.Errorf("tom reported twice: %s", f.logs.String())
	}
}

func TestSession_closeWaitsForAMonitorThatReturnsInTheTime(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = blockedGenerator
	f.ready("tom")
	held := takeHeld(f)
	f.p.started = true
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Minute))
	defer cancel()
	f.p.onMonitorWait = func() {
		f.p.putBack(t.Context(), held, held.sessions)
		close(f.p.done)
	}
	if err := f.p.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.reports(t); len(got) != 1 {
		t.Errorf("reports = %v, want the report of the session the monitor gave back", got)
	}
	if strings.Contains(f.logs.String(), "is lost") {
		t.Errorf("a session is lost: %s", f.logs.String())
	}
}

func TestSession_aPutBackRacingTheHandOverReportsEachSessionOnce(t *testing.T) {
	for range 20 {
		f := newRetention(t, Config{})
		f.hcc.GenerateReportFunc = workingGenerator
		f.ready("tom")
		held := takeHeld(f)
		var wg sync.WaitGroup
		wg.Go(func() { f.p.putBack(t.Context(), held, held.sessions) })
		f.p.closeAllSessions(t.Context(), t.Context())
		wg.Wait()
		written, lost := len(f.reports(t)), lostCount(f.logs.String(), "tom")
		if written+lost != 1 {
			t.Fatalf("tom written %d times and lost %d times, want exactly one: %s", written, lost, f.logs.String())
		}
	}
}

func TestSession_theSessionsNotAttemptedAreAllNamedAndNotifiedOnce(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = blockedGenerator
	f.hcc.NotifyErrorFunc = func(ctx context.Context, key string, _ error) {
		f.mu.Lock()
		f.errorsRaised = append(f.errorsRaised, key)
		f.mu.Unlock()
		<-ctx.Done()
	}
	ids := []string{"s1", "s2", "s3", "s4", "s5"}
	for _, id := range ids {
		f.ready(id)
	}
	over, cancel := context.WithCancel(t.Context())
	cancel()
	start := time.Now()
	f.p.closeAllSessions(t.Context(), over)
	if took := time.Since(start); took > plugins.CloseGrace {
		t.Errorf("closing took %v with a notification that never ends, over the grace", took)
	}
	for _, id := range ids {
		if !lostIn(f.logs.String(), id) {
			t.Errorf("%s is not named: %s", id, f.logs.String())
		}
	}
	if !strings.Contains(f.logs.String(), "sessions not attempted") || !strings.Contains(f.logs.String(), "sessions=5") {
		t.Errorf("no warning with the count: %s", f.logs.String())
	}
	if n := f.events(lostEvent); n != 1 {
		t.Errorf("lost events = %d, want 1", n)
	}
}

func TestSession_aStopThatEndsAfterTheFirstReportLosesTheOthers(t *testing.T) {
	f := newRetention(t, Config{})
	over, cancel := context.WithCancel(t.Context())
	var first atomic.Bool
	f.hcc.GenerateReportFunc = func(ctx context.Context, sc datamodel.ScanContext, reports iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
		if first.CompareAndSwap(false, true) {
			cancel()
		}
		return workingGenerator(ctx, sc, reports)
	}
	for _, id := range []string{"s1", "s2", "s3"} {
		f.ready(id)
	}
	f.p.closeAllSessions(t.Context(), over)
	if got := f.reports(t); len(got) != 1 {
		t.Errorf("reports = %v, want one", got)
	}
	if !strings.Contains(f.logs.String(), "sessions=2") || !strings.Contains(f.logs.String(), "reports_written=1") {
		t.Errorf("no warning with the 2 sessions not attempted: %s", f.logs.String())
	}
	lostNames := 0
	for _, id := range []string{"s1", "s2", "s3"} {
		if lostIn(f.logs.String(), id) {
			lostNames++
		}
	}
	if lostNames != 2 {
		t.Errorf("%d sessions named as lost, want 2: %s", lostNames, f.logs.String())
	}
	if n := f.events(lostEvent); n != 1 {
		t.Errorf("lost events = %d, want one for the 2 sessions", n)
	}
}

func TestSession_closeExpiredWithASlowMonitorWritesTheFallbackInTheGrace(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = blockedGenerator
	f.ready("tom")
	f.p.started = true
	deadline := time.Now().Add(100 * time.Millisecond)
	ctx, cancel := context.WithDeadline(t.Context(), deadline)
	defer cancel()
	f.p.onMonitorWait = func() {
		time.Sleep(150 * time.Millisecond)
		close(f.p.done)
	}
	if err := f.p.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if end := time.Now(); end.After(deadline.Add(plugins.CloseGrace)) {
		t.Errorf("Close ended %v past the deadline, over the grace", end.Sub(deadline))
	}
	if got := f.reports(t); len(got) != 1 {
		t.Errorf("reports = %v, want a JSON fallback", got)
	}
}

func TestSession_closeLosesOnlyWhatTheMonitorStillHolds(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = workingGenerator
	for _, id := range []string{"s1", "s2", "s3"} {
		f.ready(id)
	}
	held := takeHeld(f)
	first := held.sessions[0]
	if err := f.p.tryReport(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	f.p.release(held, first)
	f.p.started = true
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if err := f.p.Close(ctx); err != nil {
		t.Fatal(err)
	}
	logs := f.logs.String()
	if lostIn(logs, first.session.ID) {
		t.Errorf("%s was written but is named as lost: %s", first.session.ID, logs)
	}
	for _, cs := range held.sessions[1:] {
		if !lostIn(logs, cs.session.ID) {
			t.Errorf("%s is held and not named as lost: %s", cs.session.ID, logs)
		}
	}
	if got := f.reports(t); len(got) != 1 {
		t.Errorf("reports = %v, want the one written before the stop", got)
	}
	if !strings.Contains(logs, "failures=2") {
		t.Errorf("the summary does not count the 2 held sessions: %s", logs)
	}
}

func TestSession_aBatchTakenAfterTheStopIsLostCountedAndNotifiedOnce(t *testing.T) {
	f := newRetention(t, Config{})
	f.hcc.GenerateReportFunc = blockedGenerator
	f.p.closeAllSessions(t.Context(), t.Context())
	setStopping(f, false)
	f.ready("s1")
	f.ready("s2")
	setStopping(f, true)
	late := takeHeld(f)
	f.p.putBack(t.Context(), late, late.sessions)
	logs := f.logs.String()
	if !lostIn(logs, "s1") || !lostIn(logs, "s2") || !strings.Contains(logs, "arrived after the stop") {
		t.Errorf("the late sessions are not named and counted: %s", logs)
	}
	if n := f.events(lostEvent); n != 1 {
		t.Errorf("lost events = %d, want one for both", n)
	}
}

func TestLostSessions_keepsTheFirstIDsAndCountsAll(t *testing.T) {
	var lost lostSessions
	for i := range maxLostIDs + 5 {
		lost.add(strconv.Itoa(i))
	}
	if lost.count != maxLostIDs+5 || len(lost.ids) != maxLostIDs || lost.ids[0] != "0" {
		t.Errorf("count %d, ids %v", lost.count, lost.ids)
	}
}

func TestSession_aReleaseRacingTheHandOverNeitherRacesNorLosesASession(t *testing.T) {
	const sessions = 12
	for range 20 {
		f := newRetention(t, Config{})
		f.hcc.GenerateReportFunc = workingGenerator
		ids := make([]string, 0, sessions)
		for i := range sessions {
			id := fmt.Sprintf("s%02d", i)
			ids = append(ids, id)
			f.ready(id)
		}
		held := takeHeld(f)
		var wg sync.WaitGroup
		wg.Go(func() {
			for _, cs := range held.sessions {
				if err := f.p.tryReport(t.Context(), cs); err == nil {
					f.p.release(held, cs)
				}
			}
			f.p.putBack(t.Context(), held, nil)
		})
		f.p.closeAllSessions(t.Context(), t.Context())
		wg.Wait()
		logs := f.logs.String()
		lost := 0
		for _, id := range ids {
			switch n := lostCount(logs, id); {
			case n > 1:
				t.Fatalf("%s named lost %d times: %s", id, n, logs)
			case n == 1:
				lost++
			}
		}
		// One-sided on purpose: a session the monitor wrote just before the
		// hand-over may be named lost too, which the log allows.
		if written := len(f.reports(t)); written+lost < sessions {
			t.Fatalf("%d written and %d lost for %d sessions: a session is neither", written, lost, sessions)
		}
	}
}

// attemptFixture is a session held by a monitor whose normal report fails, so
// that its attempt goes on to the JSON fallback at once.
func attemptFixture(t *testing.T) (*retentionFixture, *heldBatch, *closingSession) {
	t.Helper()
	f := newRetention(t, Config{ReportRetries: 0})
	f.hcc.GenerateReportFunc = func(context.Context, datamodel.ScanContext, iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
		return plugins.GeneratedReport{}, errors.New("generator down")
	}
	f.ready("tom")
	held := takeHeld(f)
	return f, held, held.sessions[0]
}

// monitorGivesBack is what the monitor does after an attempt, then Close.
func monitorGivesBack(t *testing.T, f *retentionFixture, held *heldBatch, cs *closingSession, done bool) {
	t.Helper()
	var still []*closingSession
	if done {
		f.p.release(held, cs)
	} else {
		still = []*closingSession{cs}
	}
	f.p.putBack(t.Context(), held, still)
	close(f.p.done)
	f.p.started = true
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := f.p.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSession_aFallbackWrittenBeforeTheStopIsNotRewrittenOrLost(t *testing.T) {
	for range 20 {
		f, held, cs := attemptFixture(t)
		ctx, cancel := context.WithCancel(t.Context())
		f.hcc.NotifyErrorFunc = func(_ context.Context, key string, _ error) {
			if key == fallbackEvent {
				cancel()
			}
		}
		if !f.p.attempt(ctx, cs) {
			t.Fatal("the fallback is written: the session is done")
		}
		monitorGivesBack(t, f, held, cs, true)
		cancel()
		if got := f.reports(t); len(got) != 1 {
			t.Fatalf("reports = %v, want exactly one", got)
		}
		if strings.Contains(f.logs.String(), "is lost") {
			t.Fatalf("a written report is named lost: %s", f.logs.String())
		}
	}
}

func TestSession_aFallbackCutByTheStopIsLeftToClose(t *testing.T) {
	for range 20 {
		f, held, cs := attemptFixture(t)
		ctx, cancel := context.WithCancel(t.Context())
		var cut atomic.Bool
		prev := closeReportFile
		t.Cleanup(func() { closeReportFile = prev })
		closeReportFile = func(file *os.File) error {
			if cut.CompareAndSwap(false, true) {
				cancel()
				return errors.Join(file.Close(), ctx.Err())
			}
			return file.Close()
		}
		if f.p.attempt(ctx, cs) {
			t.Fatal("a fallback cut by the stop must leave the session to Close")
		}
		if strings.Contains(f.logs.String(), "is lost") {
			t.Fatalf("the monitor announced a loss the stop caused: %s", f.logs.String())
		}
		monitorGivesBack(t, f, held, cs, false)
		if got := f.reports(t); len(got) != 1 {
			t.Fatalf("reports = %v, want exactly one, written by Close", got)
		}
		if strings.Contains(f.logs.String(), "is lost") {
			t.Fatalf("the session is named lost: %s", f.logs.String())
		}
	}
}

func TestSession_aFallbackThatFailsForAnotherReasonIsLostOnceAndNotRetried(t *testing.T) {
	for range 20 {
		f, held, cs := attemptFixture(t)
		prev := closeReportFile
		t.Cleanup(func() { closeReportFile = prev })
		var closes atomic.Int32
		closeReportFile = func(file *os.File) error {
			if closes.Add(1) <= 2 {
				return errors.Join(file.Close(), errors.New("disk full"))
			}
			return file.Close()
		}
		if !f.p.attempt(t.Context(), cs) {
			t.Fatal("a session lost for good is done")
		}
		monitorGivesBack(t, f, held, cs, true)
		if n := lostCount(f.logs.String(), "tom"); n != 1 {
			t.Fatalf("tom named lost %d times, want once: %s", n, f.logs.String())
		}
		if n := f.events(lostEvent); n != 1 {
			t.Fatalf("lost events = %d, want 1", n)
		}
		if got := f.reports(t); len(got) != 0 {
			t.Fatalf("reports = %v, want none: Close must not retry a session lost for good", got)
		}
	}
}

// checkAndCloseSessions makes one pass of the monitor of the current run.
func (p *SessionPlugin) checkAndCloseSessions(ctx context.Context) {
	p.checkSessions(ctx, p.runGeneration())
}

// baseCtx is the context the monitor of a test is given.
func (p *SessionPlugin) baseCtx() context.Context {
	if p.runCtx != nil {
		return p.runCtx
	}
	return context.Background()
}

// A monitor that outlived a Close with a deadline and returns after the plugin
// was started again parks nothing in the new run, and its batch, which Close
// reported lost, is not reported twice.
func TestSession_aMonitorOfAnEarlierRunParksNothingInTheNewOne(t *testing.T) {
	for range 5 {
		f := newRetention(t, Config{})
		f.hcc.GenerateReportFunc = blockedGenerator
		f.ready("tom")
		held := takeHeld(f)
		f.p.started = true
		ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Minute))
		if err := f.p.Close(ctx); err != nil {
			t.Fatal(err)
		}
		cancel()
		if n := lostCount(f.logs.String(), "tom"); n != 1 {
			t.Fatalf("tom named lost %d times by Close, want once: %s", n, f.logs.String())
		}
		f.p.resetRun()
		f.p.putBack(t.Context(), held, held.sessions)
		f.p.closeMu.Lock()
		parked := len(f.p.closing)
		f.p.closeMu.Unlock()
		if parked != 0 {
			t.Fatalf("the old monitor parked %d sessions in the new run", parked)
		}
		if n := lostCount(f.logs.String(), "tom"); n != 1 {
			t.Fatalf("tom named lost %d times, want once: %s", n, f.logs.String())
		}
	}
}

// A batch of an earlier run that Close did not take is a late loss too: logged,
// counted and notified, never parked in the new run.
func TestSession_anUntakenBatchOfAnEarlierRunIsLateNotParked(t *testing.T) {
	f := newRetention(t, Config{})
	f.ready("tom")
	old := takeHeld(f)
	f.p.resetRun()
	f.p.putBack(t.Context(), old, old.sessions)
	f.p.closeMu.Lock()
	parked := len(f.p.closing)
	f.p.closeMu.Unlock()
	if parked != 0 {
		t.Fatalf("parked %d sessions of an earlier run", parked)
	}
	if !lostIn(f.logs.String(), "tom") || !strings.Contains(f.logs.String(), "arrived after the stop") {
		t.Errorf("the late batch is not logged and counted: %s", f.logs.String())
	}
	if n := f.events(lostEvent); n != 1 {
		t.Errorf("lost events = %d, want one", n)
	}
}

// The monitor and the cleanup goroutine of a run use what they were started
// with: renewing the plugin's channels and context while they end is not a race.
func TestSession_theMonitorOfAnEarlierRunEndsWithItsOwnChannels(t *testing.T) {
	f := newRetention(t, Config{RemoveEmptyDirs: true})
	f.p.tickEvery = time.Millisecond
	oldStop, oldDone, oldCtx := f.p.stop, f.p.done, f.p.runCtx
	go f.p.sessionMonitor(oldCtx, oldStop, oldDone, f.p.runGeneration())
	f.p.resetRun()
	close(oldStop)
	select {
	case <-oldDone:
	case <-time.After(monitorEndWait):
		t.Fatal("the monitor of the earlier run did not end")
	}
	select {
	case <-f.p.done:
		t.Fatal("the new run was ended by the old monitor")
	default:
	}
	f.p.cancelRun()
}

// monitorEndWait bounds how long a test waits for a monitor that must end.
const monitorEndWait = 10 * time.Second

// takeBatch of a monitor of an earlier run takes nothing.
func TestSession_aMonitorOfAnEarlierGenerationTakesNothing(t *testing.T) {
	f := newRetention(t, Config{})
	f.ready("tom")
	oldGen := f.p.runGeneration()
	f.p.resetRun()
	if hb := f.p.takeBatch(oldGen, nil); hb != nil {
		t.Fatal("a monitor of an earlier generation took a batch")
	}
	f.p.checkSessions(t.Context(), oldGen)
	if f.session("tom") == nil {
		t.Error("a monitor of an earlier generation took a session of the new run")
	}
}

// startRealPlugin initializes a plugin with its real monitor, over folders of the
// test, and a generator that is stuck until release is closed and ignores its
// context.
func startRealPlugin(t *testing.T, tick time.Duration) (p *SessionPlugin, cfg *Config, hcc *mock.MockHCContext, entered chan struct{}, release chan struct{}) {
	t.Helper()
	prev := previousRunWait
	previousRunWait = 150 * time.Millisecond
	t.Cleanup(func() { previousRunWait = prev })
	hcc = newMockHCC(t)
	hcc.WorkDir = filepath.Join(t.TempDir(), "gmhost-x")
	entered, release = make(chan struct{}), make(chan struct{})
	var once sync.Once
	hcc.GenerateReportFunc = func(context.Context, datamodel.ScanContext, iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
		once.Do(func() { close(entered) })
		<-release
		return plugins.GeneratedReport{}, errors.New("generator stopped")
	}
	root := t.TempDir()
	cfg = &Config{ReportTimeout: time.Minute, MaxDuration: 24 * time.Hour, MaxSpoolSize: "1GiB", InflightTimeout: 24 * time.Hour, Depth: 1, RootFolder: root, Delay: 1, Exports: []string{t.TempDir()}}
	p = &SessionPlugin{tickEvery: tick}
	if err := p.Init(cfg, hcc); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "tom", "a.txt")
	p.OnStartScanFile(file, "h")
	p.OnFileScanned(file, "h", datamodel.Result{})
	p.OnReport(&datamodel.Report{Filename: file, SHA256: "h"})
	return p, cfg, hcc, entered, release
}

// A run whose monitor is stuck is not followed by a new one: Init fails, and
// changes nothing, until the monitor ends. Then it succeeds, and nothing of the
// old run reaches the new one.
func TestSession_initWaitsForThePreviousRunAndFailsIfItIsStuck(t *testing.T) {
	p, cfg, hcc, entered, release := startRealPlugin(t, time.Millisecond)
	released := false
	t.Cleanup(func() {
		if !released {
			close(release)
		}
	})
	select {
	case <-entered:
	case <-time.After(monitorEndWait):
		t.Fatal("the monitor never reached the generator")
	}
	oldDone, oldSessions, oldGen := p.done, p.sessions, p.runGeneration()
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Minute))
	defer cancel()
	if err := p.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Init(cfg, hcc); !errors.Is(err, errPreviousRun) {
		t.Fatalf("Init with a stuck previous run = %v, want %v", err, errPreviousRun)
	}
	if p.done != oldDone || fmt.Sprintf("%p", p.sessions) != fmt.Sprintf("%p", oldSessions) || p.runGeneration() != oldGen {
		t.Error("a failed Init changed the state of the plugin")
	}
	close(release)
	released = true
	select {
	case <-oldDone:
	case <-time.After(monitorEndWait):
		t.Fatal("the old monitor did not end once its generator returned")
	}
	if err := p.Init(cfg, hcc); err != nil {
		t.Fatalf("Init after the previous run ended = %v", err)
	}
	p.closeMu.Lock()
	known, parked, held, stopping := len(p.known), len(p.closing), p.held, p.stopping
	p.closeMu.Unlock()
	if known != 0 || parked != 0 || held != nil || stopping {
		t.Errorf("the new run carries the old one: known %d, closing %d, held %v, stopping %v", known, parked, held, stopping)
	}
	if len(p.sessions) != 0 {
		t.Errorf("the new run has %d sessions of the old one", len(p.sessions))
	}
	if err := p.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// Init after a Close whose monitor ended is the normal path.
func TestSession_initAfterACleanCloseSucceeds(t *testing.T) {
	p, cfg, hcc, _, release := startRealPlugin(t, time.Millisecond)
	close(release)
	if err := p.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := p.Init(cfg, hcc); err != nil {
		t.Fatalf("Init after a clean Close = %v", err)
	}
	if err := p.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// A Close still running when the scanner gave up on it is waited for: the new run
// does not start beside it, and the old Close does not mark the new run as not
// started when it ends.
func TestSession_initWaitsForACloseStillRunning(t *testing.T) {
	// The monitor never ticks: it ends at once, and it is Close itself that is
	// stuck, in the generator.
	p, cfg, hcc, entered, release := startRealPlugin(t, time.Hour)
	released := false
	t.Cleanup(func() {
		if !released {
			close(release)
		}
	})
	closeDone := make(chan error, 1)
	go func() { closeDone <- p.Close(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(monitorEndWait):
		t.Fatal("Close never reached the generator")
	}
	select {
	case <-p.done:
	case <-time.After(monitorEndWait):
		t.Fatal("the monitor did not end")
	}
	if err := p.Init(cfg, hcc); !errors.Is(err, errPreviousRun) {
		t.Fatalf("Init beside a Close still running = %v, want %v", err, errPreviousRun)
	}
	close(release)
	released = true
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(monitorEndWait):
		t.Fatal("Close did not return once its generator did")
	}
	if err := p.Init(cfg, hcc); err != nil {
		t.Fatalf("Init once the Close returned = %v", err)
	}
	if !p.started {
		t.Fatal("the new run is not started: the old Close marked it stopped")
	}
	if err := p.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// Sessions a monitor of an earlier run found are lost by name and counted, never
// put back: the current run may hold a session of the same name.
func TestSession_lateLossNeverPutsASessionBack(t *testing.T) {
	f := newRetention(t, Config{})
	f.ready("tom")
	current := f.session("tom")
	old := newClosing(&Session{ID: "tom"})
	f.p.lateLoss(t.Context(), []*closingSession{old}, errEarlierRun)
	if f.session("tom") != current {
		t.Error("the session of the current run was replaced by one of an earlier run")
	}
	if !lostIn(f.logs.String(), "tom") || !strings.Contains(f.logs.String(), "arrived after the stop") {
		t.Errorf("the late loss is not logged and counted: %s", f.logs.String())
	}
	if n := f.events(lostEvent); n != 1 {
		t.Errorf("lost events = %d, want one", n)
	}
}

// setStopping makes the plugin think the stop has begun, or not.
func setStopping(f *retentionFixture, stopping bool) {
	f.p.closeMu.Lock()
	f.p.stopping = stopping
	f.p.closeMu.Unlock()
}
