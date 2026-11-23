//go:build linux

package main

import (
	"fmt"
	"log/slog"
	"runtime"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

const benchSHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func heapInUse() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func newBenchSession(tb testing.TB, budget *errorBudget, maxSize int64) *Session {
	tb.Helper()
	return &Session{
		ID:      "bench",
		pending: map[string]pendingReport{},
		limits:  spoolLimits{dir: tb.TempDir(), budget: budget, maxSize: maxSize, logger: slog.New(slog.DiscardHandler)},
	}
}

// benchReport is report i: one in errEvery is in error (none when errEvery is 0).
func benchReport(i, errEvery int) datamodel.Report {
	r := datamodel.Report{Filename: fmt.Sprintf("/in/bench/file-%d", i), SHA256: benchSHA, Malicious: i%97 == 0}
	if errEvery > 0 && i%errEvery == 0 {
		r.Error = "the file could not be analyzed"
	}
	return r
}

// fillSession adds total reports and calls mark with the heap in use after
// each count of marks.
func fillSession(tb testing.TB, s *Session, total, errEvery int, marks map[int]*uint64) {
	tb.Helper()
	for i := range total {
		if !okAdd(s, benchReport(i, errEvery)) {
			tb.Fatal("report refused")
		}
		if dst, ok := marks[i+1]; ok {
			*dst = heapInUse()
		}
	}
}

func readAll(tb testing.TB, s *Session) int {
	tb.Helper()
	n := 0
	for _, err := range s.reports(tb.Context()) {
		if err != nil {
			tb.Fatal(err)
		}
		n++
	}
	return n
}

// BenchmarkSession_oneMillionReports adds a million reports to one session and
// reads them all back: the heap must not grow with the session. Run with
// -benchtime=1x.
func BenchmarkSession_oneMillionReports(b *testing.B) {
	const (
		small = 10_000
		total = 1_000_000
	)
	for range b.N {
		s := newBenchSession(b, &errorBudget{}, 0)
		var afterSmall, after uint64
		fillSession(b, s, total, 0, map[int]*uint64{small: &afterSmall, total: &after})
		s.closeSession()
		if n := readAll(b, s); n != total {
			b.Fatalf("read %d reports, want %d", n, total)
		}
		if after > 2*afterSmall {
			b.Fatalf("heap after %d reports = %d, after %d = %d: it grows with the session", total, after, small, afterSmall)
		}
		if err := s.release(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSession_oneMillionReportsWithErrors has one report in five in error:
// the heap grows until the memory budget of the errors is spent, then stays
// flat, and the errors that went to the spool are read back. The real memory of
// a full budget is reported as budget_MiB. Run with -benchtime=1x.
func BenchmarkSession_oneMillionReportsWithErrors(b *testing.B) {
	const (
		total  = 1_000_000
		spent  = 500_000
		errPer = 5
	)
	for range b.N {
		var empty, full, end uint64
		empty = heapInUse()
		budget := &errorBudget{}
		s := newBenchSession(b, budget, 0)
		fillSession(b, s, total, errPer, map[int]*uint64{spent: &full, total: &end})
		if budget.used.Load() > maxPendingErrors {
			b.Fatalf("budget used = %d, over %d", budget.used.Load(), maxPendingErrors)
		}
		if end > full+full/5 {
			b.Fatalf("heap at %d reports = %d, at %d = %d: it still grows once the budget is spent", total, end, spent, full)
		}
		s.closeSession()
		if n := readAll(b, s); n != total {
			b.Fatalf("read %d reports, want %d: errors spilled to the spool must be read back", n, total)
		}
		b.ReportMetric(float64(full-empty)/(1<<20), "budget_MiB")
		if err := s.release(); err != nil {
			b.Fatal(err)
		}
	}
}

func TestSession_heapStopsGrowingOnceTheErrorBudgetIsSpent(t *testing.T) {
	const (
		total = 60_000
		half  = total / 2
	)
	budget := &errorBudget{limit: 256 << 10}
	s := newBenchSession(t, budget, 0)
	var atHalf, atEnd uint64
	fillSession(t, s, total, 5, map[int]*uint64{half: &atHalf, total: &atEnd})
	if budget.used.Load() > budget.limit {
		t.Fatalf("budget used = %d, over its limit %d", budget.used.Load(), budget.limit)
	}
	if atEnd > atHalf+2<<20 {
		t.Errorf("heap = %d at %d reports and %d at %d: it grows with the session past the budget", atEnd, half, atHalf, total)
	}
	s.closeSession()
	if n := readAll(t, s); n != total {
		t.Errorf("read %d reports, want %d", n, total)
	}
}

func BenchmarkSession_addReport(b *testing.B) {
	newSession := func() *Session { return newBenchSession(b, &errorBudget{}, 1<<20) }
	s := newSession()
	rep := benchReport(1, 0)
	b.ReportAllocs()
	for b.Loop() {
		if ok, st := s.addReport(rep, false); !ok || st.forced != "" {
			if err := s.release(); err != nil {
				b.Fatal(err)
			}
			s = newSession()
		}
	}
	if err := s.release(); err != nil {
		b.Fatal(err)
	}
}
