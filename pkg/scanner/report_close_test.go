package scanner

import (
	"context"
	"errors"
	"io"
	"iter"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

func TestDefaultGenerateReport_closeReturnsOnlyOnceTheSequenceIsNoLongerRead(t *testing.T) {
	for range 50 {
		ended := make(chan struct{})
		got, err := defaultGenerateReport(t.Context(), datamodel.ScanContext{}, endingSeq(ended))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = got.Content.Read(make([]byte, 10)); err != nil {
			t.Fatal(err)
		}
		if err = got.Content.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ended:
		default:
			t.Fatal("Close returned while the sequence was still being read")
		}
		if err = got.Content.Close(); err != nil {
			t.Errorf("second Close: %v", err)
		}
	}
}

func TestDefaultGenerateReport_closeBeforeAnyReadStillWaits(t *testing.T) {
	ended := make(chan struct{})
	got, err := defaultGenerateReport(t.Context(), datamodel.ScanContext{}, endingSeq(ended))
	if err != nil {
		t.Fatal(err)
	}
	if err = got.Content.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ended:
	default:
		t.Fatal("Close returned while the sequence was still being read")
	}
}

func TestDefaultGenerateReport_aCancelledContextEndsTheWriterWithNobodyReading(t *testing.T) {
	ended := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	got, err := defaultGenerateReport(ctx, datamodel.ScanContext{}, endingSeq(ended))
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	waitEnded(t, ended)
	if err = got.Content.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultGenerateReport_aPanickingSequenceFailsTheContentAndCloseReturns(t *testing.T) {
	seq := func(func(datamodel.Report, error) bool) { panic("boom") }
	got, err := defaultGenerateReport(t.Context(), datamodel.ScanContext{}, seq)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(io.Discard, got.Content); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("error = %v, want the panic as an error", err)
	}
	if err = got.Content.Close(); err != nil {
		t.Fatal(err)
	}
}

// BenchmarkDefaultGenerateReport_oneMillionReports streams a million reports
// through the default generator: the heap must not grow with their number. Run
// with -benchtime=1x.
func BenchmarkDefaultGenerateReport_oneMillionReports(b *testing.B) {
	const (
		small = 10_000
		total = 1_000_000
	)
	heap := func() uint64 {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	for range b.N {
		var afterSmall, peak uint64
		seq := func(yield func(datamodel.Report, error) bool) {
			for i := range total {
				if !yield(datamodel.Report{Filename: "/in/bench/file", SHA256: "0123456789abcdef0123456789abcdef", Malicious: i%97 == 0}, nil) {
					return
				}
				switch i + 1 {
				case small:
					afterSmall = heap()
				case total / 2:
					peak = heap()
				}
			}
		}
		got, err := defaultGenerateReport(b.Context(), datamodel.ScanContext{}, seq)
		if err != nil {
			b.Fatal(err)
		}
		n, err := io.Copy(io.Discard, got.Content)
		if err != nil {
			b.Fatal(err)
		}
		if err = got.Content.Close(); err != nil {
			b.Fatal(err)
		}
		if peak > 2*afterSmall {
			b.Fatalf("heap at %d reports = %d, at %d = %d: it grows with the reports", total/2, peak, small, afterSmall)
		}
		b.SetBytes(n)
	}
}

// A generator that keeps reading the sequence in a goroutine after Close gets
// nothing, and the sequence it ranges over ends.
func TestConnectorGenerateReport_noReportReachesTheGeneratorAfterClose(t *testing.T) {
	var (
		after   atomic.Int32
		closed  atomic.Bool
		ranOver = make(chan struct{})
		started = make(chan struct{})
		release = make(chan struct{})
		wg      sync.WaitGroup
		srcEnd  = make(chan struct{})
	)
	var yieldsAfterClose atomic.Int32
	source := func(yield func(datamodel.Report, error) bool) {
		defer close(srcEnd)
		for i := range 1_000_000 {
			if closed.Load() {
				yieldsAfterClose.Add(1)
			}
			if !yield(datamodel.Report{Filename: strconv.Itoa(i)}, nil) {
				return
			}
		}
	}
	generator := func(_ context.Context, _ datamodel.ScanContext, reports iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
		wg.Go(func() {
			defer close(ranOver)
			first := true
			for _, err := range reports {
				if err != nil {
					return
				}
				if first {
					first = false
					close(started)
					<-release
					continue
				}
				if closed.Load() {
					after.Add(1)
				}
			}
		})
		return plugins.GeneratedReport{Content: io.NopCloser(strings.NewReader("x")), Extension: ".json"}, nil
	}
	c := &Connector{generateReport: generator}
	got, err := c.GenerateReport(t.Context(), datamodel.ScanContext{}, source)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if err = got.Content.Close(); err != nil {
		t.Fatal(err)
	}
	closed.Store(true)
	close(release)
	waitEnded(t, ranOver)
	waitEnded(t, srcEnd)
	wg.Wait()
	if n := after.Load(); n != 0 {
		t.Errorf("%d reports reached the generator after Close", n)
	}
	if n := yieldsAfterClose.Load(); n > 1 {
		t.Errorf("the source was resumed %d times after Close, want at most the one that was refused", n)
	}
}

func TestConnectorGenerateReport_aFailedGeneratorGetsNothingMore(t *testing.T) {
	var after atomic.Int32
	var rangeAgain func()
	generator := func(_ context.Context, _ datamodel.ScanContext, reports iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
		rangeAgain = func() {
			for _, err := range reports {
				if err != nil {
					return
				}
				after.Add(1)
			}
		}
		return plugins.GeneratedReport{}, errors.New("down")
	}
	c := &Connector{generateReport: generator}
	if _, err := c.GenerateReport(t.Context(), datamodel.ScanContext{}, manyReports(10, nil)); err == nil {
		t.Fatal("the failure must be returned")
	}
	rangeAgain()
	if after.Load() != 0 {
		t.Errorf("%d reports reached a generator that had failed", after.Load())
	}
}

func TestConnectorGenerateReport_aPanickingGeneratorLeavesTheSequenceClosed(t *testing.T) {
	var leaked func(func(datamodel.Report, error) bool)
	generator := func(_ context.Context, _ datamodel.ScanContext, reports iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
		leaked = reports
		panic("generator bug")
	}
	c := &Connector{generateReport: generator}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic must propagate")
			}
		}()
		_, _ = c.GenerateReport(t.Context(), datamodel.ScanContext{}, manyReports(10, nil))
	}()
	n := 0
	for _, err := range leaked {
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 0 {
		t.Errorf("%d reports reached a generator that had panicked", n)
	}
}

func TestConnectorGenerateReport_theSequenceIsNotStartedOnceClosed(t *testing.T) {
	var calls int
	var started iter.Seq2[datamodel.Report, error]
	generator := func(_ context.Context, _ datamodel.ScanContext, reports iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
		started = reports
		return plugins.GeneratedReport{Content: io.NopCloser(strings.NewReader("x")), Extension: ".json"}, nil
	}
	c := &Connector{generateReport: generator}
	got, err := c.GenerateReport(t.Context(), datamodel.ScanContext{}, manyReports(10, &calls))
	if err != nil {
		t.Fatal(err)
	}
	if err = got.Content.Close(); err != nil {
		t.Fatal(err)
	}
	for _, err := range started {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls != 0 {
		t.Errorf("the source was started %d times after Close", calls)
	}
}
