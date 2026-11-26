package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

func manyReports(n int, calls *int) func(func(datamodel.Report, error) bool) {
	return func(yield func(datamodel.Report, error) bool) {
		if calls != nil {
			*calls++
		}
		for i := range n {
			if !yield(datamodel.Report{Filename: fmt.Sprintf("f%d", i), SHA256: "sha", Malicious: i%2 == 0}, nil) {
				return
			}
		}
	}
}

func TestDefaultGenerateReport_isAValidJSONArrayWithAJSONExtension(t *testing.T) {
	for _, n := range []int{0, 1, 5000} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			var calls int
			got, err := defaultGenerateReport(t.Context(), datamodel.ScanContext{}, manyReports(n, &calls))
			if err != nil {
				t.Fatal(err)
			}
			if got.Extension != ".json" {
				t.Errorf("Extension = %q, want .json: the content is JSON", got.Extension)
			}
			raw, err := io.ReadAll(got.Content)
			if err != nil {
				t.Fatal(err)
			}
			if err = got.Content.Close(); err != nil {
				t.Fatal(err)
			}
			var reports []datamodel.Report
			if err = json.Unmarshal(raw, &reports); err != nil || len(reports) != n {
				t.Fatalf("content = %d bytes, %d reports, error %v; want a JSON array of %d reports", len(raw), len(reports), err, n)
			}
			if calls != 1 {
				t.Errorf("the reports were read %d times, want once", calls)
			}
		})
	}
}

func TestDefaultGenerateReport_aFailingSequenceFailsTheContent(t *testing.T) {
	boom := errors.New("spool unreadable")
	seq := func(yield func(datamodel.Report, error) bool) {
		if !yield(datamodel.Report{Filename: "first"}, nil) {
			return
		}
		yield(datamodel.Report{}, boom)
	}
	got, err := defaultGenerateReport(t.Context(), datamodel.ScanContext{}, seq)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadAll(got.Content); !errors.Is(err, boom) {
		t.Errorf("reading the content: error = %v, want the error of the sequence: a partial report must not pass for a whole one", err)
	}
}

// endingSeq is a long sequence that tells when it is over.
func endingSeq(ended chan<- struct{}) func(func(datamodel.Report, error) bool) {
	return func(yield func(datamodel.Report, error) bool) {
		defer close(ended)
		for i := range 1_000_000 {
			if !yield(datamodel.Report{Filename: fmt.Sprintf("f%d", i)}, nil) {
				return
			}
		}
	}
}

func waitEnded(t *testing.T, ended <-chan struct{}) {
	t.Helper()
	select {
	case <-ended:
	case <-time.After(10 * time.Second):
		t.Fatal("the generator never stopped reading the reports")
	}
}

// Closing the content ends the generation: nothing keeps writing into a pipe
// nobody reads.
func TestDefaultGenerateReport_closingTheContentEndsTheGeneration(t *testing.T) {
	ended := make(chan struct{})
	got, err := defaultGenerateReport(t.Context(), datamodel.ScanContext{}, endingSeq(ended))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = got.Content.Read(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	if err = got.Content.Close(); err != nil {
		t.Fatal(err)
	}
	waitEnded(t, ended)
}

func TestDefaultGenerateReport_aCancelledContextEndsTheGeneration(t *testing.T) {
	ended := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	got, err := defaultGenerateReport(ctx, datamodel.ScanContext{}, endingSeq(ended))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	if _, err = got.Content.Read(buf); err != nil {
		t.Fatal(err)
	}
	cancel()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err = got.Content.Read(buf); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the content kept coming after the cancellation")
		}
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
	if err = got.Content.Close(); err != nil {
		t.Fatal(err)
	}
	waitEnded(t, ended)
}

// A sequence that panics must not take the process down.
func TestDefaultGenerateReport_aPanickingSequenceFailsTheContent(t *testing.T) {
	seq := func(yield func(datamodel.Report, error) bool) {
		yield(datamodel.Report{Filename: "first"}, nil)
		panic("iterator broke")
	}
	got, err := defaultGenerateReport(t.Context(), datamodel.ScanContext{}, seq)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadAll(got.Content); err == nil || !strings.Contains(err.Error(), "iterator broke") {
		t.Errorf("reading the content: error = %v, want the panic reported as an error", err)
	}
}

// The generator and the caller agree: a content if and only if no error.
func TestConnector_GenerateReport_contentIfAndOnlyIfNoError(t *testing.T) {
	closed := false
	tests := []struct {
		name       string
		generator  plugins.GenerateReport
		wantErr    bool
		wantClosed bool
	}{
		{
			name: "no content, no error",
			generator: func(context.Context, datamodel.ScanContext, iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
				return plugins.GeneratedReport{}, nil
			},
			wantErr: true,
		},
		{
			name: "content with an error is closed",
			generator: func(context.Context, datamodel.ScanContext, iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
				return plugins.GeneratedReport{Content: &closeFlag{Reader: strings.NewReader("x"), closed: &closed}}, errors.New("failed")
			},
			wantErr:    true,
			wantClosed: true,
		},
		{
			name: "content and no error",
			generator: func(context.Context, datamodel.ScanContext, iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
				return plugins.GeneratedReport{Content: io.NopCloser(strings.NewReader("x")), Extension: ".json"}, nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			closed = false
			c := &Connector{generateReport: tt.generator}
			got, err := c.GenerateReport(t.Context(), datamodel.ScanContext{}, datamodel.ReportsSeq(nil))
			if (err != nil) != tt.wantErr {
				t.Fatalf("GenerateReport() error = %v, wantErr %t", err, tt.wantErr)
			}
			if tt.wantErr && got.Content != nil {
				t.Error("a failed generation must not give a content")
			}
			if !tt.wantErr && got.Content == nil {
				t.Error("a successful generation must give a content")
			}
			if closed != tt.wantClosed {
				t.Errorf("content closed = %t, want %t", closed, tt.wantClosed)
			}
		})
	}
}

type closeFlag struct {
	io.Reader
	closed *bool
}

func (c *closeFlag) Close() error {
	*c.closed = true
	return nil
}

func BenchmarkDefaultGenerateReport(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		got, err := defaultGenerateReport(b.Context(), datamodel.ScanContext{}, manyReports(1_000_000, nil))
		if err != nil {
			b.Fatal(err)
		}
		n, err := io.Copy(io.Discard, got.Content)
		if err != nil {
			b.Fatal(err)
		}
		b.SetBytes(n)
		if err = got.Content.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
