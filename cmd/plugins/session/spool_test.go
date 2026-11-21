package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/google/go-cmp/cmp"
)

func collect(t testing.TB, seq func(func(datamodel.Report, error) bool)) ([]datamodel.Report, error) {
	t.Helper()
	var out []datamodel.Report
	for r, err := range seq {
		if err != nil {
			return out, err
		}
		out = append(out, r)
	}
	return out, nil
}

func mustLine(t testing.TB, r datamodel.Report) []byte {
	t.Helper()
	line, _, err := encodeLine(r)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func TestSpool_readsBackWhatWasAppended(t *testing.T) {
	tests := []struct {
		name  string
		count int
		pad   int
		flush bool
	}{
		{name: "empty", count: 0},
		{name: "still buffered", count: 3},
		{name: "flushed once past the buffer size", count: 200, pad: 200},
		{name: "explicit flush", count: 5, flush: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sp, err := createSpool(t.TempDir(), nil)
			if err != nil {
				t.Fatal(err)
			}
			var want []datamodel.Report
			for i := range tt.count {
				r := datamodel.Report{Filename: fmt.Sprintf("f%d", i), SHA256: strings.Repeat("a", tt.pad), Malicious: i%2 == 0}
				want = append(want, r)
				if err := sp.append(mustLine(t, r)); err != nil {
					t.Fatal(err)
				}
			}
			if tt.flush {
				if err := sp.flush(); err != nil {
					t.Fatal(err)
				}
			}
			for pass := range 2 {
				got, err := collect(t, sp.reports(t.Context()))
				if err != nil {
					t.Fatalf("pass %d: %v", pass, err)
				}
				if diff := cmp.Diff(want, got); diff != "" {
					t.Fatalf("pass %d: reports diff (-want +got):\n%s", pass, diff)
				}
			}
			if sp.count != tt.count {
				t.Errorf("count = %d, want %d", sp.count, tt.count)
			}
		})
	}
}

func TestSpool_fileIsPrivateAndExclusive(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "session")
	a, err := createSpool(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := createSpool(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.path == b.path {
		t.Fatal("two spools share a file")
	}
	fi, err := os.Stat(a.path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("spool mode = %v, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("spool dir mode = %v, want 0700", di.Mode().Perm())
	}
	if filepath.Ext(a.path) != ".jsonl" {
		t.Errorf("spool name %q has not the .jsonl extension", a.path)
	}
}

func TestCreateSpool_errors(t *testing.T) {
	if _, err := createSpool("", nil); err == nil {
		t.Error("an empty directory must be refused")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := createSpool(filepath.Join(file, "session"), nil); err == nil {
		t.Error("a directory under a file must be refused")
	}
}

func TestSpool_aMaxSizeReportIsReadBackIntact(t *testing.T) {
	big := datamodel.Report{Filename: "big", Error: strings.Repeat("é", (datamodel.MaxReportSize-200)/2)}
	line := mustLine(t, big)
	if len(line) <= datamodel.MaxReportSize-400 || len(line) > datamodel.MaxReportSize {
		t.Fatalf("test report is %d bytes, want just under MaxReportSize", len(line))
	}
	sp, err := createSpool(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := sp.append(line); err != nil {
			t.Fatal(err)
		}
	}
	got, err := collect(t, sp.reports(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("read %d reports, want 3", len(got))
	}
	for i, r := range got {
		if r.Error != big.Error {
			t.Errorf("report %d changed on the way", i)
		}
	}
}

func TestEncodeLine_boundsWhatIsOverTheLimit(t *testing.T) {
	r := datamodel.Report{Filename: "x", Malwares: []string{strings.Repeat("m", 1000)}}
	for i := range 6000 {
		r.NotAnalyzedExtractedFiles = append(r.NotAnalyzedExtractedFiles, datamodel.NotAnalyzedFile{FileName: fmt.Sprintf("%s-%d", strings.Repeat("n", 900), i)})
	}
	line, bound, err := encodeLine(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(bound.NotAnalyzedExtractedFiles) >= len(r.NotAnalyzedExtractedFiles) {
		t.Error("the returned report must be the bound one")
	}
	if len(line) > datamodel.MaxReportSize+1 {
		t.Errorf("line = %d bytes, want at most MaxReportSize", len(line))
	}
	if line[len(line)-1] != '\n' || bytes.Count(line, []byte("\n")) != 1 {
		t.Error("a line must hold one report and end with a newline")
	}
}

func TestReadLines_isStrict(t *testing.T) {
	good := `{"filename":"a"}`
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr string
	}{
		{name: "two lines", input: good + "\n" + good + "\n", want: 2},
		{name: "no final newline", input: good, want: 1},
		{name: "unknown field", input: `{"filename":"a","nope":1}` + "\n", wantErr: "bad line"},
		{name: "data after the report", input: good + ` {"filename":"b"}` + "\n", wantErr: "data after"},
		{name: "garbage", input: "not json\n", wantErr: "bad line"},
		{name: "truncated", input: `{"filename":"a`, wantErr: "bad line"},
		{name: "good then bad", input: good + "\nxx\n", want: 1, wantErr: "bad line"},
		{name: "line over the scanner limit", input: `{"filename":"` + strings.Repeat("a", spoolMaxLine) + `"}` + "\n", wantErr: "token too long"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := collect(t, readLines(t.Context(), strings.NewReader(tt.input)))
			if len(got) != tt.want {
				t.Errorf("read %d reports, want %d", len(got), tt.want)
			}
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestReadLines_stopsWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	input := strings.Repeat(`{"filename":"a"}`+"\n", 100)
	n := 0
	var gotErr error
	for _, err := range readLines(ctx, strings.NewReader(input)) {
		if err != nil {
			gotErr = err
			break
		}
		if n++; n == 3 {
			cancel()
		}
	}
	if !errors.Is(gotErr, context.Canceled) || n != 3 {
		t.Errorf("read %d reports, error %v: want 3 and context.Canceled", n, gotErr)
	}
}

func TestSpool_theConsumerMayStopEarly(t *testing.T) {
	sp, err := createSpool(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		if err := sp.append(mustLine(t, datamodel.Report{Filename: strconv.Itoa(i)})); err != nil {
			t.Fatal(err)
		}
	}
	n := 0
	for _, err := range sp.reports(t.Context()) {
		if err != nil {
			t.Fatal(err)
		}
		if n++; n == 4 {
			break
		}
	}
	if n != 4 {
		t.Errorf("n = %d, want 4", n)
	}
}

func TestSpool_aFailedWriteKeepsTheLinesBefore(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("no /dev/full")
	}
	sp, err := createSpool(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	onDisk := sp.path
	if err := sp.append(mustLine(t, datamodel.Report{Filename: "ok"})); err != nil {
		t.Fatal(err)
	}
	sp.path = "/dev/full"
	pad := strings.Repeat("p", spoolFlushSize)
	if err := sp.append(mustLine(t, datamodel.Report{Filename: "tail", SHA256: pad})); err == nil {
		t.Fatal("a write to a full device must fail")
	}
	if sp.durable != 0 {
		t.Errorf("durable = %d after a failed write, want 0", sp.durable)
	}
	if err := sp.flush(); err == nil {
		t.Error("flush of the lines kept must fail again on a full device")
	}
	sp.path = onDisk
	got, err := collect(t, sp.reports(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Filename != "ok" || sp.count != 1 {
		t.Errorf("reports = %+v (count %d), want the line accepted before the failure and not the one refused", got, sp.count)
	}
	sp.path = onDisk
	if err := sp.flush(); err != nil {
		t.Fatalf("flush once the disk works: %v", err)
	}
}

func TestSpool_aTruncatedFileIsAnErrorNotAShortReport(t *testing.T) {
	sp, err := createSpool(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if err := sp.append(mustLine(t, datamodel.Report{Filename: strconv.Itoa(i)})); err != nil {
			t.Fatal(err)
		}
	}
	if err := sp.flush(); err != nil {
		t.Fatal(err)
	}
	line := int64(len(mustLine(t, datamodel.Report{Filename: "0"})))
	if err := os.Truncate(sp.path, 3*line); err != nil {
		t.Fatal(err)
	}
	got, err := collect(t, sp.reports(t.Context()))
	if err == nil || !strings.Contains(err.Error(), "truncated") || len(got) != 3 {
		t.Fatalf("reports = %d, err = %v, want 3 then a truncation error", len(got), err)
	}
	var out bytes.Buffer
	s := &Session{pending: map[string]pendingReport{}, spool: sp}
	if err := s.copyRaw(t.Context(), &out); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Errorf("copyRaw error = %v, want a truncation error", err)
	}
}

func TestSpool_garbagePastTheDurableSizeIsNeverRead(t *testing.T) {
	sp, err := createSpool(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.append(mustLine(t, datamodel.Report{Filename: "a"})); err != nil {
		t.Fatal(err)
	}
	if err := sp.flush(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(sp.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"filename":"half`); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := collect(t, sp.reports(t.Context()))
	if err != nil || len(got) != 1 {
		t.Fatalf("reports = %v, err = %v, want the first line only", got, err)
	}
}

func TestSpool_reportsFailsWhenTheFileIsGone(t *testing.T) {
	sp, err := createSpool(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.remove(); err != nil {
		t.Fatal(err)
	}
	if err := sp.remove(); err != nil {
		t.Errorf("removing twice: %v", err)
	}
	if _, err := collect(t, sp.reports(t.Context())); err == nil {
		t.Error("reading a removed spool must fail")
	}
}

func TestSpool_copiesAsIs(t *testing.T) {
	sp, err := createSpool(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := mustLine(t, datamodel.Report{Filename: "a"})
	if err := sp.append(want); err != nil {
		t.Fatal(err)
	}
	r, err := sp.open()
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if _, err := got.ReadFrom(r); err != nil || !bytes.Equal(got.Bytes(), want) {
		t.Errorf("raw = %q (%v), want %q", got.Bytes(), err, want)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestErrorBudget(t *testing.T) {
	b := &errorBudget{limit: 100}
	if !b.reserve(60) || b.reserve(60) {
		t.Fatal("the budget must grant 60 then refuse another 60")
	}
	b.force(60)
	if got := b.used.Load(); got != 120 {
		t.Errorf("used = %d, want 120", got)
	}
	b.give(120)
	if !b.reserve(100) {
		t.Error("the whole budget must be back")
	}
	var none *errorBudget
	if !none.reserve(1 << 40) {
		t.Error("no budget means no limit")
	}
	none.force(1)
	none.give(1)
	if def := (&errorBudget{}); !def.reserve(maxPendingErrors) || def.reserve(1) {
		t.Error("a budget without limit uses maxPendingErrors")
	}
}

func TestSession_reportsStopsWhenTheContextEndsMidSpool(t *testing.T) {
	reports := make([]datamodel.Report, 0, 50)
	for i := range 50 {
		reports = append(reports, datamodel.Report{Filename: strconv.Itoa(i)})
	}
	s := testSession(t, "tom", time.Unix(1_700_000_000, 0), nil, reports...)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	n := 0
	var gotErr error
	for _, err := range s.reports(ctx) {
		if err != nil {
			gotErr = err
			break
		}
		if n++; n == 5 {
			cancel()
		}
	}
	if !errors.Is(gotErr, context.Canceled) || n != 5 {
		t.Errorf("read %d reports, error %v: want 5 and context.Canceled", n, gotErr)
	}
}
