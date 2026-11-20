package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

func TestScan_memberNameEndingWithCarriageReturnIsKept(t *testing.T) {
	s := newListSink(1<<20, 10, 1<<30)
	if err := s.scan(strings.NewReader(listing(nil, listingLine("a\r", 3)))); err != nil {
		t.Fatal(err)
	}
	if len(s.table.selected) != 1 || s.table.selected[0] != "a\r" {
		t.Errorf("selected = %q, want the name with its \\r: 7z would not find it otherwise", s.table.selected)
	}
	if len(s.anomalies) != 1 || !strings.Contains(s.anomalies[0], "control character") {
		t.Errorf("anomalies = %v, want the control character reported", s.anomalies)
	}
}

func TestScan_summaryMustMatchTheTable(t *testing.T) {
	good := listing(nil, listingLine("a", 1), listingLine("b", 1))
	tests := map[string]struct {
		input string
		want  string
	}{
		"matching":        {good, ""},
		"wrong summary":   {strings.Replace(good, "2 files", "5 files", 1), "announced 5"},
		"no summary line": {strings.Replace(good, "2 files", "", 1), "no summary"},
		"two tables": {
			listing(nil, listingLine("fake", 1)) + listing(nil, listingLine("a", 1), listingLine("b", 1)),
			"several member tables",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newListSink(1<<20, 10, 1<<30)
			if err := s.scan(strings.NewReader(tt.input)); err != nil {
				t.Fatal(err)
			}
			s.finish()
			joined := strings.Join(s.anomalies, "; ")
			if (tt.want == "") != (joined == "") || !strings.Contains(joined, tt.want) {
				t.Errorf("anomalies = %q, want %q", joined, tt.want)
			}
		})
	}
}

func TestScan_lastTableWins(t *testing.T) {
	s := newListSink(1<<20, 10, 1<<30)
	if err := s.scan(strings.NewReader(listing(nil, listingLine("fake.txt", 1)) + listing(nil, listingLine("real.txt", 1)))); err != nil {
		t.Fatal(err)
	}
	if len(s.table.selected) != 1 || s.table.selected[0] != "real.txt" {
		t.Errorf("selected = %v, want only the member of the last table", s.table.selected)
	}
}

func TestListSink_zipBombTotalsOnlyCountFilesUnderTheLimit(t *testing.T) {
	big := fmt.Sprintf("%-19s %-5s %12d %12d  %s", "2024-01-01 00:00:00", "....A", 4_000_000_000, 1000, "bomb.bin")
	small := listingLine("a.txt", 10)
	s := newListSink(5_000_000_000, 10, 1<<40)
	if err := s.scan(strings.NewReader(listing(nil, big, small))); err != nil {
		t.Fatal(err)
	}
	if s.table.totalSize != 4_000_000_010 || s.table.totalCompressed != 1001 {
		t.Errorf("totals = %d / %d, want 4000000010 / 1001", s.table.totalSize, s.table.totalCompressed)
	}
	s = newListSink(1000, 10, 1<<40)
	if err := s.scan(strings.NewReader(listing(nil, big, small))); err != nil {
		t.Fatal(err)
	}
	if s.table.totalSize != 10 {
		t.Errorf("totalSize = %d, want only the file under the limit counted", s.table.totalSize)
	}
}

func TestExtract_zipBombIsRefused(t *testing.T) {
	bomb := fmt.Sprintf("%-19s %-5s %12d %12d  %s", "2024-01-01 00:00:00", "....A", 4_000_000_000, 1000, "bomb.bin")
	sze := scriptFor(t, listing(nil, bomb), "true", filepath.Join(t.TempDir(), "args"))
	_, err := sze.extract(t.Context(), "archive.7z", t.TempDir(), nil, plugins.ExtractLimits{MaxFileSize: 1 << 40, MaxFiles: 10, MaxTotalSize: 1 << 40})
	if err == nil || !strings.Contains(err.Error(), "ZipBomb") {
		t.Errorf("extract() error = %v, want the ZipBomb refusal", err)
	}
}

func TestExtract_killedDuringListingIsAnError(t *testing.T) {
	sze := fakeSevenZip(t, "sleep 30")
	bigConfig(sze)
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := sze.extract(ctx, "archive.7z", t.TempDir(), nil, openLimits)
	if err == nil || time.Since(start) > 10*time.Second {
		t.Errorf("extract() = %v after %v, want a prompt error", err, time.Since(start))
	}
	if errors.Is(err, ErrUnsupportedFormat) || errors.Is(err, ErrInvalidPassword) {
		t.Errorf("error %v must not be taken for a plain file", err)
	}
}

// endlessListing streams a listing of n entries without holding it.
type endlessListing struct {
	n, sent int
	buf     []byte
}

func (e *endlessListing) Read(p []byte) (int, error) {
	if len(e.buf) == 0 {
		switch {
		case e.sent == 0:
			e.buf = []byte(szFileListHeader1 + "\n" + szFileListHeader2 + "\n")
			e.sent = 1
		case e.sent <= e.n:
			e.buf = []byte(listingLine(fmt.Sprintf("dir/member-%d.bin", e.sent), 100) + "\n")
			e.sent++
		default:
			return 0, io.EOF
		}
	}
	n := copy(p, e.buf)
	e.buf = e.buf[n:]
	return n, nil
}

// The cap is lowered so that the test stays fast under -race; the memory
// bound does not depend on its value.
func TestScan_oversizedListingStopsAtTheCapWithBoundedMemory(t *testing.T) {
	prevMax := maxListedEntries
	maxListedEntries = 200_000
	t.Cleanup(func() { maxListedEntries = prevMax })
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	s := newListSink(1, 1000, 1<<30)
	err := s.scan(&endlessListing{n: 2_000_000})
	runtime.GC()
	runtime.ReadMemStats(&after)
	if !errors.Is(err, errTooManyEntries) {
		t.Fatalf("scan() error = %v, want errTooManyEntries", err)
	}
	if after.HeapAlloc > before.HeapAlloc+64<<20 {
		t.Errorf("heap grew by %d MiB while reading the listing, want it bounded", (after.HeapAlloc-before.HeapAlloc)>>20)
	}
	if len(s.table.skipped.entries) != 1000 {
		t.Errorf("kept %d skipped entries, want 1000", len(s.table.skipped.entries))
	}
}

func TestBatchNames(t *testing.T) {
	names := []string{"a", "b", "c", strings.Repeat("x", 100), "d"}
	got := batchNames(names, 2, 1000)
	if len(got) != 3 || len(got[0]) != 2 || len(got[1]) != 2 || len(got[2]) != 1 {
		t.Errorf("by count: %v", got)
	}
	got = batchNames(names, 100, 50)
	for _, b := range got {
		size := 0
		for _, n := range b {
			size += len(n) + 1
		}
		if size > 50 && len(b) > 1 {
			t.Errorf("batch %v exceeds the byte budget", b)
		}
	}
	var all []string
	for _, b := range got {
		all = append(all, b...)
	}
	if strings.Join(all, ",") != strings.Join(names, ",") {
		t.Errorf("batches lose or reorder names: %v", got)
	}
	if len(batchNames(nil, 2, 10)) != 0 {
		t.Error("no names, no batch")
	}
}

func TestSanitizeOutput(t *testing.T) {
	rlo := string(rune(0x202E))
	in := "ERROR: a\x1b[31m" + rlo + "evil\nline2" + strings.Repeat("z", 5000)
	got := sanitizeOutput(in)
	if len(got) > maxQuotedOutput || strings.ContainsAny(got, "\x1b\n"+rlo) {
		t.Errorf("sanitizeOutput() = %q (%d bytes), want no control or bidi character and a bounded size", got[:60], len(got))
	}
}

func TestRemoveLinkPlaceholders_staysInsideTheOutputFolder(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outside, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "link"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "full"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(out, outside)
	if err != nil {
		t.Fatal(err)
	}
	removed := removeLinkPlaceholders(out, []string{"link", rel, "full", "absent"}, slog.New(slog.DiscardHandler))
	if removed != 1 {
		t.Errorf("removed = %d, want only the empty placeholder", removed)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Errorf("a name from 7z's output removed a file outside the output folder: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "full")); err != nil {
		t.Error("a file with content must never be removed as a placeholder")
	}
}

func TestAnomalies_areDeduplicatedAndBounded(t *testing.T) {
	var lines []string
	for i := range 5000 {
		lines = append(lines, listingLine(fmt.Sprintf("m%d\x01", i), 1))
	}
	s := newListSink(1<<20, 10, 1<<30)
	if err := s.scan(strings.NewReader(listing(nil, lines...))); err != nil {
		t.Fatal(err)
	}
	if len(s.anomalies) != 1 {
		t.Errorf("anomalies = %d entries for 5000 booby-trapped members, want 1", len(s.anomalies))
	}
	var list []string
	for i := range 10 * maxAnomalies {
		list = noteAnomaly(list, fmt.Sprintf("kind %d", i))
	}
	if len(list) != maxAnomalies {
		t.Errorf("distinct anomalies kept = %d, want the bound %d", len(list), maxAnomalies)
	}
}

func TestScan_errorsLineUnderTheTableIsAnAnomaly(t *testing.T) {
	for _, tail := range []string{"Errors: 1\n", "ERRORS:\nUnexpected end of archive\n", "Warnings: 1\n"} {
		s := newListSink(1<<20, 10, 1<<30)
		if err := s.scan(strings.NewReader(listing(nil, listingLine("a", 1)) + tail)); err != nil {
			t.Fatal(err)
		}
		if len(s.anomalies) != 1 {
			t.Errorf("tail %q: anomalies = %v, want one (a cut zip still lists and only says so there)", tail, s.anomalies)
		}
	}
}
