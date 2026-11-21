package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// Mode of the fake 7z scripts: named constant, the scripts are test fixtures.
const modeScript os.FileMode = 0o700

func fakeSevenZip(t *testing.T, body string) *sevenZipExtract {
	t.Helper()
	path := filepath.Join(t.TempDir(), "7zzs")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, modeScript); err != nil {
		t.Fatal(err)
	}
	return &sevenZipExtract{sevenZipPath: path, logger: slog.New(slog.DiscardHandler)}
}

func TestRunStream_outputIsCappedAndProcessKilled(t *testing.T) {
	prevOut, prevErr := maxSevenZipStdout, maxSevenZipStderr
	maxSevenZipStdout, maxSevenZipStderr = 64<<10, 4<<10
	t.Cleanup(func() { maxSevenZipStdout, maxSevenZipStderr = prevOut, prevErr })

	tests := map[string]string{
		"endless stdout": "yes",
		"endless stderr": "yes >&2",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			sze := fakeSevenZip(t, body)
			done := make(chan error, 1)
			go func() {
				_, err := sze.runStream(t.Context(), "", []string{"l", "archive"}, nil)
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, errSevenZipOutputTooLarge) {
					t.Errorf("runStream() error = %v, want errSevenZipOutputTooLarge", err)
				}
			case <-time.After(20 * time.Second):
				t.Fatal("runStream() did not stop an endless output")
			}
		})
	}
}

func TestRunStream_stdoutIsStreamedNotBuffered(t *testing.T) {
	sze := fakeSevenZip(t, "echo hello")
	var got string
	_, err := sze.runStream(t.Context(), "", []string{"l", "archive"}, func(r io.Reader) error {
		var buf bytes.Buffer
		_, e := buf.ReadFrom(io.LimitReader(r, 100))
		got = buf.String()
		return e
	})
	if err != nil || strings.TrimSpace(got) != "hello" {
		t.Errorf("runStream() = %q, %v, want hello", got, err)
	}
}

func TestRunStream_processThatCannotStartIsUnavailable(t *testing.T) {
	sze := &sevenZipExtract{sevenZipPath: filepath.Join(t.TempDir(), "absent"), logger: slog.New(slog.DiscardHandler)}
	_, err := sze.runStream(t.Context(), "", []string{"l", "x"}, nil)
	if !errors.Is(err, plugins.ErrExtractorUnavailable) {
		t.Errorf("runStream() error = %v, want ErrExtractorUnavailable", err)
	}
}

func TestRunStream_killedProcessIsAnError(t *testing.T) {
	sze := fakeSevenZip(t, "kill -9 $$")
	_, err := sze.runStream(t.Context(), "", []string{"l", "x"}, nil)
	if err == nil || errors.Is(err, plugins.ErrExtractorUnavailable) || errors.Is(err, plugins.ErrUnsupportedFormat) {
		t.Errorf("runStream() error = %v, want a plain extraction error", err)
	}
}

func listingLine(name string, size int) string {
	return fmt.Sprintf("%-19s %-5s %12d %12d  %s", "2024-01-01 00:00:00", "....A", size, size/10, name)
}

func listing(header []string, lines ...string) string {
	var b strings.Builder
	for _, h := range header {
		b.WriteString(h + "\n")
	}
	b.WriteString(szFileListHeader1 + "\n" + szFileListHeader2 + "\n")
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	b.WriteString(szFileListFooter + "\n")
	fmt.Fprintf(&b, "%-19s %12d %12d  %d files\n", "2024-01-01 00:00:00", 0, 0, len(lines))
	return b.String()
}

// scriptFor builds a fake 7z answering `l` with the listing and running
// onExtract for `x`, the arguments being appended to record.
func scriptFor(t *testing.T, list, onExtract, record string) *sevenZipExtract {
	t.Helper()
	listFile := filepath.Join(t.TempDir(), "listing")
	if err := os.WriteFile(listFile, []byte(list), 0o600); err != nil {
		t.Fatal(err)
	}
	body := `printf '%s\n' "$@" >> ` + record + `
for a in "$@"; do case "$a" in -o*) out="${a#-o}";; esac; done
for a in "$@"; do
  if [ "$a" = l ]; then cat ` + listFile + `; exit 0; fi
  if [ "$a" = x ]; then ` + onExtract + `; exit 0; fi
done`
	return fakeSevenZip(t, body)
}

func bigConfig(sze *sevenZipExtract) {
	sze.config = extractorConfig{}
}

var openLimits = plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100, MaxTotalSize: 1 << 30}

func TestListAndExtractDisableWildcardsWithSpd(t *testing.T) {
	record := filepath.Join(t.TempDir(), "args")
	sze := scriptFor(t, listing(nil, listingLine("a.txt", 3)), `printf abc > "$out/a.txt"`, record)
	bigConfig(sze)
	if _, err := sze.extract(t.Context(), "archive.7z", t.TempDir(), nil, openLimits); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Clean(record))
	if err != nil {
		t.Fatal(err)
	}
	var commands [][]string
	var cur []string
	for a := range strings.FieldsSeq(string(b)) {
		if strings.HasPrefix(a, "-P") && len(cur) > 0 {
			commands = append(commands, cur)
			cur = nil
		}
		cur = append(cur, a)
	}
	commands = append(commands, cur)
	seen := map[string]bool{}
	for _, args := range commands {
		spd, sep := slices.Index(args, "-spd"), slices.Index(args, "--")
		if spd < 0 || sep < 0 || spd > sep {
			t.Errorf("arguments = %v, want -spd before --", args)
		}
		seen[args[sep+1]] = true
	}
	if !seen["l"] || !seen["x"] {
		t.Errorf("commands seen = %v, want a listing and an extraction", seen)
	}
}

func TestExtract_limitsAndSkippedMembers(t *testing.T) {
	list := listing(nil, listingLine("small.txt", 3), listingLine("huge.bin", 5<<20), listingLine("second.txt", 3), listingLine("third.txt", 3))
	sze := scriptFor(t, list, `printf abc > "$out/small.txt"; printf abc > "$out/second.txt"`, filepath.Join(t.TempDir(), "args"))
	bigConfig(sze)
	limits := plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 2, MaxTotalSize: 1 << 30}
	res, err := sze.extract(t.Context(), "archive.7z", t.TempDir(), nil, limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.extractedFiles) != 2 || len(res.anomalies) != 0 {
		t.Errorf("extracted %d files, anomalies %v, want 2 and none", len(res.extractedFiles), res.anomalies)
	}
	reasons := map[string]datamodel.NotAnalyzedReason{}
	for _, e := range res.skipped.entries {
		reasons[e.FileName] = e.Reason
	}
	if res.skipped.count != 2 || reasons["huge.bin"] != datamodel.NotAnalyzedTooBig || reasons["third.txt"] != datamodel.NotAnalyzedExtractLimit {
		t.Errorf("skipped = %+v (%d), want huge.bin too-big and third.txt extract-limit", res.skipped.entries, res.skipped.count)
	}
}

func TestExtract_zeroBudgetExtractsNothing(t *testing.T) {
	sze := scriptFor(t, listing(nil, listingLine("a.txt", 3)), `printf abc > "$out/a.txt"`, filepath.Join(t.TempDir(), "args"))
	bigConfig(sze)
	res, err := sze.extract(t.Context(), "archive.7z", t.TempDir(), nil, plugins.ExtractLimits{MaxFileSize: 1 << 20})
	if err != nil || len(res.extractedFiles) != 0 || res.skipped.count != 1 {
		t.Errorf("extract() = %d files, %d skipped, %v, want nothing extracted", len(res.extractedFiles), res.skipped.count, err)
	}
}

func TestExtract_twinNameIsAnAnomaly(t *testing.T) {
	list := listing(nil, listingLine("a.txt", 3), listingLine("evil_.exe", 3), listingLine("evil_.exe", 3))
	// 7z sanitizes two members to the same name: one file is produced.
	sze := scriptFor(t, list, `printf abc > "$out/a.txt"; printf abc > "$out/evil_.exe"`, filepath.Join(t.TempDir(), "args"))
	bigConfig(sze)
	res, err := sze.extract(t.Context(), "archive.7z", t.TempDir(), nil, openLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.anomalies) != 1 || !strings.Contains(res.anomalies[0], "extracted 2 files, the listing announced 3") {
		t.Errorf("anomalies = %v, want a count mismatch 2 vs 3", res.anomalies)
	}
}

func TestExtract_tailSizeAndWarningsAreAnomalies(t *testing.T) {
	tests := map[string]string{
		"tail size":      listing([]string{"Tail Size = 12"}, listingLine("a.txt", 3)),
		"warnings block": listing(nil, listingLine("a.txt", 3)) + "WARNINGS:\nThere are some data after the end of the payload data\n",
	}
	for name, list := range tests {
		t.Run(name, func(t *testing.T) {
			sze := scriptFor(t, list, `printf abc > "$out/a.txt"`, filepath.Join(t.TempDir(), "args"))
			bigConfig(sze)
			res, err := sze.extract(t.Context(), "archive.7z", t.TempDir(), nil, openLimits)
			if err != nil || len(res.anomalies) != 1 {
				t.Errorf("extract() anomalies = %v, err = %v, want exactly one", res.anomalies, err)
			}
		})
	}
}

func TestExtract_tailSizeZeroIsNotAnAnomaly(t *testing.T) {
	sze := scriptFor(t, listing([]string{"Tail Size = 0"}, listingLine("a.txt", 3)), `printf abc > "$out/a.txt"`, filepath.Join(t.TempDir(), "args"))
	bigConfig(sze)
	res, err := sze.extract(t.Context(), "archive.7z", t.TempDir(), nil, openLimits)
	if err != nil || len(res.anomalies) != 0 {
		t.Errorf("extract() anomalies = %v, err = %v, want none", res.anomalies, err)
	}
}

func TestList_badListingsAreErrors(t *testing.T) {
	tests := map[string]string{
		"no header":          "hello\n",
		"no footer":          szFileListHeader1 + "\n" + szFileListHeader2 + "\n" + listingLine("a", 1) + "\n",
		"short entry":        listing(nil, "too short"),
		"bad line after hdr": szFileListHeader1 + "\nnot the separator\n",
	}
	for name, list := range tests {
		t.Run(name, func(t *testing.T) {
			sze := scriptFor(t, list, "true", filepath.Join(t.TempDir(), "args"))
			bigConfig(sze)
			if _, err := sze.extract(t.Context(), "archive.7z", t.TempDir(), nil, openLimits); err == nil {
				t.Error("extract() error = nil, want an error")
			}
		})
	}
}

func TestListSink_entryCapAndLineCap(t *testing.T) {
	s := newListSink(1, 1<<30, 1<<30)
	long := szFileListHeader1 + "\n" + szFileListHeader2 + "\n" + listingLine(strings.Repeat("x", buffSize), 1) + "\n"
	if err := s.scan(strings.NewReader(long)); !errors.Is(err, errBadListing) {
		t.Errorf("scan(line past 64 KiB) = %v, want errBadListing", err)
	}

	prevMax := maxListedEntries
	maxListedEntries = 2
	t.Cleanup(func() { maxListedEntries = prevMax })
	s = newListSink(1, 1<<30, 1<<30)
	err := s.scan(strings.NewReader(listing(nil, listingLine("a", 1), listingLine("b", 1), listingLine("c", 1))))
	if !errors.Is(err, errTooManyEntries) {
		t.Errorf("scan(past the entry cap) = %v, want errTooManyEntries", err)
	}
}

func TestSkipList_isBoundedAndCountsAll(t *testing.T) {
	var s skipList
	for i := range datamodel.MaxListedSubfiles + 50 {
		s.add(fmt.Sprintf("f%d", i), 1, datamodel.NotAnalyzedTooBig)
	}
	if len(s.entries) != datamodel.MaxListedSubfiles || s.count != datamodel.MaxListedSubfiles+50 {
		t.Errorf("entries = %d, count = %d", len(s.entries), s.count)
	}
}

func TestTruncateName(t *testing.T) {
	long := strings.Repeat("é", datamodel.MaxListedNameLen)
	got := truncateName(long)
	if len(got) > datamodel.MaxListedNameLen || !strings.HasSuffix(got, truncationMarker) || !utf8Valid(got) {
		t.Errorf("truncateName() = %d bytes, valid=%v", len(got), utf8Valid(got))
	}
	if truncateName("short") != "short" {
		t.Error("a short name must be kept")
	}
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "") == s }

func TestExtract_wrongPasswordIsEncrypted(t *testing.T) {
	sze := fakeSevenZip(t, `echo "ERROR: Wrong password" >&2; exit 2`)
	bigConfig(sze)
	plugin := &SevenZipExtractPlugin{sze: sze, logger: sze.logger, consoleLogger: sze.logger}
	_, err := plugin.ExtractFile("archive.7z", t.TempDir(), openLimits)
	if !errors.Is(err, plugins.ErrEncrypted) {
		t.Errorf("ExtractFile() error = %v, want ErrEncrypted", err)
	}
}

func TestExtract_notAnArchiveIsUnsupportedFormat(t *testing.T) {
	sze := fakeSevenZip(t, `echo "ERROR: file.bin : Cannot open the file as archive" >&2; exit 2`)
	bigConfig(sze)
	plugin := &SevenZipExtractPlugin{sze: sze, logger: sze.logger, consoleLogger: sze.logger}
	_, err := plugin.ExtractFile("file.bin", t.TempDir(), openLimits)
	if !errors.Is(err, plugins.ErrUnsupportedFormat) {
		t.Errorf("ExtractFile() error = %v, want ErrUnsupportedFormat", err)
	}
}

func TestExtractFile_anomalyIsAnErrorWithAnEntryNamedAfterTheArchiveForTheReport(t *testing.T) {
	sze := scriptFor(t, listing([]string{"Tail Size = 5"}, listingLine("a.txt", 3)), `printf abc > "$out/a.txt"`, filepath.Join(t.TempDir(), "args"))
	bigConfig(sze)
	plugin := &SevenZipExtractPlugin{sze: sze, logger: sze.logger, consoleLogger: sze.logger}
	ex, err := plugin.ExtractFile("/some/dir/bomb.7z", t.TempDir(), openLimits)
	if !errors.Is(err, plugins.ErrArchiveAnomaly) {
		t.Fatalf("ExtractFile() error = %v, want the anomaly", err)
	}
	if len(ex.Files) != 1 || ex.SkippedCount != 1 || len(ex.Skipped) != 1 || ex.Skipped[0].FileName != "bomb.7z" || ex.Skipped[0].Reason != datamodel.NotAnalyzedExtractError {
		t.Errorf("Extraction = %+v, want one file and an extract-error entry named bomb.7z", ex)
	}
}

func BenchmarkListSink_scan(b *testing.B) {
	lines := make([]string, 100000)
	for i := range lines {
		lines[i] = listingLine(fmt.Sprintf("dir/file-%d.bin", i), 100)
	}
	data := listing(nil, lines...)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		s := newListSink(1<<20, 1000, 1<<30)
		if err := s.scan(strings.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}

func TestRunStream_argumentListTooLongIsNotAnUnavailableExtractor(t *testing.T) {
	sze := fakeSevenZip(t, "true")
	_, err := sze.runStream(t.Context(), "", []string{"x", strings.Repeat("n", 1<<20)}, nil)
	if err == nil || errors.Is(err, plugins.ErrExtractorUnavailable) {
		t.Errorf("runStream() error = %v, want an error that is not ErrExtractorUnavailable: the archive is to blame", err)
	}
}
