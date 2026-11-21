//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

func plainListing(entries ...string) string {
	var b strings.Builder
	b.WriteString("7-Zip 25.01\n\nListing archive: a\n\n--\nPath = a\nType = zip\n\n----------\n")
	for _, e := range entries {
		b.WriteString("Path = " + e + "\nFolder = -\nEncrypted = -\nMethod = Store\n\n")
	}
	return b.String()
}

// provable is an extraction nothing hides an encryption in.
func provable() *extractResult {
	return &extractResult{listComplete: true, listedEntries: 1, produced: 1, announced: 1}
}

// One condition missing is enough to leave the encryption possible: the proof
// holds only when all of them do.
func TestExcludesEncryption_oneMissingConditionLeavesItPossible(t *testing.T) {
	sze := listingSevenZip(t, plainListing("a.txt"))
	tests := []struct {
		name   string
		mutate func(r *extractResult)
		want   bool
	}{
		{"every condition holds", func(*extractResult) {}, true},
		{"7z reported a failure on the data of a member", func(r *extractResult) { r.dataFailure = true }, false},
		{"the listing did not reach its end", func(r *extractResult) { r.listComplete = false }, false},
		{"a member was left out by a limit", func(r *extractResult) { r.skipped.add("big.bin", 10, "too-big") }, false},
		{"a member was dropped", func(r *extractResult) { r.dropped = 1 }, false},
		{"a member was left out as an anomaly, never extracted nor tested", func(r *extractResult) { r.unexamined = 1 }, false},
		{"fewer files than announced", func(r *extractResult) { r.produced = 0 }, false},
		{"more files than announced", func(r *extractResult) { r.produced = 2 }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := provable()
			tt.mutate(r)
			if got := sze.excludesEncryption(t.Context(), "a.zip", r); got != tt.want {
				t.Errorf("excludesEncryption() = %t, want %t", got, tt.want)
			}
		})
	}
}

// The technical listing is part of the proof: complete, parsed, and every member
// says it is not encrypted.
func TestExcludesEncryption_theTechnicalListingMustProveIt(t *testing.T) {
	member := func(extra string) string { return "Path = a.txt\nFolder = -\n" + extra + "Method = Store\n\n" }
	header := "7-Zip\n\n--\nPath = a\nType = zip\n\n----------\n"
	tests := []struct {
		name    string
		listing string
		want    bool
	}{
		{"every member says Encrypted = -", header + member("Encrypted = -\n"), true},
		{"a member says Encrypted = +", header + member("Encrypted = +\n"), false},
		{"a member says nothing of it", header + member(""), false},
		{"a member says something else", header + member("Encrypted = ?\n"), false},
		{"one plain member and one that says nothing", header + member("Encrypted = -\n") + member(""), false},
		{"the listing holds no member", header, false},
		{"the listing has no separator", "7-Zip\nPath = a\nType = zip\n", false},
		{"the members are not the ones announced", header + member("Encrypted = -\n") + member("Encrypted = -\n"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := provable()
			if got := listingSevenZip(t, tt.listing).excludesEncryption(t.Context(), "a.zip", r); got != tt.want {
				t.Errorf("excludesEncryption() = %t, want %t", got, tt.want)
			}
		})
	}
}

// The failures of 7z that an encryption can explain are data failures, even when
// a later password cured them: they are remembered by the listing and by the
// extraction.
func TestExtract_aFailureCuredByAnotherPasswordIsRemembered(t *testing.T) {
	plugin := realPlugin(t)
	plugin.sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
	archive, err := filepath.Abs(fixture(t, filepath.Join("t17a", "known_password.zip")))
	if err != nil {
		t.Fatal(err)
	}
	res, err := plugin.sze.extract(t.Context(), archive, t.TempDir(), nil, openLimits)
	if err != nil {
		t.Fatalf("extract() error = %v", err)
	}
	if !res.dataFailure {
		t.Error("the wrong password tried before the right one is not remembered: it must keep the proof from holding")
	}
}

// What 7z says about an archive that lets it extract everything, with nothing
// hidden, is a proof; its own flag, cleared in a header, is not one.
func TestExtractFile_encryptionIsExcludedOnlyForAStructuralAnomalyOfPlainMembers(t *testing.T) {
	tests := []struct {
		fixture      string
		wantPossible bool
	}{
		{"trailing.7z", true},
		{"twin.7z", true},
		{"t17a/enc_content.7z", true},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			ex, err := realPlugin(t).ExtractFile(fixture(t, tt.fixture), t.TempDir(), openLimits)
			_ = ex
			if err == nil {
				t.Fatal("ExtractFile() succeeded")
			}
			if got := errors.Is(err, plugins.ErrEncryptionPossible); got != tt.wantPossible && errors.Is(err, plugins.ErrArchiveAnomaly) {
				t.Errorf("encryption possible = %t, want %t (error: %v)", got, tt.wantPossible, err)
			}
		})
	}
}

// A failure of the host is not the archive's: it is a plain error, retried, never
// an anomaly and never an entry of the skipped members.
func TestExtract_anUnreadableOutputFolderIsAHostFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a folder cannot be made unreadable for root")
	}
	sze := scriptFor(t, listing(nil, listingLine("a.txt", 3)), `printf abc > "$out/a.txt"`, filepath.Join(t.TempDir(), "args"))
	bigConfig(sze)
	out := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(out, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(out, 0); err != nil {
		t.Fatal(err)
	}
	plugin := &SevenZipExtractPlugin{sze: sze, logger: sze.logger, consoleLogger: sze.logger}
	ex, err := plugin.ExtractFile("/some/dir/a.7z", out, openLimits)
	if err == nil {
		t.Fatal("ExtractFile() succeeded with an output folder that cannot be read")
	}
	if errors.Is(err, plugins.ErrArchiveAnomaly) || errors.Is(err, plugins.ErrEncryptionPossible) || errors.Is(err, plugins.ErrEncrypted) {
		t.Errorf("error = %v, want a plain error: the host failed, not the archive", err)
	}
	if ex.SkippedCount != 0 || len(ex.Skipped) != 0 {
		t.Errorf("Skipped = %+v, want nothing: a failure of the host is not an entry", ex.Skipped)
	}
}

// An output flood is deterministic: one run, an anomaly with the encryption
// possible, never retried and never a plain file.
func TestExtractFile_anOutputFloodIsOneRunAndAnAnomalyWithEncryptionPossible(t *testing.T) {
	prevOut, prevErr := maxSevenZipStdout, maxSevenZipStderr
	maxSevenZipStdout, maxSevenZipStderr = 64<<10, 4<<10
	t.Cleanup(func() { maxSevenZipStdout, maxSevenZipStderr = prevOut, prevErr })
	runs := filepath.Join(t.TempDir(), "runs")
	sze := fakeSevenZip(t, "echo run >> "+runs+"\nyes >&2")
	bigConfig(sze)
	plugin := &SevenZipExtractPlugin{sze: sze, logger: sze.logger, consoleLogger: sze.logger}
	_, err := plugin.ExtractFile("/some/dir/a.7z", t.TempDir(), openLimits)
	if !errors.Is(err, plugins.ErrArchiveAnomaly) || !errors.Is(err, plugins.ErrEncryptionPossible) {
		t.Fatalf("error = %v, want an anomaly with the encryption possible", err)
	}
	b, readErr := os.ReadFile(filepath.Clean(runs))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if n := len(b) / len("run\n"); n != 1 {
		t.Errorf("7z ran %d times for a flood that no password changes, want once", n)
	}
}

// The failures of the listing that 7z prints in its summary are data failures.
func TestListSink_theErrorsOfTheSummaryAreADataFailureAndTheWarningsAreNot(t *testing.T) {
	tests := []struct {
		name string
		meta string
		want bool
	}{
		{"errors", "Errors: 1", true},
		{"a block of errors", "ERRORS:", true},
		{"an open error", "Open ERROR: Cannot open the file as archive", true},
		{"warnings", "Warnings: 1", false},
		{"data after the end", "Tail Size = 5", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newListSink(1<<20, 100, 1<<30)
			if err := s.scan(strings.NewReader(listing([]string{tt.meta}, listingLine("a.txt", 3)))); err != nil {
				t.Fatal(err)
			}
			if s.dataFailure != tt.want {
				t.Errorf("dataFailure = %t, want %t", s.dataFailure, tt.want)
			}
		})
	}
}

// A password refused while listing is a data failure even when the next one opens
// the archive: an archive whose headers are encrypted with a known password.
func TestList_aPasswordRefusedBeforeTheRightOneIsRemembered(t *testing.T) {
	plugin := realPlugin(t)
	plugin.sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(src, []byte("member"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "headers.7z")
	if out, err := runCmd(t.Context(), plugin.sze.sevenZipPath, "a", "-t7z", "-mhe=on", "-pinfected", archive, src); err != nil {
		t.Fatalf("cannot build the archive: %v %s", err, out)
	}
	sink := newListSink(1<<20, 100, 1<<30)
	if err := plugin.sze.list(t.Context(), archive, nil, sink); err != nil {
		t.Fatalf("list() error = %v", err)
	}
	if !sink.dataFailure {
		t.Error("the empty password refused before the right one is not remembered")
	}
}

// The batch itself says it: an output folder that cannot be read leaves no member
// skipped and returns the failure of the host.
func TestRunBatch_anUnreadableOutputFolderIsAHostFailureAndSkipsNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a folder cannot be made unreadable for root")
	}
	sze := fakeSevenZip(t, "exit 0")
	out := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(out, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(out, 0); err != nil {
		t.Fatal(err)
	}
	res := &extractResult{logger: sze.logger}
	_, aborted, err := sze.runBatch(t.Context(), "", "a.7z", out, []string{"a.txt"}, res, openLimits)
	if !errors.Is(err, errOutputFolder) || !aborted {
		t.Errorf("runBatch() = aborted %t, error %v, want the failure of the host", aborted, err)
	}
	if res.skipped.count != 0 || res.dropped != 0 || len(res.anomalies) != 0 {
		t.Errorf("result = %+v, want nothing skipped nor noted: the host failed, not the archive", res)
	}
}

// fakeWithListings is a 7z that prints the table for `l` and the technical
// listing for `l -slt`, and writes a.txt for `x`.
func fakeWithListings(t *testing.T, table, technical string) *sevenZipExtract {
	t.Helper()
	dir := t.TempDir()
	for name, text := range map[string]string{"table": table, "tech": technical} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	body := `for a in "$@"; do case "$a" in -o*) out="${a#-o}";; esac; done
for a in "$@"; do [ "$a" = -slt ] && { cat ` + filepath.Join(dir, "tech") + `; exit 0; }; done
for a in "$@"; do [ "$a" = l ] && { cat ` + filepath.Join(dir, "table") + `; exit 0; }; done
printf abc > "$out/a.txt"
exit 0`
	sze := fakeSevenZip(t, body)
	bigConfig(sze)
	return sze
}

func techListing(archiveLines string) string {
	return "7-Zip 25.01\n\nListing archive: a.zip\n\n--\nPath = a.zip\nType = zip\n" + archiveLines + "\n----------\nPath = a.txt\nFolder = -\nEncrypted = -\nMethod = Store\n\n"
}

// Data after the archive, or before it, hides an archive that 7z does not list:
// the technical listing must say there is none.
func TestExcludesEncryption_dataBeforeOrAfterTheArchiveLeavesItPossible(t *testing.T) {
	tests := []struct {
		name  string
		lines string
		want  bool
	}{
		{"nothing before or after", "Physical Size = 149\n", true},
		{"a tail", "Physical Size = 149\nTail Size = 8\n", false},
		{"a tail of zero", "Tail Size = 0\n", true},
		{"a tail that cannot be read", "Tail Size = many\n", false},
		{"an offset", "Offset = 20\n", false},
		{"an offset of zero", "Offset = 0\n", true},
		{"an embedded stub", "Embedded Stub Size = 502\n", false},
		{"an embedded stub that cannot be read", "Embedded Stub Size = ??\n", false},
		{"the warning that the archive is open with an offset", "Warning: The archive is open with offset\n", false},
		{"a forged comment can only add a doubt", "Comment = \nTail Size = 0\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sze := listingSevenZip(t, techListing(tt.lines))
			if got := sze.excludesEncryption(t.Context(), "a.zip", provable()); got != tt.want {
				t.Errorf("excludesEncryption() = %t, want %t", got, tt.want)
			}
		})
	}
}

// A line of the table that 7z prints and the parser cannot read is an anomaly with
// the encryption possible, never a plain error that is retried for ever.
func TestExtractFile_aTableLineThatCannotBeReadIsAnAnomalyWithEncryptionPossible(t *testing.T) {
	sze := fakeWithListings(t, listing(nil, "garbage that is no member line"), techListing(""))
	plugin := &SevenZipExtractPlugin{sze: sze, logger: sze.logger, consoleLogger: sze.logger}
	_, err := plugin.ExtractFile("/some/dir/a.zip", t.TempDir(), openLimits)
	if !errors.Is(err, plugins.ErrArchiveAnomaly) || !errors.Is(err, plugins.ErrEncryptionPossible) {
		t.Fatalf("ExtractFile() error = %v, want an anomaly with the encryption possible", err)
	}
}

// A warning of 7z on an otherwise plain archive is a structural anomaly that
// as_file may deliver; with data after the archive it is not.
func TestExtractFile_aWarningIsEligibleOnlyWithoutDataBeforeOrAfter(t *testing.T) {
	table := listing([]string{"WARNINGS:", "Something odd in the headers", "Warnings: 1"}, listingLine("a.txt", 3))
	tests := []struct {
		name         string
		technical    string
		wantPossible bool
	}{
		{"only the warning", techListing(""), false},
		{"the warning says data follow the archive", techListing("Tail Size = 5\n"), true},
		{"the warning says the archive is open with an offset", techListing("Warning: The archive is open with offset\n"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sze := fakeWithListings(t, table, tt.technical)
			plugin := &SevenZipExtractPlugin{sze: sze, logger: sze.logger, consoleLogger: sze.logger}
			_, err := plugin.ExtractFile("/some/dir/a.zip", t.TempDir(), openLimits)
			if !errors.Is(err, plugins.ErrArchiveAnomaly) {
				t.Fatalf("ExtractFile() error = %v, want an anomaly", err)
			}
			if got := errors.Is(err, plugins.ErrEncryptionPossible); got != tt.wantPossible {
				t.Errorf("encryption possible = %t, want %t (error: %v)", got, tt.wantPossible, err)
			}
		})
	}
}

// The listing of a document is held to the budget of the extraction before
// anything is read: more members or bytes than it allows, or a ratio that is a
// bomb, is an anomaly with the encryption possible, never tested.
func TestCheckOnly_aListingOverTheBudgetIsNotTested(t *testing.T) {
	bomb := fmt.Sprintf("%-19s %-5s %12d %12d  %s", "2024-01-01 00:00:00", "....A", int64(4<<30), 4096, "bomb.bin")
	tests := []struct {
		name   string
		table  string
		limits plugins.ExtractLimits
		// leftOut: the members are left out for the budget, which is no error (the
		// caller decides what the file becomes); otherwise the listing is an anomaly.
		leftOut bool
	}{
		{"too many bytes", listing(nil, listingLine("a.bin", 2<<20)), plugins.ExtractLimits{MaxFiles: 100, MaxTotalSize: 1 << 20}, true},
		{"too many members", listing(nil, listingLine("a", 1), listingLine("b", 1), listingLine("c", 1)), plugins.ExtractLimits{MaxFiles: 2, MaxTotalSize: 1 << 30}, true},
		{"a ratio that is a bomb", listing(nil, bomb), plugins.ExtractLimits{MaxFiles: 100, MaxTotalSize: 1 << 40}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := filepath.Join(t.TempDir(), "calls")
			sze := fakeWithListings(t, tt.table, techListing(""))
			sze.sevenZipPath = recordingWrapper(t, sze.sevenZipPath, calls)
			tt.limits.CheckOnly = true
			plugin := &SevenZipExtractPlugin{sze: sze, logger: sze.logger, consoleLogger: sze.logger}
			ex, err := plugin.ExtractFile("/some/dir/a.zip", t.TempDir(), tt.limits)
			if tt.leftOut {
				if err != nil || ex.SkippedCount == 0 {
					t.Fatalf("ExtractFile() = %+v, %v, want no error and members left out for the budget", ex, err)
				}
			} else if !errors.Is(err, plugins.ErrArchiveAnomaly) || !errors.Is(err, plugins.ErrEncryptionPossible) {
				t.Fatalf("ExtractFile() error = %v, want an anomaly with the encryption possible", err)
			}
			b, readErr := os.ReadFile(filepath.Clean(calls))
			if readErr != nil || !strings.Contains(string(b), " l ") {
				t.Fatalf("the wrapper did not record the listing (%v): %q", readErr, b)
			}
			if strings.Contains(string(b), " t ") {
				t.Errorf("the members were tested although the listing is over the budget: %s", b)
			}
		})
	}
}

// recordingWrapper is a 7z that records its arguments, then runs the real one.
func recordingWrapper(t *testing.T, target, record string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "7zwrap")
	body := "#!/bin/sh\necho \" $* \" >> " + record + "\nexec " + target + " \"$@\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, modeScript); err != nil {
		t.Fatal(err)
	}
	return path
}
