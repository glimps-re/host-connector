package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"log/slog"
	"math"
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
)

const (
	mib = 1 << 20
	// slack is what may be written past a limit before the kernel or the
	// watch stops 7z: the limit itself plus a margin of one measure.
	slack = 2 * mib
)

// peakWatcher records the biggest total size of dir while a test runs.
func peakWatcher(t *testing.T, dir string) (peak func() int64) {
	t.Helper()
	var highest atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			var total int64
			_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					if info, e := d.Info(); e == nil {
						total += info.Size()
					}
				}
				return nil
			})
			for {
				cur := highest.Load()
				if total <= cur || highest.CompareAndSwap(cur, total) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
		}
	})
	t.Cleanup(func() { close(stop); wg.Wait() })
	return highest.Load
}

func gzipOfZeros(t *testing.T, path string, mebibytes int, falsifiedSize bool) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Name = "bomb"
	zeros := make([]byte, mib)
	for range mebibytes {
		if _, err := gz.Write(zeros); err != nil {
			t.Fatal(err)
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	if falsifiedSize {
		// ISIZE, the last four bytes, announces 1 byte.
		raw[len(raw)-4], raw[len(raw)-3], raw[len(raw)-2], raw[len(raw)-1] = 1, 0, 0, 0
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRealSevenZip_streamArchivesCannotWritePastTheLimit(t *testing.T) {
	limits := plugins.ExtractLimits{MaxFileSize: 4 * mib, MaxFiles: 100, MaxTotalSize: 1 << 30}
	build := map[string]func(t *testing.T, plugin *SevenZipExtractPlugin, path string){
		"gzip announcing 1 byte.gz": func(t *testing.T, _ *SevenZipExtractPlugin, path string) { gzipOfZeros(t, path, 24, true) },
		"honest gzip.gz":            func(t *testing.T, _ *SevenZipExtractPlugin, path string) { gzipOfZeros(t, path, 24, false) },
		"bzip2 without size.bz2": func(t *testing.T, plugin *SevenZipExtractPlugin, path string) {
			src := filepath.Join(t.TempDir(), "zeros")
			if err := os.WriteFile(src, make([]byte, 16*mib), 0o600); err != nil {
				t.Fatal(err)
			}
			if out, err := runCmd(t.Context(), plugin.sze.sevenZipPath, "a", "-tbzip2", path, src); err != nil {
				t.Fatalf("cannot build the bzip2: %v %s", err, out)
			}
		},
	}
	for name, mk := range build {
		for _, kernelLimit := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s, kernel limit %t", name, kernelLimit), func(t *testing.T) {
				if !kernelLimit {
					prev := limitProcess
					limitProcess = func(int, int64) error { return errors.New("injected: no limit") }
					t.Cleanup(func() { limitProcess = prev })
				}
				plugin := realPlugin(t)
				path := filepath.Join(t.TempDir(), "bomb"+filepath.Ext(name))
				mk(t, plugin, path)
				out := t.TempDir()
				peak := peakWatcher(t, out)
				ex, err := plugin.ExtractFile(path, out, limits)
				if err != nil {
					t.Fatalf("ExtractFile() error = %v", err)
				}
				if len(ex.Files) != 0 || len(ex.Skipped) != 1 || ex.Skipped[0].Reason != datamodel.NotAnalyzedTooBig {
					t.Errorf("Extraction = %+v, want the member reported too-big and nothing extracted", ex)
				}
				entries, readErr := os.ReadDir(out)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if len(entries) != 0 {
					t.Errorf("the output folder still holds %d entries: partial files must be removed", len(entries))
				}
				if kernelLimit {
					if p := peak(); p > limits.MaxFileSize+slack {
						t.Errorf("up to %d MiB were written for a limit of %d MiB: it must stop during the write", p/mib, limits.MaxFileSize/mib)
					}
				}
			})
		}
	}
}

// trapSevenZip is a 7z stand-in whose members written by `x` are 1 byte, except
// the ones named trap*, which are 3 MiB whatever the listing announced: it dies
// there with code 2, as 7z does under the kernel limit on file sizes. With
// finish true it carries on and exits with code 0.
func trapSevenZip(t *testing.T, listing string, finish ...bool) *sevenZipExtract {
	t.Helper()
	list := filepath.Join(t.TempDir(), "listing")
	if err := os.WriteFile(list, []byte(listing), 0o600); err != nil {
		t.Fatal(err)
	}
	onTrap := "exit 2"
	if len(finish) > 0 && finish[0] {
		onTrap = "true"
	}
	return fakeSevenZip(t, `
for a in "$@"; do case "$a" in -o*) out="${a#-o}";; esac; done
state=0
for a in "$@"; do
  case $state in
    0) [ "$a" = l ] && { cat `+list+`; exit 0; }; [ "$a" = x ] && state=1;;
    1) state=2;;
    2) case "$a" in
         trap*) head -c 3145728 /dev/zero > "$out/$a"; `+onTrap+`;;
         ghost) head -c 3145728 /dev/zero > "$out/unrelated";;
         *) printf x > "$out/$a";;
       esac;;
  esac
done
exit 0`)
}

func trapListing(normal int, traps ...string) string {
	lines := make([]string, 0, normal+len(traps))
	for i := range normal {
		lines = append(lines, listingLine(fmt.Sprintf("file%03d.txt", i), 1))
	}
	for _, n := range traps {
		lines = append(lines, listingLine(n, 1))
	}
	return listing(nil, lines...)
}

func skippedBy(ex extractResult, reason datamodel.NotAnalyzedReason) (names []string) {
	for _, s := range ex.skipped.entries {
		if s.Reason == reason {
			names = append(names, s.FileName)
		}
	}
	return names
}

func TestExtract_trapMembersAreReportedAloneAndTheRestIsExtracted(t *testing.T) {
	limits := plugins.ExtractLimits{MaxFileSize: mib, MaxFiles: 1000, MaxTotalSize: 1 << 30}
	tests := []struct {
		name     string
		traps    []string
		wantBig  []string
		wantErrs int
	}{
		{name: "one trap among 150", traps: []string{"trap1"}, wantBig: []string{"trap1"}},
		{name: "two traps: two relaunches", traps: []string{"trap1", "trap2"}, wantBig: []string{"trap1", "trap2"}},
		{
			name: "eight traps are still relaunched", traps: []string{"trap1", "trap2", "trap3", "trap4", "trap5", "trap6", "trap7", "trap8"},
			wantBig: []string{"trap1", "trap2", "trap3", "trap4", "trap5", "trap6", "trap7", "trap8"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sze := trapSevenZip(t, trapListing(150, tt.traps...))
			out := t.TempDir()
			res, err := sze.extract(t.Context(), "archive.7z", out, nil, limits)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.extractedFiles) != 150 {
				t.Errorf("extracted %d files, want the 150 normal members", len(res.extractedFiles))
			}
			if got := skippedBy(res, datamodel.NotAnalyzedTooBig); !equalSets(got, tt.wantBig) {
				t.Errorf("too-big = %v, want %v", got, tt.wantBig)
			}
			if got := skippedBy(res, datamodel.NotAnalyzedExtractError); len(got) != 0 {
				t.Errorf("extract-error = %v, want none", got)
			}
			if len(res.anomalies) != 0 {
				t.Errorf("anomalies = %v, want none: a member past the limit is not an anomaly of the archive", res.anomalies)
			}
		})
	}
}

func equalSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestExtract_nineTrapsExhaustTheRelaunchesAndTheRestIsLeftOut(t *testing.T) {
	traps := []string{"trap1", "trap2", "trap3", "trap4", "trap5", "trap6", "trap7", "trap8", "trap9"}
	sze := trapSevenZip(t, trapListing(20, traps...))
	res, err := sze.extract(t.Context(), "archive.7z", t.TempDir(), nil, plugins.ExtractLimits{MaxFileSize: mib, MaxFiles: 1000, MaxTotalSize: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if len(skippedBy(res, datamodel.NotAnalyzedTooBig)) != 8 {
		t.Errorf("too-big = %v, want 8 members", skippedBy(res, datamodel.NotAnalyzedTooBig))
	}
	left := skippedBy(res, datamodel.NotAnalyzedExtractLimit)
	if len(left) != 20+1 || len(res.anomalies) != 0 {
		t.Errorf("extract-limit = %d members and anomalies %v, want the 21 left members left out by the limit, no anomaly", len(left), res.anomalies)
	}
	if len(res.extractedFiles) != 0 {
		t.Errorf("%d files were handed over after an abandoned batch: nothing partial may pass", len(res.extractedFiles))
	}
}

func TestExtract_unidentifiableOffenderLeavesTheBatchOutAsExtractLimit(t *testing.T) {
	sze := trapSevenZip(t, trapListing(5, "ghost"))
	res, err := sze.extract(t.Context(), "archive.7z", t.TempDir(), nil, plugins.ExtractLimits{MaxFileSize: mib, MaxFiles: 100, MaxTotalSize: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if len(skippedBy(res, datamodel.NotAnalyzedTooBig)) != 0 || len(skippedBy(res, datamodel.NotAnalyzedExtractLimit)) != 6 || len(res.anomalies) != 0 {
		t.Errorf("skipped = %+v, anomalies %v, want the 6 members extract-limit, no anomaly and never too-big", res.skipped.entries, res.anomalies)
	}
}

func TestExtract_writingMoreThanAnnouncedBreaksTheBudgetAndLeavesEveryMemberOut(t *testing.T) {
	// Announced: 5 members of 1 byte; written: 5 x 300 KiB with a 1 MiB budget.
	sze := fakeSevenZip(t, `
list="`+filepath.Join(t.TempDir(), "listing")+`"
`+"cat > $list <<'EOF'\n"+listing(nil, listingLine("a", 1), listingLine("b", 1), listingLine("c", 1), listingLine("d", 1), listingLine("e", 1))+"EOF\n"+`
for a in "$@"; do case "$a" in -o*) out="${a#-o}";; esac; done
for a in "$@"; do [ "$a" = l ] && { cat $list; exit 0; }; done
for n in a b c d e; do head -c 307200 /dev/zero > "$out/$n"; done
exit 0`)
	res, err := sze.extract(t.Context(), "archive.7z", t.TempDir(), nil, plugins.ExtractLimits{MaxFileSize: mib, MaxFiles: 100, MaxTotalSize: mib})
	if err != nil {
		t.Fatal(err)
	}
	if got := skippedBy(res, datamodel.NotAnalyzedExtractLimit); len(got) != 5 {
		t.Errorf("extract-limit = %v, want the 5 members: a breach of the budget is a limit, decided by too_big", got)
	}
	if len(skippedBy(res, datamodel.NotAnalyzedExtractError)) != 0 || len(res.extractedFiles) != 0 || len(res.anomalies) != 0 {
		t.Errorf("result = %+v, want nothing extracted, no extract-error and no anomaly", res)
	}
}

func TestExtract_archiveRunsPastItsTimeIsKilledAsAnError(t *testing.T) {
	prevBase, prevRate := baseArchiveTimeout, archiveBytesPerSecond
	baseArchiveTimeout, archiveBytesPerSecond = time.Second, 1<<40
	t.Cleanup(func() { baseArchiveTimeout, archiveBytesPerSecond = prevBase, prevRate })
	sze := fakeSevenZip(t, `
for a in "$@"; do [ "$a" = l ] && { cat <<'EOF'
`+listing(nil, listingLine("a", 1))+`EOF
exit 0; }; done
sleep 60`)
	start := time.Now()
	_, err := sze.extract(t.Context(), "archive.7z", t.TempDir(), nil, openLimits)
	if !errors.Is(err, errSevenZipTimeout) || time.Since(start) > 15*time.Second {
		t.Errorf("extract() = %v after %v, want errSevenZipTimeout, promptly", err, time.Since(start))
	}
}

func TestArchiveTimeout_growsWithTheArchiveAndTheBudgetUpToTheCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a")
	if err := os.WriteFile(path, make([]byte, 10*mib), 0o600); err != nil {
		t.Fatal(err)
	}
	small := archiveTimeout(path, 0)
	big := archiveTimeout(path, 50*mib)
	if small < baseArchiveTimeout || big <= small || archiveTimeout(path, 1<<60) != szRunTimeout {
		t.Errorf("timeouts = %v, %v, want base <= small < big <= %v", small, big, szRunTimeout)
	}
}

func TestListSink_unknownSizeWeighsTheLargestMember(t *testing.T) {
	blank := fmt.Sprintf("%-19s %-5s %12s %12s  %s", "2024-01-01 00:00:00", "....A", "", "", "stream")
	notNumeric := fmt.Sprintf("%-19s %-5s %12s %12s  %s", "2024-01-01 00:00:00", "....A", "?", "?", "weird")
	negative := fmt.Sprintf("%-19s %-5s %12s %12s  %s", "2024-01-01 00:00:00", "....A", "-1", "-1", "neg")
	for name, line := range map[string]string{"blank": blank, "not numeric": notNumeric, "negative": negative} {
		t.Run(name, func(t *testing.T) {
			// Budget of 10 MiB with members of at most 4 MiB: two unknown members
			// fit, the third does not.
			s := newListSink(4*mib, 100, 10*mib)
			input := listing(nil, line, strings.Replace(line, line[52:], "second", 1), strings.Replace(line, line[52:], "third", 1))
			if err := s.scan(strings.NewReader(input)); err != nil {
				t.Fatal(err)
			}
			if s.table.selectedCount != 2 || s.table.selectedSize != 8*mib {
				t.Errorf("selected %d members of %d bytes, want 2 of 8 MiB (each unknown size weighs the limit, never 0)", s.table.selectedCount, s.table.selectedSize)
			}
			if got := s.table.skipped.entries; len(got) != 1 || got[0].Reason != datamodel.NotAnalyzedExtractLimit {
				t.Errorf("skipped = %+v, want the third member extract-limit", got)
			}
			if s.table.totalSize != 12*mib {
				t.Errorf("zip bomb total = %d, want the unknown sizes counted as the limit", s.table.totalSize)
			}
		})
	}
}

func TestExtract_exitCodeZeroWithAMemberPastTheLimitReportsOnlyThatMemberWithoutRelaunch(t *testing.T) {
	sze := trapSevenZip(t, trapListing(10, "trap1", "trap2"), true)
	counter := filepath.Join(t.TempDir(), "launches")
	// Count the launches of `x` through a wrapper around the stand-in.
	wrapper := fakeSevenZip(t, `for a in "$@"; do [ "$a" = x ] && echo x >> `+counter+`; done; exec `+sze.sevenZipPath+` "$@"`)
	res, err := wrapper.extract(t.Context(), "archive.7z", t.TempDir(), nil, plugins.ExtractLimits{MaxFileSize: mib, MaxFiles: 100, MaxTotalSize: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if got := skippedBy(res, datamodel.NotAnalyzedTooBig); !equalSets(got, []string{"trap1", "trap2"}) {
		t.Errorf("too-big = %v, want trap1 and trap2", got)
	}
	if len(res.extractedFiles) != 10 || len(res.anomalies) != 0 {
		t.Errorf("extracted %d files, anomalies %v, want the 10 normal members and no anomaly", len(res.extractedFiles), res.anomalies)
	}
	raw, err := os.ReadFile(filepath.Clean(counter))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(raw), "x"); n != 1 {
		t.Errorf("7z was launched %d times, want 1: nothing is relaunched when 7z finished by itself", n)
	}
}

func TestExtract_checkAfter7zAloneCatchesAMemberPastTheLimit(t *testing.T) {
	prev := guardEnabled
	guardEnabled = false
	t.Cleanup(func() { guardEnabled = prev })
	sze := trapSevenZip(t, trapListing(5, "trap1"), true)
	out := t.TempDir()
	res, err := sze.extract(t.Context(), "archive.7z", out, nil, plugins.ExtractLimits{MaxFileSize: mib, MaxFiles: 100, MaxTotalSize: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if got := skippedBy(res, datamodel.NotAnalyzedTooBig); !equalSets(got, []string{"trap1"}) || len(res.extractedFiles) != 5 {
		t.Errorf("too-big = %v, %d files extracted, want trap1 reported and the 5 others kept", got, len(res.extractedFiles))
	}
	if _, err := os.Stat(filepath.Join(out, "trap1")); err == nil {
		t.Error("the file past the limit was handed over")
	}
}

func TestExtract_wrongPasswordKeepsWhatTheListingDecided(t *testing.T) {
	list := filepath.Join(t.TempDir(), "listing")
	text := listing(nil, listingLine("big.bin", 300*mib), listingLine("small.txt", 1))
	if err := os.WriteFile(list, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	// Wrong password with the empty one, success with "infected".
	sze := fakeSevenZip(t, `
for a in "$@"; do case "$a" in -o*) out="${a#-o}";; esac; done
for a in "$@"; do [ "$a" = l ] && { cat `+list+`; exit 0; }; done
for a in "$@"; do [ "$a" = "-p-" ] && { echo "ERROR: Wrong password : small.txt" >&2; exit 2; }; done
printf x > "$out/small.txt"
exit 0`)
	sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
	res, err := sze.extract(t.Context(), "archive.7z", t.TempDir(), nil, plugins.ExtractLimits{MaxFileSize: 100 * mib, MaxFiles: 100, MaxTotalSize: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if got := skippedBy(res, datamodel.NotAnalyzedTooBig); !equalSets(got, []string{"big.bin"}) || len(res.extractedFiles) != 1 || res.passwordUsed != "infected" {
		t.Errorf("too-big = %v, %d files, password %q: the member skipped by the listing must stay reported after the password changed", got, len(res.extractedFiles), res.passwordUsed)
	}
}

func TestExtract_memberOverTheLimitIsNeverRequested(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "extracted")
	sze := fakeSevenZip(t, `
list="`+filepath.Join(t.TempDir(), "l")+`"
`+"cat > $list <<'EOF'\n"+listing(nil, listingLine("huge.bin", 300*mib))+"EOF\n"+`
for a in "$@"; do [ "$a" = l ] && { cat $list; exit 0; }; done
touch `+marker+`
exit 0`)
	res, err := sze.extract(t.Context(), "archive.7z", t.TempDir(), nil, plugins.ExtractLimits{MaxFileSize: 100 * mib, MaxFiles: 100, MaxTotalSize: 1 << 40})
	if err != nil || len(skippedBy(res, datamodel.NotAnalyzedTooBig)) != 1 {
		t.Fatalf("extract() = %+v, %v", res.skipped, err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("7z was asked to extract a member announced over the limit")
	}
}

func TestScan_memberPathNestedTooDeepIsAnAnomalyAndNotExtracted(t *testing.T) {
	deep := strings.Repeat("d/", 600) + "f"
	s := newListSink(mib, 100, 1<<30)
	if err := s.scan(strings.NewReader(listing(nil, listingLine("ok.txt", 1), listingLine(deep, 1)))); err != nil {
		t.Fatal(err)
	}
	if len(s.table.selected) != 1 || len(s.anomalies) != 1 {
		t.Errorf("selected %v, anomalies %v, want only ok.txt selected and the deep path reported", s.table.selected, s.anomalies)
	}
}

func TestRealSevenZip_zipWithDeepPathsCreatesNoFolders(t *testing.T) {
	members := make([]zipMember, 0, 20)
	for i := range 20 {
		members = append(members, zipMember{name: strings.Repeat("d/", 600) + strconv.Itoa(i), data: "x"})
	}
	path := filepath.Join(t.TempDir(), "deep.zip")
	writeZip(t, path, "", members...)
	out := t.TempDir()
	ex, err := realPlugin(t).ExtractFile(path, out, openLimits)
	requireAnomaly(t, ex, err, path)
	count := 0
	_ = filepath.WalkDir(out, func(string, os.DirEntry, error) error { count++; return nil })
	if count > 10 {
		t.Errorf("%d entries created for members that are too deep to be extracted", count)
	}
}

func TestGuard_budgetCountsFolders(t *testing.T) {
	dir := t.TempDir()
	for i := range 50 {
		if err := os.MkdirAll(filepath.Join(dir, strconv.Itoa(i), "x"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// 2*maxFiles+maxDirSlack = 0 folders allowed.
	g := &guard{dir: dir, maxFileSize: mib, maxTotal: mib, maxFiles: -maxDirSlack / 2, logger: slog.New(slog.DiscardHandler)}
	if hit := g.measure(); hit == nil || !hit.budget {
		t.Errorf("measure() = %+v, want a budget breach for the folders created", hit)
	}
}

func TestGuard_unreadableOutputIsABreach(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	dir := t.TempDir()
	sub := filepath.Join(dir, "locked")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sub, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(sub, modeScript); err != nil {
			t.Error(err)
		}
	})
	g := &guard{dir: dir, maxFileSize: mib, maxTotal: mib, maxFiles: 10, logger: slog.New(slog.DiscardHandler)}
	if hit := g.measure(); hit == nil || !hit.broken {
		t.Errorf("measure() = %+v, want a broken measure for an unreadable folder", hit)
	}
	if _, err := snapshot(dir); err == nil {
		t.Error("snapshot() of an unreadable folder error = nil: an incomplete snapshot makes a cleanup remove legitimate files")
	}
}

func TestFileLimitFor(t *testing.T) {
	tests := []struct {
		maxFile, maxTotal, written, want int64
	}{
		{100, 1000, 0, 101},
		{100, 150, 100, 51},
		{100, 150, 500, 1},
		{math.MaxInt64, math.MaxInt64, 0, 0},
	}
	for _, tt := range tests {
		if got := fileLimitFor(tt.maxFile, tt.maxTotal, tt.written); got != tt.want {
			t.Errorf("fileLimitFor(%d, %d, %d) = %d, want %d", tt.maxFile, tt.maxTotal, tt.written, got, tt.want)
		}
	}
}

func TestArchiveTimeout_doesNotOverflowOnHugeLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a")
	if err := os.WriteFile(path, make([]byte, mib), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := archiveTimeout(path, math.MaxInt64); got != szRunTimeout {
		t.Errorf("archiveTimeout(MaxInt64) = %v, want the cap %v", got, szRunTimeout)
	}
}

func TestSkipList_keepsSizesBeyondTwoGiB(t *testing.T) {
	var s skipList
	s.add("big", 3<<30, datamodel.NotAnalyzedTooBig)
	if s.entries[0].Size != 3<<30 {
		t.Errorf("size = %d, want 3 GiB reported as is", s.entries[0].Size)
	}
}

func BenchmarkGuardMeasure(b *testing.B) {
	dir := b.TempDir()
	for i := range 1000 {
		sub := filepath.Join(dir, strconv.Itoa(i%20))
		if err := os.MkdirAll(sub, 0o700); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sub, strconv.Itoa(i)), make([]byte, 1024), 0o600); err != nil {
			b.Fatal(err)
		}
	}
	g := &guard{dir: dir, maxFileSize: mib, maxTotal: 1 << 30, maxFiles: 10000, logger: slog.New(slog.DiscardHandler)}
	b.ReportAllocs()
	for b.Loop() {
		if hit := g.measure(); hit != nil {
			b.Fatalf("unexpected breach %+v", hit)
		}
	}
}

// BenchmarkExtract_bigMember extracts a 64 MiB member of a gzip with and
// without the guard and the kernel limit, to show what they cost.
func BenchmarkExtract_bigMember(b *testing.B) {
	plugin := &SevenZipExtractPlugin{}
	sze := realSevenZipForBench(b)
	plugin.sze, plugin.logger, plugin.consoleLogger = sze, sze.logger, sze.logger
	path := filepath.Join(b.TempDir(), "big.gz")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	zeros := make([]byte, mib)
	for range 64 {
		if _, err := gz.Write(zeros); err != nil {
			b.Fatal(err)
		}
	}
	if err := gz.Close(); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		b.Fatal(err)
	}
	limits := plugins.ExtractLimits{MaxFileSize: 128 * mib, MaxFiles: 100, MaxTotalSize: 1 << 30}
	for _, guarded := range []bool{false, true} {
		b.Run(fmt.Sprintf("guard=%t", guarded), func(b *testing.B) {
			prev := guardEnabled
			guardEnabled = guarded
			b.Cleanup(func() { guardEnabled = prev })
			for b.Loop() {
				out := b.TempDir()
				ex, err := plugin.ExtractFile(path, out, limits)
				if err != nil || len(ex.Files) != 1 {
					b.Fatalf("ExtractFile() = %+v, %v", ex, err)
				}
				if err := os.RemoveAll(out); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestExtract_memberAnnouncedSmallButWritingPastTheBudgetIsExtractLimitNotTooBig(t *testing.T) {
	// Announced 1 MiB, writes 50 MiB, with a 5 MiB budget and a 100 MiB per-file limit.
	sze := fakeSevenZip(t, `
list="`+filepath.Join(t.TempDir(), "l")+`"
`+"cat > $list <<'EOF'\n"+listing(nil, listingLine("liar.bin", mib))+"EOF\n"+`
for a in "$@"; do case "$a" in -o*) out="${a#-o}";; esac; done
for a in "$@"; do [ "$a" = l ] && { cat $list; exit 0; }; done
head -c 52428800 /dev/zero > "$out/liar.bin"
exit 0`)
	res, err := sze.extract(t.Context(), "archive.7z", t.TempDir(), nil, plugins.ExtractLimits{MaxFileSize: 100 * mib, MaxFiles: 100, MaxTotalSize: 5 * mib})
	if err != nil {
		t.Fatal(err)
	}
	if len(skippedBy(res, datamodel.NotAnalyzedTooBig)) != 0 || !equalSets(skippedBy(res, datamodel.NotAnalyzedExtractLimit), []string{"liar.bin"}) || len(res.anomalies) != 0 {
		t.Errorf("skipped = %+v, anomalies %v, want liar.bin extract-limit, never too-big, no anomaly", res.skipped.entries, res.anomalies)
	}
	if len(res.extractedFiles) != 0 {
		t.Errorf("%d files handed over after the budget was broken", len(res.extractedFiles))
	}
}

func TestGuard_fastWritesAreStoppedAtTheFirstMeasureCrossingTheThreshold(t *testing.T) {
	prev := guardInterval
	guardInterval = 20 * time.Millisecond
	t.Cleanup(func() { guardInterval = prev })
	// 100 files of 1 MiB written 10 ms apart; budget 3 MiB.
	sze := fakeSevenZip(t, `
list="`+filepath.Join(t.TempDir(), "l")+`"
`+"cat > $list <<'EOF'\n"+listing(nil, listingLine("a", 1))+"EOF\n"+`
for a in "$@"; do case "$a" in -o*) out="${a#-o}";; esac; done
for a in "$@"; do [ "$a" = l ] && { cat $list; exit 0; }; done
i=0
while [ $i -lt 100 ]; do head -c 1048576 /dev/zero > "$out/f$i"; i=$((i+1)); sleep 0.01; done
exit 0`)
	out := t.TempDir()
	peak := peakWatcher(t, out)
	start := time.Now()
	res, err := sze.extract(t.Context(), "archive.7z", out, nil, plugins.ExtractLimits{MaxFileSize: 100 * mib, MaxFiles: 1000, MaxTotalSize: 3 * mib})
	if err != nil {
		t.Fatal(err)
	}
	if len(skippedBy(res, datamodel.NotAnalyzedExtractLimit)) != 1 {
		t.Errorf("skipped = %+v, want the member extract-limit", res.skipped.entries)
	}
	if p := peak(); p > 12*mib {
		t.Errorf("up to %d MiB were written for a budget of 3 MiB: the first measure past the threshold must stop 7z", p/mib)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("took %v: 7z was not stopped", time.Since(start))
	}
}

func TestExtract_nineTrapsAcrossBatchesAreEightRelaunchesInTotal(t *testing.T) {
	// 450 normal members make 3 batches; one trap lands in each of the first
	// three batches, and six more in the last one: 9 traps in all.
	var lines []string
	for i := range 450 {
		lines = append(lines, listingLine(fmt.Sprintf("file%03d.txt", i), 1))
		if i == 10 {
			lines = append(lines, listingLine("trap-a", 1))
		}
	}
	traps := []string{"trap-b", "trap-c", "trap-d", "trap-e", "trap-f", "trap-g", "trap-h", "trap-i"}
	for _, n := range traps {
		lines = append(lines, listingLine(n, 1))
	}
	sze := trapSevenZip(t, listing(nil, lines...))
	res, err := sze.extract(t.Context(), "archive.7z", t.TempDir(), nil, plugins.ExtractLimits{MaxFileSize: mib, MaxFiles: 1000, MaxTotalSize: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(skippedBy(res, datamodel.NotAnalyzedTooBig)); n != 8 {
		t.Errorf("too-big = %d members, want 8: the relaunches are counted over all the batches", n)
	}
	if len(skippedBy(res, datamodel.NotAnalyzedExtractLimit)) == 0 || len(res.anomalies) != 0 {
		t.Errorf("skipped = %d, anomalies %v, want the members left after the 8th relaunch as extract-limit", res.skipped.count, res.anomalies)
	}
}

func TestRealSevenZip_budgetLeftIsTheKernelLimitAndLeavesTheMemberOut(t *testing.T) {
	// The per-file limit is 1 GiB but only 4 MiB of budget remain: the kernel
	// stops the file at the budget, which is an archive that lied, not a big member.
	limits := plugins.ExtractLimits{MaxFileSize: 1 << 30, MaxFiles: 100, MaxTotalSize: 4 * mib}
	plugin := realPlugin(t)
	path := filepath.Join(t.TempDir(), "bomb.gz")
	gzipOfZeros(t, path, 24, true)
	out := t.TempDir()
	peak := peakWatcher(t, out)
	ex, err := plugin.ExtractFile(path, out, limits)
	if err != nil {
		t.Fatal(err)
	}
	var tooBig, extractErr int
	for _, s := range ex.Skipped {
		switch s.Reason {
		case datamodel.NotAnalyzedTooBig:
			tooBig++
		case datamodel.NotAnalyzedExtractLimit:
			extractErr++
		}
	}
	if tooBig != 0 || extractErr == 0 || len(ex.Files) != 0 {
		t.Errorf("Extraction = %+v, want an extract-limit entry and never too-big", ex)
	}
	if p := peak(); p > limits.MaxTotalSize+slack {
		t.Errorf("up to %d MiB were written for a budget of 4 MiB", p/mib)
	}
}
