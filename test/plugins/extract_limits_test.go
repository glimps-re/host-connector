//go:build linux && (e2e || e2e_plugins)

package plugins

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// zeroReader reads zeros for ever.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// bombZip is a ZIP of one member of size zeros: tiny, and it inflates to size.
func bombZip(t *testing.T, size int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("zeros.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.CopyN(w, zeroReader{}, size); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// bombGzip is a gzip of size zeros.
func bombGzip(t *testing.T, size int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := io.CopyN(gz, zeroReader{}, size); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// P20: archives built to exhaust the extraction (a ZIP and a gzip that inflate
// to far more than the limit) are not extracted past the limit, are not
// delivered, and stay in INPUT with an error in the report.
func TestE2E_extractionBombsAreStopped(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		make func(*testing.T, int64) []byte
	}{
		{name: "bomb.zip", make: bombZip},
		{name: "bomb.gz", make: bombGzip},
	} {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  map[string]any{"recursive_extract_max_size": "4MiB"},
				Files:   []harness.File{{Path: tt.name, Content: tt.make(t, 64<<20)}},
				Want: map[string]harness.Outcome{
					tt.name: {In: harness.Input, Error: "left out by the limits of the extraction"},
				},
			})
		})
	}
}

// maxWorkBytes bounds what the work directory may hold at any moment while an
// archive that forges a bomb is judged: the embedded 7-Zip it holds is a few
// MiB, a bomb written out would be gigabytes.
const maxWorkBytes = 64 << 20

// bombJudgmentBound bounds the time to judge a bomb.
const bombJudgmentBound = 30 * time.Second

// treeSize adds up the sizes of the regular files below dir, as they are on the
// disk: a link (the plugin stages the archive it runs 7-Zip on as one) is not
// followed and counts for nothing. A folder that does not exist, or any other
// failure of the walk, is an error; an entry that goes away while it is
// measured (a clean-up in progress) is not, and a walk that ends early for that
// reason gives the partial total of that sample, which is harmless since only
// the largest sample counts.
func treeSize(dir string) (total int64, err error) {
	if _, err = os.Lstat(dir); err != nil {
		return 0, err
	}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if path != dir && errors.Is(walkErr, fs.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, infoErr := d.Info()
		switch {
		case errors.Is(infoErr, fs.ErrNotExist):
			return nil
		case infoErr != nil:
			return infoErr
		}
		total += info.Size()
		return nil
	})
	return total, err
}

// sizeWatch samples the size of a folder from its start to its stop, so that a
// file written and removed within one judgment is still seen.
type sizeWatch struct {
	max  atomic.Int64
	mu   sync.Mutex
	err  error
	quit chan struct{}
	done chan struct{}
	once sync.Once
}

// watchSize samples the work directory of the run every 50 ms until stop or the end of the test.
func watchSize(t *testing.T, in *harness.Instance) *sizeWatch {
	t.Helper()
	w := &sizeWatch{quit: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		for {
			size, err := treeSize(in.Work)
			switch {
			case err != nil:
				w.mu.Lock()
				if w.err == nil {
					w.err = err
				}
				w.mu.Unlock()
			case size > w.max.Load():
				w.max.Store(size)
			}
			select {
			case <-w.quit:
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()
	t.Cleanup(func() { _, _ = w.stop() })
	return w
}

// stop ends the sampling and returns the largest size seen, and the first
// failure of the walk if any.
func (w *sizeWatch) stop() (largest int64, err error) {
	w.once.Do(func() { close(w.quit) })
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.max.Load(), w.err
}

// assertNoBigWrite fails when the work directory was ever bigger than
// maxWorkBytes, when it could not be measured, or when nothing was ever seen
// there (the sampling would then prove nothing).
func assertNoBigWrite(t *testing.T, w *sizeWatch) {
	t.Helper()
	largest, err := w.stop()
	if err != nil {
		t.Errorf("the work directory could not be measured: %v", err)
	}
	if largest == 0 {
		t.Error("nothing was ever seen in the work directory: the sampling proves nothing")
	}
	if largest > maxWorkBytes {
		t.Errorf("the work directory held %d bytes at some point: the archive was written out", largest)
	}
}

// T48c: a ZIP that forges a bomb is refused, under the default limits, within a
// bounded time and without being written out: 40 members of 90 MB, each declared
// with no packed byte, stay under the per-member and total limits but cannot be
// real.
func TestE2E_aForgedZipOfEmptyPackedMembersIsABomb(t *testing.T) {
	gm := gmalware.New(t, false)
	in := harness.Start(t, gm, harness.Options{Plugins: map[string]map[string]any{"extract": nil}})
	work := watchSize(t, in)
	entries := make([]rawEntry, 0, 40)
	for i := range 40 {
		entries = append(entries, rawEntry{name: fmt.Sprintf("zeros%02d.bin", i), declared: 90_000_000})
	}
	archive := rawZip{entries: entries}.bytes()
	start := time.Now()
	path := in.Drop(t, "bomb.zip", archive)
	in.WaitFor(t, "the connector to call the archive a bomb", func() bool { return in.LogHas("potential ZipBomb") })
	if judged := time.Since(start); judged > bombJudgmentBound {
		t.Errorf("the bomb was judged in %s, want at most %s", judged, bombJudgmentBound)
	}
	in.StaysInInput(t, path, archive)
	assertNoBigWrite(t, work)
}

// T48c: a solid 7z whose first member is larger than the limit for a member and
// made of zeros (23 KB packed for 150 MiB) is left out by the limits of the
// extraction: it stays in INPUT in error and the member is not written out. It
// is not called a bomb: its members within the limit do not declare 3 GB.
func TestE2E_aSolidSevenZipWithAHugeFirstMemberIsLeftOutAndNotWrittenOut(t *testing.T) {
	gm := gmalware.New(t, false)
	in := harness.Start(t, gm, harness.Options{Plugins: map[string]map[string]any{"extract": nil}})
	work := watchSize(t, in)
	bin := sevenZip(t)
	src := t.TempDir()
	f, err := os.OpenFile(filepath.Clean(filepath.Join(src, "a-zeros.bin")), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(150 << 20); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(src, "b-small.txt"), []byte(strings.Repeat("a small member after the bomb ", 40)), 0o600); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "bomb.7z")
	if out, runErr := harness.RunCommand(src, bin, "a", "-t7z", "-ms=on", archivePath, "a-zeros.bin", "b-small.txt"); runErr != nil {
		t.Fatalf("cannot build the archive: %v\n%s", runErr, out)
	}
	archive, err := os.ReadFile(filepath.Clean(archivePath))
	if err != nil {
		t.Fatal(err)
	}
	path := in.Drop(t, "bomb.7z", archive)
	in.StaysInInput(t, path, archive)
	if !in.LogHas("left out by the limits of the extraction") {
		t.Error("the log does not say the member was left out by the limits of the extraction")
	}
	assertNoBigWrite(t, work)
}

// treeSize counts regular files only: a link is no failure and no size, a
// missing folder is an error.
func TestTreeSize(t *testing.T) {
	dir := t.TempDir()
	harness.Write(t, filepath.Join(dir, "a.bin"), make([]byte, 1000))
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	harness.Write(t, filepath.Join(dir, "sub", "b.bin"), make([]byte, 24))
	if err := os.Symlink(filepath.Join(dir, "a.bin"), filepath.Join(dir, "link-to-file")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "sub"), filepath.Join(dir, "link-to-dir")); err != nil {
		t.Fatal(err)
	}
	total, err := treeSize(dir)
	if err != nil || total != 1024 {
		t.Errorf("treeSize = %d, %v; want 1024 and no error: links count for nothing and are no failure", total, err)
	}
	if _, err = treeSize(filepath.Join(dir, "missing")); err == nil {
		t.Error("treeSize of a missing folder is not an error")
	}
}

// p3/T62: a docx, a jar or an apk over the check limits (10,001 entries) is
// analyzed whole and delivered as a plain file, under the default policies. It
// counts as analyzed, and its members are listed as not analyzed for the
// extract limit, with the exact count.
func TestE2E_anOverLimitDocumentIsDeliveredWithItsMembersUnchecked(t *testing.T) {
	s := harness.Scenario{
		Plugins: map[string]map[string]any{"extract": nil},
		Want:    map[string]harness.Outcome{},
	}
	docs := map[string][]byte{}
	for _, kind := range []string{"docx", "jar", "apk"} {
		doc := bigDocument(t, kind, "delivered "+kind, overLimitEntries, false)
		names := entryNamesOf(t, doc)
		docs[kind] = doc
		s.Files = append(s.Files, harness.File{Path: "big." + kind, Content: doc})
		s.Want["big."+kind] = harness.Outcome{
			In:                 harness.Output,
			SubmittedAs:        []string{"big." + kind},
			ServiceVerdict:     harness.Given,
			NotAnalyzedMembers: &harness.MemberList{Reason: datamodel.NotAnalyzedExtractLimit, Count: overLimitEntries},
			Entry: func(e datamodel.Report) string {
				return strings.Join(overLimitViolations(e, overLimitEntries, names), "; ")
			},
		}
	}
	in := harness.Run(t, s)
	for kind, doc := range docs {
		if n := len(in.ReportsOf(t, doc)); n != 1 {
			t.Errorf("%s: %d report entries for the document, want 1", kind, n)
		}
	}
}

// p3/T62: a detection on an over-limit document still quarantines it: it never
// reaches OUTPUT, and its report lists no unchecked member, as the detection
// is the outcome.
func TestE2E_anOverLimitDocumentThatIsMalwareIsQuarantined(t *testing.T) {
	harness.Run(t, harness.Scenario{
		Plugins: map[string]map[string]any{"extract": nil},
		Files: []harness.File{
			{Path: "bad.docx", Content: bigDocument(t, "docx", "malicious", overLimitEntries, false), Verdict: harness.Malicious},
		},
		Want: map[string]harness.Outcome{
			"bad.docx": {In: harness.Quarantine, Malware: datamodel.MalwareDetected, NotAnalyzedMembers: harness.NoMembers},
		},
	})
}

// p3/T62: the relief is for documents only. An ordinary zip over the limits is
// still left out and held in INPUT, whatever its entries; a document of the
// same run is delivered, so the difference is the type, not the load.
func TestE2E_anOrdinaryZipOverTheLimitsIsStillHeld(t *testing.T) {
	harness.Run(t, harness.Scenario{
		Plugins: map[string]map[string]any{"extract": nil},
		Files: []harness.File{
			{Path: "big.zip", Content: bigPlainZip(t, "ordinary", overLimitEntries)},
			{Path: "ctl.docx", Content: bigDocument(t, "docx", "control", overLimitEntries, false)},
		},
		Want: map[string]harness.Outcome{
			"big.zip":  {In: harness.Input, Error: "left out by the limits of the extraction", NotAnalyzedMembers: harness.NoMembers},
			"ctl.docx": {In: harness.Output, NotAnalyzedMembers: &harness.MemberList{Reason: datamodel.NotAnalyzedExtractLimit}},
		},
	})
}

// randomBytes is incompressible and reproducible.
func randomBytes(t *testing.T, n int, seed byte) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.NewChaCha8([32]byte{seed}).Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// mib is one MiB.
const mib = 1 << 20

// stored packs the members as a ZIP of stored members.
func stored(t *testing.T, members map[string]string) []byte {
	t.Helper()
	entries := make([]rawEntry, 0, len(members))
	for name, data := range members {
		entries = append(entries, rawEntry{name: name, data: data})
	}
	slices.SortFunc(entries, func(x, y rawEntry) int { return strings.Compare(x.name, y.name) })
	return rawZip{entries: entries}.bytes()
}

// T77b: max_file_size bounds what is submitted, not what is extracted. A nested
// archive above max_file_size is opened and the detected sample inside it is
// analyzed: the outer archive is quarantined.
func TestE2E_aNestedArchiveAboveMaxFileSizeIsOpened(t *testing.T) {
	bad := harness.File{Path: "a-bad.bin", Content: []byte(strings.Repeat("a sample inside a nested archive above max_file_size ", 40)), Verdict: harness.Malicious}
	pad1 := harness.File{Path: "pad1.bin", Content: randomBytes(t, 768<<10, 1)}
	pad2 := harness.File{Path: "pad2.bin", Content: randomBytes(t, 768<<10, 3)}
	inner := archive(t, "inner.zip", stored, bad, pad1, pad2)
	if len(inner.Content) <= mib {
		t.Fatalf("inner is %d bytes, want more than 1MiB", len(inner.Content))
	}
	harness.Run(t, harness.Scenario{
		Plugins: map[string]map[string]any{"extract": nil},
		Config:  map[string]any{"max_file_size": "1MiB"},
		Files: []harness.File{
			archive(t, "outer.zip", stored, inner),
		},
		Want: map[string]harness.Outcome{
			"outer.zip":                     {In: harness.Quarantine, Malware: datamodel.MalwareDetected},
			"outer.zip/inner.zip/a-bad.bin": {ServiceVerdict: harness.Given},
		},
	})
}

// T77b: a member that is not an archive and is above max_file_size is still
// too big: with the default policy (error) the archive stays in INPUT.
func TestE2E_aNonArchiveMemberAboveMaxFileSizeIsTooBig(t *testing.T) {
	harness.Run(t, harness.Scenario{
		Plugins: map[string]map[string]any{"extract": nil},
		Config:  map[string]any{"max_file_size": "1MiB"},
		Files: []harness.File{
			archive(t, "outer.zip", stored, harness.File{Path: "big.bin", Content: randomBytes(t, 2*mib, 2)}),
		},
		Want: map[string]harness.Outcome{
			"outer.zip": {In: harness.Input, Error: "first: big.bin: file is too big to be analyzed: size 2 MiB exceeds max_file_size 1 MiB"},
		},
	})
}
