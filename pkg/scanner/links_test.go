package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// linkExtractor writes members (name -> content) and reports links, for the
// archive named archive; any other archive gets sub, a zip, as its only member
// when sub is not empty.
func linkExtractor(t *testing.T, archive string, members map[string]string, links []datamodel.NotAnalyzedFile, linksCount int, sub string) plugins.ExtractFile {
	t.Helper()
	return func(archivePath, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		if filepath.Base(archivePath) != archive {
			p := filepath.Join(outputDir, sub)
			if err := os.WriteFile(p, []byte(zipOf(t, 0)), 0o600); err != nil {
				return plugins.Extraction{}, err
			}
			return plugins.Extraction{Files: []string{p}}, nil
		}
		var e plugins.Extraction
		for n, c := range members {
			p := filepath.Join(outputDir, n)
			if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
				return plugins.Extraction{}, err
			}
			e.Files = append(e.Files, p)
			e.Size += uint64(len(c))
		}
		e.Links, e.LinksCount = links, linksCount
		return e, nil
	}
}

func notAnalyzedOf(r datamodel.Result) map[string]datamodel.NotAnalyzedFile {
	m := make(map[string]datamodel.NotAnalyzedFile, len(r.NotAnalyzedSubfiles))
	for _, f := range r.NotAnalyzedSubfiles {
		m[f.FileName] = f
	}
	return m
}

func TestLinks_aLinkAndAnEmptyMemberAreListedAndTheArchiveIsDelivered(t *testing.T) {
	tests := []struct {
		name      string
		sub       string
		wantLink  string
		wantEmpty string
	}{
		{"top level", "", "lnk", "empty.bin"},
		{"nested", "sub.zip", "sub.zip/lnk", "sub.zip/empty.bin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archive := "a.zip"
			if tt.sub != "" {
				archive = tt.sub
			}
			r := runAcc(t, accSetup{
				policy: Unanalyzable{TooBig: PolicyError},
				files:  map[string]string{"a.zip": zipOf(t, 0)},
				extract: linkExtractor(t, archive, map[string]string{"empty.bin": "", "ok.bin": "ok"},
					[]datamodel.NotAnalyzedFile{{FileName: "lnk", Size: 99, Reason: datamodel.NotAnalyzedTooBig}}, 1, tt.sub),
			})
			got := r.one(t, "a.zip")
			if got.result.Error != nil || got.result.Malware || got.src.TooBig {
				t.Fatalf("result = %+v: an archive with a link and an empty member must be delivered", got.result)
			}
			if !r.exists(r.out, "a.zip") {
				t.Error("a.zip was not delivered")
			}
			if got.result.NotAnalyzedSubfilesCount != 2 {
				t.Errorf("NotAnalyzedSubfilesCount = %d, want 2", got.result.NotAnalyzedSubfilesCount)
			}
			listed := notAnalyzedOf(got.result)
			if f := listed[tt.wantLink]; f.Reason != datamodel.NotAnalyzedSymlink || f.Size != 0 {
				t.Errorf("link entry = %+v, want %q with reason symlink and no size (listed %v)", f, tt.wantLink, got.result.NotAnalyzedSubfiles)
			}
			if f := listed[tt.wantEmpty]; f.Reason != datamodel.NotAnalyzedEmpty {
				t.Errorf("empty entry = %+v, want %q with reason empty (listed %v)", f, tt.wantEmpty, got.result.NotAnalyzedSubfiles)
			}
		})
	}
}

func TestLinks_anArchiveOfLinksOnlyIsAnalyzedAsAFileAndListsThem(t *testing.T) {
	links := []datamodel.NotAnalyzedFile{{FileName: "a", Reason: datamodel.NotAnalyzedSymlink}, {FileName: "b", Reason: datamodel.NotAnalyzedSymlink}}
	r := runAcc(t, accSetup{
		policy:  Unanalyzable{TooBig: PolicyError},
		files:   map[string]string{"a.zip": zipOf(t, 0)},
		extract: linkExtractor(t, "a.zip", nil, links, 2, ""),
	})
	got := r.one(t, "a.zip")
	if got.result.Error != nil || got.result.Malware {
		t.Fatalf("result = %+v, want a delivered archive", got.result)
	}
	if r.submitted.Load() != 1 {
		t.Errorf("submitted %d file(s), want the archive itself once", r.submitted.Load())
	}
	if got.result.NotAnalyzedSubfilesCount != 2 || len(got.result.NotAnalyzedSubfiles) != 2 {
		t.Errorf("not analyzed = %v (count %d), want both links", got.result.NotAnalyzedSubfiles, got.result.NotAnalyzedSubfilesCount)
	}
}

func TestLinks_manyLinksAreCappedWithAnExactCount(t *testing.T) {
	const n = 5000
	links := make([]datamodel.NotAnalyzedFile, n)
	for i := range links {
		links[i] = datamodel.NotAnalyzedFile{FileName: "l" + strings.Repeat("x", i%7), Reason: datamodel.NotAnalyzedSymlink}
	}
	r := runAcc(t, accSetup{
		files:   map[string]string{"a.zip": zipOf(t, 0)},
		extract: linkExtractor(t, "a.zip", map[string]string{"ok.bin": "ok"}, links, n, ""),
	})
	got := r.one(t, "a.zip")
	if len(got.result.NotAnalyzedSubfiles) > datamodel.MaxListedSubfiles {
		t.Errorf("listed %d links, want at most %d", len(got.result.NotAnalyzedSubfiles), datamodel.MaxListedSubfiles)
	}
	if got.result.NotAnalyzedSubfilesCount != n {
		t.Errorf("NotAnalyzedSubfilesCount = %d, want %d", got.result.NotAnalyzedSubfilesCount, n)
	}
}

func TestLinks_aNestedPrefixKeepsTheNameWithinTheBound(t *testing.T) {
	long := strings.Repeat("n", datamodel.MaxListedNameLen-2)
	r := runAcc(t, accSetup{
		files: map[string]string{"a.zip": zipOf(t, 0)},
		extract: linkExtractor(t, "sub.zip", map[string]string{"ok.bin": "ok"},
			[]datamodel.NotAnalyzedFile{{FileName: long}}, 1, "sub.zip"),
	})
	got := r.one(t, "a.zip")
	if len(got.result.NotAnalyzedSubfiles) != 1 {
		t.Fatalf("listed %v, want the link once", got.result.NotAnalyzedSubfiles)
	}
	name := got.result.NotAnalyzedSubfiles[0].FileName
	if len(name) > datamodel.MaxListedNameLen || !strings.HasPrefix(name, "sub.zip/") {
		t.Errorf("name of %d bytes, prefix %q: want at most %d bytes under sub.zip/", len(name), name[:min(len(name), 12)], datamodel.MaxListedNameLen)
	}
}

func TestBoundLinks(t *testing.T) {
	hostile := []datamodel.NotAnalyzedFile{
		{FileName: strings.Repeat("é", datamodel.MaxListedNameLen), Size: 1 << 40, Reason: datamodel.NotAnalyzedTooBig},
		{FileName: "ctl\x00\x1b[31m\u202egnp.exe", Size: -5},
		{FileName: "bad\xff\xfeutf8"},
	}
	tests := []struct {
		name      string
		e         plugins.Extraction
		wantLen   int
		wantCount int
	}{
		{"none", plugins.Extraction{}, 0, 0},
		{"negative count, no list", plugins.Extraction{LinksCount: -7}, 0, 0},
		{"negative count is raised to the list", plugins.Extraction{Links: hostile, LinksCount: -1}, 3, 3},
		{"count below the list", plugins.Extraction{Links: hostile, LinksCount: 1}, 3, 3},
		{"huge count is clamped", plugins.Extraction{Links: hostile, LinksCount: int(^uint(0) >> 1)}, 3, datamodel.MaxFileCount},
		{"count without a list", plugins.Extraction{LinksCount: 42}, 0, 42},
		{"list over the cap", plugins.Extraction{Links: make([]datamodel.NotAnalyzedFile, datamodel.MaxListedSubfiles+10)}, datamodel.MaxListedSubfiles, datamodel.MaxListedSubfiles + 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			links, count := boundLinks(tt.e)
			if len(links) != tt.wantLen || count != tt.wantCount {
				t.Fatalf("boundLinks() = %d entries, count %d; want %d, %d", len(links), count, tt.wantLen, tt.wantCount)
			}
			for i, f := range links {
				if f.Reason != datamodel.NotAnalyzedSymlink || f.Size != 0 || len(f.FileName) > datamodel.MaxListedNameLen {
					t.Errorf("entry %d = reason %q, size %d, name of %d bytes: want a symlink with no size within the bound", i, f.Reason, f.Size, len(f.FileName))
				}
			}
		})
	}
}

func TestBoundLinks_doesNotChangeTheExtractorsList(t *testing.T) {
	src := []datamodel.NotAnalyzedFile{{FileName: "x", Size: 3, Reason: datamodel.NotAnalyzedTooBig}}
	boundLinks(plugins.Extraction{Links: src})
	if src[0].Size != 3 || src[0].Reason != datamodel.NotAnalyzedTooBig {
		t.Errorf("the list of the extractor was changed: %+v", src[0])
	}
}

func TestListedNames_linksMakeTheListingNotWhole(t *testing.T) {
	for _, e := range []plugins.Extraction{
		{Names: []string{"a"}, Links: []datamodel.NotAnalyzedFile{{FileName: "l"}}},
		{Names: []string{"a"}, LinksCount: 1},
	} {
		prev := ExtractFile
		t.Cleanup(func() { ExtractFile = prev })
		ExtractFile = func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) { return e, nil }
		c, err := NewConnector(Config{WorkDir: t.TempDir(), Extract: true}, nil, cleanSubmitter())
		if err != nil {
			t.Fatal(err)
		}
		names, known, err := c.listedNames(fileToAnalyze{location: filepath.Join(t.TempDir(), "a.zip")}, 10, logger)
		if err != nil || known || names != nil {
			t.Errorf("listedNames(%+v) = %v, known %v, err %v; want unknown names", e, names, known, err)
		}
	}
}

func TestLinks_aNestedArchiveOfLinksOnlyIsListedUnderItsName(t *testing.T) {
	extract := func(archivePath, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		if filepath.Base(archivePath) == "sub.zip" {
			return plugins.Extraction{LinksCount: 2, Links: []datamodel.NotAnalyzedFile{{FileName: "l1"}, {FileName: "l2"}}}, nil
		}
		members := map[string]string{"a.txt": "ok", "sub.zip": zipOf(t, 0)}
		var e plugins.Extraction
		for n, c := range members {
			p := filepath.Join(outputDir, n)
			if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
				return plugins.Extraction{}, err
			}
			e.Files = append(e.Files, p)
		}
		return e, nil
	}
	r := runAcc(t, accSetup{
		policy:  Unanalyzable{TooBig: PolicyError},
		files:   map[string]string{"top.zip": zipOf(t, 0)},
		extract: extract,
	})
	got := r.one(t, "top.zip")
	if got.result.Error != nil || got.result.Malware || got.src.TooBig {
		t.Fatalf("result = %+v, want a delivered archive", got.result)
	}
	listed := notAnalyzedOf(got.result)
	for _, name := range []string{"sub.zip/l1", "sub.zip/l2"} {
		if listed[name].Reason != datamodel.NotAnalyzedSymlink {
			t.Errorf("%s not listed as a symlink: %v", name, got.result.NotAnalyzedSubfiles)
		}
	}
	if got.result.NotAnalyzedSubfilesCount != 2 {
		t.Errorf("NotAnalyzedSubfilesCount = %d, want 2", got.result.NotAnalyzedSubfilesCount)
	}
}

func TestLinks_linksBesideLimitSkipsWithNoExtractedFile(t *testing.T) {
	extract := func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
		return plugins.Extraction{
			Skipped:      []datamodel.NotAnalyzedFile{{FileName: "big.bin", Size: 10, Reason: datamodel.NotAnalyzedExtractLimit}},
			SkippedCount: 1,
			Links:        []datamodel.NotAnalyzedFile{{FileName: "lnk"}},
			LinksCount:   1,
		}, nil
	}
	r := runAcc(t, accSetup{
		policy:  Unanalyzable{TooBig: PolicyPass},
		files:   map[string]string{"a.zip": zipOf(t, 0)},
		extract: extract,
	})
	got := r.one(t, "a.zip")
	if got.result.Error != nil || got.result.Malware {
		t.Fatalf("result = %+v, want a delivered archive", got.result)
	}
	listed := notAnalyzedOf(got.result)
	if listed["lnk"].Reason != datamodel.NotAnalyzedSymlink || listed["big.bin"].Reason != datamodel.NotAnalyzedExtractLimit || got.result.NotAnalyzedSubfilesCount != 2 {
		t.Errorf("not analyzed = %v (count %d), want the link and the skipped member", got.result.NotAnalyzedSubfiles, got.result.NotAnalyzedSubfilesCount)
	}
}
