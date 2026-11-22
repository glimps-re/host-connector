package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// The path rules in the real pipeline.
func TestPathFilter_pipeline(t *testing.T) {
	t.Run("a forbidden file is malware and is quarantined, never submitted", func(t *testing.T) {
		r := runAcc(t, accSetup{
			files:      map[string]string{"a.exe": "X", "b.txt": "Y"},
			pathFilter: mustPathFilter(t, []string{`\.exe$`}, nil),
		})
		got := r.one(t, "a.exe")
		if !got.result.Malware || got.result.MalwareReason != datamodel.FilteredFilePath || r.quarantined(t) != 1 || r.exists(r.out, "a.exe") {
			t.Errorf("result = %+v, quarantined %d, delivered %t, want a quarantined forbidden file", got.result, r.quarantined(t), r.exists(r.out, "a.exe"))
		}
		if r.submitted.Load() != 1 {
			t.Errorf("%d files submitted, want only b.txt", r.submitted.Load())
		}
	})
	t.Run("a skipped file is delivered, marked policy-skipped, not submitted", func(t *testing.T) {
		r := runAcc(t, accSetup{
			files:      map[string]string{"trusted.bin": "X"},
			pathFilter: mustPathFilter(t, nil, []string{`trusted\.bin$`}),
		})
		got := r.one(t, "trusted.bin")
		if got.result.NotAnalyzedReason != datamodel.NotAnalyzedPolicySkipped || !r.exists(r.out, "trusted.bin") || r.submitted.Load() != 0 {
			t.Errorf("result = %+v, delivered %t, submitted %d, want a delivered file marked policy-skipped", got.result, r.exists(r.out, "trusted.bin"), r.submitted.Load())
		}
	})
	t.Run("a forbidden member makes its archive malware", func(t *testing.T) {
		r := runAcc(t, accSetup{
			files:      map[string]string{"pack.zip": zipOf(t, 10)},
			extract:    archiveOf("ok.txt", "tool.exe"),
			pathFilter: mustPathFilter(t, []string{`pack\.zip/.*\.exe$`}, nil),
		})
		got := r.one(t, "pack.zip")
		if !got.result.Malware || r.exists(r.out, "pack.zip") || r.quarantined(t) != 1 {
			t.Errorf("malware %t, delivered %t, quarantined %d, want a quarantined archive", got.result.Malware, r.exists(r.out, "pack.zip"), r.quarantined(t))
		}
	})
	t.Run("a member matching a skip pattern is not analyzed and is listed policy-skipped", func(t *testing.T) {
		r := runAcc(t, accSetup{
			files:      map[string]string{"pack.zip": zipOf(t, 10)},
			extract:    archiveOf("ok.txt", "docs-readme.txt"),
			pathFilter: mustPathFilter(t, nil, []string{`pack\.zip/docs-`}),
			submit: func(n string) (gdetect.Result, error) {
				if n == "docs-readme.txt" {
					t.Error("a member that matches a skip pattern was analyzed")
				}
				return gdetect.Result{}, nil
			},
		})
		got := r.one(t, "pack.zip")
		found := false
		for _, f := range got.result.NotAnalyzedSubfiles {
			found = found || (f.FileName == "docs-readme.txt" && f.Reason == datamodel.NotAnalyzedPolicySkipped)
		}
		if !found || !r.exists(r.out, "pack.zip") {
			t.Errorf("not analyzed = %+v, delivered %t, want the member listed and the archive delivered", got.result.NotAnalyzedSubfiles, r.exists(r.out, "pack.zip"))
		}
	})
	t.Run("a skipped archive is not extracted", func(t *testing.T) {
		var extracted atomic.Bool
		r := runAcc(t, accSetup{
			files: map[string]string{"pack.zip": zipOf(t, 10)},
			extract: func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
				extracted.Store(true)
				return plugins.Extraction{}, nil
			},
			pathFilter: mustPathFilter(t, nil, []string{`pack\.zip$`}),
		})
		got := r.one(t, "pack.zip")
		if got.result.NotAnalyzedReason != datamodel.NotAnalyzedPolicySkipped || !r.exists(r.out, "pack.zip") || extracted.Load() {
			t.Errorf("result = %+v, extracted %t, want a skipped archive delivered, marked policy-skipped, never extracted", got.result, extracted.Load())
		}
	})
	t.Run("a refusal of a plugin beats a skipped path", func(t *testing.T) {
		r := runAcc(t, accSetup{
			files:      map[string]string{"trusted.bin": "X"},
			pathFilter: mustPathFilter(t, nil, []string{`trusted\.bin$`}),
			scanFile: func(string, string, string, bool) *datamodel.Result {
				return &datamodel.Result{Malware: true, Malwares: []string{"type"}, MalwareReason: datamodel.FilteredFileType}
			},
		})
		got := r.one(t, "trusted.bin")
		if !got.result.Malware || r.exists(r.out, "trusted.bin") {
			t.Errorf("result = %+v, want the plugin's refusal to win", got.result)
		}
	})
}

// listing is an extractor that lists the names on a NamesOnly call and counts what
// it extracts.
type listing struct {
	// answer, when set, is the whole answer to a NamesOnly call.
	answer    *plugins.Extraction
	names     []string
	err       error
	listings  atomic.Int32
	extracted atomic.Int32
}

func (l *listing) extract(_, _ string, limits plugins.ExtractLimits) (plugins.Extraction, error) {
	if !limits.NamesOnly {
		l.extracted.Add(1)
		return plugins.Extraction{}, nil
	}
	l.listings.Add(1)
	if l.answer != nil {
		return *l.answer, nil
	}
	if l.err != nil {
		return plugins.Extraction{}, l.err
	}
	if l.names == nil {
		return plugins.Extraction{}, nil
	}
	return plugins.Extraction{Names: append([]string{}, l.names...)}, nil
}

func TestPathFilter_skippedArchiveStillMeetsForbiddenPaths(t *testing.T) {
	skipArchive := []string{`pack\.zip$`}
	forbidExe := []string{`\.exe$`}
	tests := []struct {
		name         string
		forbidden    []string
		list         *listing
		wantListings int32
		// wantExtracted is whether the archive is extracted: the skip was withdrawn.
		wantExtracted bool
		outcome       accOutcome
		wantReason    datamodel.NotAnalyzedReason
	}{
		{"a forbidden member refuses the skipped archive", forbidExe, &listing{names: []string{"docs/a.txt", "a.exe"}}, 1, false, accQuarantined, ""},
		{"no member matches: skipped, never extracted", forbidExe, &listing{names: []string{"a.txt"}}, 1, false, accMoved, datamodel.NotAnalyzedPolicySkipped},
		{"no forbidden rule: the archive is not even listed", nil, &listing{names: []string{"a.exe"}}, 0, false, accMoved, datamodel.NotAnalyzedPolicySkipped},
		{"a member that is forbidden in a nested folder", []string{`pack\.zip/x/y/.*\.exe$`}, &listing{names: []string{"x/y/z.exe"}}, 1, false, accQuarantined, ""},
		{"an archive of no file is skipped", forbidExe, &listing{names: []string{}}, 1, false, accMoved, datamodel.NotAnalyzedPolicySkipped},
		{"an extractor that gives no names: the skip is withdrawn", forbidExe, &listing{}, 1, true, accMoved, ""},
		{"an extractor that cannot list: the skip is withdrawn", forbidExe, &listing{err: plugins.ErrListingUnsupported}, 1, true, accMoved, ""},
		{"encrypted headers: the skip is withdrawn", forbidExe, &listing{err: plugins.ErrEncrypted}, 1, true, accMoved, ""},
		{"a damaged archive: the skip is withdrawn", forbidExe, &listing{err: plugins.ErrArchiveAnomaly}, 1, true, accMoved, ""},
		{"an extractor that is down: a retry, in INPUT", forbidExe, &listing{err: plugins.ErrExtractorUnavailable}, 1, false, accNone, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runAcc(t, accSetup{
				files:      map[string]string{"pack.zip": zipOf(t, 10)},
				extract:    tt.list.extract,
				pathFilter: mustPathFilter(t, tt.forbidden, skipArchive),
			})
			if got := tt.list.listings.Load(); got != tt.wantListings {
				t.Errorf("%d listing(s), want %d", got, tt.wantListings)
			}
			if got := tt.list.extracted.Load() > 0; got != tt.wantExtracted {
				t.Errorf("extracted %t, want %t", got, tt.wantExtracted)
			}
			moved, quarantined := r.exists(r.out, "pack.zip"), r.quarantined(t)
			switch tt.outcome {
			case accMoved:
				if !moved || quarantined != 0 || r.one(t, "pack.zip").result.NotAnalyzedReason != tt.wantReason {
					t.Errorf("moved %t, quarantined %d, want a delivered archive marked %q", moved, quarantined, tt.wantReason)
				}
			case accQuarantined:
				got := r.one(t, "pack.zip").result
				if moved || quarantined != 1 || !got.Malware || got.MalwareReason != datamodel.FilteredFilePath {
					t.Errorf("moved %t, quarantined %d, result %+v, want a quarantined archive, forbidden path", moved, quarantined, got)
				}
			case accNone:
				if moved || quarantined != 0 || !r.exists(r.in, "pack.zip") {
					t.Errorf("moved %t, quarantined %d, inInput %t, want it left in INPUT", moved, quarantined, r.exists(r.in, "pack.zip"))
				}
			}
			if wantSubmitted := int32(0); !tt.wantExtracted && r.submitted.Load() != wantSubmitted {
				t.Errorf("%d submission(s), want none", r.submitted.Load())
			}
		})
	}
	for name, tt := range map[string]struct {
		answer   plugins.Extraction
		maxFiles int
	}{
		"an extractor that ignores NamesOnly and extracts": {answer: plugins.Extraction{Names: []string{"a.txt"}, Files: []string{"/tmp/x"}}},
		"members left out":                       {answer: plugins.Extraction{Names: []string{"a.txt"}, SkippedCount: 1}},
		"more names than the files left to list": {answer: plugins.Extraction{Names: []string{"a", "b", "c", "d", "e", "f"}}, maxFiles: 5},
	} {
		t.Run("the names are not trusted: "+name, func(t *testing.T) {
			l := &listing{answer: &tt.answer}
			r := runAcc(t, accSetup{
				files:           map[string]string{"pack.zip": zipOf(t, 10)},
				extract:         l.extract,
				extractMaxFiles: tt.maxFiles,
				pathFilter:      mustPathFilter(t, forbidExe, skipArchive),
			})
			if l.extracted.Load() == 0 || r.one(t, "pack.zip").result.NotAnalyzedReason == datamodel.NotAnalyzedPolicySkipped {
				t.Errorf("extracted %d, want the skip withdrawn: the archive is processed as any archive", l.extracted.Load())
			}
		})
	}
	t.Run("a withdrawn skip leaves the forbidden rules to the members, as for any archive", func(t *testing.T) {
		r := runAcc(t, accSetup{
			files: map[string]string{"pack.zip": zipOf(t, 10)},
			extract: func(src, outputDir string, limits plugins.ExtractLimits) (plugins.Extraction, error) {
				if limits.NamesOnly {
					return plugins.Extraction{}, plugins.ErrListingUnsupported
				}
				return archiveOf("ok.txt", "tool.exe")(src, outputDir, limits)
			},
			pathFilter: mustPathFilter(t, forbidExe, skipArchive),
		})
		if got := r.one(t, "pack.zip").result; !got.Malware || got.MalwareReason != datamodel.FilteredFilePath || r.exists(r.out, "pack.zip") {
			t.Errorf("result = %+v, want the archive refused for tool.exe once extracted", got)
		}
	})
}

// The path rules match the path as the file system gives it as well as the
// logical one: a forbidden rule catches either, a skip needs both.
func TestPathFilter_rawAndLogicalForms(t *testing.T) {
	tests := []struct {
		name               string
		file               string
		extract            plugins.ExtractFile
		forbidden, skipped []string
		check              func(t *testing.T, r *accRun, got datamodel.Result)
	}{
		{
			name: "a raw name with a control character under a rule written for it", file: "run.exe\n",
			forbidden: []string{`\.exe\n$`}, check: wantForbidden,
		},
		{
			name: "the rule that catches trailing characters", file: "run.exe\n",
			forbidden: []string{`\.exe[^/]*$`}, check: wantForbidden,
		},
		{
			name: "an end anchor sees through a trailing newline", file: "run.exe\n",
			forbidden: []string{`\.exe$`}, check: wantForbidden,
		},
		{
			name: "a name whose logical form is skipped but not its raw form is analyzed", file: "a\x01b.txt",
			skipped: []string{`a_b\.txt$`}, check: func(t *testing.T, r *accRun, got datamodel.Result) {
				t.Helper()
				if got.NotAnalyzedReason == datamodel.NotAnalyzedPolicySkipped || r.submitted.Load() != 1 {
					t.Errorf("result = %+v, submitted %d, want the file analyzed", got, r.submitted.Load())
				}
			},
		},
		{
			name: "a member with a control character is matched in both forms", file: "pack.zip", extract: archiveOf("ok.txt", "x\n.exe"),
			forbidden: []string{`x\n\.exe$`}, check: wantForbidden,
		},
		{
			name: "a top-level archive is matched by its logical name", file: "pack\nx.zip", extract: archiveOf("ok.txt"),
			forbidden: []string{`/in/pack_x\.zip$`}, check: wantForbidden,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := "X"
			if tt.extract != nil {
				content = zipOf(t, 10)
			}
			r := runAcc(t, accSetup{files: map[string]string{tt.file: content}, extract: tt.extract, pathFilter: mustPathFilter(t, tt.forbidden, tt.skipped)})
			tt.check(t, r, r.one(t, tt.file).result)
		})
	}
}

func wantForbidden(t *testing.T, _ *accRun, got datamodel.Result) {
	t.Helper()
	if !got.Malware || got.MalwareReason != datamodel.FilteredFilePath {
		t.Errorf("result = %+v, want a forbidden path", got)
	}
}

// archiveOf is an extractor that gives the named plain members.
func archiveOf(names ...string) plugins.ExtractFile {
	return func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		files := make([]string, 0, len(names))
		for _, n := range names {
			p := filepath.Join(outputDir, n)
			if err := os.WriteFile(p, []byte("C-"+n), 0o600); err != nil {
				return plugins.Extraction{}, err
			}
			files = append(files, p)
		}
		return plugins.Extraction{Files: files}, nil
	}
}

func TestPathFilter_skippedArchiveMembers(t *testing.T) {
	t.Run("a member declared with .. is matched where the extractor writes it", func(t *testing.T) {
		l := &listing{names: []string{"../secret/evil.exe", "./a/../../b/./c.exe"}}
		r := runAcc(t, accSetup{
			files:      map[string]string{"pack.zip": zipOf(t, 10)},
			extract:    l.extract,
			pathFilter: mustPathFilter(t, []string{`pack\.zip/secret/evil\.exe$`}, []string{`pack\.zip$`}),
		})
		got := r.one(t, "pack.zip").result
		if !got.Malware || got.MalwareReason != datamodel.FilteredFilePath || r.exists(r.out, "pack.zip") {
			t.Errorf("result = %+v, want the archive refused for ../secret/evil.exe, as 7-Zip writes it to secret/evil.exe", got)
		}
	})
	t.Run("every forbidden member is named in the report", func(t *testing.T) {
		l := &listing{names: []string{"a.exe", "docs/readme.txt", "sub/b.exe"}}
		r := runAcc(t, accSetup{
			files:      map[string]string{"pack.zip": zipOf(t, 10)},
			extract:    l.extract,
			pathFilter: mustPathFilter(t, []string{`\.exe$`}, []string{`pack\.zip$`}),
		})
		got := r.one(t, "pack.zip").result
		names := make([]string, 0, len(got.MaliciousSubfiles))
		for name, sub := range got.MaliciousSubfiles {
			names = append(names, filepath.Base(name))
			if !sub.Malware || sub.MalwareReason != datamodel.FilteredFilePath || !slices.Equal(sub.Malwares, []string{"forbidden_file_path"}) {
				t.Errorf("member %s = %+v, want a forbidden path", name, sub)
			}
		}
		slices.Sort(names)
		if !slices.Equal(names, []string{"a.exe", "b.exe"}) {
			t.Errorf("malicious subfiles = %v, want a.exe and b.exe", names)
		}
	})
	t.Run("the time spent on a listing is bounded", func(t *testing.T) {
		now := time.Now()
		prev := pathRulesClock
		pathRulesClock = func() time.Time { now = now.Add(20 * time.Second); return now }
		t.Cleanup(func() { pathRulesClock = prev })
		l := &listing{names: []string{"a.txt", "b.txt", "c.txt"}}
		r := runAcc(t, accSetup{
			files:      map[string]string{"pack.zip": zipOf(t, 10)},
			extract:    l.extract,
			pathFilter: mustPathFilter(t, []string{`\.exe$`}, []string{`pack\.zip$`}),
		})
		if r.exists(r.out, "pack.zip") || !r.exists(r.in, "pack.zip") || len(r.captures) != 0 {
			t.Errorf("delivered %t, in INPUT %t, %d actions, want an error that leaves it in INPUT", r.exists(r.out, "pack.zip"), r.exists(r.in, "pack.zip"), len(r.captures))
		}
	})
}

func TestExtractPath(t *testing.T) {
	tests := []struct{ name, declared, want string }{
		{"a plain name", "a.txt", "a.txt"},
		{"a folder", "d/a.txt", "d/a.txt"},
		{"one level up", "../secret/evil.exe", "secret/evil.exe"},
		{"two levels up", "../../x", "x"},
		{"dots in the middle", "./a/../b/./c", "a/b/c"},
		{"empty components", "a//b///c", "a/b/c"},
		{"an absolute path", "/abs/x", "abs/x"},
		{"only dots", "..", ""},
		{"nothing", "", ""},
		{"a name that ends with a dot dot", "a/..", "a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractedPath(tt.declared); got != tt.want {
				t.Errorf("extractedPath(%q) = %q, want %q", tt.declared, got, tt.want)
			}
		})
	}
}

// Each listing of a skipped archive takes from the extraction budget of its
// top-level file, like an extraction: the archives past it are not listed.
func TestPathFilter_listingsCountAgainstTheExtractionBudget(t *testing.T) {
	for name, names := range map[string][]string{"names given": {}, "names unknown": nil} {
		t.Run(name, func(t *testing.T) { listingsAgainstBudget(t, names) })
	}
}

func listingsAgainstBudget(t *testing.T, names []string) {
	t.Helper()
	var checks, extractions atomic.Int32
	extract := func(_, outputDir string, limits plugins.ExtractLimits) (plugins.Extraction, error) {
		if limits.NamesOnly {
			checks.Add(1)
			return plugins.Extraction{Names: names}, nil
		}
		if extractions.Add(1) > 1 {
			return plugins.Extraction{}, nil
		}
		files := make([]string, 0, 3)
		for i := range 3 {
			p := filepath.Join(outputDir, fmt.Sprintf("m%d.zip", i))
			if err := os.WriteFile(p, []byte(zipOf(t, 10)+strconv.Itoa(i)), 0o600); err != nil {
				return plugins.Extraction{}, err
			}
			files = append(files, p)
		}
		return plugins.Extraction{Files: files, Size: 3}, nil
	}
	r := runAcc(t, accSetup{
		files:           map[string]string{"big.zip": zipOf(t, 10)},
		extract:         extract,
		extractMaxFiles: 5,
		pathFilter:      mustPathFilter(t, []string{`\.exe$`}, []string{`/m[0-9]\.zip$`}),
	})
	if got := checks.Load(); got != 2 {
		t.Errorf("%d listings, want 2: three members were extracted of a budget of 5, each listing takes one", got)
	}
	if len(r.captures) != 1 || r.captures[0].result.Error == nil || !strings.Contains(r.captures[0].result.Error.Error(), "m2.zip") || r.exists(r.out, "big.zip") || !r.exists(r.in, "big.zip") {
		t.Errorf("captures %d, in OUTPUT %t, in INPUT %t, want m2.zip, which the budget did not let list, an error that leaves the archive in INPUT", len(r.captures), r.exists(r.out, "big.zip"), r.exists(r.in, "big.zip"))
	}
}

// The time that matching takes is added up over the listings of a file: the time
// between two listings does not count, a slow matching does.
func TestMatchMembers_theTimeIsAddedUpOverTheListingsOfAFile(t *testing.T) {
	now := time.Now()
	step := time.Millisecond
	prev := pathRulesClock
	pathRulesClock = func() time.Time { now = now.Add(step); return now }
	t.Cleanup(func() { pathRulesClock = prev })
	c := &Connector{config: Config{PathFilter: mustPathFilter(t, []string{`\.exe$`}, nil)}}
	archive := func(run *ongoing) fileToAnalyze {
		return fileToAnalyze{location: "/in/a.zip", run: run}
	}
	names := []string{"a.txt", "b.txt"}
	t.Run("two listings 31 s apart", func(t *testing.T) {
		run := &ongoing{}
		for range 2 {
			if _, err := c.matchMembers(archive(run), names, logger); err != nil {
				t.Fatalf("matchMembers() = %v, want a fast matching accepted", err)
			}
			now = now.Add(31 * time.Second)
		}
	})
	t.Run("a slow matching is refused, over the listings of a file as well", func(t *testing.T) {
		step = 11 * time.Second
		t.Cleanup(func() { step = time.Millisecond })
		run := &ongoing{}
		if _, err := c.matchMembers(archive(run), names[:1], logger); err != nil {
			t.Fatalf("the first listing: matchMembers() = %v, want it within the budget", err)
		}
		if _, err := c.matchMembers(archive(run), names[:1], logger); !errors.Is(err, errPathRulesSlow) {
			t.Errorf("the second listing: matchMembers() = %v, want errPathRulesSlow: 22 s were spent by the first", err)
		}
		if _, err := c.matchMembers(archive(&ongoing{}), []string{"a", "b", "c", "d"}, logger); !errors.Is(err, errPathRulesSlow) {
			t.Errorf("matchMembers() = %v, want errPathRulesSlow for a listing that is slow by itself", err)
		}
	})
	t.Run("an archive with no run is an error", func(t *testing.T) {
		if _, err := c.matchMembers(archive(nil), names, logger); !errors.Is(err, errNoRun) {
			t.Errorf("matchMembers() = %v, want errNoRun", err)
		}
	})
	t.Run("a context that ended stops the matching", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		stopped := &Connector{config: c.config, workCtx: ctx}
		if _, err := stopped.matchMembers(archive(&ongoing{}), names, logger); !errors.Is(err, context.Canceled) {
			t.Errorf("matchMembers() = %v, want context.Canceled", err)
		}
	})
}

func TestDefaultExtractor_cannotListNames(t *testing.T) {
	_, err := ExtractFile("/nonexistent", t.TempDir(), plugins.ExtractLimits{NamesOnly: true})
	if !errors.Is(err, plugins.ErrListingUnsupported) {
		t.Errorf("ExtractFile(NamesOnly) error = %v, want ErrListingUnsupported", err)
	}
}

// The members are named in the report as they are listed, once each even when their
// names are cut to the same text, and the archive carries its own size and the
// members none.
func TestPathFilter_refusedMembersAreNamedOnce(t *testing.T) {
	long := strings.Repeat("d/", datamodel.MaxListedNameLen)
	l := &listing{names: []string{long + "a.exe", long + "b.exe"}}
	r := runAcc(t, accSetup{
		files:      map[string]string{"pack.zip": zipOf(t, 10)},
		extract:    l.extract,
		pathFilter: mustPathFilter(t, []string{`\.exe$`}, []string{`pack\.zip$`}),
	})
	got := r.one(t, "pack.zip").result
	if len(got.MaliciousSubfiles) != 2 {
		t.Fatalf("%d members named, want 2 even though their names are cut to the same text", len(got.MaliciousSubfiles))
	}
	for name, sub := range got.MaliciousSubfiles {
		if len(name) > datamodel.MaxListedNameLen || sub.FileSize != 0 || sub.SHA256 != "" || sub.Location != "" {
			t.Errorf("member %q = %+v, want a name within the bound and neither the size, the hash nor the place of the archive", name, sub)
		}
	}
	if got.FileSize == 0 {
		t.Error("the refusal carries no size for the archive")
	}
}
