package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// t17aFixture is a connector with a fake extractor and an action that keeps the
// results of the archives.
type t17aFixture struct {
	c       *Connector
	mu      sync.Mutex
	results []datamodel.Result
}

func newT17aFixture(t *testing.T, u Unanalyzable) *t17aFixture {
	t.Helper()
	f := &t17aFixture{}
	c, err := NewConnector(Config{Extract: true, WorkDir: t.TempDir(), RecursiveExtractMaxDepth: 3, ExtractMinThreshold: 1, Workers: 2, Unanalyzable: u}, nil, archiveCleanSubmitter())
	if err != nil {
		t.Fatal(err)
	}
	c.action = &MockAction{HandleMock: func(_ context.Context, _ Source, r datamodel.Result, _ *datamodel.Report) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.results = append(f.results, r)
		return nil
	}}
	t.Cleanup(func() { c.Close(t.Context()) })
	f.c = c
	return f
}

func (f *t17aFixture) extract(t *testing.T) error {
	t.Helper()
	location, sha := createArchive(t, []string{"content"})
	info, err := os.Stat(location)
	if err != nil {
		t.Fatal(err)
	}
	var size int64
	var files int
	archive := fileToAnalyze{sha256: sha, location: location, filename: filepath.Base(location), identity: IdentityOf(info), size: info.Size()}
	return f.c.recursiveExtract(archive, 0, &size, &files, logger)
}

// drain processes the files waiting for analysis, until none is left.
func (f *t17aFixture) drain() {
	for {
		select {
		case in := <-f.c.analysisChan:
			f.c.processFile(in)
		default:
			return
		}
	}
}

func (f *t17aFixture) only(t *testing.T) datamodel.Result {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.results) != 1 {
		t.Fatalf("%d archive results, want 1: %+v", len(f.results), f.results)
	}
	return f.results[0]
}

func writeMember(t *testing.T, outputDir, name, content string) string {
	t.Helper()
	root, err := os.OpenRoot(outputDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := root.Close(); e != nil {
			t.Error(e)
		}
	}()
	if err = root.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(outputDir, name)
}

var limitSkips = []datamodel.NotAnalyzedFile{
	{FileName: "big.bin", Size: 500, Reason: datamodel.NotAnalyzedTooBig},
	{FileName: "many/1", Size: 3, Reason: datamodel.NotAnalyzedExtractLimit},
}

// The members the extraction leaves out because of its limits follow the policy
// of the files too big, in a top-level archive and in a sub-archive.
func TestRecursiveExtract_membersLeftOutByTheLimitsFollowTheTooBigPolicy(t *testing.T) {
	for _, nested := range []bool{false, true} {
		for _, policy := range []string{PolicyError, PolicyPass, PolicyMitigate} {
			t.Run(fmt.Sprintf("nested=%v/%s", nested, policy), func(t *testing.T) {
				prev := ExtractFile
				t.Cleanup(func() { ExtractFile = prev })
				var calls int
				ExtractFile = func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
					calls++
					if nested && calls == 1 {
						inner, _ := createArchive(t, []string{"inner"})
						raw, err := os.ReadFile(filepath.Clean(inner))
						if err != nil {
							return plugins.Extraction{}, err
						}
						return plugins.Extraction{Files: []string{writeMember(t, outputDir, "b.zip", string(raw))}, Size: uint64(len(raw))}, nil
					}
					return plugins.Extraction{Files: []string{writeMember(t, outputDir, "ok.txt", "fine content")}, Size: 12, Skipped: limitSkips, SkippedCount: 7}, nil
				}
				f := newT17aFixture(t, Unanalyzable{TooBig: policy})
				err := f.extract(t)
				if policy == PolicyError && !nested {
					if !errors.Is(err, errInnerPermanent) {
						t.Fatalf("recursiveExtract() = %v, want a permanent error: the archive stays in INPUT", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				f.drain()
				f.drain()
				r := f.only(t)
				switch policy {
				case PolicyError:
					if r.Error == nil {
						t.Errorf("result = %+v, want the archive in error", r)
					}
				case PolicyPass:
					if r.Error != nil || r.Malware || r.NotAnalyzedSubfilesCount != 7 || len(r.NotAnalyzedSubfiles) != 2 {
						t.Errorf("result = %+v, want a clean archive listing 2 members of 7 left out", r)
					}
				case PolicyMitigate:
					if !r.Malware || r.MalwareReason != datamodel.TooBig || r.NotAnalyzedSubfilesCount != 7 {
						t.Errorf("result = %+v, want malware too-big and the members listed", r)
					}
				}
			})
		}
	}
}

// When every member was left out, the archive ends at once with what it lists.
func TestRecursiveExtract_anArchiveWhoseMembersAreAllLeftOutEndsWithTheList(t *testing.T) {
	prev := ExtractFile
	t.Cleanup(func() { ExtractFile = prev })
	ExtractFile = func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
		return plugins.Extraction{Skipped: limitSkips, SkippedCount: 2}, nil
	}
	f := newT17aFixture(t, Unanalyzable{TooBig: PolicyPass})
	if err := f.extract(t); err != nil {
		t.Fatal(err)
	}
	r := f.only(t)
	if r.Error != nil || r.NotAnalyzedSubfilesCount != 2 || len(r.NotAnalyzedSubfiles) != 2 {
		t.Errorf("result = %+v, want the two members listed", r)
	}
}

// An archive whose password is unknown is a file to which the policy of the
// encrypted files applies, never a plain file.
func TestRecursiveExtract_anEncryptedArchiveFollowsTheEncryptedPolicy(t *testing.T) {
	for _, policy := range []string{PolicyError, PolicyPass, PolicyMitigate} {
		t.Run(policy, func(t *testing.T) {
			prev := ExtractFile
			t.Cleanup(func() { ExtractFile = prev })
			ExtractFile = func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
				return plugins.Extraction{}, fmt.Errorf("x: %w", plugins.ErrEncrypted)
			}
			f := newT17aFixture(t, Unanalyzable{Encrypted: policy})
			var got []datamodel.Result
			f.c.action = &MockAction{HandleMock: func(_ context.Context, _ Source, r datamodel.Result, _ *datamodel.Report) error {
				got = append(got, r)
				return nil
			}}
			if err := f.extract(t); err != nil {
				t.Fatal(err)
			}
			f.drain()
			if len(got) != 1 {
				t.Fatalf("%d results, want 1", len(got))
			}
			switch r := got[0]; policy {
			case PolicyError:
				// The file is small, so it was analyzed and the policy decides after.
				if !errors.Is(r.Error, errEncrypted) {
					t.Errorf("result = %+v, want errEncrypted", r)
				}
			case PolicyPass:
				if r.Error != nil || r.Malware || r.NotAnalyzedReason != datamodel.NotAnalyzedEncrypted {
					t.Errorf("result = %+v, want a clean file marked encrypted", r)
				}
			case PolicyMitigate:
				if !r.Malware || r.MalwareReason != datamodel.Encrypted {
					t.Errorf("result = %+v, want malware with the reason encrypted", r)
				}
			}
		})
	}
}

// An encrypted archive inside an archive is a member under the same policy.
func TestRecursiveExtract_anEncryptedSubArchiveIsAMemberUnderThePolicy(t *testing.T) {
	prev := ExtractFile
	t.Cleanup(func() { ExtractFile = prev })
	var calls int
	ExtractFile = func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		calls++
		if calls == 1 {
			inner, _ := createArchive(t, []string{"inner"})
			raw, err := os.ReadFile(filepath.Clean(inner))
			if err != nil {
				return plugins.Extraction{}, err
			}
			return plugins.Extraction{Files: []string{writeMember(t, outputDir, "b.zip", string(raw))}, Size: uint64(len(raw))}, nil
		}
		return plugins.Extraction{}, fmt.Errorf("x: %w", plugins.ErrEncrypted)
	}
	f := newT17aFixture(t, Unanalyzable{Encrypted: PolicyPass})
	if err := f.extract(t); err != nil {
		t.Fatal(err)
	}
	f.drain()
	r := f.only(t)
	want := []datamodel.NotAnalyzedFile{{FileName: "b.zip", Size: 0, Reason: datamodel.NotAnalyzedEncrypted}}
	if r.Error != nil || len(r.NotAnalyzedSubfiles) != 1 || r.NotAnalyzedSubfiles[0].FileName != want[0].FileName || r.NotAnalyzedSubfiles[0].Reason != want[0].Reason {
		t.Errorf("result = %+v, want b.zip listed as not analyzed (encrypted)", r)
	}
}

// nestedExtractor yields a member and an inner archive on its first call, and
// whatever inner does on the next ones.
func nestedExtractor(t *testing.T, inner func(outputDir string) (plugins.Extraction, error)) (plugins.ExtractFile, *int) {
	t.Helper()
	calls := new(int)
	return func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		*calls++
		if *calls == 1 {
			innerZip, _ := createArchive(t, []string{"inner"})
			raw, err := os.ReadFile(filepath.Clean(innerZip))
			if err != nil {
				return plugins.Extraction{}, err
			}
			return plugins.Extraction{
				Files: []string{writeMember(t, outputDir, "ok.txt", "fine content"), writeMember(t, outputDir, "b.zip", string(raw))},
				Size:  uint64(12 + len(raw)),
			}, nil
		}
		return inner(outputDir)
	}, calls
}

// An archive the limits of the extraction do not let open (depth, number of
// files) is left out, not analyzed as a plain file: the policy of the files too
// big decides.
func TestRecursiveExtract_anArchiveBeyondTheLimitsFollowsTheTooBigPolicy(t *testing.T) {
	limits := map[string]func(c *Config){
		"depth":  func(c *Config) { c.RecursiveExtractMaxDepth = 1 },
		"budget": func(c *Config) { c.RecursiveExtractMaxFiles = 1 },
	}
	for name, limit := range limits {
		for _, policy := range []string{PolicyError, PolicyPass, PolicyMitigate} {
			t.Run(name+"/"+policy, func(t *testing.T) {
				prev := ExtractFile
				t.Cleanup(func() { ExtractFile = prev })
				var calls *int
				ExtractFile, calls = nestedExtractor(t, func(string) (plugins.Extraction, error) {
					t.Error("the inner archive must not be opened beyond the limits")
					return plugins.Extraction{}, nil
				})
				f := newT17aFixture(t, Unanalyzable{TooBig: policy, Encrypted: policy})
				limit(&f.c.config)
				if err := f.extract(t); err != nil {
					t.Fatal(err)
				}
				f.drain()
				f.drain()
				r := f.only(t)
				if *calls != 1 {
					t.Errorf("%d extractions, want only the top-level one", *calls)
				}
				switch policy {
				case PolicyError:
					if r.Error == nil {
						t.Errorf("result = %+v, want the archive in error", r)
					}
				case PolicyPass:
					if r.Error != nil || r.Malware || len(r.NotAnalyzedSubfiles) != 1 || r.NotAnalyzedSubfiles[0].FileName != "b.zip" || r.NotAnalyzedSubfiles[0].Reason != datamodel.NotAnalyzedExtractLimit {
						t.Errorf("result = %+v, want b.zip listed as left out by the limits", r)
					}
				case PolicyMitigate:
					if !r.Malware || r.MalwareReason != datamodel.TooBig {
						t.Errorf("result = %+v, want malware too-big", r)
					}
				}
			})
		}
	}
}

// A small archive, even encrypted, goes through the extractor whatever
// extract_min_size: the policy of the encrypted files applies to it.
func TestDispatch_anEncryptedArchiveUnderExtractMinSizeFollowsThePolicy(t *testing.T) {
	for _, policy := range []string{PolicyError, PolicyPass, PolicyMitigate} {
		t.Run(policy, func(t *testing.T) {
			prev := ExtractFile
			t.Cleanup(func() { ExtractFile = prev })
			var extractions int
			ExtractFile = func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
				extractions++
				return plugins.Extraction{}, fmt.Errorf("x: %w", plugins.ErrEncrypted)
			}
			in := t.TempDir()
			location, _ := createArchive(t, []string{"content"})
			raw, err := os.ReadFile(filepath.Clean(location))
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) >= 8000 {
				t.Fatalf("the test archive is %d bytes, it must be under the default extract_min_size", len(raw))
			}
			src := writeMember(t, in, "secret.zip", string(raw))
			c, err := NewConnector(Config{Roots: []string{in}, Extract: true, WorkDir: t.TempDir(), Workers: 2, Unanalyzable: Unanalyzable{Encrypted: policy}}, nil, cleanSubmitter())
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var results []datamodel.Result
			c.action = &MockAction{HandleMock: func(_ context.Context, _ Source, r datamodel.Result, _ *datamodel.Report) error {
				mu.Lock()
				defer mu.Unlock()
				results = append(results, r)
				return nil
			}}
			if err = c.Start(); err != nil {
				t.Fatal(err)
			}
			if err = c.ScanFile(t.Context(), src); err != nil {
				t.Fatal(err)
			}
			c.Close(t.Context())
			mu.Lock()
			defer mu.Unlock()
			if extractions != 1 || len(results) != 1 {
				t.Fatalf("%d extractions and %d results, want 1 and 1", extractions, len(results))
			}
			switch r := results[0]; policy {
			case PolicyError:
				if !errors.Is(r.Error, errEncrypted) {
					t.Errorf("result = %+v, want errEncrypted", r)
				}
			case PolicyPass:
				if r.Error != nil || r.NotAnalyzedReason != datamodel.NotAnalyzedEncrypted {
					t.Errorf("result = %+v, want marked encrypted", r)
				}
			case PolicyMitigate:
				if !r.Malware || r.MalwareReason != datamodel.Encrypted {
					t.Errorf("result = %+v, want malware encrypted", r)
				}
			}
		})
	}
}

// A top-level archive that fails for good under the error policy is reported
// with its error, as one analyzed in error, and left in place.
func TestPipeline_anArchiveThatFailsForGoodIsReportedWithItsError(t *testing.T) {
	prev := ExtractFile
	t.Cleanup(func() { ExtractFile = prev })
	ExtractFile = func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
		return plugins.Extraction{Skipped: limitSkips, SkippedCount: 2}, nil
	}
	in := t.TempDir()
	location, _ := createArchive(t, []string{"content"})
	raw, err := os.ReadFile(filepath.Clean(location))
	if err != nil {
		t.Fatal(err)
	}
	src := writeMember(t, in, "a.zip", string(raw))
	c, err := NewConnector(Config{Roots: []string{in}, Extract: true, WorkDir: t.TempDir(), Workers: 2}, nil, cleanSubmitter())
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var reports []datamodel.Report
	var actions int
	c.action = &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error {
		mu.Lock()
		defer mu.Unlock()
		actions++
		return nil
	}}
	c.RegisterOnReport(func(r *datamodel.Report) {
		mu.Lock()
		defer mu.Unlock()
		reports = append(reports, *r)
	})
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	if err = c.ScanFile(t.Context(), src); err != nil {
		t.Fatal(err)
	}
	c.Close(t.Context())
	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 1 || reports[0].Error == "" || reports[0].Filename != src {
		t.Errorf("reports = %+v, want exactly one for the archive, with its error", reports)
	}
	if actions != 0 {
		t.Errorf("%d actions ran on a failed archive", actions)
	}
	if _, err = os.Stat(src); err != nil {
		t.Errorf("the archive is not in place: %v", err)
	}
}

// A sub-archive whose members were all left out ends the parent with the list
// (or the verdict) and one action, next to a clean member.
func TestRecursiveExtract_aSubArchiveWithEveryMemberLeftOutEndsTheParent(t *testing.T) {
	for _, policy := range []string{PolicyPass, PolicyMitigate} {
		t.Run(policy, func(t *testing.T) {
			prev := ExtractFile
			t.Cleanup(func() { ExtractFile = prev })
			ExtractFile, _ = nestedExtractor(t, func(string) (plugins.Extraction, error) {
				return plugins.Extraction{Skipped: limitSkips[:1], SkippedCount: 1}, nil
			})
			f := newT17aFixture(t, Unanalyzable{TooBig: policy})
			if err := f.extract(t); err != nil {
				t.Fatal(err)
			}
			f.drain()
			f.drain()
			r := f.only(t)
			switch policy {
			case PolicyPass:
				if r.Error != nil || r.Malware || len(r.NotAnalyzedSubfiles) != 1 || r.NotAnalyzedSubfiles[0].FileName != "b.zip/big.bin" {
					t.Errorf("result = %+v, want b.zip/big.bin listed", r)
				}
			case PolicyMitigate:
				if !r.Malware || r.MalwareReason != datamodel.TooBig {
					t.Errorf("result = %+v, want malware too-big", r)
				}
			}
		})
	}
}

// An encrypted archive over max_file_size follows the policy without being
// submitted; only a top-level one is marked too big for the move.
func TestRecursiveExtract_anEncryptedArchiveOverMaxFileSizeIsNotSubmitted(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(fmt.Sprintf("nested=%v", nested), func(t *testing.T) {
			prev := ExtractFile
			t.Cleanup(func() { ExtractFile = prev })
			var calls int
			ExtractFile = func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
				calls++
				if nested && calls == 1 {
					return plugins.Extraction{Files: []string{writeMember(t, outputDir, "b.zip", "an encrypted archive of some size")}, Size: 33}, nil
				}
				return plugins.Extraction{}, fmt.Errorf("x: %w", plugins.ErrEncrypted)
			}
			var submitted int
			var mu sync.Mutex
			submitter := archiveCleanSubmitter()
			submitter.WaitForFileMock = func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) {
				mu.Lock()
				defer mu.Unlock()
				submitted++
				return gdetect.Result{}, nil
			}
			echoReader(submitter)
			f := newT17aFixture(t, Unanalyzable{Encrypted: PolicyPass})
			f.c.submitter = submitter
			f.c.config.MaxFileSize = 10
			var sources []Source
			f.c.action = &MockAction{HandleMock: func(_ context.Context, src Source, r datamodel.Result, _ *datamodel.Report) error {
				f.mu.Lock()
				defer f.mu.Unlock()
				sources = append(sources, src)
				f.results = append(f.results, r)
				return nil
			}}
			location, sha := createArchive(t, []string{"content"})
			info, err := os.Stat(location)
			if err != nil {
				t.Fatal(err)
			}
			var size int64
			var files int
			archive := fileToAnalyze{sha256: sha, location: location, filename: filepath.Base(location), identity: IdentityOf(info), size: info.Size()}
			if err = f.c.recursiveExtract(archive, 0, &size, &files, logger); err != nil {
				t.Fatal(err)
			}
			f.drain()
			f.drain()
			f.mu.Lock()
			defer f.mu.Unlock()
			if submitted != 0 {
				t.Errorf("%d submissions, want none: the archive is encrypted and over the limit", submitted)
			}
			if len(sources) != 1 || sources[0].TooBig == nested {
				t.Errorf("sources = %+v, want TooBig = %v", sources, !nested)
			}
		})
	}
}

// Only a plugin result that merely dispenses the file from analysis is marked
// as passed without analysis: a refusal, whatever it says, is not.
func TestMarkPolicySkipped(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name string
		in   datamodel.Result
		want bool
	}{
		{"a waiver", datamodel.Result{}, true},
		{"malware", datamodel.Result{Malware: true}, false},
		{"an error", datamodel.Result{Error: boom}, false},
		{"an analysis error", datamodel.Result{AnalysisError: "x"}, false},
		{"already marked", datamodel.Result{NotAnalyzedReason: datamodel.NotAnalyzedTooBig}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.in
			markPolicySkipped(&r, "/in/f")
			if got := r.NotAnalyzedReason == datamodel.NotAnalyzedPolicySkipped; got != tt.want {
				t.Errorf("marked = %v, want %v (%+v)", got, tt.want, r)
			}
		})
	}
}

// A member the plugins refuse with an analysis error is not listed among the
// files not analyzed of its archive: it is an error of the archive.
func TestRecursiveExtract_aMemberRefusedWithAnAnalysisErrorIsNotListedAsPassed(t *testing.T) {
	prev := ExtractFile
	t.Cleanup(func() { ExtractFile = prev })
	ExtractFile = func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		return plugins.Extraction{Files: []string{writeMember(t, outputDir, "m.txt", "member")}, Size: 6}, nil
	}
	f := newT17aFixture(t, Unanalyzable{})
	f.c.RegisterOnScanFile(func(_, _, _ string, isArchive bool) *datamodel.Result {
		if isArchive {
			return nil
		}
		return &datamodel.Result{AnalysisError: "the plugin could not decide"}
	})
	if err := f.extract(t); err != nil {
		t.Fatal(err)
	}
	f.drain()
	r := f.only(t)
	if len(r.NotAnalyzedSubfiles) != 0 || r.NotAnalyzedSubfilesCount != 0 {
		t.Errorf("result = %+v, want the member not listed as passed", r)
	}
	if r.AnalysisError == "" {
		t.Errorf("result = %+v, want the analysis error kept", r)
	}
}

// An archive the limits did not let open is submitted first, then follows the
// stricter of the policies of the files too big and of the encrypted files: its
// content is unknown and it may be encrypted.
func TestRecursiveExtract_aLimitSkippedArchiveFollowsTheStricterPolicy(t *testing.T) {
	rank := map[string]int{PolicyPass: 0, PolicyMitigate: 1, PolicyError: 2}
	for _, tooBig := range []string{PolicyError, PolicyPass, PolicyMitigate} {
		for _, encrypted := range []string{PolicyError, PolicyPass, PolicyMitigate} {
			t.Run(tooBig+"/"+encrypted, func(t *testing.T) {
				prev := ExtractFile
				t.Cleanup(func() { ExtractFile = prev })
				ExtractFile, _ = nestedExtractor(t, func(string) (plugins.Extraction, error) {
					t.Error("the inner archive must not be opened beyond the limit")
					return plugins.Extraction{}, nil
				})
				f := newT17aFixture(t, Unanalyzable{TooBig: tooBig, Encrypted: encrypted})
				f.c.config.RecursiveExtractMaxDepth = 1
				var submitted int
				var mu sync.Mutex
				submitter := archiveCleanSubmitter()
				inner := submitter.WaitForFileMock
				submitter.WaitForFileMock = func(ctx context.Context, p string, o gdetect.WaitForOptions) (gdetect.Result, error) {
					mu.Lock()
					submitted++
					mu.Unlock()
					return inner(ctx, p, o)
				}
				echoReader(submitter)
				f.c.submitter = submitter
				if err := f.extract(t); err != nil {
					t.Fatal(err)
				}
				f.drain()
				f.drain()
				r := f.only(t)
				stricter := tooBig
				if rank[encrypted] > rank[tooBig] {
					stricter = encrypted
				}
				mu.Lock()
				defer mu.Unlock()
				if submitted != 2 {
					t.Errorf("%d submissions, want the clean member and the archive left out", submitted)
				}
				switch stricter {
				case PolicyError:
					if r.Error == nil {
						t.Errorf("result = %+v, want the archive in error", r)
					}
				case PolicyMitigate:
					if !r.Malware || r.MalwareReason != datamodel.TooBig {
						t.Errorf("result = %+v, want malware", r)
					}
				case PolicyPass:
					if r.Error != nil || r.Malware || len(r.NotAnalyzedSubfiles) != 1 {
						t.Errorf("result = %+v, want b.zip listed as passed", r)
					}
				}
			})
		}
	}
}

// A malicious verdict on an archive left out wins over every policy, and an
// archive over max_file_size is not submitted at all.
func TestRecursiveExtract_aLimitSkippedArchiveKnownAsMalwareIsMalware(t *testing.T) {
	prev := ExtractFile
	t.Cleanup(func() { ExtractFile = prev })
	ExtractFile, _ = nestedExtractor(t, func(string) (plugins.Extraction, error) {
		return plugins.Extraction{}, nil
	})
	f := newT17aFixture(t, Unanalyzable{TooBig: PolicyPass, Encrypted: PolicyPass})
	f.c.config.RecursiveExtractMaxDepth = 1
	submitter := archiveCleanSubmitter()
	submitter.WaitForFileMock = func(_ context.Context, p string, _ gdetect.WaitForOptions) (gdetect.Result, error) {
		if filepath.Base(p) == "b.zip" {
			return gdetect.Result{Malware: true, Malwares: []string{"evil"}}, nil
		}
		return gdetect.Result{}, nil
	}
	echoReader(submitter)
	f.c.submitter = submitter
	if err := f.extract(t); err != nil {
		t.Fatal(err)
	}
	f.drain()
	f.drain()
	if r := f.only(t); !r.Malware {
		t.Errorf("result = %+v, want malware: the verdict on the archive left out wins", r)
	}
}

// An ordinary binary is not an archive: at the maximum depth or beyond the
// budget it is analyzed as the file it is, and a small one does not start 7z.
func TestRecursiveExtract_anOrdinaryBinaryIsNotLeftOutNorExtracted(t *testing.T) {
	prev := ExtractFile
	t.Cleanup(func() { ExtractFile = prev })
	var extractions int
	ExtractFile = func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		extractions++
		if extractions == 1 {
			return plugins.Extraction{Files: []string{writeMember(t, outputDir, "tool.bin", string([]byte{0x7f, 0x01, 0x02, 0xff, 0xfe, 0x00, 0x10, 0x80}))}, Size: 8}, nil
		}
		return plugins.Extraction{}, nil
	}
	f := newT17aFixture(t, Unanalyzable{TooBig: PolicyError, Encrypted: PolicyError})
	f.c.config.RecursiveExtractMaxDepth = 1
	if err := f.extract(t); err != nil {
		t.Fatal(err)
	}
	f.drain()
	r := f.only(t)
	if r.Error != nil || r.Malware || len(r.NotAnalyzedSubfiles) != 0 {
		t.Errorf("result = %+v, want the binary analyzed normally", r)
	}
	if extractions != 1 {
		t.Errorf("%d extractions, want only the archive", extractions)
	}
}

func TestIsSmallArchive_onlyAKnownArchiveFormatStartsTheExtractor(t *testing.T) {
	c, err := NewConnector(Config{WorkDir: t.TempDir()}, nil, cleanSubmitter())
	if err != nil {
		t.Fatal(err)
	}
	zipPath, _ := createArchive(t, []string{"content"})
	dir := t.TempDir()
	binary := writeMember(t, dir, "tool.bin", string([]byte{0x7f, 0x01, 0x02, 0xff, 0xfe, 0x00, 0x10, 0x80}))
	text := writeMember(t, dir, "note.txt", "plain text")
	for name, tt := range map[string]struct {
		path string
		want bool
	}{"a zip": {zipPath, true}, "an unknown binary": {binary, false}, "a text": {text, false}} {
		t.Run(name, func(t *testing.T) {
			if got := c.isSmallArchive(fileToAnalyze{location: tt.path}); got != tt.want {
				t.Errorf("isSmallArchive() = %v, want %v", got, tt.want)
			}
			if got := c.isArchiveType(tt.path); got != tt.want {
				t.Errorf("isArchiveType() = %v, want %v", got, tt.want)
			}
		})
	}
}
