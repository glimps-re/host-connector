package scanner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

func policyConnector(t *testing.T, u Unanalyzable, maxSize int64, submitter *gdetectMock.MockGDetectSubmitter) *Connector {
	t.Helper()
	c, err := NewConnector(Config{MaxFileSize: maxSize, Unanalyzable: u, WorkDir: t.TempDir()}, nil, submitter)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func malwareSubmitter() *gdetectMock.MockGDetectSubmitter {
	return echoReader(&gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForFileMock: func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) {
			return gdetect.Result{Malware: true, Malwares: []string{"evil"}}, nil
		},
	})
}

func TestUnanalyzable_defaultsAndValidation(t *testing.T) {
	c := policyConnector(t, Unanalyzable{}, 100, cleanSubmitter())
	if got := c.config.Unanalyzable; got != (Unanalyzable{TooBig: PolicyError, Empty: PolicyPass, Encrypted: PolicyError, ExtractError: PolicyError, AnalysisError: PolicyError}) {
		t.Errorf("defaults = %+v", got)
	}
	for _, bad := range []Unanalyzable{{TooBig: "skip"}, {Empty: "error"}, {Encrypted: "skip"}, {ExtractError: "pass"}, {TooBig: "bogus"}, {AnalysisError: "skip"}} {
		if _, err := NewConnector(Config{Unanalyzable: bad, WorkDir: t.TempDir()}, nil, cleanSubmitter()); err == nil {
			t.Errorf("NewConnector(%+v) accepted an invalid policy", bad)
		}
	}
}

func TestAnalyzeFile_tooBigPolicies(t *testing.T) {
	in := fileToAnalyze{filename: "f", location: "/in/f", sha256: "sha", size: 500}
	tests := []struct {
		policy string
		check  func(t *testing.T, r datamodel.Result)
	}{
		{PolicyError, func(t *testing.T, r datamodel.Result) {
			if !errors.Is(r.Error, errFileTooBig) || r.Malware || r.NotAnalyzedReason != "" {
				t.Errorf("result = %+v, want errFileTooBig only", r)
			}
		}},
		{PolicyPass, func(t *testing.T, r datamodel.Result) {
			if r.Error != nil || r.Malware || r.NotAnalyzedReason != datamodel.NotAnalyzedTooBig || r.FilteredVolume != 500 {
				t.Errorf("result = %+v, want passed marked too-big", r)
			}
		}},
		{PolicyMitigate, func(t *testing.T, r datamodel.Result) {
			want := datamodel.Result{Filename: "f", Location: "/in/f", SHA256: "sha", FileSize: 500, FilteredVolume: 500, Malware: true, Score: 1000, MalwareReason: datamodel.TooBig}
			if r.Error != nil || r.Malware != want.Malware || r.Score != want.Score || r.MalwareReason != want.MalwareReason || r.FilteredVolume != want.FilteredVolume || r.FileSize != want.FileSize {
				t.Errorf("result = %+v, want %+v", r, want)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.policy, func(t *testing.T) {
			c := policyConnector(t, Unanalyzable{TooBig: tt.policy}, 100, cleanSubmitter())
			tt.check(t, c.analyzeFile(in))
		})
	}
}

func TestAnalyzeFile_emptyPolicies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	in := fileToAnalyze{filename: "empty", location: path, sha256: shaOf(""), size: 0}
	c := policyConnector(t, Unanalyzable{}, 100, cleanSubmitter())
	if r := c.analyzeFile(in); r.Error != nil || r.Malware || r.NotAnalyzedReason != datamodel.NotAnalyzedEmpty {
		t.Errorf("pass: result = %+v", r)
	}
	c = policyConnector(t, Unanalyzable{Empty: PolicyMitigate}, 100, cleanSubmitter())
	if r := c.analyzeFile(in); r.Error != nil || !r.Malware || r.MalwareReason != datamodel.Empty {
		t.Errorf("mitigate: result = %+v", r)
	}
}

func TestAnalyzeFile_encryptedPolicies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.zip")
	if err := os.WriteFile(path, []byte("encrypted archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := fileToAnalyze{filename: "a.zip", location: path, sha256: shaOf("encrypted archive"), size: 17, encrypted: true}
	for _, tt := range []struct {
		policy string
		check  func(r datamodel.Result) bool
	}{
		{PolicyError, func(r datamodel.Result) bool { return errors.Is(r.Error, errEncrypted) }},
		{PolicyPass, func(r datamodel.Result) bool {
			return r.Error == nil && !r.Malware && r.NotAnalyzedReason == datamodel.NotAnalyzedEncrypted
		}},
		{PolicyMitigate, func(r datamodel.Result) bool {
			return r.Error == nil && r.Malware && r.MalwareReason == datamodel.Encrypted
		}},
	} {
		t.Run(tt.policy, func(t *testing.T) {
			c := policyConnector(t, Unanalyzable{Encrypted: tt.policy}, 1000, cleanSubmitter())
			if r := c.analyzeFile(in); !tt.check(r) {
				t.Errorf("result = %+v", r)
			}
		})
		t.Run(tt.policy+" known malware wins", func(t *testing.T) {
			c := policyConnector(t, Unanalyzable{Encrypted: tt.policy}, 1000, malwareSubmitter())
			r := c.analyzeFile(in)
			if !r.Malware || r.MalwareReason != datamodel.MalwareDetected || r.Error != nil || r.NotAnalyzedReason != "" {
				t.Errorf("result = %+v, want the detection whatever the policy", r)
			}
		})
	}
	t.Run("larger than max_file_size is not submitted", func(t *testing.T) {
		submitted := false
		sub := cleanSubmitter()
		sub.WaitForReaderMock = func(context.Context, io.Reader, gdetect.WaitForOptions) (gdetect.Result, error) {
			submitted = true
			return gdetect.Result{}, nil
		}
		c := policyConnector(t, Unanalyzable{Encrypted: PolicyPass, TooBig: PolicyError}, 5, sub)
		r := c.analyzeFile(in)
		if submitted || r.NotAnalyzedReason != datamodel.NotAnalyzedEncrypted {
			t.Errorf("submitted=%v result=%+v, want the encrypted policy and no submission", submitted, r)
		}
	})
}

func TestAnalyzeFile_aFilteredFileIsMarkedPolicySkipped(t *testing.T) {
	c := policyConnector(t, Unanalyzable{}, 100, cleanSubmitter())
	c.onScanFileCbs = append(c.onScanFileCbs, func(string, string, string, bool) *datamodel.Result {
		return &datamodel.Result{}
	})
	r := c.analyzeFile(fileToAnalyze{filename: "f", location: "/in/f", size: 3})
	if r.NotAnalyzedReason != datamodel.NotAnalyzedPolicySkipped {
		t.Errorf("result = %+v, want policy-skipped", r)
	}
	c.onScanFileCbs = []func(string, string, string, bool) *datamodel.Result{func(string, string, string, bool) *datamodel.Result {
		return &datamodel.Result{Malware: true, MalwareReason: datamodel.FilteredFileType}
	}}
	if r = c.analyzeFile(fileToAnalyze{filename: "f", location: "/in/f", size: 3}); r.NotAnalyzedReason != "" {
		t.Errorf("a mitigated file must not be marked as passed: %+v", r)
	}
}

func TestRestoreHardened_aPluginCannotEraseWhatWasNotAnalyzed(t *testing.T) {
	prev := datamodel.Result{NotAnalyzedReason: datamodel.NotAnalyzedTooBig, NotAnalyzedSubfilesCount: 2, NotAnalyzedSubfiles: []datamodel.NotAnalyzedFile{{FileName: "a"}, {FileName: "b"}}}
	next := datamodel.Result{}
	if !restoreHardened(prev, &next) || next.NotAnalyzedReason != prev.NotAnalyzedReason || next.NotAnalyzedSubfilesCount != 2 || len(next.NotAnalyzedSubfiles) != 2 {
		t.Errorf("restoreHardened left %+v", next)
	}
}

func TestReportAction_copiesTheUnanalyzedFieldsAndTheError(t *testing.T) {
	res := datamodel.Result{
		Error:                    errFileTooBig,
		NotAnalyzedReason:        datamodel.NotAnalyzedTooBig,
		NotAnalyzedSubfiles:      []datamodel.NotAnalyzedFile{{FileName: "m", Reason: datamodel.NotAnalyzedEncrypted}},
		NotAnalyzedSubfilesCount: 7,
	}
	report := &datamodel.Report{}
	if err := (&ReportAction{}).Handle(t.Context(), Source{Path: "/in/f"}, res, report); err != nil {
		t.Fatal(err)
	}
	if report.Error != errFileTooBig.Error() || report.NotAnalyzedReason != datamodel.NotAnalyzedTooBig || report.NotAnalyzedExtractedCount != 7 || len(report.NotAnalyzedExtractedFiles) != 1 {
		t.Errorf("report = %+v", report)
	}
}

func TestPrintAction_aFileLetThroughUnanalyzedIsPrintedWithoutVerbose(t *testing.T) {
	var out bytes.Buffer
	a := &PrintAction{Out: &out}
	res := datamodel.Result{SHA256: "sha", NotAnalyzedReason: datamodel.NotAnalyzedTooBig}
	if err := a.Handle(t.Context(), Source{Path: "/in/f"}, res, &datamodel.Report{}); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "reason: not analyzed (too big), content not verified") {
		t.Errorf("printed %q", got)
	}
	out.Reset()
	res = datamodel.Result{SHA256: "sha", NotAnalyzedSubfilesCount: 3}
	if err := a.Handle(t.Context(), Source{Path: "/in/f"}, res, &datamodel.Report{}); err != nil || !strings.Contains(out.String(), "3 extracted file(s) not analyzed") {
		t.Errorf("printed %q (%v)", out.String(), err)
	}
	out.Reset()
	if err := a.Handle(t.Context(), Source{Path: "/in/f"}, datamodel.Result{SHA256: "sha"}, &datamodel.Report{}); err != nil || out.Len() != 0 {
		t.Errorf("a clean file printed %q without verbose (%v)", out.String(), err)
	}
}

func TestGetMitigationReason_emptyAndEncryptedAreInvalid(t *testing.T) {
	for _, r := range []datamodel.MalwareReason{datamodel.Empty, datamodel.Encrypted} {
		if got := getMitigationReason(r); got == "" {
			t.Errorf("getMitigationReason(%s) is empty", r)
		}
	}
}

// What the pipeline does to a file too big under each policy, end to end:
// error leaves it in place, pass moves it and says so, mitigate does not move it.
func TestPipeline_tooBigPolicyEndToEnd(t *testing.T) {
	for _, tt := range []struct {
		policy    string
		wantMoved bool
		wantNote  datamodel.NotAnalyzedReason
	}{
		{PolicyError, false, ""},
		{PolicyPass, true, datamodel.NotAnalyzedTooBig},
		{PolicyMitigate, false, ""},
	} {
		t.Run(tt.policy, func(t *testing.T) {
			noOpenInputs(t)
			in, dest := t.TempDir(), t.TempDir()
			file := filepath.Join(in, "big.bin")
			if err := os.WriteFile(file, []byte("0123456789"), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := NewConnector(Config{
				Roots: []string{in}, WorkDir: t.TempDir(), Workers: 1, MaxFileSize: 4,
				MoveTo: dest, MoveFrom: in, Actions: Actions{Move: true},
				Unanalyzable: Unanalyzable{TooBig: tt.policy},
			}, nil, cleanSubmitter())
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var reports []datamodel.Report
			c.onReportCbs = append(c.onReportCbs, func(r *datamodel.Report) {
				mu.Lock()
				defer mu.Unlock()
				reports = append(reports, *r)
			})
			if err = c.Start(); err != nil {
				t.Fatal(err)
			}
			if err = c.ScanFile(t.Context(), file); err != nil {
				t.Fatal(err)
			}
			c.Close(t.Context())
			moved := filesUnder(t, dest)
			if (len(moved) > 0 && filepath.Base(moved[0]) == "big.bin") != tt.wantMoved {
				t.Errorf("destination holds %v, wantMoved=%v", moved, tt.wantMoved)
			}
			mu.Lock()
			defer mu.Unlock()
			if tt.wantMoved {
				if len(reports) != 1 || reports[0].NotAnalyzedReason != tt.wantNote || reports[0].MovedTo == "" {
					t.Errorf("reports = %+v, want one marked %s and moved", reports, tt.wantNote)
				}
			}
		})
	}
}

// The pipeline itself says a file was not analyzed because it is too big, under
// every policy, and the actions get it in Source.TooBig; a file within the
// limit, or one whose result merely says "too big", does not.
func TestProcessFile_theSourceSaysTheFileWasTooBig(t *testing.T) {
	tests := []struct {
		name      string
		policy    string
		size      int
		encrypted bool
		want      bool
	}{
		{"too big, error", PolicyError, 500, false, true},
		{"too big, pass", PolicyPass, 500, false, true},
		{"too big, mitigate", PolicyMitigate, 500, false, true},
		{"encrypted over the limit, pass", PolicyPass, 500, true, true},
		{"within the limit", PolicyPass, 50, false, false},
		{"encrypted within the limit", PolicyPass, 50, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := Unanalyzable{TooBig: tt.policy, Encrypted: tt.policy}
			c := policyConnector(t, policy, 100, cleanSubmitter())
			var got []Source
			var mu sync.Mutex
			c.action = &MockAction{HandleMock: func(_ context.Context, src Source, _ datamodel.Result, _ *datamodel.Report) error {
				mu.Lock()
				defer mu.Unlock()
				got = append(got, src)
				return nil
			}}
			location := filepath.Join(t.TempDir(), "f.bin")
			if err := os.WriteFile(location, bytes.Repeat([]byte("x"), tt.size), 0o600); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(location)
			if err != nil {
				t.Fatal(err)
			}
			sha, err := getFileSHA256(location)
			if err != nil {
				t.Fatal(err)
			}
			c.processFile(fileToAnalyze{sha256: sha, location: location, filename: "f.bin", identity: IdentityOf(info), size: info.Size(), encrypted: tt.encrypted})
			mu.Lock()
			defer mu.Unlock()
			if len(got) != 1 {
				t.Fatalf("%d actions, want 1", len(got))
			}
			if got[0].TooBig != tt.want {
				t.Errorf("Source.TooBig = %v, want %v", got[0].TooBig, tt.want)
			}
		})
	}
}

// A plugin that lets a file through before the size is looked at is a
// decision of the plugin, not of the size: the file is not marked too big.
func TestAnalyze_aFileLetThroughByAPluginIsNotTooBig(t *testing.T) {
	c := policyConnector(t, Unanalyzable{TooBig: PolicyPass}, 100, cleanSubmitter())
	c.onScanFileCbs = append(c.onScanFileCbs, func(string, string, string, bool) *datamodel.Result { return &datamodel.Result{} })
	var tooBig bool
	r := c.analyze(fileToAnalyze{filename: "f", location: "/in/f", size: 500}, &tooBig)
	if tooBig {
		t.Error("tooBig set for a file decided by a plugin")
	}
	if r.NotAnalyzedReason != datamodel.NotAnalyzedPolicySkipped {
		t.Errorf("reason = %q, want policy-skipped", r.NotAnalyzedReason)
	}
}

// A plugin that lets a whole archive through (skipped type, whitelisted path)
// does not analyze any member: the archive is marked policy-skipped, and a
// sub-archive is listed in the files not analyzed of its parent.
func policySkippedArchiveConnector(t *testing.T, results *[]datamodel.Result, mu *sync.Mutex) (*Connector, string, FileIdentity, string) {
	t.Helper()
	c := &Connector{
		action: &MockAction{HandleMock: func(_ context.Context, _ Source, r datamodel.Result, _ *datamodel.Report) error {
			mu.Lock()
			defer mu.Unlock()
			*results = append(*results, r)
			return nil
		}},
		archiveStatus: newArchiveStatusHandler(),
	}
	c.RegisterOnScanFile(func(_, location, _ string, isArchive bool) *datamodel.Result {
		if isArchive && strings.HasSuffix(location, "b.zip") || isArchive && strings.HasSuffix(location, "a.zip") && !strings.Contains(location, "parent") {
			return &datamodel.Result{}
		}
		return nil
	})
	dir := t.TempDir()
	location := filepath.Join(dir, "a.zip")
	if err := os.WriteFile(location, []byte("archive content"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(location)
	if err != nil {
		t.Fatal(err)
	}
	sha, err := getFileSHA256(location)
	if err != nil {
		t.Fatal(err)
	}
	return c, location, IdentityOf(info), sha
}

func TestAnalyzeArchiveFile_aTopLevelArchiveLetThroughByAPluginIsPolicySkipped(t *testing.T) {
	var results []datamodel.Result
	var mu sync.Mutex
	c, location, id, sha := policySkippedArchiveConnector(t, &results, &mu)
	archiveID := c.archiveStatus.addStatus(archiveStatus{archiveLocation: location, sha256: sha, identity: id, tmpFolder: t.TempDir(), total: 1, result: datamodel.Result{SHA256: sha, FileSize: 15}})
	in := fileToAnalyze{archiveID: archiveID, archiveLocation: location, archiveSHA256: sha, archiveSize: 15, filename: "x.txt", location: location + ".x"}
	if err := c.analyzeArchiveFile(in); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(results) != 1 || results[0].NotAnalyzedReason != datamodel.NotAnalyzedPolicySkipped || results[0].Error != nil {
		t.Fatalf("results = %+v, want one result marked policy-skipped", results)
	}
}

func TestAnalyzeArchiveFile_aSubArchiveLetThroughByAPluginIsListedByItsParent(t *testing.T) {
	var results []datamodel.Result
	var mu sync.Mutex
	c, location, id, sha := policySkippedArchiveConnector(t, &results, &mu)
	parent := filepath.Join(filepath.Dir(location), "parent", "a.zip")
	if err := os.MkdirAll(filepath.Dir(parent), 0o750); err != nil {
		t.Fatal(err)
	}
	parentID := c.archiveStatus.addStatus(archiveStatus{archiveLocation: location, sha256: sha, identity: id, tmpFolder: t.TempDir(), total: 1, result: datamodel.Result{SHA256: sha, FileSize: 15}})
	child := filepath.Join(filepath.Dir(location), "b.zip")
	childID := c.archiveStatus.addStatus(archiveStatus{archiveLocation: child, tmpFolder: t.TempDir(), total: 1, parentArchive: parentArchive{statusID: parentID, relPath: "b.zip"}})
	in := fileToAnalyze{archiveID: childID, archiveLocation: child, archiveSHA256: "child-sha", archiveSize: 99, filename: "y.txt", location: child + ".y"}
	if err := c.analyzeArchiveFile(in); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(results) != 1 {
		t.Fatalf("results = %+v, want the action of the top-level archive only", results)
	}
	want := []datamodel.NotAnalyzedFile{{FileName: "b.zip", Size: 99, Reason: datamodel.NotAnalyzedPolicySkipped}}
	if !slices.Equal(results[0].NotAnalyzedSubfiles, want) || results[0].NotAnalyzedSubfilesCount != 1 {
		t.Errorf("not analyzed = %+v (count %d), want %+v", results[0].NotAnalyzedSubfiles, results[0].NotAnalyzedSubfilesCount, want)
	}
}

func TestMergeResult_keepsTheReasonOfAMemberMitigatedWithoutAnalysis(t *testing.T) {
	for _, reason := range []datamodel.MalwareReason{datamodel.Encrypted, datamodel.Empty, datamodel.TooBig} {
		t.Run(string(reason), func(t *testing.T) {
			got := mergeResult(datamodel.Result{}, datamodel.Result{Malware: true, MalwareReason: reason}, "m", nil)
			if !got.Malware || got.MalwareReason != reason {
				t.Errorf("mergeResult() = %+v, want malware with reason %q", got, reason)
			}
		})
	}
	// A detection still wins over the reasons of the files not analyzed.
	got := mergeResult(datamodel.Result{Malware: true, MalwareReason: datamodel.Encrypted}, datamodel.Result{Malware: true, MalwareReason: datamodel.MalwareDetected}, "m", nil)
	if got.MalwareReason != datamodel.MalwareDetected {
		t.Errorf("reason = %q, want a detection to win", got.MalwareReason)
	}
}

// The size of an archive let through by a plugin is the pipeline's, whatever
// the plugin says: a wrong one would fail the check before the action and give
// the action the wrong time limit.
func TestAnalyzeArchiveFile_thePluginCannotChangeTheSizeOfTheArchive(t *testing.T) {
	var results []datamodel.Result
	var mu sync.Mutex
	c, location, id, sha := policySkippedArchiveConnector(t, &results, &mu)
	c.onScanFileCbs = []func(string, string, string, bool) *datamodel.Result{func(string, string, string, bool) *datamodel.Result {
		return &datamodel.Result{FileSize: 1 << 40, SHA256: "forged"}
	}}
	archiveID := c.archiveStatus.addStatus(archiveStatus{archiveLocation: location, sha256: sha, identity: id, tmpFolder: t.TempDir(), total: 1})
	in := fileToAnalyze{archiveID: archiveID, archiveLocation: location, archiveSHA256: sha, archiveSize: 15, filename: "x.txt", location: location + ".x"}
	if err := c.analyzeArchiveFile(in); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(results) != 1 || results[0].Error != nil || results[0].FileSize != 15 || results[0].SHA256 != sha {
		t.Fatalf("results = %+v, want one action with the size and the hash of the pipeline", results)
	}
}

func TestAnalyze_aResultOfAPluginWithoutHashOrSizeGetsThePipelines(t *testing.T) {
	c := policyConnector(t, Unanalyzable{}, 100, cleanSubmitter())
	c.onScanFileCbs = append(c.onScanFileCbs, func(string, string, string, bool) *datamodel.Result { return &datamodel.Result{} })
	r := c.analyzeFile(fileToAnalyze{filename: "f", location: "/in/f", sha256: "sha", size: 7})
	if r.SHA256 != "sha" || r.FileSize != 7 {
		t.Errorf("result = %+v, want the hash and the size of the pipeline", r)
	}
}

func TestRestoreHardened_restoresAListThatWasChangedNotOnlyShortened(t *testing.T) {
	prev := datamodel.Result{NotAnalyzedSubfilesCount: 1, NotAnalyzedSubfiles: []datamodel.NotAnalyzedFile{{FileName: "a", Reason: datamodel.NotAnalyzedTooBig}}}
	next := datamodel.Result{NotAnalyzedSubfilesCount: 1, NotAnalyzedSubfiles: []datamodel.NotAnalyzedFile{{FileName: "b", Reason: datamodel.NotAnalyzedTooBig}}}
	if !restoreHardened(prev, &next) || next.NotAnalyzedSubfiles[0].FileName != "a" {
		t.Errorf("next = %+v, want the list of prev back", next.NotAnalyzedSubfiles)
	}
}

// A top-level archive matched by a plugin rule goes through recursiveExtract,
// which asks the plugins itself: the archive is moved once, marked
// policy-skipped, with the size and the hash of the pipeline whatever the plugin
// answered.
func TestRecursiveExtract_aTopLevelArchiveLetThroughByAPluginIsMarkedAndKeepsItsSize(t *testing.T) {
	for name, pluginSize := range map[string]int64{"size left empty": 0, "size filled by the plugin": 1 << 40} {
		t.Run(name, func(t *testing.T) {
			prev := ExtractFile
			t.Cleanup(func() { ExtractFile = prev })
			ExtractFile = func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
				root, err := os.OpenRoot(outputDir)
				if err != nil {
					return plugins.Extraction{}, err
				}
				defer func() {
					if e := root.Close(); e != nil {
						t.Error(e)
					}
				}()
				if err = root.WriteFile("m.txt", []byte("member"), 0o600); err != nil {
					return plugins.Extraction{}, err
				}
				return plugins.Extraction{Files: []string{filepath.Join(outputDir, "m.txt")}, Size: 6}, nil
			}
			c, err := NewConnector(Config{Extract: true, WorkDir: t.TempDir(), ExtractMinThreshold: 1, Workers: 2}, nil, cleanSubmitter())
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
			c.RegisterOnScanFile(func(_, _, _ string, isArchive bool) *datamodel.Result {
				if isArchive {
					return &datamodel.Result{FileSize: pluginSize, SHA256: "forged"}
				}
				return nil
			})
			t.Cleanup(func() { c.Close(t.Context()) })
			location, sha := createArchive(t, []string{"content"})
			info, err := os.Stat(location)
			if err != nil {
				t.Fatal(err)
			}
			var size int64
			var files int
			archive := fileToAnalyze{sha256: sha, location: location, filename: filepath.Base(location), identity: IdentityOf(info), size: info.Size()}
			if err = c.recursiveExtract(archive, 0, &size, &files, logger); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(results) != 1 {
				t.Fatalf("%d actions, want the archive handled once: %+v", len(results), results)
			}
			r := results[0]
			if r.Error != nil || r.NotAnalyzedReason != datamodel.NotAnalyzedPolicySkipped || r.FileSize != info.Size() || r.SHA256 != sha {
				t.Errorf("result = %+v, want policy-skipped, no error, size %d and the pipeline's hash", r, info.Size())
			}
		})
	}
}

// The empty policy by move mode: an empty file is delivered as a new empty file
// (pass) unless the move renames, where only skipping is available; leaving the
// key out is never a reason to refuse the start.
func TestUnanalyzable_resolveByMoveMode(t *testing.T) {
	tests := []struct {
		name         string
		empty        string
		mode         MoveMode
		want         string
		wantFallback bool
		wantErr      bool
	}{
		{"absent with copy delivers", "", MoveModeCopy, PolicyPass, false, false},
		{"absent with no mode delivers", "", "", PolicyPass, false, false},
		{"absent with rename skips and warns", "", MoveModeRename, PolicySkip, true, false},
		{"explicit pass with copy", PolicyPass, MoveModeCopy, PolicyPass, false, false},
		{"explicit pass with rename is refused", PolicyPass, MoveModeRename, "", false, true},
		{"explicit skip with rename", PolicySkip, MoveModeRename, PolicySkip, false, false},
		{"explicit mitigate with rename", PolicyMitigate, MoveModeRename, PolicyMitigate, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, fallback, err := Unanalyzable{Empty: tt.empty}.resolve(tt.mode)
			if (err != nil) != tt.wantErr {
				t.Fatalf("resolve() error = %v, want error %v", err, tt.wantErr)
			}
			if err == nil && (got.Empty != tt.want || fallback != tt.wantFallback) {
				t.Errorf("resolve() = %q, fallback %v; want %q, %v", got.Empty, fallback, tt.want, tt.wantFallback)
			}
			if (CheckUnanalyzable(Unanalyzable{Empty: tt.empty}, tt.mode) != nil) != tt.wantErr {
				t.Error("CheckUnanalyzable disagrees with resolve")
			}
		})
	}
}

type captured struct {
	mu   sync.Mutex
	logs []string
}

func (c *captured) Enabled(context.Context, slog.Level) bool { return true }
func (c *captured) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logs = append(c.logs, r.Level.String()+" "+r.Message)
	return nil
}
func (c *captured) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *captured) WithGroup(string) slog.Handler      { return c }

// The fallback to skip is said in a Warn at each start.
func TestNewConnector_theFallbackToSkipWarns(t *testing.T) {
	prev := logger
	t.Cleanup(func() { logger = prev })
	rec := &captured{}
	logger = slog.New(rec)
	for _, tt := range []struct {
		mode     MoveMode
		wantWarn bool
	}{{MoveModeRename, true}, {MoveModeCopy, false}} {
		rec.mu.Lock()
		rec.logs = nil
		rec.mu.Unlock()
		cfg := Config{MoveMode: tt.mode, Actions: Actions{Move: true}, MoveTo: t.TempDir(), MoveFrom: t.TempDir(), WorkDir: t.TempDir()}
		if _, err := NewConnector(cfg, nil, cleanSubmitter()); err != nil {
			t.Fatal(err)
		}
		rec.mu.Lock()
		warned := slices.ContainsFunc(rec.logs, func(l string) bool {
			return strings.HasPrefix(l, "WARN ") && strings.Contains(l, "unanalyzable_policy.empty")
		})
		rec.mu.Unlock()
		if warned != tt.wantWarn {
			t.Errorf("mode %q: warned = %v, want %v (%v)", tt.mode, warned, tt.wantWarn, rec.logs)
		}
	}
}

// With the move action off the mode means nothing: pass is accepted with rename,
// and an empty policy left out is not turned into skip.
func TestNewConnector_theMoveModeCountsOnlyWhileTheMoveIsOn(t *testing.T) {
	prev := logger
	t.Cleanup(func() { logger = prev })
	rec := &captured{}
	logger = slog.New(rec)
	c, err := NewConnector(Config{MoveMode: MoveModeRename, Unanalyzable: Unanalyzable{Empty: PolicyPass}, WorkDir: t.TempDir()}, nil, cleanSubmitter())
	if err != nil || c.config.Unanalyzable.Empty != PolicyPass {
		t.Fatalf("NewConnector(rename, pass, move off) = %v, %v; want pass accepted", c, err)
	}
	c, err = NewConnector(Config{MoveMode: MoveModeRename, WorkDir: t.TempDir()}, nil, cleanSubmitter())
	if err != nil || c.config.Unanalyzable.Empty != PolicyPass {
		t.Fatalf("NewConnector(rename, absent, move off) = %v, %v; want the default pass", c, err)
	}
	rec.mu.Lock()
	warned := slices.ContainsFunc(rec.logs, func(l string) bool { return strings.Contains(l, "unanalyzable_policy.empty") })
	rec.mu.Unlock()
	if warned {
		t.Errorf("a Warn about the empty policy with the move off: %v", rec.logs)
	}
	if _, err = NewConnector(Config{MoveMode: MoveModeRename, Actions: Actions{Move: true}, MoveTo: t.TempDir(), MoveFrom: t.TempDir(), Unanalyzable: Unanalyzable{Empty: PolicyPass}, WorkDir: t.TempDir()}, nil, cleanSubmitter()); err == nil {
		t.Error("pass with rename and the move on must be refused")
	}
}
