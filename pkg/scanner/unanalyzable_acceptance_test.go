package scanner

import (
	"archive/zip"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/quarantine"
)

const accMax = 200

type accCapture struct {
	src    Source
	result datamodel.Result
	report datamodel.Report
}

type accRun struct {
	in, out, qdir string
	captures      []accCapture
	submitted     atomic.Int32
	scanErr       map[string]error
}

func (r *accRun) one(t *testing.T, name string) accCapture {
	t.Helper()
	var got []accCapture
	for _, c := range r.captures {
		if filepath.Base(c.src.Path) == name {
			got = append(got, c)
		}
	}
	if len(got) != 1 {
		t.Fatalf("the actions ran %d time(s) for %s, want once", len(got), name)
	}
	return got[0]
}

func (r *accRun) exists(dir, name string) bool {
	_, err := os.Lstat(filepath.Join(dir, name))
	return err == nil
}

func (r *accRun) quarantined(t *testing.T) int {
	t.Helper()
	locks, err := filepath.Glob(filepath.Join(r.qdir, "*.lock"))
	if err != nil {
		t.Fatal(err)
	}
	return len(locks)
}

type accSetup struct {
	policy  Unanalyzable
	files   map[string]string // name -> content
	extract plugins.ExtractFile
	// submit answers the analysis of a file by its name; nil means a clean verdict.
	submit func(name string) (gdetect.Result, error)
	// scanned is registered as an OnFileScanned callback.
	scanned plugins.OnFileScanned
	// maxDepth is the extraction depth, 3 when 0.
	maxDepth int
	// remove deletes the detected files instead of quarantining them.
	remove bool
	// inform receives the console line of each file.
	inform io.WriteCloser
}

// runAcc runs the real pipeline (move + quarantine actions) on the files.
func runAcc(t *testing.T, s accSetup) *accRun {
	t.Helper()
	root := t.TempDir()
	r := &accRun{in: filepath.Join(root, "in"), out: filepath.Join(root, "out"), qdir: t.TempDir(), scanErr: map[string]error{}}
	for _, d := range []string{r.in, r.out} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	q, err := quarantine.NewQuarantineHandler(t.Context(), quarantine.Config{Location: r.qdir, LockPassword: "infected"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := q.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	prev := ExtractFile
	t.Cleanup(func() { ExtractFile = prev })
	extract := s.extract
	if extract == nil {
		extract = func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
			return plugins.Extraction{}, plugins.ErrUnsupportedFormat
		}
	}
	ExtractFile = extract

	var mu sync.Mutex
	capture := &MockAction{HandleMock: func(_ context.Context, src Source, res datamodel.Result, rep *datamodel.Report) error {
		mu.Lock()
		defer mu.Unlock()
		r.captures = append(r.captures, accCapture{src, res, *rep})
		return nil
	}}
	submitter := archiveCleanSubmitter()
	submitter.WaitForFileMock = func(_ context.Context, path string, _ gdetect.WaitForOptions) (gdetect.Result, error) {
		r.submitted.Add(1)
		if s.submit != nil {
			return s.submit(filepath.Base(path))
		}
		return gdetect.Result{}, nil
	}
	echoReader(submitter)
	submitter.GetResultBySHA256Mock = func(context.Context, string) (gdetect.Result, error) {
		return gdetect.Result{}, gdetect.HTTPError{Code: 404}
	}
	c, err := NewConnector(Config{
		MaxFileSize: accMax, Unanalyzable: s.policy, WorkDir: t.TempDir(),
		Extract: s.extract != nil, ExtractMinThreshold: 1, Workers: 2, ExtractWorkers: 1,
		RecursiveExtractMaxDepth: cmp.Or(s.maxDepth, 3),
		Actions:                  Actions{Move: true, Quarantine: !s.remove, Deleted: s.remove, Inform: s.inform != nil, InformDest: s.inform},
		MoveFrom:                 r.in, MoveTo: r.out, MoveMode: MoveModeCopy,
		CustomActions: []Action{capture},
	}, q, submitter)
	if err != nil {
		t.Fatal(err)
	}
	if s.scanned != nil {
		c.RegisterOnFileScanned(s.scanned)
	}
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	for name, content := range s.files {
		p := filepath.Join(r.in, name)
		if err = os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		r.scanErr[name] = c.ScanFile(t.Context(), p)
	}
	c.Close(t.Context())
	return r
}

// zipOf is a real zip (so that the pipeline identifies an archive) of at least
// size bytes, or the smallest one when size is 0.
func zipOf(t *testing.T, size int) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if size > 0 {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: "pad.bin", Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(bytes.Repeat([]byte("P"), size)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// memberExtractor extracts the given members (name -> content) from any archive.
func memberExtractor(members map[string]string) plugins.ExtractFile {
	return fakeExtractor(func(outputDir string) (uint64, []string, error) {
		var files []string
		var size uint64
		for n, c := range members {
			p := filepath.Join(outputDir, n)
			if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
				return 0, nil, err
			}
			files = append(files, p)
			size += uint64(len(c))
		}
		return size, files, nil
	})
}

type accOutcome int

const (
	accMoved accOutcome = iota
	accQuarantined
	accNone // stays in INPUT, nothing delivered
)

// The missing table of T16: each too_big policy × (simple file, archive that
// is not extractable, archive member) → result, action, report, Source.TooBig.
func TestT16a_tooBigPolicyTable(t *testing.T) {
	big := strings.Repeat("B", accMax+1)
	type want struct {
		outcome   accOutcome
		tooBig    bool
		reason    datamodel.NotAnalyzedReason
		malware   bool
		malReason datamodel.MalwareReason
		errIs     error
		hasErr    bool
		members   int // not-analyzed subfiles listed on the result
		malSubs   int
	}
	kinds := []struct {
		name  string
		setup func(p Unanalyzable) accSetup
		file  string
	}{
		{"simple file", func(p Unanalyzable) accSetup {
			return accSetup{policy: p, files: map[string]string{"f.bin": big}}
		}, "f.bin"},
		{"non-extractable archive", func(p Unanalyzable) accSetup {
			return accSetup{policy: p, files: map[string]string{"a.zip": big}, extract: func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
				return plugins.Extraction{}, plugins.ErrUnsupportedFormat
			}}
		}, "a.zip"},
		{"archive member", func(p Unanalyzable) accSetup {
			return accSetup{policy: p, files: map[string]string{"a.zip": zipOf(t, 0)}, extract: memberExtractor(map[string]string{"m.bin": big})}
		}, "a.zip"},
	}
	wants := map[string]map[string]want{
		PolicyError: {
			"simple file":             {outcome: accNone, tooBig: true, hasErr: true, errIs: errFileTooBig},
			"non-extractable archive": {outcome: accNone, tooBig: true, hasErr: true, errIs: errFileTooBig},
			"archive member":          {outcome: accNone, tooBig: false, hasErr: true},
		},
		PolicyPass: {
			"simple file":             {outcome: accMoved, tooBig: true, reason: datamodel.NotAnalyzedTooBig},
			"non-extractable archive": {outcome: accMoved, tooBig: true, reason: datamodel.NotAnalyzedTooBig},
			"archive member":          {outcome: accMoved, tooBig: false, members: 1},
		},
		PolicyMitigate: {
			"simple file":             {outcome: accQuarantined, tooBig: true, malware: true, malReason: datamodel.TooBig},
			"non-extractable archive": {outcome: accQuarantined, tooBig: true, malware: true, malReason: datamodel.TooBig},
			"archive member":          {outcome: accQuarantined, tooBig: false, malware: true, malSubs: 1},
		},
	}
	for _, policy := range []string{PolicyError, PolicyPass, PolicyMitigate} {
		for _, k := range kinds {
			w := wants[policy][k.name]
			t.Run(policy+"/"+k.name, func(t *testing.T) {
				r := runAcc(t, k.setup(Unanalyzable{TooBig: policy}))
				got := r.one(t, k.file)
				if got.src.TooBig != w.tooBig {
					t.Errorf("Source.TooBig = %v, want %v", got.src.TooBig, w.tooBig)
				}
				if (got.result.Error != nil) != w.hasErr || (w.errIs != nil && !errors.Is(got.result.Error, w.errIs)) {
					t.Errorf("Result.Error = %v, want error=%v (%v)", got.result.Error, w.hasErr, w.errIs)
				}
				if got.result.Malware != w.malware || (w.malReason != "" && got.result.MalwareReason != w.malReason) {
					t.Errorf("malware = %v/%q, want %v/%q", got.result.Malware, got.result.MalwareReason, w.malware, w.malReason)
				}
				if got.result.NotAnalyzedReason != w.reason {
					t.Errorf("NotAnalyzedReason = %q, want %q", got.result.NotAnalyzedReason, w.reason)
				}
				if len(got.result.NotAnalyzedSubfiles) != w.members || got.result.NotAnalyzedSubfilesCount != w.members {
					t.Errorf("NotAnalyzedSubfiles = %v (count %d), want %d", got.result.NotAnalyzedSubfiles, got.result.NotAnalyzedSubfilesCount, w.members)
				}
				for name, sub := range got.result.MaliciousSubfiles {
					if sub.MalwareReason != datamodel.TooBig {
						t.Errorf("member %s reason = %q, want too-big", name, sub.MalwareReason)
					}
				}
				if len(got.result.MaliciousSubfiles) != w.malSubs {
					t.Errorf("MaliciousSubfiles = %v, want %d", got.result.MaliciousSubfiles, w.malSubs)
				}
				if got.report.NotAnalyzedReason != w.reason || got.report.NotAnalyzedExtractedCount != w.members || len(got.report.NotAnalyzedExtractedFiles) != w.members {
					t.Errorf("report = reason %q, %d listed, count %d; want %q, %d", got.report.NotAnalyzedReason, len(got.report.NotAnalyzedExtractedFiles), got.report.NotAnalyzedExtractedCount, w.reason, w.members)
				}
				if w.hasErr && got.report.Error == "" {
					t.Error("Report.Error is empty for a failed file")
				}
				if !w.hasErr && got.report.Error != "" {
					t.Errorf("Report.Error = %q for a file that did not fail", got.report.Error)
				}
				moved, quarantined := r.exists(r.out, k.file), r.quarantined(t)
				switch w.outcome {
				case accMoved:
					if !moved || quarantined != 0 {
						t.Errorf("moved=%v quarantined=%d, want delivered to OUTPUT only", moved, quarantined)
					}
				case accQuarantined:
					if moved || quarantined != 1 {
						t.Errorf("moved=%v quarantined=%d, want quarantined only", moved, quarantined)
					}
				case accNone:
					if moved || quarantined != 0 || !r.exists(r.in, k.file) {
						t.Errorf("moved=%v quarantined=%d inInput=%v, want left in INPUT", moved, quarantined, r.exists(r.in, k.file))
					}
				}
				if r.submitted.Load() > 1 {
					t.Errorf("%d submission(s): a file over max_file_size must never be submitted", r.submitted.Load())
				}
			})
		}
	}
}

// A large archive that is extracted and whose members are analyzed is not "too
// big": whatever the policy, TooBig stays false and nothing is marked.
func TestT16a_largeExtractedArchiveIsNeverTooBig(t *testing.T) {
	for _, policy := range []string{PolicyError, PolicyPass, PolicyMitigate} {
		t.Run(policy, func(t *testing.T) {
			r := runAcc(t, accSetup{
				policy:  Unanalyzable{TooBig: policy},
				files:   map[string]string{"big.zip": zipOf(t, 4*accMax)},
				extract: memberExtractor(map[string]string{"m.bin": "small"}),
			})
			got := r.one(t, "big.zip")
			if got.src.TooBig {
				t.Error("Source.TooBig = true for an extracted archive")
			}
			if got.result.Error != nil || got.result.Malware || got.result.NotAnalyzedReason != "" || got.result.NotAnalyzedSubfilesCount != 0 {
				t.Errorf("result = %+v, want clean and fully analyzed", got.result)
			}
			if !r.exists(r.out, "big.zip") {
				t.Error("the verified archive was not delivered")
			}
		})
	}
}

// Size exactly max_file_size is analyzed; max+1 is not.
func TestT16a_sizeBoundary(t *testing.T) {
	tests := []struct {
		name       string
		size       int
		wantTooBig bool
	}{
		{"max-1", accMax - 1, false},
		{"max", accMax, false},
		{"max+1", accMax + 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runAcc(t, accSetup{policy: Unanalyzable{TooBig: PolicyPass}, files: map[string]string{"f.bin": strings.Repeat("x", tt.size)}})
			got := r.one(t, "f.bin")
			if got.src.TooBig != tt.wantTooBig {
				t.Errorf("Source.TooBig = %v, want %v", got.src.TooBig, tt.wantTooBig)
			}
			if (got.result.NotAnalyzedReason == datamodel.NotAnalyzedTooBig) != tt.wantTooBig {
				t.Errorf("NotAnalyzedReason = %q", got.result.NotAnalyzedReason)
			}
			if wantSub := int32(0); tt.wantTooBig && r.submitted.Load() != wantSub {
				t.Errorf("submitted %d times, want 0", r.submitted.Load())
			} else if !tt.wantTooBig && r.submitted.Load() != 1 {
				t.Errorf("submitted %d times, want 1", r.submitted.Load())
			}
		})
	}
}

// Zero-length file: skip refuses at submission; mitigate quarantines with
// reason empty; extract_error / pass are refused by the configuration.
func TestT16a_emptyFile(t *testing.T) {
	t.Run("skip", func(t *testing.T) {
		r := runAcc(t, accSetup{policy: Unanalyzable{Empty: PolicySkip}, files: map[string]string{"e.bin": ""}})
		if len(r.captures) != 0 || !r.exists(r.in, "e.bin") || r.exists(r.out, "e.bin") {
			t.Errorf("an empty file under skip must be left alone: %d action run(s)", len(r.captures))
		}
	})
	t.Run("mitigate", func(t *testing.T) {
		r := runAcc(t, accSetup{policy: Unanalyzable{Empty: PolicyMitigate}, files: map[string]string{"e.bin": ""}})
		got := r.one(t, "e.bin")
		if !got.result.Malware || got.result.MalwareReason != datamodel.Empty || got.src.TooBig {
			t.Errorf("result = %+v TooBig=%v, want malware/empty, TooBig false", got.result, got.src.TooBig)
		}
		if r.quarantined(t) != 1 || r.exists(r.out, "e.bin") {
			t.Error("an empty file under mitigate must be quarantined, not delivered")
		}
		if r.submitted.Load() != 0 {
			t.Error("an empty file must not be submitted")
		}
	})
	t.Run("pass is accepted with copy and refused with rename", func(t *testing.T) {
		if _, err := NewConnector(Config{Unanalyzable: Unanalyzable{Empty: PolicyPass}, MoveMode: MoveModeCopy, WorkDir: t.TempDir()}, nil, cleanSubmitter()); err != nil {
			t.Errorf("empty: pass with copy refused: %v", err)
		}
		rename := Config{Unanalyzable: Unanalyzable{Empty: PolicyPass}, MoveMode: MoveModeRename, Actions: Actions{Move: true}, MoveTo: t.TempDir(), MoveFrom: t.TempDir(), WorkDir: t.TempDir()}
		if _, err := NewConnector(rename, nil, cleanSubmitter()); err == nil {
			t.Error("empty: pass with rename and the move on accepted")
		}
		rename.Actions.Move = false
		if _, err := NewConnector(rename, nil, cleanSubmitter()); err != nil {
			t.Errorf("the mode means nothing with the move off: %v", err)
		}
	})
}

// A member that is empty inside an archive is unchanged by the empty policy.
func TestT16a_emptyArchiveMemberIsUnchanged(t *testing.T) {
	for _, p := range []string{PolicySkip, PolicyMitigate} {
		t.Run(p, func(t *testing.T) {
			r := runAcc(t, accSetup{
				policy:  Unanalyzable{Empty: p},
				files:   map[string]string{"a.zip": zipOf(t, 0)},
				extract: memberExtractor(map[string]string{"empty.bin": "", "ok.bin": "ok"}),
			})
			got := r.one(t, "a.zip")
			if got.result.Malware || got.result.NotAnalyzedSubfilesCount != 0 || got.src.TooBig {
				t.Errorf("result = %+v: empty members of archives must be unchanged", got.result)
			}
		})
	}
}

func TestT16a_configValidation(t *testing.T) {
	tests := []struct {
		name string
		u    Unanalyzable
		ok   bool
	}{
		{"defaults", Unanalyzable{}, true},
		{"too_big error", Unanalyzable{TooBig: "error"}, true},
		{"too_big pass", Unanalyzable{TooBig: "pass"}, true},
		{"too_big mitigate", Unanalyzable{TooBig: "mitigate"}, true},
		{"too_big skip", Unanalyzable{TooBig: "skip"}, false},
		{"empty skip", Unanalyzable{Empty: "skip"}, true},
		{"empty mitigate", Unanalyzable{Empty: "mitigate"}, true},
		{"empty error", Unanalyzable{Empty: "error"}, false},
		{"encrypted error", Unanalyzable{Encrypted: "error"}, true},
		{"encrypted pass", Unanalyzable{Encrypted: "pass"}, true},
		{"encrypted mitigate", Unanalyzable{Encrypted: "mitigate"}, true},
		{"encrypted skip", Unanalyzable{Encrypted: "skip"}, false},
		{"extract_error error", Unanalyzable{ExtractError: "error"}, true},
		{"extract_error pass", Unanalyzable{ExtractError: "pass"}, false},
		{"extract_error as_file", Unanalyzable{ExtractError: "as_file"}, true},
		{"case matters", Unanalyzable{TooBig: "PASS"}, false},
		{"whitespace", Unanalyzable{TooBig: " pass"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewConnector(Config{Unanalyzable: tt.u, WorkDir: t.TempDir()}, nil, cleanSubmitter())
			if (err == nil) != tt.ok {
				t.Errorf("NewConnector(%+v) error = %v, want ok=%v", tt.u, err, tt.ok)
			}
		})
	}
}

// S11: a plugin that rejects a file non-maliciously is visible as policy-skipped.
func TestT16a_policySkippedIsVisible(t *testing.T) {
	c := policyConnector(t, Unanalyzable{}, accMax, cleanSubmitter())
	c.onScanFileCbs = []plugins.OnScanFile{func(string, string, string, bool) *datamodel.Result {
		return &datamodel.Result{}
	}}
	in := fileToAnalyze{filename: "f", location: "/in/f", sha256: "s", size: 5}
	res := c.analyzeFile(in)
	if res.NotAnalyzedReason != datamodel.NotAnalyzedPolicySkipped {
		t.Errorf("NotAnalyzedReason = %q, want policy-skipped", res.NotAnalyzedReason)
	}
	if res.Malware || res.Error != nil {
		t.Errorf("result = %+v: a policy skip is neither malware nor error", res)
	}
}

// Report bounds (S14): hostile lists never exceed the limits and the encoding
// stays under MaxReportSize.
func TestT16a_reportBounds(t *testing.T) {
	long := strings.Repeat("é", 5000)
	huge := make([]datamodel.NotAnalyzedFile, 50_000)
	for i := range huge {
		huge[i] = datamodel.NotAnalyzedFile{FileName: fmt.Sprintf("%s-%d", long, i), Size: 1, Reason: datamodel.NotAnalyzedTooBig}
	}
	mal := make([]datamodel.ExtractedFile, 5000)
	for i := range mal {
		mal[i] = datamodel.ExtractedFile{FileName: long + strconv.Itoa(i), Malwares: make([]string, 500)}
	}
	names := make([]string, 10_000)
	for i := range names {
		names[i] = long
	}
	res := datamodel.Result{
		Error:               errors.New(long + long),
		NotAnalyzedSubfiles: huge, NotAnalyzedSubfilesCount: 50_000,
		MaliciousSubfiles: map[string]datamodel.Result{}, Malwares: names,
	}
	rep := &datamodel.Report{}
	a := &ReportAction{}
	if err := a.Handle(t.Context(), Source{Path: "/in/a.zip", SHA256: "s"}, res, rep); err != nil {
		t.Fatal(err)
	}
	rep.MaliciousExtractedFiles = mal
	rep.Bound()
	if len(rep.NotAnalyzedExtractedFiles) > datamodel.MaxListedSubfiles {
		t.Errorf("%d not-analyzed entries, max %d", len(rep.NotAnalyzedExtractedFiles), datamodel.MaxListedSubfiles)
	}
	if rep.NotAnalyzedExtractedCount != 50_000 {
		t.Errorf("NotAnalyzedExtractedCount = %d, want the exact 50000", rep.NotAnalyzedExtractedCount)
	}
	if len(rep.Malwares) > datamodel.MaxReportMalwares {
		t.Errorf("%d malwares, max %d", len(rep.Malwares), datamodel.MaxReportMalwares)
	}
	if len(rep.MaliciousExtractedFiles) > datamodel.MaxReportMaliciousFiles {
		t.Errorf("%d malicious files", len(rep.MaliciousExtractedFiles))
	}
	if len(rep.Error) > datamodel.MaxListedNameLen+32 {
		t.Errorf("Error is %d bytes", len(rep.Error))
	}
	for _, f := range rep.NotAnalyzedExtractedFiles {
		if len(f.FileName) > datamodel.MaxListedNameLen+32 {
			t.Fatalf("name of %d bytes", len(f.FileName))
		}
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > datamodel.MaxReportSize {
		t.Errorf("encoded report is %d bytes, max %d", len(b), datamodel.MaxReportSize)
	}
	if rep.NotAnalyzedReason != "" || rep.Error == "" {
		t.Errorf("Report.Error / reason not copied: %q %q", rep.Error, rep.NotAnalyzedReason)
	}
}

// S23: OnFileScanned cannot wipe the not-analyzed marks.
func TestT16a_onFileScannedCannotEraseNotAnalyzed(t *testing.T) {
	c := policyConnector(t, Unanalyzable{TooBig: PolicyPass}, accMax, cleanSubmitter())
	c.onFileScannedCbs = []namedFileScanned{{plugin: "p", fn: func(string, string, datamodel.Result) *datamodel.Result {
		return &datamodel.Result{}
	}}}
	in := fileToAnalyze{filename: "f", location: "/in/f", sha256: "s", size: accMax + 1}
	res := c.analyzeFile(in)
	if res.NotAnalyzedReason != datamodel.NotAnalyzedTooBig {
		t.Errorf("NotAnalyzedReason = %q after OnFileScanned: S23 guard missing", res.NotAnalyzedReason)
	}
}

// extract_error is error or as_file: another value is refused at startup.
func TestT16a_extractErrorOnlyErrorOrAsFile(t *testing.T) {
	for _, v := range []string{"pass", "mitigate", "skip"} {
		if _, err := NewConnector(Config{Unanalyzable: Unanalyzable{ExtractError: v}, WorkDir: t.TempDir()}, nil, cleanSubmitter()); err == nil {
			t.Errorf("extract_error=%q accepted", v)
		}
	}
}
