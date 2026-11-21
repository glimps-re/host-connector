package scanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// nestedExtract answers the extraction of evil.zip with outer, and the one of
// every archive after it (inner.zip) with inner; a name of unavailable makes the
// extraction of inner.zip fail like a down extractor.
func nestedExtract(t *testing.T, outer, inner []string, innerUnavailable bool) plugins.ExtractFile {
	t.Helper()
	return nestedExtractThen(t, outer, inner, innerUnavailable, nil)
}

// nestedExtractThen is nestedExtract that calls beforeFail just before the
// extraction of inner.zip fails.
func nestedExtractThen(t *testing.T, outer, inner []string, innerUnavailable bool, beforeFail func()) plugins.ExtractFile {
	t.Helper()
	var calls atomic.Int32
	write := func(outputDir string, names []string) (plugins.Extraction, error) {
		files := make([]string, 0, len(names))
		for _, n := range names {
			content := "C-" + n
			if n == "inner.zip" {
				content = zipOf(t, 10)
			}
			p := filepath.Join(outputDir, n)
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				return plugins.Extraction{}, err
			}
			files = append(files, p)
		}
		return plugins.Extraction{Files: files}, nil
	}
	return func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		if calls.Add(1) == 1 {
			return write(outputDir, outer)
		}
		if innerUnavailable {
			if beforeFail != nil {
				beforeFail()
			}
			return plugins.Extraction{}, fmt.Errorf("7z: %w", plugins.ErrExtractorUnavailable)
		}
		return write(outputDir, inner)
	}
}

func detectNamed(names ...string) func(string) (gdetect.Result, error) {
	return func(n string) (gdetect.Result, error) {
		if slices.Contains(names, n) {
			return gdetect.Result{Malware: true, Malwares: []string{"evil"}}, nil
		}
		return gdetect.Result{}, nil
	}
}

// The decision of a plugin on a sub-archive is taken before any member of it is
// sent, so it can never replace what the archive learned from its members, nor
// what its siblings found: a detection next to a waived or refused sub-archive
// keeps the whole archive malware.
func TestArchiveDetection_aDetectionNextToASubArchiveTheyDecideOnKeepsTheArchiveMalware(t *testing.T) {
	behaviours := map[string]func() *datamodel.Result{
		"waiver":                func() *datamodel.Result { return &datamodel.Result{} },
		"refusal with an error": func() *datamodel.Result { return &datamodel.Result{Error: errors.New("refused by the plugin")} },
		"refusal as malware":    func() *datamodel.Result { return &datamodel.Result{Malware: true, Malwares: []string{"plugin"}} },
	}
	for name, behave := range behaviours {
		for _, remove := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/remove=%t", name, remove), func(t *testing.T) {
				for range 5 {
					r := runAcc(t, accSetup{
						files:   map[string]string{"evil.zip": zipOf(t, 10)},
						extract: nestedExtract(t, []string{"a-bad.bin", "inner.zip"}, []string{"x.bin", "y.bin"}, false),
						remove:  remove, workers: 4,
						submit: detectNamed("a-bad.bin"),
						scanFile: func(n, _, _ string, isArchive bool) *datamodel.Result {
							if isArchive && filepath.Base(n) == "inner.zip" {
								return behave()
							}
							return nil
						},
					})
					got := r.one(t, "evil.zip")
					if !got.result.Malware || got.result.MalwareReason != datamodel.MalwareDetected {
						t.Fatalf("result = malware %t, reason %q, want a detection that wins", got.result.Malware, got.result.MalwareReason)
					}
					if r.exists(r.out, "evil.zip") {
						t.Fatal("an archive with a detection was delivered")
					}
				}
			})
		}
	}
}

// A sub-archive let through by a plugin ends with no member sent, and is listed
// by its parent, which is delivered.
func TestArchiveDetection_aSubArchiveLetThroughIsNeverOpenedAndIsListedByItsParent(t *testing.T) {
	var innerMembers atomic.Int32
	r := runAcc(t, accSetup{
		files:   map[string]string{"evil.zip": zipOf(t, 10)},
		extract: nestedExtract(t, []string{"inner.zip"}, []string{"x.bin", "y.bin"}, false),
		workers: 4,
		submit: func(n string) (gdetect.Result, error) {
			if n == "x.bin" || n == "y.bin" {
				innerMembers.Add(1)
			}
			return gdetect.Result{}, nil
		},
		scanFile: func(n, _, _ string, isArchive bool) *datamodel.Result {
			if isArchive && filepath.Base(n) == "inner.zip" {
				return &datamodel.Result{}
			}
			return nil
		},
	})
	if innerMembers.Load() != 0 {
		t.Errorf("%d members of a sub-archive the plugin let through were analyzed, want none", innerMembers.Load())
	}
	got := r.one(t, "evil.zip")
	if got.result.Malware || got.result.Error != nil || !r.exists(r.out, "evil.zip") {
		t.Fatalf("result = %+v, delivered %t, want the archive delivered", got.result, r.exists(r.out, "evil.zip"))
	}
	found := false
	for _, f := range got.result.NotAnalyzedSubfiles {
		found = found || (f.FileName == "inner.zip" && f.Reason == datamodel.NotAnalyzedPolicySkipped)
	}
	if !found {
		t.Errorf("not analyzed = %+v, want inner.zip listed as policy-skipped", got.result.NotAnalyzedSubfiles)
	}
}

func TestArchiveDetection_aSubArchiveRefusedAsMalwareMakesItsParentMalware(t *testing.T) {
	r := runAcc(t, accSetup{
		files:   map[string]string{"evil.zip": zipOf(t, 10)},
		extract: nestedExtract(t, []string{"inner.zip"}, []string{"x.bin"}, false),
		scanFile: func(n, _, _ string, isArchive bool) *datamodel.Result {
			if isArchive && filepath.Base(n) == "inner.zip" {
				return &datamodel.Result{Malware: true, Malwares: []string{"plugin"}}
			}
			return nil
		},
	})
	got := r.one(t, "evil.zip")
	if !got.result.Malware || r.exists(r.out, "evil.zip") || r.quarantined(t) != 1 {
		t.Errorf("malware %t, delivered %t, quarantined %d: want a quarantined archive", got.result.Malware, r.exists(r.out, "evil.zip"), r.quarantined(t))
	}
}

// What an archive learned from its members is never replaced by a result given
// to the whole archive, and an archive with members in flight is not finished
// by one.
func TestArchiveStatus_setArchiveResultNeverReplacesWhatTheMembersFound(t *testing.T) {
	t.Run("a merged detection is kept", func(t *testing.T) {
		h := newArchiveStatusHandler()
		id := h.addStatus(archiveStatus{total: 1})
		h.addInnerFileResult(id, "bad", datamodel.Result{Malware: true, Malwares: []string{"evil"}, MalwareReason: datamodel.MalwareDetected})
		ok, busy := h.setArchiveResult(id, datamodel.Result{NotAnalyzedReason: datamodel.NotAnalyzedPolicySkipped})
		st, _ := h.getStatus(id)
		if !ok || busy || !st.result.Malware || st.result.MalwareReason != datamodel.MalwareDetected || len(st.result.Malwares) != 1 {
			t.Errorf("ok %t, busy %t, result %+v: want the detection kept in the result given to the archive", ok, busy, st.result)
		}
		if st.result.NotAnalyzedReason != datamodel.NotAnalyzedPolicySkipped {
			t.Errorf("result = %+v, want what was given merged in", st.result)
		}
	})
	t.Run("an error of a member is kept", func(t *testing.T) {
		h := newArchiveStatusHandler()
		id := h.addStatus(archiveStatus{total: 2})
		h.addInnerError(id, "m", errInnerTransient)
		h.setArchiveResult(id, datamodel.Result{})
		st, _ := h.getStatus(id)
		if st.result.Error == nil || len(st.result.ErrorSubfiles) != 1 {
			t.Errorf("result = %+v, want the error of the member kept", st.result)
		}
	})
	t.Run("members in flight refuse it", func(t *testing.T) {
		h := newArchiveStatusHandler()
		id := h.addStatus(archiveStatus{total: 3})
		h.markDispatching(id)
		h.addInnerFileResult(id, "a", datamodel.Result{})
		ok, busy := h.setArchiveResult(id, datamodel.Result{})
		st, _ := h.getStatus(id)
		if !ok || !busy || st.finished || st.analyzed != 1 {
			t.Errorf("ok %t, busy %t, finished %t, analyzed %d: want a refusal that drops no member", ok, busy, st.finished, st.analyzed)
		}
	})
	t.Run("before any member is sent it is honoured", func(t *testing.T) {
		h := newArchiveStatusHandler()
		id := h.addStatus(archiveStatus{total: 3})
		ok, busy := h.setArchiveResult(id, datamodel.Result{})
		st, _ := h.getStatus(id)
		if !ok || busy || !st.finished {
			t.Errorf("ok %t, busy %t, finished %t, want the archive finished", ok, busy, st.finished)
		}
	})
	t.Run("a detection without a reason gets one", func(t *testing.T) {
		h := newArchiveStatusHandler()
		id := h.addStatus(archiveStatus{total: 1})
		h.setArchiveResult(id, datamodel.Result{Malware: true})
		if st, _ := h.getStatus(id); st.result.MalwareReason != datamodel.MalwareDetected {
			t.Errorf("reason = %q, want malware-detected", st.result.MalwareReason)
		}
	})
}

// An extractor that goes down while a member is still being analyzed must not make
// the archive lose a detection that comes after: the archive waits for that
// member, and ends with its detection (quarantined or deleted, never delivered), the
// members never sent listed as errors. Without a detection it is abandoned, left in
// INPUT, and tried again. The member is held until the extractor has failed.
func TestArchiveDetection_anExtractorThatGoesDownWhileAMemberIsInFlightDoesNotLoseItsDetection(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(fmt.Sprintf("remove=%t", remove), func(t *testing.T) {
			for range 5 {
				failed := make(chan struct{})
				var once sync.Once
				r := runAcc(t, accSetup{
					files:   map[string]string{"evil.zip": zipOf(t, 10)},
					extract: nestedExtractThen(t, []string{"a-bad.bin", "inner.zip", "z.bin"}, nil, true, func() { once.Do(func() { close(failed) }) }),
					remove:  remove, workers: 4,
					submit: func(n string) (gdetect.Result, error) {
						if n == "a-bad.bin" {
							<-failed
						}
						return detectNamed("a-bad.bin")(n)
					},
				})
				if len(r.captures) != 1 {
					t.Fatalf("%d actions, want one: the detected member must not be lost; in INPUT = %t", len(r.captures), r.exists(r.in, "evil.zip"))
				}
				res := r.captures[0].result
				if !res.Malware || res.MalwareReason != datamodel.MalwareDetected || r.exists(r.out, "evil.zip") {
					t.Fatalf("result = malware %t, reason %q, delivered %t", res.Malware, res.MalwareReason, r.exists(r.out, "evil.zip"))
				}
				if _, listed := res.ErrorSubfiles["inner.zip"]; !listed || res.Error == nil {
					t.Errorf("error = %v, subfiles = %v, want the members never sent listed", res.Error, res.ErrorSubfiles)
				}
			}
		})
	}
	t.Run("without a detection the archive is abandoned, left in INPUT and retried", func(t *testing.T) {
		for range 5 {
			failed := make(chan struct{})
			var once sync.Once
			r := runAcc(t, accSetup{
				files:   map[string]string{"evil.zip": zipOf(t, 10)},
				extract: nestedExtractThen(t, []string{"a.bin", "inner.zip"}, nil, true, func() { once.Do(func() { close(failed) }) }),
				workers: 4,
				submit: func(n string) (gdetect.Result, error) {
					if n == "a.bin" {
						<-failed
					}
					return gdetect.Result{}, nil
				},
			})
			if len(r.captures) != 0 || !r.exists(r.in, "evil.zip") || r.exists(r.out, "evil.zip") {
				t.Fatalf("%d actions, in INPUT %t, in OUTPUT %t: want an abandoned archive left in place", len(r.captures), r.exists(r.in, "evil.zip"), r.exists(r.out, "evil.zip"))
			}
		}
	})
}

// A detection always says why: a plugin that gives malware with no reason, a
// member merged with none, get malware-detected, in the result, the report and
// the mitigation event.
func TestArchiveDetection_aDetectionAlwaysHasAReason(t *testing.T) {
	t.Run("OnScanFile refusal", func(t *testing.T) {
		rec := recordMitigations(t)
		r := runAcc(t, accSetup{
			files: map[string]string{"p.bin": "X"},
			scanFile: func(string, string, string, bool) *datamodel.Result {
				return &datamodel.Result{Malware: true, Malwares: []string{"plug"}}
			},
		})
		got := r.one(t, "p.bin")
		if got.result.MalwareReason != datamodel.MalwareDetected || got.report.MalwareReason != datamodel.MalwareDetected {
			t.Errorf("reason = %q, report %q, want malware-detected", got.result.MalwareReason, got.report.MalwareReason)
		}
		if reasons := rec.reasonsOf("p.bin"); len(reasons) != 1 || reasons[0] == "" {
			t.Errorf("mitigation reasons = %v, want one, not empty", reasons)
		}
	})
	t.Run("OnFileScanned", func(t *testing.T) {
		rec := recordMitigations(t)
		r := runAcc(t, accSetup{
			files: map[string]string{"p.bin": "X"},
			scanned: func(_, _ string, res datamodel.Result) *datamodel.Result {
				res.Malware, res.Malwares = true, []string{"plug"}
				return &res
			},
		})
		got := r.one(t, "p.bin")
		if got.report.MalwareReason != datamodel.MalwareDetected {
			t.Errorf("report reason = %q, want malware-detected", got.report.MalwareReason)
		}
		if reasons := rec.reasonsOf("p.bin"); len(reasons) != 1 || reasons[0] == "" {
			t.Errorf("mitigation reasons = %v, want one, not empty", reasons)
		}
	})
	t.Run("a member merged without one", func(t *testing.T) {
		got := mergeResult(datamodel.Result{}, datamodel.Result{Malware: true}, "m", nil)
		if got.MalwareReason != datamodel.MalwareDetected {
			t.Errorf("reason = %q, want malware-detected", got.MalwareReason)
		}
	})
	t.Run("the mitigation reason of an unknown one is a detection", func(t *testing.T) {
		if got := getMitigationReason(""); got == "" {
			t.Error("a mitigation reason must never be empty")
		}
	})
}

// D6, whatever the plugin or the analysis does to a file or a sub-archive next to
// a detection, the archive is malware: never delivered, quarantined.
func TestArchiveDetection_aDetectionIsNeverLostWhateverHappensToItsNeighbours(t *testing.T) {
	type target struct {
		name    string
		outer   []string
		inner   []string
		decided string // the name a plugin decides on
		archive bool
	}
	targets := []target{
		{"member", []string{"a-bad.bin", "m.bin"}, nil, "m.bin", false},
		{"sub-archive", []string{"a-bad.bin", "inner.zip"}, []string{"x.bin"}, "inner.zip", true},
	}
	behaviours := map[string]struct {
		plugin func() *datamodel.Result
		submit func(string) (gdetect.Result, error)
	}{
		"waiver":                 {plugin: func() *datamodel.Result { return &datamodel.Result{} }},
		"refusal with an error":  {plugin: func() *datamodel.Result { return &datamodel.Result{Error: errors.New("refused")} }},
		"refusal as malware":     {plugin: func() *datamodel.Result { return &datamodel.Result{Malware: true, Malwares: []string{"p"}} }},
		"analysis error (error)": {submit: func(string) (gdetect.Result, error) { return gdetect.Result{Error: "analysis failed"}, nil }},
	}
	for _, tg := range targets {
		for name, b := range behaviours {
			if tg.archive && b.submit != nil {
				continue // an archive is not submitted
			}
			t.Run(tg.name+"/"+name, func(t *testing.T) {
				submit := func(n string) (gdetect.Result, error) {
					if n == "a-bad.bin" {
						return gdetect.Result{Malware: true, Malwares: []string{"evil"}}, nil
					}
					if b.submit != nil && n == tg.decided {
						return b.submit(n)
					}
					return gdetect.Result{}, nil
				}
				r := runAcc(t, accSetup{
					files:   map[string]string{"evil.zip": zipOf(t, 10)},
					extract: nestedExtract(t, tg.outer, tg.inner, false),
					workers: 4, submit: submit,
					scanFile: func(n, _, _ string, isArchive bool) *datamodel.Result {
						if b.plugin != nil && filepath.Base(n) == tg.decided && isArchive == tg.archive {
							return b.plugin()
						}
						return nil
					},
				})
				got := r.one(t, "evil.zip")
				if !got.result.Malware || r.exists(r.out, "evil.zip") || r.quarantined(t) != 1 {
					t.Errorf("malware %t, delivered %t, quarantined %d: want a quarantined archive", got.result.Malware, r.exists(r.out, "evil.zip"), r.quarantined(t))
				}
				if got.result.MalwareReason != datamodel.MalwareDetected {
					t.Errorf("reason = %q, want malware-detected", got.result.MalwareReason)
				}
			})
		}
	}
}

// The plugins see an archive through the verified descriptor, not through the
// path it was deposited at: a writer could swap that path after the core opened
// the file. The logical name is unchanged.
func TestArchiveDetection_aPluginIsGivenTheDescriptorPathOfATopLevelArchive(t *testing.T) {
	var mu sync.Mutex
	var names, locations []string
	r := runAcc(t, accSetup{
		files:   map[string]string{"evil.zip": zipOf(t, 10)},
		extract: nestedExtract(t, []string{"a.bin"}, nil, false),
		scanFile: func(n, loc, _ string, isArchive bool) *datamodel.Result {
			if isArchive {
				mu.Lock()
				names, locations = append(names, n), append(locations, loc)
				mu.Unlock()
			}
			return nil
		},
	})
	deposit := filepath.Join(r.in, "evil.zip")
	mu.Lock()
	defer mu.Unlock()
	if len(names) != 1 || names[0] != deposit {
		t.Fatalf("names = %v, want the logical path %q unchanged", names, deposit)
	}
	if locations[0] == deposit || !strings.Contains(locations[0], "/fd/") {
		t.Errorf("location = %q, want the descriptor path, not the deposit path %q", locations[0], deposit)
	}
}

// An archive abandoned while members were in flight, one of which is then found
// malicious, ends with its detection: the members never sent are inner errors.
func TestArchiveDetection_anArchiveAbandonedBeforeADetectionComesInEndsWithIt(t *testing.T) {
	var results []datamodel.Result
	var mu sync.Mutex
	c, location, id, sha := policySkippedArchiveConnector(t, &results, &mu)
	archiveID := c.archiveStatus.addStatus(archiveStatus{
		archiveLocation: location, sha256: sha, identity: id, tmpFolder: t.TempDir(), total: 3,
		result: datamodel.Result{SHA256: sha, FileSize: 15},
	})
	res, ok := c.archiveStatus.abandon(archiveID, []string{"never1.bin", "never2.bin"})
	if !ok || res.detected || res.removeNow {
		t.Fatalf("abandon() = %+v, %t, want an abandoned archive with a member in flight", res, ok)
	}
	finished, ok := c.archiveStatus.addInnerFileResult(archiveID, "bad.bin", datamodel.Result{Malware: true, Malwares: []string{"evil"}, MalwareReason: datamodel.MalwareDetected})
	if !ok || !finished {
		t.Fatalf("addInnerFileResult() = %t, %t, want the archive finished by its last member", finished, ok)
	}
	if err := c.finishArchiveAnalysis(archiveID); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(results) != 1 || !results[0].Malware {
		t.Fatalf("results = %+v, want one action with the detection", results)
	}
	if _, listed := results[0].ErrorSubfiles["never1.bin"]; !listed || results[0].Error == nil {
		t.Errorf("error = %v, subfiles = %v, want the members never sent listed", results[0].Error, results[0].ErrorSubfiles)
	}
}

// abandon(): what each state of an archive comes to when its extraction is given
// up, and what is counted.
func TestArchiveStatus_abandon(t *testing.T) {
	names := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("m%d", i)
		}
		return out
	}
	tests := []struct {
		name      string
		status    archiveStatus
		unsent    []string
		want      abandonResult
		wantTotal int
		kept      bool // the status is still there
	}{
		{"no detection, nothing in flight: gone", archiveStatus{total: 5, analyzed: 3}, names(2), abandonResult{removeNow: true}, 3, false},
		{"no detection, members in flight: waits", archiveStatus{total: 5, analyzed: 1}, names(2), abandonResult{inFlight: true}, 3, true},
		{"a detection, nothing in flight: finish now", archiveStatus{total: 5, analyzed: 3, result: datamodel.Result{Malware: true}}, names(2), abandonResult{detected: true, finish: true}, 3, true},
		{"a detection, members in flight: the last one finishes", archiveStatus{total: 5, analyzed: 1, result: datamodel.Result{Malware: true}}, names(2), abandonResult{detected: true}, 3, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newArchiveStatusHandler()
			tt.status.tmpFolder = "/tmp/x"
			id := h.addStatus(tt.status)
			got, ok := h.abandon(id, tt.unsent)
			tt.want.folder = "/tmp/x"
			if !ok || got != tt.want {
				t.Fatalf("abandon() = %+v, %t, want %+v", got, ok, tt.want)
			}
			st, found := h.getStatus(id)
			if found != tt.kept {
				t.Fatalf("status kept = %t, want %t", found, tt.kept)
			}
			if found && st.total != tt.wantTotal {
				t.Errorf("total = %d, want %d: the unsent members are no longer waited for", st.total, tt.wantTotal)
			}
			if found && got.detected && st.result.Error == nil {
				t.Error("a detection with members never sent must say they are errors")
			}
		})
	}
	t.Run("an archive already being finished is not abandoned", func(t *testing.T) {
		h := newArchiveStatusHandler()
		id := h.addStatus(archiveStatus{total: 1})
		h.claimFinish(id)
		if _, ok := h.abandon(id, names(1)); ok {
			t.Error("abandon() = ok on an archive whose finish was claimed")
		}
	})
	t.Run("the unsent members are listed within the bound and counted exactly", func(t *testing.T) {
		h := newArchiveStatusHandler()
		many := datamodel.MaxListedSubfiles + 50
		id := h.addStatus(archiveStatus{total: many + 1, result: datamodel.Result{Malware: true}})
		if _, ok := h.abandon(id, names(many)); !ok {
			t.Fatal("abandon() refused")
		}
		st, _ := h.getStatus(id)
		if listed := datamodel.ListedErrors(st.result.ErrorSubfiles); listed != datamodel.MaxListedSubfiles {
			t.Errorf("%d members listed, want the bound %d", listed, datamodel.MaxListedSubfiles)
		}
		if st.inner.count != many {
			t.Errorf("%d errors counted, want all %d", st.inner.count, many)
		}
		if _, more := st.result.ErrorSubfiles[datamodel.MoreErrorsKey]; !more {
			t.Error("the members not listed must be said with the count key")
		}
	})
	t.Run("the names kept for a late detection are bounded and copied", func(t *testing.T) {
		h := newArchiveStatusHandler()
		many := datamodel.MaxListedSubfiles + 50
		id := h.addStatus(archiveStatus{total: many + 5})
		unsent := names(many)
		if _, ok := h.abandon(id, unsent); !ok {
			t.Fatal("abandon() refused")
		}
		unsent[0] = "changed by the caller"
		st, _ := h.getStatus(id)
		if len(st.unsent) != datamodel.MaxListedSubfiles || st.unsentCount != many || st.unsent[0] != "m0" {
			t.Errorf("kept %d names (first %q) for %d unsent, want the first %d, copied", len(st.unsent), st.unsent[0], st.unsentCount, datamodel.MaxListedSubfiles)
		}
	})
}

// threeLevels answers the extraction of evil.zip with inner.zip and one member
// that is not an archive, the one of inner.zip with m.bin and deep.zip, and the one
// of deep.zip with a failure of the extractor.
func threeLevels(t *testing.T, beforeFail func()) plugins.ExtractFile {
	t.Helper()
	var calls atomic.Int32
	write := func(outputDir string, names ...string) (plugins.Extraction, error) {
		files := make([]string, 0, len(names))
		for _, n := range names {
			content := "C-" + n
			if strings.HasSuffix(n, ".zip") {
				content = zipOf(t, 10)
			}
			p := filepath.Join(outputDir, n)
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				return plugins.Extraction{}, err
			}
			files = append(files, p)
		}
		return plugins.Extraction{Files: files}, nil
	}
	return func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		switch calls.Add(1) {
		case 1:
			return write(outputDir, "inner.zip", "z-last.bin")
		case 2:
			return write(outputDir, "m.bin", "deep.zip")
		default:
			if beforeFail != nil {
				beforeFail()
			}
			return plugins.Extraction{}, fmt.Errorf("7z: %w", plugins.ErrExtractorUnavailable)
		}
	}
}

// A sub-archive abandoned with a member in flight reports by itself: its parent is
// not told the extractor failed, it waits for it, and the detection of that member
// reaches the top-level archive; without one the file is left in place.
func TestArchiveDetection_aSubArchiveAbandonedWithAMemberInFlightReportsToItsParent(t *testing.T) {
	for range 5 {
		failed := make(chan struct{})
		var once sync.Once
		r := runAcc(t, accSetup{
			files:   map[string]string{"evil.zip": zipOf(t, 10)},
			extract: threeLevels(t, func() { once.Do(func() { close(failed) }) }),
			workers: 4,
			submit: func(n string) (gdetect.Result, error) {
				if n == "m.bin" {
					<-failed
					return gdetect.Result{Malware: true, Malwares: []string{"evil"}}, nil
				}
				return gdetect.Result{}, nil
			},
		})
		if len(r.captures) != 1 {
			t.Fatalf("%d actions, want one: the detection of a member of a sub-archive was lost; in INPUT = %t", len(r.captures), r.exists(r.in, "evil.zip"))
		}
		res := r.captures[0].result
		if !res.Malware || res.MalwareReason != datamodel.MalwareDetected || r.exists(r.out, "evil.zip") {
			t.Fatalf("result = malware %t, reason %q, delivered %t", res.Malware, res.MalwareReason, r.exists(r.out, "evil.zip"))
		}
	}
	t.Run("without a detection", func(t *testing.T) {
		for range 5 {
			failed := make(chan struct{})
			var once sync.Once
			r := runAcc(t, accSetup{
				files:   map[string]string{"evil.zip": zipOf(t, 10)},
				extract: threeLevels(t, func() { once.Do(func() { close(failed) }) }),
				workers: 4,
				submit: func(n string) (gdetect.Result, error) {
					if n == "m.bin" {
						<-failed
					}
					return gdetect.Result{}, nil
				},
			})
			if len(r.captures) != 0 || !r.exists(r.in, "evil.zip") || r.exists(r.out, "evil.zip") {
				t.Fatalf("%d actions, in INPUT %t, in OUTPUT %t: want the file left in place, abandoned", len(r.captures), r.exists(r.in, "evil.zip"), r.exists(r.out, "evil.zip"))
			}
		}
	})
}

// A plugin decides on a top-level archive through the real extraction: a waiver is
// marked and delivered, and what it says of the size and the hash is the
// pipeline's.
func TestArchiveDetection_aTopLevelArchiveLetThroughKeepsThePipelinesSizeAndHash(t *testing.T) {
	r := runAcc(t, accSetup{
		files:   map[string]string{"evil.zip": zipOf(t, 10)},
		extract: nestedExtract(t, []string{"a.bin"}, nil, false),
		scanFile: func(_, _, _ string, isArchive bool) *datamodel.Result {
			if isArchive {
				return &datamodel.Result{FileSize: 1 << 40, SHA256: "forged"}
			}
			return nil
		},
	})
	got := r.one(t, "evil.zip")
	info, err := os.Stat(filepath.Join(r.out, "evil.zip"))
	if err != nil {
		t.Fatalf("the archive is not delivered: %v", err)
	}
	if got.result.NotAnalyzedReason != datamodel.NotAnalyzedPolicySkipped || got.result.FileSize != info.Size() || got.result.SHA256 == "forged" {
		t.Errorf("result = %+v, want policy-skipped with the size %d and the hash of the pipeline", got.result, info.Size())
	}
	if r.submitted.Load() != 0 {
		t.Errorf("%d members were analyzed in an archive let through", r.submitted.Load())
	}
}

// The console line of a detection says why, even when the plugin left the reason
// empty.
type lineSink struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lineSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lineSink) Close() error { return nil }
func (l *lineSink) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestArchiveDetection_theConsoleLineOfADetectionWithoutReasonSaysWhy(t *testing.T) {
	sink := &lineSink{}
	runAcc(t, accSetup{
		files:  map[string]string{"p.bin": "X"},
		inform: sink,
		scanFile: func(string, string, string, bool) *datamodel.Result {
			return &datamodel.Result{Malware: true, Malwares: []string{"plug"}}
		},
	})
	if line := sink.String(); !strings.Contains(line, "p.bin") || !strings.Contains(line, string(datamodel.MalwareDetected)) {
		t.Errorf("console = %q, want the line of p.bin to say malware-detected", line)
	}
}

// A member that a plugin refuses as malware without reason, merged into its
// archive through the real pipeline, gives malware-detected.
func TestArchiveDetection_aMemberDetectedWithoutReasonGivesTheArchiveOne(t *testing.T) {
	r := runAcc(t, accSetup{
		files:   map[string]string{"evil.zip": zipOf(t, 10)},
		extract: nestedExtract(t, []string{"a.bin", "b.bin"}, nil, false),
		scanFile: func(name, _, _ string, isArchive bool) *datamodel.Result {
			if !isArchive && filepath.Base(name) == "b.bin" {
				return &datamodel.Result{Malware: true, Malwares: []string{"plug"}}
			}
			return nil
		},
	})
	got := r.one(t, "evil.zip")
	if !got.result.Malware || got.result.MalwareReason != datamodel.MalwareDetected || got.report.MalwareReason != datamodel.MalwareDetected {
		t.Errorf("result = malware %t, reason %q, report reason %q, want malware-detected", got.result.Malware, got.result.MalwareReason, got.report.MalwareReason)
	}
}

// A sub-archive abandoned with a member in flight takes its live ancestors with
// it, in the same critical section: until its caller reaches the parent, the last
// member of the sub-archive can end it, and the parent must not take that for the
// end of a normal member.
func TestArchiveStatus_abandonTakesTheLiveAncestorsWithIt(t *testing.T) {
	chain := func(h *archiveStatusHandler) (grand, parent, child string) {
		grand = h.addStatus(archiveStatus{total: 2, analyzed: 1})
		parent = h.addStatus(archiveStatus{total: 1, parentArchive: parentArchive{statusID: grand, relPath: "p.zip"}})
		child = h.addStatus(archiveStatus{total: 3, analyzed: 1, parentArchive: parentArchive{statusID: parent, relPath: "s.zip"}})
		return
	}
	abandoned := func(h *archiveStatusHandler, id string) bool {
		st, _ := h.getStatus(id)
		return st.abandoned
	}
	t.Run("members in flight: every ancestor is abandoned", func(t *testing.T) {
		h := newArchiveStatusHandler()
		grand, parent, child := chain(h)
		if res, ok := h.abandon(child, []string{"x"}); !ok || !res.inFlight {
			t.Fatalf("abandon() = %+v, %t, want members in flight", res, ok)
		}
		if !abandoned(h, parent) || !abandoned(h, grand) {
			t.Errorf("parent abandoned %t, grandparent abandoned %t, want both", abandoned(h, parent), abandoned(h, grand))
		}
	})
	t.Run("the last member then ends the sub-archive: its parent ends abandoned, not clean", func(t *testing.T) {
		h := newArchiveStatusHandler()
		_, parent, child := chain(h)
		if _, ok := h.abandon(child, []string{"x"}); !ok {
			t.Fatal("abandon() refused")
		}
		finished, ok := h.addInnerFileResult(child, "m.bin", datamodel.Result{})
		if !ok || !finished {
			t.Fatalf("the last member: finished %t, ok %t", finished, ok)
		}
		h.deleteStatus(child)
		finished, ok = h.addInnerError(parent, "s.zip", errUnsent)
		st, _ := h.getStatus(parent)
		if !ok || !finished || !st.abandoned || st.inner.count != 1 {
			t.Errorf("parent: finished %t, ok %t, abandoned %t, errors %d, want it ended, abandoned, with the sub-archive counted as an error", finished, ok, st.abandoned, st.inner.count)
		}
	})
	t.Run("nothing in flight: the ancestors are left alone", func(t *testing.T) {
		h := newArchiveStatusHandler()
		grand, parent, child := chain(h)
		st, _ := h.getStatus(child)
		st.analyzed = 3
		h.statusByID[child] = st
		if res, ok := h.abandon(child, nil); !ok || !res.removeNow {
			t.Fatalf("abandon() = %+v, %t, want removeNow", res, ok)
		}
		if abandoned(h, parent) || abandoned(h, grand) {
			t.Error("an ancestor was abandoned although the sub-archive left no member in flight")
		}
	})
	t.Run("a detection is not abandoned and does not abandon its parent", func(t *testing.T) {
		h := newArchiveStatusHandler()
		grand, parent, child := chain(h)
		st, _ := h.getStatus(child)
		st.result.Malware = true
		h.statusByID[child] = st
		if res, ok := h.abandon(child, []string{"x"}); !ok || !res.detected {
			t.Fatalf("abandon() = %+v, %t, want a detection kept", res, ok)
		}
		if abandoned(h, parent) || abandoned(h, grand) {
			t.Error("an ancestor was abandoned for an archive that ends with its detection")
		}
	})
	t.Run("an ancestor that claimed its finish stops the walk", func(t *testing.T) {
		h := newArchiveStatusHandler()
		grand, parent, child := chain(h)
		h.claimFinish(parent)
		if _, ok := h.abandon(child, []string{"x"}); !ok {
			t.Fatal("abandon() refused")
		}
		if abandoned(h, parent) || abandoned(h, grand) {
			t.Error("the walk went past an ancestor that is being finished")
		}
	})
	t.Run("an ancestor that is gone stops the walk", func(t *testing.T) {
		h := newArchiveStatusHandler()
		grand, parent, child := chain(h)
		h.deleteStatus(parent)
		if _, ok := h.abandon(child, []string{"x"}); !ok {
			t.Fatal("abandon() refused")
		}
		if abandoned(h, grand) {
			t.Error("the walk went past a missing ancestor")
		}
	})
}

// abandonArchive on an archive that its own last member already ended is not the
// failure of the extractor: the caller must not count its members unsent again.
func TestAbandonArchive_anArchiveAlreadyEndedIsNotAnExtractorFailure(t *testing.T) {
	c := &Connector{archiveStatus: newArchiveStatusHandler()}
	err := c.abandonArchive("gone", []string{"x"}, logger)
	if !errors.Is(err, errAbandonedInFlight) || errors.Is(err, plugins.ErrExtractorUnavailable) {
		t.Errorf("abandonArchive() = %v, want errAbandonedInFlight", err)
	}
}
