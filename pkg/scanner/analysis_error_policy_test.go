package scanner

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// The table of unanalyzable_policy.analysis_error: what the policy decides when
// the analysis fails and finds nothing, and what it never decides when there is
// a detection.
func TestAnalysisErrorPolicy(t *testing.T) {
	failed := gdetect.Result{Error: "engine failed: https://svc.example/secret-token", FileSize: 7}
	detected := gdetect.Result{Malware: true, Malwares: []string{"evil"}}
	detectedWithError := gdetect.Result{Malware: true, Malwares: []string{"evil"}, Error: "engine failed"}
	byName := func(verdicts map[string]gdetect.Result) func(string) (gdetect.Result, error) {
		return func(name string) (gdetect.Result, error) { return verdicts[name], nil }
	}
	members := memberExtractor(map[string]string{"ok.bin": "OK", "bad.bin": "BAD"})
	type outcome int
	const (
		kept       outcome = iota // stays in INPUT, in error, nothing delivered
		mitigated                 // malware: quarantined or removed, never delivered
		delivered                 // in OUTPUT, marked not analyzed
		detectedBy                // malware-detected: quarantined or removed
		ownPolicy                 // malware by the policy of what made the file unanalyzable
	)
	tests := []struct {
		name    string
		file    string
		content string
		setup   accSetup
		// members is set when the archive is extracted and the analysis of its members
		// is what is under test.
		members bool
		base    Unanalyzable       // the other policies, analysis_error is set by the table
		want    map[string]outcome // by policy
		// ownReason and ownConsole are the reason and the console reason of an
		// ownPolicy outcome.
		ownReason  datamodel.MalwareReason
		ownConsole events.MitigationReason
	}{
		{
			name: "a file the analysis failed on", file: "f.bin", content: "CONTENT",
			setup: accSetup{submit: func(string) (gdetect.Result, error) { return failed, nil }},
			want:  map[string]outcome{PolicyError: kept, PolicyMitigate: mitigated, PolicyPass: delivered},
		},
		{
			name: "a file with a detection and an error", file: "f.bin", content: "CONTENT",
			setup: accSetup{submit: func(string) (gdetect.Result, error) { return detectedWithError, nil }},
			want:  map[string]outcome{PolicyError: detectedBy, PolicyMitigate: detectedBy, PolicyPass: detectedBy},
		},
		{
			name: "an encrypted archive the analysis fails on, encrypted: error", file: "e.zip", content: zipOf(t, 10),
			setup: accSetup{
				extract: func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
					return plugins.Extraction{}, plugins.ErrEncrypted
				},
				submit: func(string) (gdetect.Result, error) { return failed, nil },
			},
			base: Unanalyzable{Encrypted: PolicyError},
			want: map[string]outcome{PolicyError: kept, PolicyMitigate: kept, PolicyPass: kept},
		},
		{
			name: "an encrypted archive the analysis fails on, encrypted: mitigate", file: "e.zip", content: zipOf(t, 10),
			setup: accSetup{
				extract: func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
					return plugins.Extraction{}, plugins.ErrEncrypted
				},
				submit: func(string) (gdetect.Result, error) { return failed, nil },
			},
			base:      Unanalyzable{Encrypted: PolicyMitigate},
			want:      map[string]outcome{PolicyError: ownPolicy, PolicyMitigate: ownPolicy, PolicyPass: ownPolicy},
			ownReason: datamodel.Encrypted, ownConsole: events.ReasonInvalid,
		},
		{
			name: "an encrypted archive the analysis fails on, encrypted: pass", file: "e.zip", content: zipOf(t, 10),
			setup: accSetup{
				extract: func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
					return plugins.Extraction{}, plugins.ErrEncrypted
				},
				submit: func(string) (gdetect.Result, error) { return failed, nil },
			},
			base: Unanalyzable{Encrypted: PolicyPass},
			want: map[string]outcome{PolicyError: kept, PolicyMitigate: mitigated, PolicyPass: delivered},
		},
		{
			name: "a damaged archive handled as a file, the analysis of it fails, extract_error: as_file", file: "d.zip", content: zipOf(t, 10),
			setup: accSetup{
				extract: func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
					return plugins.Extraction{}, fmt.Errorf("7z: %w", plugins.ErrArchiveAnomaly)
				},
				submit: func(string) (gdetect.Result, error) { return failed, nil },
			},
			base: Unanalyzable{ExtractError: PolicyAsFile},
			want: map[string]outcome{PolicyError: kept, PolicyMitigate: mitigated, PolicyPass: delivered},
		},
		{
			name: "an archive the limits left unopened, the analysis of it fails, too_big: error", file: "l.zip", content: zipOf(t, 10),
			setup: accSetup{
				maxDepth: 1,
				extract:  memberExtractor(map[string]string{"inner.zip": zipOf(t, 10)}),
				submit:   byName(map[string]gdetect.Result{"inner.zip": failed}),
			},
			base: Unanalyzable{TooBig: PolicyError, Encrypted: PolicyError},
			want: map[string]outcome{PolicyError: kept, PolicyMitigate: kept, PolicyPass: kept},
		},
		{
			name: "an archive the limits left unopened, the analysis of it fails, too_big: mitigate", file: "l.zip", content: zipOf(t, 10),
			setup: accSetup{
				maxDepth: 1,
				extract:  memberExtractor(map[string]string{"inner.zip": zipOf(t, 10)}),
				submit:   byName(map[string]gdetect.Result{"inner.zip": failed}),
			},
			base:      Unanalyzable{TooBig: PolicyMitigate, Encrypted: PolicyMitigate},
			want:      map[string]outcome{PolicyError: ownPolicy, PolicyMitigate: ownPolicy, PolicyPass: ownPolicy},
			ownReason: datamodel.TooBig, ownConsole: events.ReasonTooBig,
		},
		{
			name: "an archive with a member the analysis failed on", file: "a.zip", content: zipOf(t, 10), members: true,
			setup: accSetup{extract: members, submit: byName(map[string]gdetect.Result{"bad.bin": failed})},
			want:  map[string]outcome{PolicyError: kept, PolicyMitigate: mitigated, PolicyPass: delivered},
		},
		{
			name: "an archive with a detected member and a member the analysis failed on", file: "a.zip", content: zipOf(t, 10), members: true,
			setup: accSetup{extract: members, submit: byName(map[string]gdetect.Result{"bad.bin": detected, "ok.bin": failed})},
			want:  map[string]outcome{PolicyError: detectedBy, PolicyMitigate: detectedBy, PolicyPass: detectedBy},
		},
		{
			name: "an archive with a member that has a detection and an error", file: "a.zip", content: zipOf(t, 10), members: true,
			setup: accSetup{extract: members, submit: byName(map[string]gdetect.Result{"bad.bin": detectedWithError})},
			want:  map[string]outcome{PolicyError: detectedBy, PolicyMitigate: detectedBy, PolicyPass: detectedBy},
		},
	}
	for _, tt := range tests {
		for _, policy := range []string{PolicyError, PolicyMitigate, PolicyPass} {
			want := tt.want[policy]
			for _, variant := range []string{"", "remove", "rename"} {
				remove, rename := variant == "remove", variant == "rename"
				malware := want == mitigated || want == detectedBy || want == ownPolicy
				if (remove && !malware) || (rename && want != delivered) {
					continue
				}
				name := tt.name + "/" + policy
				if variant != "" {
					name += "/" + variant
				}
				t.Run(name, func(t *testing.T) {
					rec := recordMitigations(t)
					var out bytes.Buffer
					s := tt.setup
					s.files = map[string]string{tt.file: tt.content}
					s.policy = tt.base
					s.policy.AnalysisError = policy
					s.remove = remove
					s.rename = rename
					s.inform = NopCloser(&out)
					r := runAcc(t, s)
					got := r.one(t, tt.file)
					line := out.String()
					lockReports, err := filepath.Glob(filepath.Join(r.out, tt.file+"-lockreport*.json"))
					if err != nil {
						t.Fatal(err)
					}

					switch want {
					case kept:
						if got.result.Malware || got.report.Malicious || got.report.NotAnalyzedReason != "" {
							t.Errorf("result = %+v: a failed analysis alone is neither malware nor delivered", got.result)
						}
						if r.exists(r.out, tt.file) || len(lockReports) != 0 || !r.exists(r.in, tt.file) || r.quarantined(t) != 0 {
							t.Errorf("INPUT has it = %v, OUTPUT has it = %v, lock reports = %d, quarantined = %d: want it left in INPUT, nothing else", r.exists(r.in, tt.file), r.exists(r.out, tt.file), len(lockReports), r.quarantined(t))
						}
						if got.report.Error == "" || strings.Contains(got.report.Error, "secret-token") {
							t.Errorf("report.Error = %q, want a text of the connector that does not carry the one of the service", got.report.Error)
						}
						own := tt.base != (Unanalyzable{})
						if own && got.result.AnalysisError != "" && got.result.Error != nil {
							t.Errorf("AnalysisError = %q next to Error = %v: a file held for its own reason is counted once", got.result.AnalysisError, got.result.Error)
						}
						if !own && !tt.members && got.report.Error != analysisFailedText {
							t.Errorf("report.Error = %q, want %q", got.report.Error, analysisFailedText)
						}
						for member, text := range got.report.ErrorExtractedFiles {
							if !own && (text != memberAnalysisFailedText || strings.Contains(text, "secret-token")) {
								t.Errorf("ErrorExtractedFiles[%q] = %q, want the fixed text without the one of the service", member, text)
							}
							if strings.Contains(text, "secret-token") {
								t.Errorf("ErrorExtractedFiles[%q] = %q carries the text of the service", member, text)
							}
						}
						if !own && tt.members && (got.report.Error != membersAnalysisFailedText(1) || len(got.report.ErrorExtractedFiles) != 1) {
							t.Errorf("report.Error = %q, ErrorExtractedFiles = %v, want the archive in error with its failed member named", got.report.Error, got.report.ErrorExtractedFiles)
						}
					case mitigated, detectedBy, ownPolicy:
						wantReason, wantConsole := datamodel.AnalysisError, events.ReasonError
						switch want {
						case detectedBy:
							wantReason, wantConsole = datamodel.MalwareDetected, events.ReasonMalware
						case ownPolicy:
							wantReason, wantConsole = tt.ownReason, tt.ownConsole
						}
						if want == ownPolicy && got.result.AnalysisError != "" {
							t.Errorf("AnalysisError = %q: a file held for its own reason is counted once", got.result.AnalysisError)
						}
						if want == mitigated && !tt.members && got.result.AnalyzedVolume != 0 {
							t.Errorf("AnalyzedVolume = %d, want 0: nothing was analyzed", got.result.AnalyzedVolume)
						}
						if want == mitigated && !tt.members && (got.result.Score < mitigationScore || got.result.FilteredVolume != int64(len(tt.content))) {
							t.Errorf("Score = %d, FilteredVolume = %d, want at least %d and %d", got.result.Score, got.result.FilteredVolume, mitigationScore, len(tt.content))
						}
						if tt.members && got.report.Error != "" {
							t.Errorf("report.Error = %q: an archive with a detection stays a detection, not an error", got.report.Error)
						}
						if !got.report.Malicious || got.report.MalwareReason != wantReason || got.report.NotAnalyzedReason != "" {
							t.Errorf("report = Malicious %v, reason %q, not analyzed %q, want malware %q", got.report.Malicious, got.report.MalwareReason, got.report.NotAnalyzedReason, wantReason)
						}
						if r.exists(r.out, tt.file) || len(lockReports) != 1 {
							t.Errorf("OUTPUT has it = %v, lock reports = %d, want a lock report and no file", r.exists(r.out, tt.file), len(lockReports))
						}
						if remove {
							if r.exists(r.in, tt.file) || r.quarantined(t) != 0 {
								t.Errorf("remove mode: in INPUT = %v, quarantined = %d", r.exists(r.in, tt.file), r.quarantined(t))
							}
						} else if r.quarantined(t) != 1 {
							t.Errorf("quarantined = %d, want 1", r.quarantined(t))
						}
						if reasons := rec.reasonsOf(tt.file); !slices.Equal(reasons, []events.MitigationReason{wantConsole}) {
							t.Errorf("console mitigation reasons = %v, want [%s]", reasons, wantConsole)
						}
						for _, want := range []string{"flagged: true", "reason: " + string(wantReason)} {
							if !strings.Contains(line, want) {
								t.Errorf("console line %q lacks %q", line, want)
							}
						}
					case delivered:
						if got.report.Malicious || got.report.Error != "" || got.result.AnalysisError != "" || len(got.report.ErrorExtractedFiles) != 0 {
							t.Errorf("report = %+v: a file passed is neither malware nor in error", got.report)
						}
						if !tt.members {
							if got.report.NotAnalyzedReason != datamodel.NotAnalyzedAnalysisError {
								t.Errorf("NotAnalyzedReason = %q, want %q", got.report.NotAnalyzedReason, datamodel.NotAnalyzedAnalysisError)
							}
						} else if n := got.report.NotAnalyzedExtractedFiles; len(n) != 1 || n[0].Reason != datamodel.NotAnalyzedAnalysisError || got.report.NotAnalyzedExtractedCount != 1 {
							t.Errorf("NotAnalyzedExtractedFiles = %+v (count %d), want the failed member listed as %q", n, got.report.NotAnalyzedExtractedCount, datamodel.NotAnalyzedAnalysisError)
						}
						if !tt.members && (got.result.FilteredVolume != int64(len(tt.content)) || got.result.AnalyzedVolume != 0) {
							t.Errorf("FilteredVolume = %d, AnalyzedVolume = %d, want %d and 0: a byte is never counted as both", got.result.FilteredVolume, got.result.AnalyzedVolume, len(tt.content))
						}
						if !rename {
							// Verified copy: a file whose content changes after its analysis
							// is not delivered. Only a file too big goes by name.
							if classOf(got.src) != classCopy || got.src.TooBig {
								t.Errorf("class = %v, TooBig = %v, want a verified copy", classOf(got.src), got.src.TooBig)
							}
							if !isACopy(t, filepath.Join(r.out, tt.file), got.src.Identity.Ino) {
								t.Error("the delivered file is the source: it was renamed, not copied")
							}
						}
						delivered, err := os.ReadFile(filepath.Join(r.out, tt.file))
						if err != nil || string(delivered) != tt.content {
							t.Errorf("OUTPUT file = %q (%v), want the content copied", delivered, err)
						}
						if r.exists(r.in, tt.file) || r.quarantined(t) != 0 {
							t.Errorf("still in INPUT = %v, quarantined = %d", r.exists(r.in, tt.file), r.quarantined(t))
						}
						wantLine := "not analyzed (analysis error), content not verified"
						if tt.members {
							wantLine = "1 extracted file(s) not analyzed"
						}
						if !strings.Contains(line, wantLine) {
							t.Errorf("console line %q lacks %q", line, wantLine)
						}
					}
				})
			}
		}
	}
}

func TestResolve_analysisErrorPolicy(t *testing.T) {
	for in, want := range map[string]string{"": PolicyError, PolicyError: PolicyError, PolicyMitigate: PolicyMitigate, PolicyPass: PolicyPass} {
		got, _, err := Unanalyzable{AnalysisError: in}.resolve(MoveModeCopy)
		if err != nil || got.AnalysisError != want {
			t.Errorf("resolve(%q) = %q, %v, want %q", in, got.AnalysisError, err, want)
		}
	}
	for _, bad := range []string{"skip", "as_file", "Pass", "bogus"} {
		if _, _, err := (Unanalyzable{AnalysisError: bad}).resolve(MoveModeCopy); err == nil || !strings.Contains(err.Error(), "analysis_error") {
			t.Errorf("resolve(%q) error = %v, want a refusal naming analysis_error", bad, err)
		}
	}
}

// A file that its own policy lets through is not "passed without analysis" when the
// analysis then fails and analysis_error decides otherwise: the log says what was
// applied, once.
func TestAnalysisErrorPolicy_logsWhatIsApplied(t *testing.T) {
	failed := gdetect.Result{Error: "engine failed"}
	encrypted := func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
		return plugins.Extraction{}, plugins.ErrEncrypted
	}
	tests := []struct {
		name     string
		base     Unanalyzable
		want     []string
		notWant  []string
		analysis string
	}{
		{"its own policy lets it through, analysis_error: error keeps it", Unanalyzable{Encrypted: PolicyPass}, nil, []string{"file passed without analysis", "file passed, its analysis failed", "file mitigated"}, PolicyError},
		{"its own policy lets it through, analysis_error: pass delivers it", Unanalyzable{Encrypted: PolicyPass}, []string{"file passed, its analysis failed"}, []string{"file passed without analysis"}, PolicyPass},
		{"its own policy lets it through, analysis_error: mitigate", Unanalyzable{Encrypted: PolicyPass}, []string{"file mitigated, its analysis failed"}, []string{"file passed without analysis"}, PolicyMitigate},
		{"its own policy mitigates it", Unanalyzable{Encrypted: PolicyMitigate}, []string{"file mitigated without analysis", "analysis failed on a file that its own policy holds"}, []string{"file passed"}, PolicyPass},
		{"its own policy keeps it", Unanalyzable{Encrypted: PolicyError}, []string{"analysis failed on a file that its own policy holds"}, []string{"file passed", "file mitigated"}, PolicyPass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)
			s := accSetup{
				files:   map[string]string{"e.zip": zipOf(t, 10)},
				extract: encrypted,
				submit:  func(string) (gdetect.Result, error) { return failed, nil },
				policy:  tt.base,
			}
			s.policy.AnalysisError = tt.analysis
			runAcc(t, s)
			for _, want := range tt.want {
				if n := strings.Count(logs.String(), want); n != 1 {
					t.Errorf("%q is logged %d times, want once: %s", want, n, logs)
				}
			}
			for _, not := range tt.notWant {
				if strings.Contains(logs.String(), not) {
					t.Errorf("%q is logged: %s", not, logs)
				}
			}
		})
	}
}

// Every policy that mitigates gives the file a score of at least mitigationScore and
// never lowers a higher one.
func TestMitigation_theScoreIsNeverLowered(t *testing.T) {
	c := &Connector{config: Config{Unanalyzable: Unanalyzable{Encrypted: PolicyMitigate, TooBig: PolicyMitigate, AnalysisError: PolicyMitigate}}}
	input := fileToAnalyze{filename: "f", location: "/in/f", size: 10, encrypted: true}
	for _, score := range []int{0, 999, 1000, 1500} {
		want := max(score, mitigationScore)
		analyzed := datamodel.Result{Score: score, AnalysisError: "failed"}
		if got := c.policiedResult(input, datamodel.Result{Score: score}, datamodel.NotAnalyzedEncrypted, PolicyMitigate, nil); got.Score != want {
			t.Errorf("policiedResult(score %d) = %d, want %d", score, got.Score, want)
		}
		if got := c.applyAnalysisErrorPolicy(fileToAnalyze{filename: "f", location: "/in/f", size: 10}, analyzed); got.Score != want {
			t.Errorf("applyAnalysisErrorPolicy(score %d) = %d, want %d", score, got.Score, want)
		}
		res := datamodel.Result{Score: score}
		if err := c.applyLimitSkips(plugins.Extraction{}, 1, &res, "/in/a.zip"); err != nil || res.Score != want {
			t.Errorf("applyLimitSkips(score %d) = %d, %v, want %d", score, res.Score, err, want)
		}
	}
	if got := c.unanalyzedResult(input, datamodel.NotAnalyzedTooBig, PolicyMitigate, nil); got.Score != mitigationScore {
		t.Errorf("unanalyzedResult() = %d, want %d", got.Score, mitigationScore)
	}
}

// The volumes of the members of an archive add up without wrapping around.
func TestMergeResult_volumesSaturate(t *testing.T) {
	const top = int64(math.MaxInt64)
	merged := mergeResult(
		datamodel.Result{AnalyzedVolume: top, FilteredVolume: top - 1},
		datamodel.Result{AnalyzedVolume: 1, FilteredVolume: 2},
		"member", nil)
	if merged.AnalyzedVolume != top || merged.FilteredVolume != top {
		t.Errorf("volumes = %d and %d, want both saturated at %d", merged.AnalyzedVolume, merged.FilteredVolume, top)
	}
	for _, tt := range []struct{ a, b, want int64 }{{1, 2, 3}, {top, 0, top}, {top, 1, top}, {top - 1, 1, top}, {0, top, top}, {5, -3, 2}} {
		if got := addVolume(tt.a, tt.b); got != tt.want {
			t.Errorf("addVolume(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// The volumes of the members left out are added without wrapping around: two
// members that declare more than half of the largest volume saturate it.
func TestApplyLimitSkips_theVolumeSaturates(t *testing.T) {
	c := &Connector{config: Config{Unanalyzable: Unanalyzable{TooBig: PolicyPass}}}
	half := int64(math.MaxInt64/2 + 1)
	extraction := plugins.Extraction{Skipped: []datamodel.NotAnalyzedFile{
		{FileName: "a.bin", Size: half, Reason: datamodel.NotAnalyzedTooBig},
		{FileName: "b.bin", Size: half, Reason: datamodel.NotAnalyzedTooBig},
	}}
	var result datamodel.Result
	if err := c.applyLimitSkips(extraction, 2, &result, "/in/a.zip"); err != nil {
		t.Fatal(err)
	}
	if result.FilteredVolume != math.MaxInt64 {
		t.Errorf("FilteredVolume = %d, want %d: the sum must saturate, not wrap to a negative", result.FilteredVolume, int64(math.MaxInt64))
	}
}
