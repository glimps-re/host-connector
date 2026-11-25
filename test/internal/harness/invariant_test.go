//go:build linux

package harness

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	hcquarantine "github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
)

// fixture is the folders of a run, filled by hand.
type fixture struct {
	t    *testing.T
	spec checkSpec
	gm   *gmalware.GMalware
	n    int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{t: t, gm: gmalware.New(t, false)}
	f.spec = checkSpec{
		output: filepath.Join(root, "output"), reports: filepath.Join(root, "reports"), quarantine: filepath.Join(root, "quarantine"),
		Expectations: Expectations{maxFileSize: 1 << 20},
	}
	for _, d := range []string{f.spec.output, f.spec.reports, f.spec.quarantine} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *fixture) deliver(name string, content []byte) {
	f.t.Helper()
	Write(f.t, filepath.Join(f.spec.output, name), content)
}

func (f *fixture) report(entries ...datamodel.Report) {
	f.t.Helper()
	f.n++
	raw, err := json.Marshal(entries)
	if err != nil {
		f.t.Fatal(err)
	}
	Write(f.t, filepath.Join(f.spec.reports, datamodel.SessionReportPrefix+strconv.Itoa(f.n)+".json"), raw)
}

// quarantined puts the container of a file in the quarantine, named as the
// connector names it.
func (f *fixture) quarantined(path string, content []byte) {
	f.t.Helper()
	Write(f.t, filepath.Join(f.spec.quarantine, hcquarantine.ComputeCacheID(path, gmalware.SHA256Hex(content))+".lock"), []byte("locked"))
}

func (f *fixture) violations() string {
	return strings.Join(outputViolations(f.spec, f.gm), "\n")
}

func entry(content []byte, mutate func(*datamodel.Report)) datamodel.Report {
	r := datamodel.Report{Filename: "f", SHA256: gmalware.SHA256Hex(content)}
	if mutate != nil {
		mutate(&r)
	}
	return r
}

func reason(r datamodel.NotAnalyzedReason) func(*datamodel.Report) {
	return func(e *datamodel.Report) { e.NotAnalyzedReason = r }
}

func TestOutputViolations(t *testing.T) {
	content := []byte("some delivered content")
	member := []byte("a member of the archive")
	tests := []struct {
		name  string
		setup func(f *fixture)
		want  string
	}{
		{name: "analyzed clean file", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.report(entry(content, nil))
			f.gm.See(content)
		}},
		{name: "empty output"},
		{name: "file in no report", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.gm.See(content)
		}, want: "in no session report"},
		{name: "file never analyzed", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.report(entry(content, nil))
		}, want: "never analyzed"},
		{name: "no report, lost by a declared crash, analyzed clean", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.gm.See(content)
			f.spec.CrashLost(content)
		}},
		{name: "no report, lost by a declared crash, never analyzed", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.spec.CrashLost(content)
		}, want: "in no session report"},
		{name: "no report, lost by a declared crash, but the service reported an analysis error", setup: func(f *fixture) {
			f.gm.MarkAnalysisError(content, "the analysis failed")
			f.deliver("a.txt", content)
			f.gm.See(content)
			f.spec.CrashLost(content)
		}, want: "in no session report"},
		{name: "no report, no crash declared", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.gm.See(content)
		}, want: "in no session report"},
		{name: "no report, lost by a declared crash, but programmed malware", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.gm.See(content)
			f.spec.CrashLost(content)
		}, want: "programmed as malware"},
		{name: "reported malicious", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.gm.See(content)
			f.report(entry(content, func(r *datamodel.Report) { r.Malicious = true }))
		}, want: "reported malicious"},
		{name: "reported in error", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.report(entry(content, func(r *datamodel.Report) { r.Error = "boom" }))
		}, want: "reported in error"},
		{name: "error then a valid report", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.gm.See(content)
			f.report(entry(content, func(r *datamodel.Report) { r.Error = "outage" }), entry(content, nil))
		}},
		{name: "link in output", setup: func(f *fixture) {
			if err := os.Symlink("/etc/hostname", filepath.Join(f.spec.output, "link")); err != nil {
				t.Fatal(err)
			}
		}, want: "link: not a regular file"},
		{name: "unreadable report", setup: func(f *fixture) {
			Write(t, filepath.Join(f.spec.reports, datamodel.SessionReportPrefix+"bad.json"), []byte("{not json"))
		}, want: "unreadable report"},

		{name: "programmed malware with a clean report", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.report(entry(content, nil))
		}, want: "programmed as malware"},
		{name: "programmed malware with a not-analyzed reason", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.report(entry(content, reason(datamodel.NotAnalyzedPolicySkipped)))
			f.spec.Allow(datamodel.NotAnalyzedPolicySkipped)
		}, want: "programmed as malware"},
		{name: "programmed malware in an archive report", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.zip", content)
			f.report(entry(content, func(r *datamodel.Report) { r.TotalExtractedFile = 1 }))
		}, want: "programmed as malware"},

		{name: "empty file with the empty reason", setup: func(f *fixture) {
			f.deliver("a.txt", nil)
			f.report(entry(nil, reason(datamodel.NotAnalyzedEmpty)))
		}},
		{name: "non-empty file with the empty reason", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.report(entry(content, reason(datamodel.NotAnalyzedEmpty)))
		}, want: "nothing justifies"},
		{name: "big file with the too-big reason", setup: func(f *fixture) {
			big := bytes.Repeat([]byte("x"), 1<<20+1)
			f.deliver("a.bin", big)
			f.report(entry(big, reason(datamodel.NotAnalyzedTooBig)))
		}},
		{name: "small file with the too-big reason", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.report(entry(content, reason(datamodel.NotAnalyzedTooBig)))
		}, want: "nothing justifies"},
		{name: "too-big reason with no known limit", setup: func(f *fixture) {
			f.spec.maxFileSize = 0
			f.deliver("a.txt", content)
			f.report(entry(content, reason(datamodel.NotAnalyzedTooBig)))
		}, want: "nothing justifies"},
		{name: "reason the scenario did not declare", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.report(entry(content, reason(datamodel.NotAnalyzedPolicySkipped)))
		}, want: "nothing justifies"},
		{name: "reason the scenario declared", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.report(entry(content, reason(datamodel.NotAnalyzedPolicySkipped)))
			f.spec.Allow(datamodel.NotAnalyzedPolicySkipped)
		}},
		{name: "unknown reason", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.report(entry(content, reason("whatever")))
			f.spec.Allow("whatever")
		}, want: "nothing justifies"},
		{name: "member delivered not analyzed for an undeclared reason", setup: func(f *fixture) {
			f.deliver("a.zip", content)
			f.spec.Archive(content, member)
			f.gm.See(member)
			f.report(entry(content, func(r *datamodel.Report) {
				r.TotalExtractedFile = 2
				r.NotAnalyzedExtractedFiles = []datamodel.NotAnalyzedFile{{FileName: "m", Size: 10, Reason: datamodel.NotAnalyzedEncrypted}}
			}))
		}, want: `member "m" delivered not analyzed`},
		{name: "archive whose every member was left out too big", setup: func(f *fixture) {
			f.deliver("a.zip", content)
			f.report(entry(content, func(r *datamodel.Report) {
				r.NotAnalyzedExtractedFiles = []datamodel.NotAnalyzedFile{
					{FileName: "big1.bin", Size: 1<<20 + 1, Reason: datamodel.NotAnalyzedTooBig},
					{FileName: "big2.bin", Size: 1<<20 + 2, Reason: datamodel.NotAnalyzedTooBig},
				}
			}))
		}},

		{name: "flagged content delivered", setup: func(f *fixture) {
			f.spec.Flag(content)
			f.deliver("a.txt", content)
			f.gm.See(content)
			f.report(entry(content, nil))
		}, want: "programmed as malware"},
		{name: "archive with a flagged member delivered whole", setup: func(f *fixture) {
			member := []byte("a member flagged by its path")
			f.spec.Flag(member)
			f.spec.Archive(content, member)
			f.deliver("a.zip", content)
			f.gm.See(content)
			f.report(entry(content, nil))
		}, want: "programmed as malware"},
		{name: "restored malware with the restored reason", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.report(entry(content, func(r *datamodel.Report) { r.Malicious = true }), entry(content, reason(datamodel.NotAnalyzedRestored)))
			f.spec.Release(content)
		}},
		{name: "restored malware with the restored flag", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.report(entry(content, func(r *datamodel.Report) { r.Malicious = true }), entry(content, func(r *datamodel.Report) { r.HasBeenRestored = true }))
			f.spec.Release(content)
		}},
		{name: "restored malware with no restored report", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.report(entry(content, func(r *datamodel.Report) { r.Malicious = true }))
			f.spec.Release(content)
		}, want: "without a restored entry"},
		{name: "two copies of a restored malware", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.deliver("b.txt", content)
			f.report(entry(content, func(r *datamodel.Report) { r.HasBeenRestored = true }))
			f.spec.Release(content)
		}, want: "in OUTPUT 2 times"},
		{name: "two copies of a restored malware, two declared", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.deliver("b.txt", content)
			f.report(entry(content, func(r *datamodel.Report) { r.HasBeenRestored = true }))
			f.spec.ReleaseCopies(content, 2)
		}},
		{name: "three copies of a restored malware, two declared", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.deliver("b.txt", content)
			f.deliver("c.txt", content)
			f.report(entry(content, func(r *datamodel.Report) { r.HasBeenRestored = true }))
			f.spec.ReleaseCopies(content, 2)
		}, want: "in OUTPUT 3 times, 2 allowed"},
		{name: "restored entry reporting a malicious member", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.report(entry(content, func(r *datamodel.Report) {
				r.HasBeenRestored = true
				r.MaliciousExtractedFiles = []datamodel.ExtractedFile{{FileName: "m"}}
			}))
			f.spec.Release(content)
		}, want: "reported malicious"},
		{name: "restored entry with a reason nothing justifies", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.report(entry(content, func(r *datamodel.Report) {
				r.HasBeenRestored = true
				r.NotAnalyzedReason = datamodel.NotAnalyzedTooBig
			}))
			f.spec.Release(content)
		}, want: "nothing justifies"},
		{name: "restored entry with a member delivered not analyzed for nothing", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.report(entry(content, func(r *datamodel.Report) {
				r.HasBeenRestored = true
				r.NotAnalyzedExtractedFiles = []datamodel.NotAnalyzedFile{{FileName: "m", Size: 5, Reason: datamodel.NotAnalyzedEncrypted}}
			}))
			f.spec.Release(content)
		}, want: `member "m" of the restored entry`},
		{name: "restored entry in error", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.report(entry(content, func(r *datamodel.Report) {
				r.HasBeenRestored = true
				r.Error = "boom"
			}))
			f.spec.Release(content)
		}, want: "in error"},
		{name: "declared archive with a malware member, delivered whole and clean", setup: func(f *fixture) {
			member := []byte("the malware inside")
			f.gm.MarkMalicious(member)
			f.deliver("a.zip", content)
			f.spec.Archive(content, member)
			f.gm.See(content)
			f.report(entry(content, nil))
		}, want: "programmed as malware"},
		{name: "malware delivered with the restored reason and no release", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.report(entry(content, reason(datamodel.NotAnalyzedRestored)))
			f.spec.Allow(datamodel.NotAnalyzedRestored)
		}, want: "programmed as malware"},
		{name: "archive of an analyzed member", setup: func(f *fixture) {
			f.deliver("a.zip", content)
			f.spec.Archive(content, member)
			f.gm.See(member)
			f.report(entry(content, func(r *datamodel.Report) { r.TotalExtractedFile = 1 }))
		}},
		{name: "archive the scenario did not declare", setup: func(f *fixture) {
			f.deliver("a.zip", content)
			f.report(entry(content, func(r *datamodel.Report) { r.TotalExtractedFile = 1 }))
		}, want: "members the scenario did not declare"},
		{name: "archive no member of which was analyzed", setup: func(f *fixture) {
			f.deliver("a.zip", content)
			f.spec.Archive(content, member)
			f.report(entry(content, func(r *datamodel.Report) { r.TotalExtractedFile = 1 }))
		}, want: "no member was ever analyzed"},
		{name: "archive with a malware member", setup: func(f *fixture) {
			f.gm.MarkMalicious(member)
			f.deliver("a.zip", content)
			f.spec.Archive(content, member)
			f.gm.See(member)
			f.report(entry(content, func(r *datamodel.Report) { r.TotalExtractedFile = 1 }))
		}, want: "a member is programmed as malware"},
		{name: "archive with a failed member", setup: func(f *fixture) {
			f.deliver("a.zip", content)
			f.spec.Archive(content, member)
			f.gm.See(member)
			f.report(entry(content, func(r *datamodel.Report) {
				r.TotalExtractedFile = 1
				r.ErrorExtractedFiles = map[string]string{"m": "x"}
			}))
		}, want: "members in error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			if tt.setup != nil {
				tt.setup(f)
			}
			got := f.violations()
			if tt.want == "" && got != "" {
				t.Errorf("violations = %q, want none", got)
			}
			if tt.want != "" && !strings.Contains(got, tt.want) {
				t.Errorf("violations = %q, want one containing %q", got, tt.want)
			}
		})
	}
}

func TestOutputViolations_lockReport(t *testing.T) {
	bad := []byte("a malware")
	tests := []struct {
		name       string
		content    func(sha, id string) string
		programmed bool
		quarantine bool
		want       string
	}{
		{name: "detection of a quarantined malware", content: detectionOf, programmed: true, quarantine: true},
		{name: "not a report", content: func(string, string) string { return "MZ binary content" }, programmed: true, quarantine: true, want: "not a report"},
		{name: "unknown field", content: func(sha, id string) string {
			return strings.TrimSuffix(detectionOf(sha, id), "}") + `,"payload":"MZ"}`
		}, programmed: true, quarantine: true, want: "not a report"},
		{name: "trailing payload", content: func(sha, id string) string { return detectionOf(sha, id) + "\nMZ-payload" }, programmed: true, quarantine: true, want: "followed by more data"},
		{name: "a second report", content: func(sha, id string) string { return detectionOf(sha, id) + detectionOf(sha, id) }, programmed: true, quarantine: true, want: "followed by more data"},
		{name: "clean file behind the name", content: func(sha, id string) string {
			return strings.Replace(detectionOf(sha, id), `"malicious":true`, `"malicious":false`, 1)
		}, programmed: true, quarantine: true, want: "not malicious"},
		{name: "file not programmed as malware", content: detectionOf, quarantine: true, want: "did not program"},
		{name: "nothing in the quarantine", content: detectionOf, programmed: true, want: "not in the quarantine"},
		{name: "mitigation ID of another file", content: func(sha, _ string) string { return detectionOf(sha, "abc") }, programmed: true, quarantine: true, want: "mitigation ID"},
		{name: "no SHA256", content: func(string, string) string { return `{"malicious":true}` }, programmed: true, quarantine: true, want: "no verifiable SHA256"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			if tt.programmed {
				f.gm.MarkMalicious(bad)
			}
			if tt.quarantine {
				f.quarantined(inputBadPath, bad)
			}
			sum := gmalware.SHA256Hex(bad)
			f.deliver("bad.txt-lockreport211126_0818.json", []byte(tt.content(sum, hcquarantine.ComputeCacheID(inputBadPath, sum))))
			got := f.violations()
			if tt.want == "" && got != "" {
				t.Errorf("violations = %q, want none", got)
			}
			if tt.want != "" && !strings.Contains(got, tt.want) {
				t.Errorf("violations = %q, want one containing %q", got, tt.want)
			}
		})
	}
}

const inputBadPath = "/input/tom/bad.txt"

func detectionOf(sha, id string) string {
	return `{"filename":"` + inputBadPath + `","sha256":"` + sha + `","malicious":true,"mitigation-id":"` + id + `"}`
}

// The lock report of an archive is the one of a declared archive with a
// malware member.
func TestOutputViolations_lockReportOfAnArchive(t *testing.T) {
	archive, member := []byte("an archive"), []byte("its malware member")
	for _, tt := range []struct {
		name       string
		declared   bool
		programmed bool
		flagged    bool
		want       string
	}{
		{name: "declared with a malware member", declared: true, programmed: true},
		{name: "declared with no malware member", declared: true, want: "did not program"},
		{name: "not declared", programmed: true, want: "did not program"},
		{name: "declared with a flagged member", declared: true, flagged: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			if tt.programmed {
				f.gm.MarkMalicious(member)
			}
			if tt.flagged {
				f.spec.Flag(member)
			}
			if tt.declared {
				f.spec.Archive(archive, member)
			}
			sum := gmalware.SHA256Hex(archive)
			f.quarantined(inputBadPath, archive)
			f.deliver("bad.zip-lockreport211126_0818.json", []byte(detectionOf(sum, hcquarantine.ComputeCacheID(inputBadPath, sum))))
			got := f.violations()
			if tt.want == "" && got != "" {
				t.Errorf("violations = %q, want none", got)
			}
			if tt.want != "" && !strings.Contains(got, tt.want) {
				t.Errorf("violations = %q, want one containing %q", got, tt.want)
			}
		})
	}
}

// The lock report of a malware that was restored stays in OUTPUT although the
// quarantine no longer holds it, but only when the reports show the restore.
func TestOutputViolations_lockReportOfARestoredMalware(t *testing.T) {
	bad := []byte("a malware")
	f := newFixture(t)
	f.gm.MarkMalicious(bad)
	sum := gmalware.SHA256Hex(bad)
	f.deliver("bad.txt-lockreport211126_0818.json", []byte(detectionOf(sum, hcquarantine.ComputeCacheID(inputBadPath, sum))))
	if got := f.violations(); !strings.Contains(got, "not in the quarantine") {
		t.Errorf("violations = %q, want the missing container flagged", got)
	}
	f.report(entry(bad, func(r *datamodel.Report) { r.HasBeenRestored = true }))
	if got := f.violations(); !strings.Contains(got, "not in the quarantine") {
		t.Errorf("violations = %q, want the missing container flagged: the scenario did not declare the restore", got)
	}
	f.spec.Release(bad)
	if got := f.violations(); got != "" {
		t.Errorf("violations = %q, want none once the restore is declared and shown by the reports", got)
	}
}

// A lock report padded past the bound cannot hide data behind the cap of the
// read, and a lock report that is itself a programmed malware is flagged.
// With the quarantine off, the detection report of a file left in place names
// no container: accepted only when the scenario declares the quarantine off.
func TestOutputViolations_lockReportWithoutContainerWhenTheQuarantineIsOff(t *testing.T) {
	bad := []byte("a malware")
	sum := gmalware.SHA256Hex(bad)
	report := `{"filename":"` + inputBadPath + `","sha256":"` + sum + `","malicious":true}`
	for _, off := range []bool{false, true} {
		f := newFixture(t)
		f.gm.MarkMalicious(bad)
		f.spec.QuarantineOff = off
		f.deliver("bad.txt-lockreport211126_0818.json", []byte(report))
		got := f.violations()
		if off && got != "" {
			t.Errorf("quarantine off: violations = %q, want none", got)
		}
		if !off && !strings.Contains(got, "mitigation ID") {
			t.Errorf("quarantine on: violations = %q, want the missing mitigation ID flagged", got)
		}
	}
}

func TestOutputViolations_lockReportTraps(t *testing.T) {
	t.Run("padding past the bound", func(t *testing.T) {
		f := newFixture(t)
		path := filepath.Join(f.spec.output, "bad.txt-lockreport211126_0818.json")
		Write(t, path, []byte(detectionOf("x", "y")))
		if err := os.Truncate(path, maxReportSize+1); err != nil {
			t.Fatal(err)
		}
		if got := f.violations(); !strings.Contains(got, "larger than a report can be") {
			t.Errorf("violations = %q", got)
		}
	})
	t.Run("a programmed malware under the name", func(t *testing.T) {
		f := newFixture(t)
		payload := []byte("MZ malware named like a lock report")
		f.gm.MarkMalicious(payload)
		f.deliver("x-lockreport211126_0818.json", payload)
		if got := f.violations(); !strings.Contains(got, "programmed as malware") {
			t.Errorf("violations = %q", got)
		}
	})
}

func TestEffectiveMaxFileSize(t *testing.T) {
	tests := []struct {
		name    string
		conf    map[string]any
		want    int64
		wantErr bool
	}{
		{name: "100MiB", conf: map[string]any{"max_file_size": "100MiB"}, want: 100 << 20},
		{name: "1MiB", conf: map[string]any{"max_file_size": "1MiB"}, want: 1 << 20},
		{name: "10KB", conf: map[string]any{"max_file_size": "10KB"}, want: 10000},
		{name: "above the limit", conf: map[string]any{"max_file_size": "5GB"}, want: 100 << 20},
		{name: "zero", conf: map[string]any{"max_file_size": "0"}, want: 100 << 20},
		{name: "negative without unit", conf: map[string]any{"max_file_size": "-1"}, wantErr: true},
		{name: "not a size", conf: map[string]any{"max_file_size": "plenty"}, wantErr: true},
		{name: "empty", conf: map[string]any{"max_file_size": ""}, wantErr: true},
		{name: "absent", conf: map[string]any{}, wantErr: true},
		{name: "not a string", conf: map[string]any{"max_file_size": 5}, wantErr: true},
		{name: "syndetect", conf: map[string]any{"max_file_size": "1GiB", "gmalware_syndetect": true}, wantErr: true},
		{name: "syndetect as a string", conf: map[string]any{"max_file_size": "1GiB", "gmalware_syndetect": "true"}, wantErr: true},
		{name: "syndetect as a string, off", conf: map[string]any{"max_file_size": "1GiB", "gmalware_syndetect": "false"}, want: 100 << 20},
		{name: "syndetect off", conf: map[string]any{"max_file_size": "1MiB", "gmalware_syndetect": false}, want: 1 << 20},
		{name: "syndetect as a number", conf: map[string]any{"max_file_size": "1GiB", "gmalware_syndetect": 1}, wantErr: true},
		{name: "syndetect not a boolean", conf: map[string]any{"max_file_size": "1GiB", "gmalware_syndetect": "maybe"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := effectiveMaxFileSize(tt.conf)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Errorf("effectiveMaxFileSize(%v) = %d, %v; want %d, error %v", tt.conf, got, err, tt.want, tt.wantErr)
			}
		})
	}
}
