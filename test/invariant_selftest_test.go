//go:build linux

package test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"testing/iotest"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	hcquarantine "github.com/glimps-re/host-connector/pkg/quarantine"
)

// see makes the service say it analyzed the content.
func (g *gmalware) see(content []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	sum := sha256Hex(content)
	g.given[sum] = g.verdicts[sum]
}

// fixture is the folders of a run, filled by hand.
type fixture struct {
	t    *testing.T
	spec checkSpec
	gm   *gmalware
	n    int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{t: t, gm: newGMalware(t, false)}
	f.spec = checkSpec{
		output: filepath.Join(root, "output"), reports: filepath.Join(root, "reports"), quarantine: filepath.Join(root, "quarantine"),
		expectations: expectations{maxFileSize: 1 << 20},
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
	write(f.t, filepath.Join(f.spec.output, name), content)
}

func (f *fixture) report(entries ...datamodel.Report) {
	f.t.Helper()
	f.n++
	raw, err := json.Marshal(entries)
	if err != nil {
		f.t.Fatal(err)
	}
	write(f.t, filepath.Join(f.spec.reports, datamodel.SessionReportPrefix+strconv.Itoa(f.n)+".json"), raw)
}

// quarantined puts the container of a file in the quarantine, named as the
// connector names it.
func (f *fixture) quarantined(path string, content []byte) {
	f.t.Helper()
	write(f.t, filepath.Join(f.spec.quarantine, hcquarantine.ComputeCacheID(path, sha256Hex(content))+".lock"), []byte("locked"))
}

func (f *fixture) violations() string {
	return strings.Join(outputViolations(f.spec, f.gm), "\n")
}

func entry(content []byte, mutate func(*datamodel.Report)) datamodel.Report {
	r := datamodel.Report{Filename: "f", SHA256: sha256Hex(content)}
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
			f.gm.see(content)
		}},
		{name: "empty output"},
		{name: "file in no report", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.gm.see(content)
		}, want: "in no session report"},
		{name: "file never analyzed", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.report(entry(content, nil))
		}, want: "never analyzed"},
		{name: "reported malicious", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.gm.see(content)
			f.report(entry(content, func(r *datamodel.Report) { r.Malicious = true }))
		}, want: "reported malicious"},
		{name: "reported in error", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.report(entry(content, func(r *datamodel.Report) { r.Error = "boom" }))
		}, want: "reported in error"},
		{name: "error then a valid report", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.gm.see(content)
			f.report(entry(content, func(r *datamodel.Report) { r.Error = "outage" }), entry(content, nil))
		}},
		{name: "link in output", setup: func(f *fixture) {
			if err := os.Symlink("/etc/hostname", filepath.Join(f.spec.output, "link")); err != nil {
				t.Fatal(err)
			}
		}, want: "link: not a regular file"},
		{name: "unreadable report", setup: func(f *fixture) {
			write(t, filepath.Join(f.spec.reports, datamodel.SessionReportPrefix+"bad.json"), []byte("{not json"))
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
			f.spec.allow(datamodel.NotAnalyzedPolicySkipped)
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
			f.spec.allow(datamodel.NotAnalyzedPolicySkipped)
		}},
		{name: "unknown reason", setup: func(f *fixture) {
			f.deliver("a.txt", content)
			f.report(entry(content, reason("whatever")))
			f.spec.allow("whatever")
		}, want: "nothing justifies"},
		{name: "member delivered not analyzed for an undeclared reason", setup: func(f *fixture) {
			f.deliver("a.zip", content)
			f.spec.archive(content, member)
			f.gm.see(member)
			f.report(entry(content, func(r *datamodel.Report) {
				r.TotalExtractedFile = 2
				r.NotAnalyzedExtractedFiles = []datamodel.NotAnalyzedFile{{FileName: "m", Size: 10, Reason: datamodel.NotAnalyzedEncrypted}}
			}))
		}, want: `member "m" delivered not analyzed`},

		{name: "flagged content delivered", setup: func(f *fixture) {
			f.spec.flag(content)
			f.deliver("a.txt", content)
			f.gm.see(content)
			f.report(entry(content, nil))
		}, want: "programmed as malware"},
		{name: "archive with a flagged member delivered whole", setup: func(f *fixture) {
			member := []byte("a member flagged by its path")
			f.spec.flag(member)
			f.spec.archive(content, member)
			f.deliver("a.zip", content)
			f.gm.see(content)
			f.report(entry(content, nil))
		}, want: "programmed as malware"},
		{name: "restored malware with the restored reason", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.report(entry(content, func(r *datamodel.Report) { r.Malicious = true }), entry(content, reason(datamodel.NotAnalyzedRestored)))
			f.spec.release(content)
		}},
		{name: "restored malware with the restored flag", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.report(entry(content, func(r *datamodel.Report) { r.Malicious = true }), entry(content, func(r *datamodel.Report) { r.HasBeenRestored = true }))
			f.spec.release(content)
		}},
		{name: "restored malware with no restored report", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.report(entry(content, func(r *datamodel.Report) { r.Malicious = true }))
			f.spec.release(content)
		}, want: "without a restored entry"},
		{name: "two copies of a restored malware", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.deliver("b.txt", content)
			f.report(entry(content, func(r *datamodel.Report) { r.HasBeenRestored = true }))
			f.spec.release(content)
		}, want: "in OUTPUT 2 times"},
		{name: "restored entry reporting a malicious member", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.report(entry(content, func(r *datamodel.Report) {
				r.HasBeenRestored = true
				r.MaliciousExtractedFiles = []datamodel.ExtractedFile{{FileName: "m"}}
			}))
			f.spec.release(content)
		}, want: "reported malicious"},
		{name: "restored entry with a reason nothing justifies", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.report(entry(content, func(r *datamodel.Report) {
				r.HasBeenRestored = true
				r.NotAnalyzedReason = datamodel.NotAnalyzedTooBig
			}))
			f.spec.release(content)
		}, want: "nothing justifies"},
		{name: "restored entry with a member delivered not analyzed for nothing", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.report(entry(content, func(r *datamodel.Report) {
				r.HasBeenRestored = true
				r.NotAnalyzedExtractedFiles = []datamodel.NotAnalyzedFile{{FileName: "m", Size: 5, Reason: datamodel.NotAnalyzedEncrypted}}
			}))
			f.spec.release(content)
		}, want: `member "m" of the restored entry`},
		{name: "restored entry in error", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.report(entry(content, func(r *datamodel.Report) {
				r.HasBeenRestored = true
				r.Error = "boom"
			}))
			f.spec.release(content)
		}, want: "in error"},
		{name: "declared archive with a malware member, delivered whole and clean", setup: func(f *fixture) {
			member := []byte("the malware inside")
			f.gm.MarkMalicious(member)
			f.deliver("a.zip", content)
			f.spec.archive(content, member)
			f.gm.see(content)
			f.report(entry(content, nil))
		}, want: "programmed as malware"},
		{name: "malware delivered with the restored reason and no release", setup: func(f *fixture) {
			f.gm.MarkMalicious(content)
			f.deliver("a.txt", content)
			f.report(entry(content, reason(datamodel.NotAnalyzedRestored)))
			f.spec.allow(datamodel.NotAnalyzedRestored)
		}, want: "programmed as malware"},
		{name: "archive of an analyzed member", setup: func(f *fixture) {
			f.deliver("a.zip", content)
			f.spec.archive(content, member)
			f.gm.see(member)
			f.report(entry(content, func(r *datamodel.Report) { r.TotalExtractedFile = 1 }))
		}},
		{name: "archive the scenario did not declare", setup: func(f *fixture) {
			f.deliver("a.zip", content)
			f.report(entry(content, func(r *datamodel.Report) { r.TotalExtractedFile = 1 }))
		}, want: "members the scenario did not declare"},
		{name: "archive no member of which was analyzed", setup: func(f *fixture) {
			f.deliver("a.zip", content)
			f.spec.archive(content, member)
			f.report(entry(content, func(r *datamodel.Report) { r.TotalExtractedFile = 1 }))
		}, want: "no member was ever analyzed"},
		{name: "archive with a malware member", setup: func(f *fixture) {
			f.gm.MarkMalicious(member)
			f.deliver("a.zip", content)
			f.spec.archive(content, member)
			f.gm.see(member)
			f.report(entry(content, func(r *datamodel.Report) { r.TotalExtractedFile = 1 }))
		}, want: "a member is programmed as malware"},
		{name: "archive with a failed member", setup: func(f *fixture) {
			f.deliver("a.zip", content)
			f.spec.archive(content, member)
			f.gm.see(member)
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
			sum := sha256Hex(bad)
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

// analyze submits content to the fake and returns the status of the answer
// and, when the submission was accepted, the result of the analysis.
func analyze(t *testing.T, gm *gmalware, content []byte) (status int, res map[string]any) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", "f")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = part.Write(content); err != nil {
		t.Fatal(err)
	}
	if err = mw.Close(); err != nil {
		t.Fatal(err)
	}
	post, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gm.URL+"/api/lite/v2/submit", &body)
	if err != nil {
		t.Fatal(err)
	}
	post.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	var sub struct {
		UUID string `json:"uuid"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&sub); err != nil {
		t.Fatal(err)
	}
	return getResult(t, gm, sub.UUID)
}

func getResult(t *testing.T, gm *gmalware, uuid string) (status int, res map[string]any) {
	t.Helper()
	get, err := http.NewRequestWithContext(t.Context(), http.MethodGet, gm.URL+"/api/lite/v2/results/"+uuid, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(get)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, nil
	}
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, res
}

// The fake service answers what it is told: a verdict per content, a failure
// on request, and it remembers what it gave.
func TestGMalware_programmable(t *testing.T) {
	gm := newGMalware(t, false)
	bad, good := []byte("bad content"), []byte("good content")
	gm.MarkMalicious(bad)

	if _, res := analyze(t, gm, bad); res["is_malware"] != true {
		t.Errorf("verdict of the marked content = %v, want malware", res["is_malware"])
	}
	if _, res := analyze(t, gm, good); res["is_malware"] != false {
		t.Errorf("verdict of another content = %v, want clean", res["is_malware"])
	}
	if v, ok := gm.Given(sha256Hex(bad)); !ok || !v.malware {
		t.Errorf("Given(bad) = %v, %v, want a malware verdict", v, ok)
	}
	if _, ok := gm.Given(sha256Hex([]byte("never sent"))); ok {
		t.Error("Given reports a result nobody asked for")
	}
	if status, _ := getResult(t, gm, "00000000-0000-0000-0000-000000000000"); status != http.StatusNotFound {
		t.Errorf("status of an unknown analysis = %d, want 404", status)
	}
	if _, ok := gm.Given(""); ok {
		t.Error("an unknown analysis was recorded as given")
	}

	gm.FailWith(http.StatusServiceUnavailable)
	if status, _ := analyze(t, gm, good); status != http.StatusServiceUnavailable {
		t.Errorf("status during the outage = %d, want 503", status)
	}
	if gm.failed.Load() == 0 {
		t.Error("the failed request is not counted")
	}
	gm.FailWith(0)
	if status, _ := analyze(t, gm, good); status != http.StatusOK {
		t.Errorf("status after the outage = %d, want 200", status)
	}

	gm.DelaySubmissions(300 * time.Millisecond)
	at := time.Now()
	analyze(t, gm, good)
	if took := time.Since(at); took < 300*time.Millisecond {
		t.Errorf("a delayed submission was answered in %s", took)
	}
}

// The fake console refuses what strays from the SDK protocol and says so.
func TestFakeConsole_protocol(t *testing.T) {
	c := newFakeConsole(t, map[string]any{})
	do := func(method, path, auth, body string) int {
		req, err := http.NewRequestWithContext(t.Context(), method, c.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}
	good := "ApiKey " + consoleAPIKey
	if got := do(http.MethodPost, "/api/v1/connectors/register", good, "{}"); got != http.StatusOK {
		t.Errorf("register = %d, want 200", got)
	}
	for name, got := range map[string]int{
		"wrong method":  do(http.MethodGet, "/api/v1/connectors/register", good, ""),
		"no key":        do(http.MethodPost, "/api/v1/connectors/register", "", "{}"),
		"unknown route": do(http.MethodPost, "/api/v1/connectors/elsewhere", good, "{}"),
		"bad event":     do(http.MethodPost, "/api/v1/connectors/events", good, "{not json"),
	} {
		if got != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", name, got)
		}
	}
	if n := len(c.ProtocolErrors()); n != 4 {
		t.Errorf("protocol errors = %d, want 4: %v", n, c.ProtocolErrors())
	}
	id := c.Push(t, "stop", nil)
	if _, acked := c.Ack(id); acked {
		t.Error("a task nobody acknowledged is reported acknowledged")
	}
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
				f.spec.flag(member)
			}
			if tt.declared {
				f.spec.archive(archive, member)
			}
			sum := sha256Hex(archive)
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
	sum := sha256Hex(bad)
	f.deliver("bad.txt-lockreport211126_0818.json", []byte(detectionOf(sum, hcquarantine.ComputeCacheID(inputBadPath, sum))))
	if got := f.violations(); !strings.Contains(got, "not in the quarantine") {
		t.Errorf("violations = %q, want the missing container flagged", got)
	}
	f.report(entry(bad, func(r *datamodel.Report) { r.HasBeenRestored = true }))
	if got := f.violations(); !strings.Contains(got, "not in the quarantine") {
		t.Errorf("violations = %q, want the missing container flagged: the scenario did not declare the restore", got)
	}
	f.spec.release(bad)
	if got := f.violations(); got != "" {
		t.Errorf("violations = %q, want none once the restore is declared and shown by the reports", got)
	}
}

// A lock report padded past the bound cannot hide data behind the cap of the
// read, and a lock report that is itself a programmed malware is flagged.
func TestOutputViolations_lockReportTraps(t *testing.T) {
	t.Run("padding past the bound", func(t *testing.T) {
		f := newFixture(t)
		path := filepath.Join(f.spec.output, "bad.txt-lockreport211126_0818.json")
		write(t, path, []byte(detectionOf("x", "y")))
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

type failingWriter struct {
	header http.Header
	err    error
}

func (w *failingWriter) Header() http.Header       { return w.header }
func (w *failingWriter) WriteHeader(int)           {}
func (w *failingWriter) Write([]byte) (int, error) { return 0, w.err }

// A fake that cannot answer says so, except when the connector closed the
// connection, which is only noted.
func TestErrLog(t *testing.T) {
	req := func(ctx context.Context, body io.Reader) *http.Request {
		return httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/lite/v2/submit", body)
	}
	t.Run("a closed connection is a note", func(t *testing.T) {
		var l errLog
		r := req(t.Context(), nil)
		l.json(&failingWriter{header: http.Header{}, err: syscall.EPIPE}, r, map[string]any{})
		l.text(&failingWriter{header: http.Header{}, err: syscall.ECONNRESET}, r, "x")
		if got := l.Errors(); len(got) != 0 {
			t.Errorf("errors = %v, want none for a closed connection", got)
		}
		if got := l.AbortedUploads(); got != 0 {
			t.Errorf("aborted = %d, want 0: a failed answer is not an aborted upload", got)
		}
	})
	t.Run("another write failure is an error naming the endpoint", func(t *testing.T) {
		var l errLog
		l.text(&failingWriter{header: http.Header{}, err: io.ErrShortWrite}, req(t.Context(), nil), "x")
		got := l.Errors()
		if len(got) != 1 || !strings.Contains(got[0], "POST /api/lite/v2/submit") {
			t.Errorf("errors = %v, want one naming the endpoint", got)
		}
	})
	t.Run("a cut body that nobody announced is an error", func(t *testing.T) {
		var l errLog
		l.drain(req(t.Context(), iotest.ErrReader(io.ErrUnexpectedEOF)), 10)
		if got := l.Errors(); len(got) != 1 {
			t.Errorf("errors = %v, want one", got)
		}
	})
	t.Run("an announced abort that never happens is unconsumed", func(t *testing.T) {
		var l errLog
		l.ExpectAbortedUploads(2)
		l.drain(req(t.Context(), iotest.ErrReader(io.ErrUnexpectedEOF)), 10)
		if got := l.Unconsumed(); got != 1 {
			t.Errorf("unconsumed = %d, want 1", got)
		}
	})
	t.Run("a cut body that was announced is a note, once", func(t *testing.T) {
		var l errLog
		l.ExpectAbortedUploads(1)
		l.drain(req(t.Context(), iotest.ErrReader(io.ErrUnexpectedEOF)), 10)
		if got := l.Errors(); len(got) != 0 {
			t.Fatalf("errors = %v, want none for an announced abort", got)
		}
		if got := l.AbortedUploads(); got != 1 {
			t.Errorf("aborted = %d, want 1", got)
		}
		l.drain(req(t.Context(), iotest.ErrReader(io.ErrUnexpectedEOF)), 10)
		if got := l.Errors(); len(got) != 1 {
			t.Errorf("errors = %v, want the second, unannounced abort to be an error", got)
		}
	})
	t.Run("a cancelled request does not excuse a cut body", func(t *testing.T) {
		var l errLog
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		l.drain(req(ctx, iotest.ErrReader(io.ErrUnexpectedEOF)), 10)
		if got := l.Errors(); len(got) != 1 {
			t.Errorf("errors = %v, want one", got)
		}
	})
	t.Run("a connection reset while reading is a note and an aborted upload", func(t *testing.T) {
		var l errLog
		l.drain(req(t.Context(), iotest.ErrReader(syscall.ECONNRESET)), 10)
		if got := l.Errors(); len(got) != 0 {
			t.Errorf("errors = %v, want none", got)
		}
		if got := l.AbortedUploads(); got != 1 {
			t.Errorf("aborted = %d, want 1", got)
		}
	})
}

// A verdict whose answer never reached the connector is not given: a connector
// that fails open must not pass for one that analyzed the file.
func TestGMalware_givenOnlyOnceWritten(t *testing.T) {
	content := []byte("some content")
	sum := sha256Hex(content)
	uuid := "00000000-0000-0000-0000-000000000001"
	newReq := func() *http.Request {
		return httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/lite/v2/results/"+uuid, http.NoBody)
	}
	setup := func() *gmalware {
		g := &gmalware{uuids: map[string]string{uuid: sum}, verdicts: map[string]verdict{}, given: map[string]verdict{}}
		return g
	}

	g := setup()
	g.results(&failingWriter{header: http.Header{}, err: syscall.ECONNRESET}, newReq())
	if _, ok := g.Given(sum); ok {
		t.Error("a verdict that was not delivered is reported as given")
	}
	if g.answered.Load() != 0 {
		t.Error("an answer that was not delivered is counted")
	}

	g = setup()
	g.results(httptest.NewRecorder(), newReq())
	if _, ok := g.Given(sum); !ok {
		t.Error("a delivered verdict is not reported as given")
	}
}

// resultOver asks the fake, through its server, for the result of a content
// that was submitted, with a client that gives up after patience.
func resultOver(t *testing.T, gm *gmalware, content []byte, patience time.Duration) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", "f")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = part.Write(content); err != nil {
		t.Fatal(err)
	}
	if err = mw.Close(); err != nil {
		t.Fatal(err)
	}
	post, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gm.URL+"/api/lite/v2/submit", &body)
	if err != nil {
		t.Fatal(err)
	}
	post.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var sub struct {
		UUID string `json:"uuid"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&sub); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), patience)
	defer cancel()
	get, err := http.NewRequestWithContext(ctx, http.MethodGet, gm.URL+"/api/lite/v2/results/"+sub.UUID, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := http.DefaultClient.Do(get)
	if err != nil {
		return
	}
	_ = r2.Body.Close()
}

// A verdict that a client gave up waiting for is not given, although the
// server wrote it without an error: net/http buffers the write, only the
// request context tells that nobody listens.
func TestGMalware_givenOnlyToAClientThatWaited(t *testing.T) {
	content := []byte("some content for the slow server")
	sum := sha256Hex(content)

	gm := newGMalware(t, false)
	gm.DelayResults(600 * time.Millisecond)
	resultOver(t, gm, content, 150*time.Millisecond)
	waitFor(t, "the slow handler to end", func() bool { return gm.handled.Load() == 1 })
	if _, ok := gm.Given(sum); ok {
		t.Error("a verdict nobody waited for is reported as given")
	}
	if gm.answered.Load() != 0 {
		t.Error("an answer nobody waited for is counted")
	}

	gm = newGMalware(t, false)
	gm.DelayResults(100 * time.Millisecond)
	resultOver(t, gm, content, 5*time.Second)
	// The handler records once it has flushed, which can be after the client
	// has read the answer.
	waitFor(t, "the verdict to be reported as given", func() bool {
		_, ok := gm.Given(sum)
		return ok && gm.answered.Load() == 1
	})
}

// A scenario announces the uploads it expects the connector to cut, once, on
// the instance: the fake and the final check are told the same number.
func TestInstance_expectAbortedUploads(t *testing.T) {
	in := &instance{gm: newGMalware(t, false)}
	in.expectAbortedUploads(1)
	in.expectAbortedUploads(2)
	if in.abortedUploads != 3 || in.gm.Unconsumed() != 3 {
		t.Errorf("announced = %d, unconsumed = %d, want 3 and 3", in.abortedUploads, in.gm.Unconsumed())
	}
}
