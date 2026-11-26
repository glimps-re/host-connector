//go:build linux

package harness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	hcquarantine "github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/test/internal/fakes/console"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
)

var (
	cleanFile = File{Path: "clean.txt", Content: []byte("clean")}
	badFile   = File{Path: "bad.txt", Content: []byte("bad"), Verdict: Malicious}
)

// entryOf is a report entry of a file, by its path below INPUT/tom.
func entryOf(path string, mutate func(*datamodel.Report)) datamodel.Report {
	r := datamodel.Report{Filename: path}
	if mutate != nil {
		mutate(&r)
	}
	return r
}

func detected(e *datamodel.Report) {
	e.Malicious, e.MalwareReason = true, datamodel.MalwareDetected
}

func restoredMark(e *datamodel.Report) {
	e.HasBeenRestored, e.NotAnalyzedReason = true, datamodel.NotAnalyzedRestored
}

// state is what a run left behind it, put there by hand. Paths are below
// INPUT/tom, and so are the file names of the reports.
type state struct {
	conf        map[string]any
	agent       bool
	input       []File
	output      []File
	moved       []File // dropped in INPUT, then moved to OUTPUT
	quarantine  []File
	zipped      []File // quarantined in a zip container
	reports     []datamodel.Report
	lockReports []datamodel.Report
	consumed    map[string]int // entries an Await saw, by path
	submitted   []File
	given       []File
	temps       []string // temporary files of a restore
	dirs        []string // folders of INPUT
}

func newRun(t *testing.T, s Scenario, st state) *run {
	t.Helper()
	root := t.TempDir()
	in := &Instance{
		Input: filepath.Join(root, "input"), Output: filepath.Join(root, "output"),
		Quarantine: filepath.Join(root, "quarantine"), Export: filepath.Join(root, "reports"),
		Stderr: &syncBuffer{}, conf: st.conf,
	}
	tom := filepath.Join(in.Input, "tom")
	for _, d := range []string{tom, filepath.Join(in.Output, "tom"), in.Quarantine, filepath.Join(in.Export, "tom")} {
		mkdir(t, d)
	}
	r := &run{s: s, in: in, gm: gmalware.New(t), files: map[string]File{}, final: map[string]File{}, consumed: map[string]int{}, inodes: map[string]uint64{}}
	r.validate(t)
	for _, f := range s.Files {
		r.remember("", f)
	}
	for _, f := range st.input {
		write(t, filepath.Join(tom, f.Path), f.Content)
		r.inodes[f.Path] = inode(t, filepath.Join(tom, f.Path))
	}
	for _, f := range st.output {
		write(t, filepath.Join(in.Output, "tom", f.Path), f.Content)
	}
	for _, f := range st.moved {
		write(t, filepath.Join(tom, f.Path), f.Content)
		r.inodes[f.Path] = inode(t, filepath.Join(tom, f.Path))
		if err := os.Rename(filepath.Join(tom, f.Path), filepath.Join(in.Output, "tom", f.Path)); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range st.quarantine {
		write(t, r.lockPath(f.Path, f.Content), []byte("a tar container"))
	}
	for _, f := range st.zipped {
		write(t, r.lockPath(f.Path, f.Content), []byte("PK\x03\x04 a zip container"))
	}
	absolute := func(entries []datamodel.Report) []datamodel.Report {
		for i := range entries {
			entries[i].Filename = filepath.Join(tom, entries[i].Filename)
		}
		return entries
	}
	if len(st.reports) > 0 {
		write(t, filepath.Join(in.Export, "tom", datamodel.SessionReportPrefix+"1.json"), marshal(t, absolute(st.reports)))
	}
	for i, e := range absolute(st.lockReports) {
		rel, err := filepath.Rel(tom, e.Filename)
		if err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(in.Output, "tom", rel+"-lockreport"+strconv.Itoa(i)+".json"), marshal(t, e))
	}
	maps.Copy(r.consumed, st.consumed)
	for _, f := range st.submitted {
		submit(t, r.gm.URL, filepath.Join(tom, f.Path), f.Content)
	}
	for _, f := range st.given {
		r.gm.See(f.Content)
	}
	for _, p := range st.temps {
		write(t, filepath.Join(tom, p), nil)
	}
	for _, d := range st.dirs {
		mkdir(t, filepath.Join(tom, d))
	}
	if st.agent {
		in.Console = console.New(t, nil)
	}
	return r
}

func mkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, path string, content []byte) {
	t.Helper()
	mkdir(t, filepath.Dir(path))
	Write(t, path, content)
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// submit sends a content to the fake service as the connector does.
func submit(t *testing.T, url, name string, content []byte) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = part.Write(content); err != nil {
		t.Fatal(err)
	}
	if err = mw.Close(); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url+"/api/lite/v2/submit", mw.FormDataContentType(), &body) //nolint:noctx // a self-test against a local fake
	if err != nil {
		t.Fatal(err)
	}
	if err = resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRows(t *testing.T) {
	archive := File{Path: "a.zip", Content: []byte("an archive"), Members: []File{{Path: "d/m.txt", Content: []byte("a member")}}}
	moveOn := map[string]any{"actions": map[string]any{"move": true}}
	for _, tt := range []struct {
		name     string
		scenario Scenario
		state    state
		want     []row
	}{
		{
			name: "every file as wanted",
			scenario: Scenario{
				Files: []File{cleanFile, badFile},
				Want:  map[string]Outcome{"clean.txt": {In: Output}, "bad.txt": {In: Quarantine, Malware: datamodel.MalwareDetected}},
			},
			state: state{output: []File{cleanFile}, quarantine: []File{badFile}, reports: []datamodel.Report{entryOf("clean.txt", nil), entryOf("bad.txt", detected)}},
			want: []row{
				{name: "clean.txt", want: "output / clean", got: "output / clean", ok: true},
				{name: "bad.txt", want: "quarantine / malware:malware-detected", got: "quarantine / malware:malware-detected", ok: true},
				{name: "containers", want: "1", got: "1", ok: true},
			},
		},
		{
			name: "a malware delivered",
			scenario: Scenario{
				Files: []File{badFile},
				Want:  map[string]Outcome{"bad.txt": {In: Quarantine, Malware: datamodel.MalwareDetected}},
			},
			state: state{output: []File{badFile}, reports: []datamodel.Report{entryOf("bad.txt", detected)}},
			want: []row{
				{name: "bad.txt", want: "quarantine / malware:malware-detected", got: "output / malware:malware-detected"},
				{name: "containers", want: "1", got: "0"},
			},
		},
		{
			name: "other bytes delivered",
			scenario: Scenario{
				Files: []File{cleanFile},
				Want:  map[string]Outcome{"clean.txt": {In: Output}},
			},
			state: state{output: []File{{Path: "clean.txt", Content: []byte("other")}}, reports: []datamodel.Report{entryOf("clean.txt", nil)}},
			want: []row{
				{name: "clean.txt", want: "output / clean", got: "output (other bytes) / clean"},
				{name: "containers", want: "0", got: "0", ok: true},
			},
		},
		{
			name: "every report entry is shown",
			scenario: Scenario{
				Files: []File{badFile},
				Want:  map[string]Outcome{"bad.txt": {In: Quarantine, Malware: datamodel.MalwareDetected}},
			},
			state: state{quarantine: []File{badFile}, reports: []datamodel.Report{entryOf("bad.txt", detected), entryOf("bad.txt", nil)}},
			want: []row{
				{name: "bad.txt", want: "quarantine / malware:malware-detected", got: "quarantine / malware:malware-detected, clean"},
				{name: "containers", want: "1", got: "1", ok: true},
			},
		},
		{
			name: "a file nowhere, without report",
			scenario: Scenario{
				Files: []File{cleanFile},
				Want:  map[string]Outcome{"clean.txt": {In: Output}},
			},
			want: []row{
				{name: "clean.txt", want: "output / clean", got: "nowhere / no report"},
				{name: "containers", want: "0", got: "0", ok: true},
			},
		},
		{
			name: "a file kept in INPUT has its report checked",
			scenario: Scenario{
				Files: []File{cleanFile, badFile},
				Want:  map[string]Outcome{"clean.txt": {In: Input}, "bad.txt": {In: Input}},
			},
			state: state{input: []File{cleanFile, badFile}, reports: []datamodel.Report{entryOf("clean.txt", nil)}},
			want: []row{
				{name: "clean.txt", want: "input / clean", got: "input / clean", ok: true},
				{name: "bad.txt", want: "input / clean", got: "input / no report"},
				{name: "containers", want: "0", got: "0", ok: true},
			},
		},
		{
			name: "a file left in INPUT without report",
			scenario: Scenario{
				Files: []File{cleanFile, badFile, {Path: "moved.txt", Content: []byte("moved")}},
				Want: map[string]Outcome{
					"clean.txt": {In: Input, NoReport: true},
					"bad.txt":   {In: Input, NoReport: true},
					"moved.txt": {In: Input, NoReport: true},
				},
			},
			state: state{input: []File{cleanFile, badFile}, moved: []File{{Path: "moved.txt", Content: []byte("moved")}}, reports: []datamodel.Report{entryOf("bad.txt", detected)}},
			want: []row{
				{name: "clean.txt", want: "input / no report", got: "input / no report", ok: true},
				{name: "bad.txt", want: "input / no report", got: "input / malware:malware-detected"},
				{name: "moved.txt", want: "input / no report", got: "output / no report"},
				{name: "containers", want: "0", got: "0", ok: true},
			},
		},
		{
			name: "a copy or the dropped file delivered",
			scenario: Scenario{
				Files: []File{cleanFile, {Path: "moved.txt", Content: []byte("moved")}, {Path: "copy.txt", Content: []byte("copy")}, {Path: "same.txt", Content: []byte("same")}},
				Want: map[string]Outcome{
					"clean.txt": {Delivery: Copied},
					"moved.txt": {Delivery: SameFile},
					"copy.txt":  {Delivery: SameFile},
					"same.txt":  {Delivery: Copied},
				},
			},
			state: state{
				input:  []File{cleanFile, {Path: "copy.txt", Content: []byte("copy")}},
				output: []File{cleanFile, {Path: "copy.txt", Content: []byte("copy")}},
				moved:  []File{{Path: "moved.txt", Content: []byte("moved")}, {Path: "same.txt", Content: []byte("same")}},
			},
			want: []row{
				{name: "clean.txt", want: "copied", got: "copied", ok: true},
				{name: "moved.txt", want: "same file", got: "same file", ok: true},
				{name: "copy.txt", want: "same file", got: "copied"},
				{name: "same.txt", want: "copied", got: "same file"},
				{name: "containers", want: "0", got: "0", ok: true},
			},
		},
		{
			name: "the entries an Await saw are history",
			scenario: Scenario{
				Files: []File{cleanFile},
				Want:  map[string]Outcome{"clean.txt": {In: Output}},
			},
			state: state{
				output:   []File{cleanFile},
				reports:  []datamodel.Report{entryOf("clean.txt", func(e *datamodel.Report) { e.Error = "503" }), entryOf("clean.txt", nil)},
				consumed: map[string]int{"clean.txt": 1},
			},
			want: []row{
				{name: "clean.txt", want: "output / clean", got: "output / clean", ok: true},
				{name: "containers", want: "0", got: "0", ok: true},
			},
		},
		{
			name: "the report of a file held with an error",
			scenario: Scenario{
				Files: []File{cleanFile, badFile},
				Want:  map[string]Outcome{"clean.txt": {In: Input, Error: "damaged"}, "bad.txt": {In: Input, Error: "damaged"}},
			},
			state: state{
				input: []File{cleanFile, badFile},
				reports: []datamodel.Report{
					entryOf("clean.txt", func(e *datamodel.Report) { e.Error = "the archive is damaged" }),
					entryOf("bad.txt", func(e *datamodel.Report) { e.Error = "encrypted" }),
				},
			},
			want: []row{
				{name: "clean.txt", want: `input / clean error~"damaged"`, got: `input / clean error="the archive is damaged"`, ok: true},
				{name: "bad.txt", want: `input / clean error~"damaged"`, got: `input / clean error="encrypted"`},
				{name: "containers", want: "0", got: "0", ok: true},
			},
		},
		{
			name: "an error nobody wants",
			scenario: Scenario{
				Files: []File{cleanFile},
				Want:  map[string]Outcome{"clean.txt": {In: Output}},
			},
			state: state{output: []File{cleanFile}, reports: []datamodel.Report{entryOf("clean.txt", func(e *datamodel.Report) { e.Error = "move failed" })}},
			want: []row{
				{name: "clean.txt", want: "output / clean", got: `output / clean error="move failed"`},
				{name: "containers", want: "0", got: "0", ok: true},
			},
		},
		{
			name: "a lock report when the move is on",
			scenario: Scenario{
				Files: []File{badFile, {Path: "other.txt", Content: []byte("other"), Verdict: Malicious}},
				Want: map[string]Outcome{
					"bad.txt":   {In: Quarantine, Malware: datamodel.MalwareDetected},
					"other.txt": {In: Quarantine, Malware: datamodel.MalwareDetected},
				},
			},
			state: state{
				conf: moveOn, quarantine: []File{badFile, {Path: "other.txt", Content: []byte("other")}},
				reports:     []datamodel.Report{entryOf("bad.txt", detected), entryOf("other.txt", detected)},
				lockReports: []datamodel.Report{entryOf("bad.txt", detected)},
			},
			want: []row{
				{name: "bad.txt", want: "quarantine / malware:malware-detected / 1 lock report(s)", got: "quarantine / malware:malware-detected / 1 lock report(s)", ok: true},
				{name: "other.txt", want: "quarantine / malware:malware-detected / 1 lock report(s)", got: "quarantine / malware:malware-detected / 0 lock report(s)"},
				{name: "containers", want: "2", got: "2", ok: true},
			},
		},
		{
			name: "one lock report per quarantine",
			scenario: Scenario{
				Files: []File{badFile, {Path: "other.txt", Content: []byte("other"), Verdict: Malicious}},
				Want: map[string]Outcome{
					"bad.txt":   {In: Quarantine, Malware: datamodel.MalwareDetected},
					"other.txt": {In: Quarantine, Malware: datamodel.MalwareDetected},
				},
			},
			state: state{
				conf: moveOn, quarantine: []File{badFile, {Path: "other.txt", Content: []byte("other")}},
				reports: []datamodel.Report{
					entryOf("bad.txt", detected), entryOf("bad.txt", restoredMark), entryOf("bad.txt", detected),
					entryOf("other.txt", detected), entryOf("other.txt", restoredMark), entryOf("other.txt", detected),
				},
				lockReports: []datamodel.Report{entryOf("bad.txt", detected), entryOf("bad.txt", detected), entryOf("other.txt", detected)},
				consumed:    map[string]int{"bad.txt": 2, "other.txt": 2},
			},
			want: []row{
				{name: "bad.txt", want: "quarantine / malware:malware-detected / 2 lock report(s)", got: "quarantine / malware:malware-detected / 2 lock report(s)", ok: true},
				{name: "other.txt", want: "quarantine / malware:malware-detected / 2 lock report(s)", got: "quarantine / malware:malware-detected / 1 lock report(s)"},
				{name: "containers", want: "2", got: "2", ok: true},
			},
		},
		{
			name: "an awaited state with no newer entry is checked on the last entry",
			scenario: Scenario{
				Files: []File{cleanFile, badFile},
				Want:  map[string]Outcome{"clean.txt": {In: Output}, "bad.txt": {In: Quarantine, Malware: datamodel.MalwareDetected}},
			},
			state: state{
				output: []File{cleanFile}, quarantine: []File{badFile},
				reports:  []datamodel.Report{entryOf("clean.txt", nil), entryOf("bad.txt", func(e *datamodel.Report) { e.Error = "503" })},
				consumed: map[string]int{"clean.txt": 1, "bad.txt": 1},
			},
			want: []row{
				{name: "clean.txt", want: "output / clean", got: "output / clean", ok: true},
				{name: "bad.txt", want: "quarantine / malware:malware-detected", got: `quarantine / clean error="503"`},
				{name: "containers", want: "1", got: "1", ok: true},
			},
		},
		{
			name: "a name that is not UTF-8 is found by its report name",
			scenario: Scenario{
				Files: []File{{Path: "a\xff/x.txt", Content: []byte("x")}, {Path: "b\xff\xfe/bad.txt", Content: []byte("bad"), Verdict: Malicious}},
				Want: map[string]Outcome{
					"a\xff/x.txt":       {In: Output},
					"b\xff\xfe/bad.txt": {In: Quarantine, Malware: datamodel.MalwareDetected},
				},
			},
			state: state{
				conf: moveOn, output: []File{{Path: "a\xff/x.txt", Content: []byte("x")}}, quarantine: []File{{Path: "b\xff\xfe/bad.txt", Content: []byte("bad")}},
				reports:     []datamodel.Report{entryOf("a\xff/x.txt", nil), entryOf("b\xff\xfe/bad.txt", detected)},
				lockReports: []datamodel.Report{entryOf("b\xff\xfe/bad.txt", detected)},
			},
			want: []row{
				{name: "a\xff/x.txt", want: "output / clean", got: "output / clean", ok: true},
				{name: "b\xff\xfe/bad.txt", want: "quarantine / malware:malware-detected / 1 lock report(s)", got: "quarantine / malware:malware-detected / 1 lock report(s)", ok: true},
				{name: "containers", want: "1", got: "1", ok: true},
			},
		},
		{
			name: "the format of the container",
			scenario: Scenario{
				Files: []File{badFile},
				Want:  map[string]Outcome{"bad.txt": {In: Quarantine, Malware: datamodel.MalwareDetected, Container: Zip}},
			},
			state: state{quarantine: []File{badFile}, reports: []datamodel.Report{entryOf("bad.txt", detected)}},
			want: []row{
				{name: "bad.txt", want: "quarantine / malware:malware-detected / container zip", got: "quarantine / malware:malware-detected / container tar"},
				{name: "containers", want: "1", got: "1", ok: true},
			},
		},
		{
			name: "a restored file",
			scenario: Scenario{
				Files: []File{badFile, {Path: "again.bin", Content: []byte("again")}, {Path: "sub/third.bin", Content: []byte("third")}},
				Want: map[string]Outcome{
					"bad.txt":       {In: Output, Restored: true},
					"again.bin":     {In: Output, Restored: true},
					"sub/third.bin": {In: Output, Restored: true},
				},
			},
			state: state{
				output: []File{badFile, {Path: "again.bin", Content: []byte("again")}, {Path: "sub/third.bin", Content: []byte("third")}},
				zipped: []File{{Path: "again.bin", Content: []byte("again")}},
				temps:  []string{"sub/" + hcquarantine.TempPrefix + "x"},
				reports: []datamodel.Report{
					entryOf("bad.txt", detected),
					entryOf("bad.txt", restoredMark),
					entryOf("again.bin", nil),
					entryOf("sub/third.bin", restoredMark),
				},
				consumed: map[string]int{"bad.txt": 1},
			},
			want: []row{
				{name: "bad.txt", want: "output / restored / container removed", got: "output / not-analyzed:restored restored / container removed", ok: true},
				{name: "again.bin", want: "output / restored / container removed", got: "output / clean / container still there"},
				{name: "sub/third.bin", want: "output / restored / container removed", got: `output / not-analyzed:restored restored / temporary files [".gmhost-tmp-x"]`},
				{name: "containers", want: "0", got: "1"},
			},
		},
		{
			name: "what the service saw",
			scenario: Scenario{
				Files: []File{archive, cleanFile},
				Want: map[string]Outcome{
					"a.zip":         {SubmittedAs: []string{"a.zip"}, Submissions: 1},
					"a.zip/d/m.txt": {SubmittedAs: []string{"a.zip/d/m.txt"}, ServiceVerdict: Given},
					"clean.txt":     {Submissions: 2, ServiceVerdict: NotGiven},
				},
			},
			state: state{submitted: []File{{Path: "a.zip/d/m.txt", Content: []byte("a member")}, cleanFile}, given: []File{cleanFile}},
			want: []row{
				{name: "a.zip", want: `submitted as ["INPUT/tom/a.zip"] / 1 submission(s)`, got: `submitted as [] / 0 submission(s)`},
				{name: "a.zip/d/m.txt", want: `submitted as ["INPUT/tom/a.zip/d/m.txt"] / verdict given`, got: `submitted as ["INPUT/tom/a.zip/d/m.txt"] / verdict not given`},
				{name: "clean.txt", want: "2 submission(s) / verdict not given", got: "1 submission(s) / verdict given"},
				{name: "containers", want: "0", got: "0", ok: true},
			},
		},
		{
			name: "the members a report lists",
			scenario: Scenario{
				Files: []File{archive, cleanFile},
				Want: map[string]Outcome{
					"a.zip": {
						MaliciousMembers:   map[string]datamodel.MalwareReason{"a.exe": datamodel.FilteredFilePath},
						NotAnalyzedMembers: &MemberList{Reason: datamodel.NotAnalyzedExtractLimit, Count: 3, Includes: "word/document.xml"},
					},
					"clean.txt": {MaliciousMembers: map[string]datamodel.MalwareReason{"b.exe": datamodel.FilteredFilePath}, NotAnalyzedMembers: NoMembers()},
				},
			},
			state: state{reports: []datamodel.Report{
				entryOf("a.zip", func(e *datamodel.Report) {
					e.MaliciousExtractedFiles = []datamodel.ExtractedFile{{FileName: "x/a.exe", MalwareReason: datamodel.FilteredFilePath}}
					e.NotAnalyzedExtractedFiles = []datamodel.NotAnalyzedFile{{FileName: "d/word/document.xml", Reason: datamodel.NotAnalyzedExtractLimit}}
					e.NotAnalyzedExtractedCount = 3
				}),
				entryOf("clean.txt", func(e *datamodel.Report) {
					e.MaliciousExtractedFiles = []datamodel.ExtractedFile{{FileName: "in.zip", ExtractedFiles: []datamodel.ExtractedFile{{FileName: "in.zip/b.exe", MalwareReason: datamodel.FilteredFileType}}}}
					e.NotAnalyzedExtractedFiles = []datamodel.NotAnalyzedFile{{FileName: "c", Reason: datamodel.NotAnalyzedEncrypted}}
					e.NotAnalyzedExtractedCount = 1
				}),
			}},
			want: []row{
				{
					name: "a.zip", ok: true,
					want: `malicious members a.exe:filtered-filepath / members not analyzed extract-limit count=3 including "word/document.xml"`,
					got:  "malicious members x/a.exe:filtered-filepath / members not analyzed extract-limit count=3 listed=1",
				},
				{
					name: "clean.txt",
					want: "malicious members b.exe:filtered-filepath / no member not analyzed",
					got:  "malicious members in.zip: in.zip/b.exe:filtered-filetype / members not analyzed encrypted count=1 listed=1",
				},
				{name: "containers", want: "0", got: "0", ok: true},
			},
		},
		{
			name: "a check of every entry",
			scenario: Scenario{
				Files: []File{cleanFile},
				Want: map[string]Outcome{"clean.txt": {Entry: func(e datamodel.Report) string {
					if e.FileSize != 5 {
						return fmt.Sprintf("size %d", e.FileSize)
					}
					return ""
				}}},
			},
			state: state{reports: []datamodel.Report{entryOf("clean.txt", func(e *datamodel.Report) { e.FileSize = 5 }), entryOf("clean.txt", nil)}},
			want: []row{
				{name: "clean.txt", want: "entry check", got: "size 0"},
				{name: "containers", want: "0", got: "0", ok: true},
			},
		},
		{
			name: "the console, the session reports and the folders",
			scenario: Scenario{
				Files:               []File{cleanFile},
				Want:                map[string]Outcome{"clean.txt": {}},
				WantMitigations:     []string{"malware"},
				WantConsoleErrors:   []string{"host-config-rejected"},
				WantConsoleResolved: []string{},
				WantSessionReports:  2,
				WantGone:            []string{"deep", "kept"},
			},
			state: state{agent: true, reports: []datamodel.Report{entryOf("clean.txt", nil)}, dirs: []string{"kept"}},
			want: []row{
				{name: "clean.txt", ok: true},
				{name: "containers", want: "0", got: "0", ok: true},
				{name: "console mitigations", want: `["malware"]`, got: `[]`},
				{name: "console errors", want: `["host-config-rejected"] among them`, got: `[]`},
				{name: "console resolutions", want: `[] among them`, got: `[]`, ok: true},
				{name: "session reports", want: "2", got: "1"},
				{name: "deep", want: "gone", got: "gone", ok: true},
				{name: "kept", want: "gone", got: "still there"},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := newRun(t, tt.scenario, tt.state)
			got := r.rows(tt.scenario.Want, true)
			if len(got) != len(tt.want) {
				t.Fatalf("rows:\n%s\nwant %d rows", r.table(tt.scenario.Want, true), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("row %d:\n got  %+v\n want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestTable(t *testing.T) {
	many := Scenario{Want: map[string]Outcome{}}
	output := make([]File, 0, maxPassedRows)
	reports := make([]datamodel.Report, 0, maxPassedRows)
	for i := range maxPassedRows {
		f := File{Path: fmt.Sprintf("f%02d.txt", i), Content: []byte(strconv.Itoa(i))}
		many.Files = append(many.Files, f)
		many.Want[f.Path] = Outcome{In: Output}
		output = append(output, f)
		reports = append(reports, entryOf(f.Path, nil))
	}
	for _, tt := range []struct {
		name     string
		scenario Scenario
		state    state
		want     string
	}{
		{
			name: "every row",
			scenario: Scenario{
				Files: []File{cleanFile, badFile},
				Want:  map[string]Outcome{"clean.txt": {In: Output}, "bad.txt": {In: Quarantine, Malware: datamodel.MalwareDetected}},
			},
			state: state{output: []File{cleanFile, badFile}, reports: []datamodel.Report{entryOf("clean.txt", nil), entryOf("bad.txt", detected)}},
			want: "" +
				"file        want                                   got\n" +
				"clean.txt   output / clean                         output / clean                     ✓\n" +
				"bad.txt     quarantine / malware:malware-detected  output / malware:malware-detected  ✗\n" +
				"containers  1                                      0                                  ✗\n",
		},
		{
			name:     "past the limit, only the rows that differ",
			scenario: many,
			state:    state{output: output[1:], reports: reports},
			want: "" +
				"file     want            got\n" +
				"f00.txt  output / clean  nowhere / clean  ✗\n" +
				"(50 rows as wanted not shown)\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := newRun(t, tt.scenario, tt.state)
			if got := r.table(tt.scenario.Want, true); got != tt.want {
				t.Errorf("table:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}
