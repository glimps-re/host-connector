//go:build linux

package harness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"text/tabwriter"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	hcquarantine "github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
)

// Verdict is what the fake service answers for a file of a scenario.
type Verdict int

const (
	Clean Verdict = iota
	Malicious
	// MaliciousWithError is a detection with an analysis error beside it.
	MaliciousWithError
	// AnalysisError is an analysis error and no detection.
	AnalysisError
	// OtherSHA256 is a clean verdict whose result carries a SHA256 that is not
	// the one of the file.
	OtherSHA256
)

// Place is where a file of a scenario ends up.
type Place string

const (
	Input      Place = "input"
	Output     Place = "output"
	Quarantine Place = "quarantine"
	// nowhere is a file that left INPUT and is neither delivered nor
	// quarantined.
	nowhere Place = "nowhere"
)

// Format is the format of a quarantine container.
type Format string

const (
	Tar Format = "tar"
	Zip Format = "zip"
)

// Delivery tells whether the file in OUTPUT is a copy of the dropped file or
// the dropped file itself (the same inode).
type Delivery string

const (
	Copied   Delivery = "copied"
	SameFile Delivery = "same file"
)

// ServiceVerdict tells whether the service gave its verdict on a content.
type ServiceVerdict string

const (
	Given    ServiceVerdict = "given"
	NotGiven ServiceVerdict = "not given"
)

// File is a file a scenario adds below the owner folder of INPUT. Members are
// the members of an archive, with paths relative to it: their verdicts are
// programmed, and Want may name them as "<archive path>/<member path>".
type File struct {
	Path    string
	Content []byte
	Verdict Verdict
	Members []File
}

// MemberList is the list of the members of an archive a report says were not
// analyzed: every listed member has Reason, Count is the exact number of them
// (at least one when 0), and one listed name ends with Includes.
type MemberList struct {
	Reason   datamodel.NotAnalyzedReason
	Count    int
	Includes string
}

// NoMembers is a report that lists no member as not analyzed.
func NoMembers() *MemberList { return &MemberList{} }

// Outcome is the state of a file. The file must have report entries (by its
// INPUT path), and they must all carry exactly Malware and NotAnalyzed, and an
// error containing Error (no error when Error is empty). The entries an Await
// of the file already saw are not checked again: they are its history. An
// empty In checks no place and no report: the outcome of an archive member
// says only what the service saw of it. The other fields are checked when set.
type Outcome struct {
	In          Place
	Malware     datamodel.MalwareReason
	NotAnalyzed datamodel.NotAnalyzedReason
	Error       string
	// NoReport is a file without any report entry, in place of the entries
	// above. It is checked with the other files: with In Input, it must then
	// hold for NotDeliveredWindow.
	NoReport bool
	// Restored is a file delivered with the restored mark: its one entry is a
	// restored one, and its container is gone.
	Restored  bool
	Container Format
	Delivery  Delivery
	// SubmittedAs are the names the service was told, relative to INPUT/tom.
	SubmittedAs []string
	// Submissions is the exact number of submissions of the content.
	Submissions        int
	ServiceVerdict     ServiceVerdict
	MaliciousMembers   map[string]datamodel.MalwareReason
	NotAnalyzedMembers *MemberList
	// Entry checks every report entry, for what the fields above cannot say: it
	// returns what is wrong, or "".
	Entry func(datamodel.Report) string
}

// Scenario is a run of the connector told as its input (configuration, files
// and verdicts, then steps) and the state it must reach.
type Scenario struct {
	Agent   bool
	Timeout string
	Config  map[string]any
	Plugins map[string]map[string]any

	Files []File
	Steps []Step

	Want map[string]Outcome
	// WantMitigations are the reasons of the mitigation events the console
	// receives, in any order (agent mode only).
	WantMitigations []string
	// WantConsoleErrors and WantConsoleResolved are console event types that
	// must be among the errors and the resolutions the console received.
	WantConsoleErrors   []string
	WantConsoleResolved []string
	// WantSessionReports is the number of session reports of the owner, when
	// not 0.
	WantSessionReports int
	// WantGone are folders below INPUT/tom that must be removed.
	WantGone []string
	// WantRefused is a start the connector refuses: the reason in its log.
	WantRefused string
}

// Step is what happens during a run, after the files of the scenario are added.
type Step struct {
	files []File
	do    func(t *testing.T, r *run)
}

// AddFileToInput adds files to INPUT, or rewrites them.
func AddFileToInput(files ...File) Step {
	return Step{files: files, do: func(t *testing.T, r *run) {
		t.Helper()
		r.add(t, files)
	}}
}

// Await waits for a file to be in a state before the next step. The report
// entries it saw are then the history of the file: the later checks of the
// file look at the newer entries, or at the last one when there is none.
func Await(path string, o Outcome) Step {
	return Step{do: func(t *testing.T, r *run) {
		t.Helper()
		f, ok := r.files[path]
		if !ok {
			t.Fatalf("await %s, which the scenario has not added yet", path)
		}
		r.declare(f, o)
		r.wait(t, "await "+path, map[string]Outcome{path: o}, false)
		r.consumed[path] = len(r.observe()[reportName(r.inputPath(path))])
	}}
}

// AwaitDelivered waits for files to be in OUTPUT with their bytes, without
// looking at their reports.
func AwaitDelivered(paths ...string) Step {
	return Step{do: func(t *testing.T, r *run) {
		t.Helper()
		r.in.WaitFor(t, "the delivery of "+strings.Join(paths, ", "), func() bool {
			return !slices.ContainsFunc(paths, func(p string) bool { return !r.delivered(p) })
		})
	}}
}

// Restore restores a quarantined file through the console. Its answer must be
// empty when wantAckErr is, else contain it.
func Restore(path, wantAckErr string) Step {
	return Step{do: func(t *testing.T, r *run) {
		t.Helper()
		r.in.RestoreFile(t, r.inputPath(path), r.files[path].Content, wantAckErr)
	}}
}

// RestoreID asks the console to restore a container by its ID.
func RestoreID(id, wantAckErr string) Step {
	return Step{do: func(t *testing.T, r *run) {
		t.Helper()
		r.in.task(t, "restore", map[string]string{"id": id}, wantAckErr)
	}}
}

// UpdateConfig serves the configuration with change merged over it and pushes
// an update-config task.
func UpdateConfig(change map[string]any, wantAckErr string) Step {
	return Step{do: func(t *testing.T, r *run) {
		t.Helper()
		conf := r.in.WithConf(t, change)
		r.in.needConsole(t)
		r.in.Console.SetConfig(conf)
		r.in.task(t, "update-config", nil, wantAckErr)
		if wantAckErr == "" {
			r.in.conf = conf
			if !r.in.actionOn("quarantine") {
				r.in.Expect.QuarantineOff = true
			}
		}
	}}
}

// Task pushes a console task without content (stop, start).
func Task(action, wantAckErr string) Step {
	return Step{do: func(t *testing.T, r *run) {
		t.Helper()
		r.in.task(t, action, nil, wantAckErr)
	}}
}

// Restart stops the connector and starts it again with change merged over its
// configuration, and waits for it to watch again.
func Restart(change map[string]any) Step {
	return Step{do: func(t *testing.T, r *run) {
		t.Helper()
		r.in.Restart(t, change)
	}}
}

// ServiceDown makes the service answer status to the analyses.
func ServiceDown(status int) Step {
	return Step{do: func(_ *testing.T, r *run) { r.gm.FailWith(status) }}
}

// ServiceUp ends ServiceDown.
func ServiceUp() Step {
	return Step{do: func(_ *testing.T, r *run) { r.gm.FailWith(0) }}
}

// AwaitServiceFailure waits for the service to have failed a request.
func AwaitServiceFailure() Step {
	return Step{do: func(t *testing.T, r *run) {
		t.Helper()
		r.in.WaitFor(t, "a failure of the service", func() bool { return r.gm.Failed.Load() > 0 })
	}}
}

// AwaitConsoleError waits for the console to receive an error of this type.
func AwaitConsoleError(typ string) Step {
	return Step{do: func(t *testing.T, r *run) {
		t.Helper()
		r.in.needConsole(t)
		r.in.WaitFor(t, "the console error "+typ, func() bool { return slices.Contains(r.in.Console.ErrorTypes(), typ) })
	}}
}

// Stop stops the connector with SIGTERM; it must exit cleanly.
func Stop() Step {
	return Step{do: func(t *testing.T, r *run) {
		t.Helper()
		r.in.Stop(t)
	}}
}

// run is a scenario being played.
type run struct {
	s  Scenario
	in *Instance
	gm *gmalware.GMalware
	// files are the files added so far, by key (their path, or the path of a
	// member below its archive), in order of keys.
	files map[string]File
	keys  []string
	// final holds the last version of every file of the scenario.
	final map[string]File
	// consumed counts, by key, the report entries an Await already checked.
	consumed map[string]int
	// inodes holds the inode of every file the run wrote to INPUT, by key.
	inodes map[string]uint64
}

// Run plays a scenario and returns its instance once the wanted state is
// reached; a difference fails the test with the wanted and observed states.
func Run(t *testing.T, s Scenario) *Instance {
	t.Helper()
	t.Parallel()
	gm := gmalware.New(t)
	in := Start(t, gm, Options{Agent: s.Agent, Timeout: s.Timeout, Config: s.Config, Plugins: s.Plugins})
	if s.WantRefused != "" {
		if _, err := in.Wait(t, 20*time.Second); err == nil {
			t.Fatal("the connector started, want it refused")
		}
		if !in.LogHas(s.WantRefused) {
			t.Fatalf("the log does not give the reason %q:\n%s", s.WantRefused, in.Stderr.String())
		}
		return in
	}
	r := &run{s: s, in: in, gm: gm, files: map[string]File{}, final: map[string]File{}, consumed: map[string]int{}, inodes: map[string]uint64{}}
	r.validate(t)
	r.add(t, s.Files)
	for _, step := range s.Steps {
		step.do(t, r)
	}
	r.wait(t, "the final state", s.Want, true)
	return in
}

// validate checks that every top-level file has a wanted outcome and that
// every outcome names a file.
func (r *run) validate(t *testing.T) {
	t.Helper()
	known := map[string]bool{}
	var walk func(prefix string, files []File)
	walk = func(prefix string, files []File) {
		for _, f := range files {
			key := prefix + f.Path
			known[key] = true
			if prefix == "" {
				r.final[key] = f
			}
			walk(key+"/", f.Members)
		}
	}
	walk("", r.s.Files)
	for _, step := range r.s.Steps {
		walk("", step.files)
	}
	for key := range r.final {
		if _, ok := r.s.Want[key]; !ok {
			t.Fatalf("the scenario wants no outcome for %s", key)
		}
	}
	for key := range r.s.Want {
		if !known[key] {
			t.Fatalf("the scenario wants an outcome for %s, which it never adds", key)
		}
	}
}

func (r *run) add(t *testing.T, files []File) {
	t.Helper()
	for _, f := range files {
		r.remember("", f)
		r.declare(f, r.s.Want[f.Path])
	}
	for _, f := range files {
		r.inodes[f.Path] = inode(t, r.in.Drop(t, f.Path, f.Content))
	}
}

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Sys().(*syscall.Stat_t).Ino
}

// remember programs the verdicts of a file and its members and keeps them by
// key.
func (r *run) remember(prefix string, f File) {
	key := prefix + f.Path
	if _, seen := r.files[key]; !seen {
		r.keys = append(r.keys, key)
	}
	r.files[key] = f
	switch f.Verdict {
	case Malicious:
		r.gm.MarkMalicious(f.Content)
	case MaliciousWithError:
		r.gm.MarkMaliciousWithError(f.Content, "an engine crashed")
	case AnalysisError:
		r.gm.MarkAnalysisError(f.Content, "the analysis failed")
	case OtherSHA256:
		r.gm.AnswerOtherSHA256(f.Content)
	case Clean:
	}
	if len(f.Members) > 0 {
		r.in.Expect.Archive(f.Content, memberContents(f.Members)...)
	}
	for _, m := range f.Members {
		r.remember(key+"/", m)
	}
}

func memberContents(members []File) (contents [][]byte) {
	for _, m := range members {
		contents = append(contents, m.Content)
		contents = append(contents, memberContents(m.Members)...)
	}
	return contents
}

// declare tells the checker of OUTPUT what the outcome of a file implies.
func (r *run) declare(f File, o Outcome) {
	if o.Malware != "" && f.Verdict != Malicious && f.Verdict != MaliciousWithError {
		r.in.Expect.Flag(f.Content)
	}
	if o.NotAnalyzed != "" {
		r.in.Expect.Allow(o.NotAnalyzed)
	}
	if o.NotAnalyzedMembers != nil && o.NotAnalyzedMembers.Reason != "" {
		r.in.Expect.Allow(o.NotAnalyzedMembers.Reason)
	}
}

func (r *run) inputPath(key string) string {
	return filepath.Join(r.in.Input, "tom", key)
}

// wait waits for the files to reach their outcomes (and, when global, for the
// checks of the whole run). A file wanted in INPUT must then stay as wanted
// for NotDeliveredWindow.
func (r *run) wait(t *testing.T, what string, want map[string]Outcome, global bool) {
	t.Helper()
	if err := r.in.poll(time.Minute, r.in.exited, func() bool { return r.reached(want, global) }); err != nil {
		t.Fatalf("%s was not reached: %v:\n%s", what, err, r.table(want, global))
	}
	if !slices.ContainsFunc(slices.Collect(maps.Values(want)), func(o Outcome) bool { return o.In == Input }) {
		return
	}
	if r.in.poll(NotDeliveredWindow, r.in.exited, func() bool { return !r.reached(want, global) }) == nil {
		t.Fatalf("%s did not hold:\n%s", what, r.table(want, global))
	}
}

// row is a line of the table, or one check of a file: what is wanted and what
// is observed.
type row struct {
	name, want, got string
	ok              bool
}

func (r *run) reached(want map[string]Outcome, global bool) bool {
	for _, row := range r.rows(want, global) {
		if !row.ok {
			return false
		}
	}
	return true
}

// rows observes the run once.
func (r *run) rows(want map[string]Outcome, global bool) []row {
	byName := r.observe()
	var rows []row
	for _, key := range r.keys {
		o, ok := want[key]
		if !ok {
			continue
		}
		var w, g []string
		pass := true
		for _, c := range r.checks(key, o, byName) {
			w, g = append(w, c.want), append(g, c.got)
			pass = pass && c.ok
		}
		rows = append(rows, row{name: key, want: strings.Join(w, " / "), got: strings.Join(g, " / "), ok: pass})
	}
	if global {
		rows = append(rows, r.globalRows()...)
	}
	return rows
}

// observe returns the report entries, by file name.
func (r *run) observe() map[string][]datamodel.Report {
	byName := map[string][]datamodel.Report{}
	for _, entries := range ReadReports(r.in) {
		for _, e := range entries {
			byName[e.Filename] = append(byName[e.Filename], e)
		}
	}
	return byName
}

// checks are the checks of one file, in the order of the fields of Outcome.
func (r *run) checks(key string, o Outcome, byName map[string][]datamodel.Report) (cs []row) {
	f := r.files[key]
	path := r.inputPath(key)
	history := byName[reportName(path)]
	entries := history[min(r.consumed[key], len(history)):]
	if len(entries) == 0 && r.consumed[key] > 0 {
		entries = history[len(history)-1:]
	}
	if o.In != "" {
		place := r.place(key)
		c := same("", string(o.In), string(place))
		if place == Output && !r.delivered(key) {
			c.got, c.ok = "output (other bytes)", false
		}
		cs = append(cs, c)
	}
	switch {
	case o.Restored:
		cs = append(cs, row{want: "restored", got: describeEntries(entries), ok: restored(entries)})
	case o.NoReport:
		cs = append(cs, row{want: "no report", got: describeEntries(history), ok: len(history) == 0})
	case o.In != "" || o.Error != "":
		cs = append(cs, row{want: describeWantReport(o), got: describeEntries(entries), ok: reportMatches(o, entries)})
	}
	if o.In == Quarantine && r.in.actionOn("move") {
		want := 0
		for _, e := range history {
			if e.Malicious {
				want++
			}
		}
		cs = append(cs, same("", fmt.Sprintf("%d lock report(s)", want), fmt.Sprintf("%d lock report(s)", r.lockReports(path))))
	}
	if o.Container != "" {
		cs = append(cs, same("", "container "+string(o.Container), "container "+r.container(key)))
	}
	if o.Restored {
		cs = append(cs, same("", "container removed", r.restoreLeftovers(key)))
	}
	if o.Delivery != "" {
		cs = append(cs, same("", string(o.Delivery), r.delivery(key)))
	}
	if o.SubmittedAs != nil {
		names := r.gm.SubmittedNames(f.Content)
		want := make([]string, 0, len(o.SubmittedAs))
		for _, n := range o.SubmittedAs {
			want = append(want, r.inputPath(n))
		}
		cs = append(cs, row{want: fmt.Sprintf("submitted as %q", r.shortNames(want)), got: fmt.Sprintf("submitted as %q", r.shortNames(names)), ok: slices.Equal(names, want)})
	}
	if o.Submissions != 0 {
		cs = append(cs, same("", fmt.Sprintf("%d submission(s)", o.Submissions), fmt.Sprintf("%d submission(s)", len(r.gm.SubmittedNames(f.Content)))))
	}
	if o.ServiceVerdict != "" {
		got := NotGiven
		if _, given := r.gm.Given(gmalware.SHA256Hex(f.Content)); given {
			got = Given
		}
		cs = append(cs, same("", "verdict "+string(o.ServiceVerdict), "verdict "+string(got)))
	}
	if o.MaliciousMembers != nil {
		cs = append(cs, row{want: describeMalicious(o.MaliciousMembers), got: describeEntriesMalicious(entries), ok: maliciousMembersMatch(o.MaliciousMembers, entries)})
	}
	if o.NotAnalyzedMembers != nil {
		cs = append(cs, row{want: describeMemberList(o.NotAnalyzedMembers), got: describeEntriesNotAnalyzed(entries), ok: notAnalyzedMembersMatch(o.NotAnalyzedMembers, entries)})
	}
	if o.Entry != nil {
		cs = append(cs, same("", "entry check", entryProblems(o.Entry, entries)))
	}
	return cs
}

func (r *run) place(key string) Place {
	f := r.files[key]
	path := r.inputPath(key)
	switch {
	case exists(path):
		return Input
	case exists(filepath.Join(r.in.Output, "tom", key)):
		return Output
	case exists(r.lockPath(key, f.Content)):
		return Quarantine
	default:
		return nowhere
	}
}

func (r *run) lockPath(key string, content []byte) string {
	return r.in.LockOf(r.inputPath(key), content)
}

// delivered tells whether the file in OUTPUT has the bytes of the file.
func (r *run) delivered(key string) bool {
	got, err := os.ReadFile(filepath.Clean(filepath.Join(r.in.Output, "tom", key)))
	return err == nil && bytes.Equal(got, r.files[key].Content)
}

func (r *run) delivery(key string) string {
	info, err := os.Stat(filepath.Join(r.in.Output, "tom", key))
	switch {
	case err != nil:
		return "not delivered"
	case info.Sys().(*syscall.Stat_t).Ino == r.inodes[key]:
		return string(SameFile)
	default:
		return string(Copied)
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// actionOn tells whether an action is on in the current configuration.
func (in *Instance) actionOn(name string) bool {
	actions, _ := in.conf["actions"].(map[string]any)
	on, _ := actions[name].(bool)
	return on
}

// lockReports counts the lock reports in OUTPUT that are the report of the
// file at path.
func (r *run) lockReports(path string) (n int) {
	rel, err := filepath.Rel(r.in.Input, path)
	if err != nil {
		return 0
	}
	dir := filepath.Dir(filepath.Join(r.in.Output, rel))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if !isLockReport(e.Name()) {
			continue
		}
		report, err := decodeLockReport(filepath.Join(dir, e.Name()))
		if err == nil && report.Filename == reportName(path) {
			n++
		}
	}
	return n
}

// reportName is the file name a report gives to path: JSON replaces each byte
// that is not UTF-8 with U+FFFD.
func reportName(path string) string {
	return string([]rune(path))
}

func decodeLockReport(path string) (report datamodel.Report, err error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return report, err
	}
	err = json.Unmarshal(raw, &report)
	return report, err
}

// container says the format of the container of a file: zip, tar or none.
func (r *run) container(key string) string {
	raw, err := os.ReadFile(filepath.Clean(r.lockPath(key, r.files[key].Content)))
	switch {
	case err != nil:
		return "none"
	case bytes.HasPrefix(raw, []byte("PK\x03\x04")):
		return string(Zip)
	default:
		return string(Tar)
	}
}

// restoreLeftovers says what a restore left behind it: its container, or a
// temporary file in the folder of the file.
func (r *run) restoreLeftovers(key string) string {
	if exists(r.lockPath(key, r.files[key].Content)) {
		return "container still there"
	}
	temps, err := filepath.Glob(filepath.Join(filepath.Dir(r.inputPath(key)), hcquarantine.TempPrefix+"*"))
	if err != nil || len(temps) > 0 {
		names := make([]string, 0, len(temps))
		for _, tmp := range temps {
			names = append(names, filepath.Base(tmp))
		}
		return fmt.Sprintf("temporary files %q", names)
	}
	return "container removed"
}

// shortNames writes "INPUT" in place of the INPUT folder in the names, for the
// table: a name relative to INPUT/tom stays as it is.
func (r *run) shortNames(names []string) []string {
	prefix := r.in.Input + string(filepath.Separator)
	short := make([]string, 0, len(names))
	for _, n := range names {
		if rest, ok := strings.CutPrefix(n, prefix); ok {
			n = "INPUT/" + rest
		}
		short = append(short, n)
	}
	return short
}

func reportMatches(o Outcome, entries []datamodel.Report) bool {
	if len(entries) == 0 {
		return false
	}
	for _, e := range entries {
		if e.Malicious != (o.Malware != "") || e.MalwareReason != o.Malware || e.NotAnalyzedReason != o.NotAnalyzed {
			return false
		}
		if (o.Error == "") != (e.Error == "") || !strings.Contains(e.Error, o.Error) {
			return false
		}
	}
	return true
}

func restored(entries []datamodel.Report) bool {
	if len(entries) != 1 {
		return false
	}
	e := entries[0]
	return RestoredEntry(e) && !e.Malicious && e.Error == "" && e.NotAnalyzedReason == datamodel.NotAnalyzedRestored && len(e.NotAnalyzedExtractedFiles) == 0
}

// maliciousMember finds a malicious member by the suffix of its name.
func maliciousMember(members []datamodel.ExtractedFile, suffix string) (datamodel.ExtractedFile, bool) {
	for _, m := range flatten(members) {
		if m.FileName == suffix || strings.HasSuffix(m.FileName, "/"+suffix) {
			return m, true
		}
	}
	return datamodel.ExtractedFile{}, false
}

func flatten(members []datamodel.ExtractedFile) (all []datamodel.ExtractedFile) {
	for _, m := range members {
		all = append(all, m)
		all = append(all, flatten(m.ExtractedFiles)...)
	}
	return all
}

func maliciousMembersMatch(want map[string]datamodel.MalwareReason, entries []datamodel.Report) bool {
	if len(entries) == 0 {
		return false
	}
	for _, e := range entries {
		for suffix, reason := range want {
			m, ok := maliciousMember(e.MaliciousExtractedFiles, suffix)
			if !ok || m.MalwareReason != reason {
				return false
			}
		}
	}
	return true
}

func notAnalyzedMembersMatch(want *MemberList, entries []datamodel.Report) bool {
	if len(entries) == 0 {
		return false
	}
	for _, e := range entries {
		list := e.NotAnalyzedExtractedFiles
		if want.Reason == "" && want.Count == 0 && want.Includes == "" {
			if len(list) > 0 || e.NotAnalyzedExtractedCount != 0 {
				return false
			}
			continue
		}
		if len(list) == 0 || e.NotAnalyzedExtractedCount < len(list) {
			return false
		}
		if want.Count != 0 && e.NotAnalyzedExtractedCount != want.Count {
			return false
		}
		for _, m := range list {
			if want.Reason != "" && m.Reason != want.Reason {
				return false
			}
		}
		if want.Includes != "" && !slices.ContainsFunc(list, func(m datamodel.NotAnalyzedFile) bool { return strings.HasSuffix(m.FileName, want.Includes) }) {
			return false
		}
	}
	return true
}

func entryProblems(f func(datamodel.Report) string, entries []datamodel.Report) string {
	if len(entries) == 0 {
		return "no report"
	}
	var problems []string
	for _, e := range entries {
		if p := f(e); p != "" {
			problems = append(problems, p)
		}
	}
	if len(problems) == 0 {
		return "entry check"
	}
	return strings.Join(problems, "; ")
}

// globalRows are the checks of the whole run.
func (r *run) globalRows() (rows []row) {
	wanted := 0
	for key := range r.final {
		if r.s.Want[key].In == Quarantine {
			wanted++
		}
	}
	locks, _ := filepath.Glob(filepath.Join(r.in.Quarantine, "*.lock"))
	rows = append(rows, same("containers", strconv.Itoa(wanted), strconv.Itoa(len(locks))))
	if c := r.in.Console; c != nil {
		got := c.MitigationReasons()
		rows = append(rows, row{
			name: "console mitigations", want: fmt.Sprintf("%q", r.s.WantMitigations), got: fmt.Sprintf("%q", got),
			ok: slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(r.s.WantMitigations))),
		})
		if r.s.WantConsoleErrors != nil {
			rows = append(rows, containsRow("console errors", r.s.WantConsoleErrors, c.ErrorTypes()))
		}
		if r.s.WantConsoleResolved != nil {
			rows = append(rows, containsRow("console resolutions", r.s.WantConsoleResolved, c.ResolvedTypes()))
		}
	}
	if r.s.WantSessionReports != 0 {
		reports, _ := filepath.Glob(filepath.Join(r.in.Export, "tom", datamodel.SessionReportPrefix+"*"))
		rows = append(rows, same("session reports", strconv.Itoa(r.s.WantSessionReports), strconv.Itoa(len(reports))))
	}
	for _, dir := range r.s.WantGone {
		got := "gone"
		if exists(r.inputPath(dir)) {
			got = "still there"
		}
		rows = append(rows, same(dir, "gone", got))
	}
	return rows
}

func same(name, want, got string) row {
	return row{name: name, want: want, got: got, ok: want == got}
}

func containsRow(name string, want, got []string) row {
	ok := true
	for _, w := range want {
		ok = ok && slices.Contains(got, w)
	}
	return row{name: name, want: fmt.Sprintf("%q among them", want), got: fmt.Sprintf("%q", got), ok: ok}
}

// maxPassedRows is the number of rows past which the table shows only the
// rows that differ.
const maxPassedRows = 50

func (r *run) table(want map[string]Outcome, global bool) string {
	rows := r.rows(want, global)
	hidden := 0
	if len(rows) > maxPassedRows {
		rows = slices.DeleteFunc(rows, func(rw row) bool {
			if rw.ok {
				hidden++
			}
			return rw.ok
		})
	}
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "file\twant\tgot")
	for _, rw := range rows {
		mark := "✗"
		if rw.ok {
			mark = "✓"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", rw.name, rw.want, rw.got, mark)
	}
	_ = w.Flush()
	if hidden > 0 {
		_, _ = fmt.Fprintf(&b, "(%d rows as wanted not shown)\n", hidden)
	}
	return b.String()
}

func describeWantReport(o Outcome) string {
	s := reasons(o.Malware != "", o.Malware, o.NotAnalyzed)
	if o.Error != "" {
		s += " error~" + strconv.Quote(o.Error)
	}
	return s
}

func describeEntries(entries []datamodel.Report) string {
	if len(entries) == 0 {
		return "no report"
	}
	var rs []string
	for _, e := range entries {
		s := reasons(e.Malicious, e.MalwareReason, e.NotAnalyzedReason)
		if RestoredEntry(e) {
			s += " restored"
		}
		if e.Error != "" {
			s += " error=" + strconv.Quote(e.Error)
		}
		rs = append(rs, s)
	}
	return strings.Join(rs, ", ")
}

func reasons(malicious bool, malware datamodel.MalwareReason, notAnalyzed datamodel.NotAnalyzedReason) string {
	var parts []string
	if malicious {
		parts = append(parts, "malware:"+string(malware))
	}
	if notAnalyzed != "" {
		parts = append(parts, "not-analyzed:"+string(notAnalyzed))
	}
	if len(parts) == 0 {
		return "clean"
	}
	return strings.Join(parts, " ")
}

func describeMalicious(want map[string]datamodel.MalwareReason) string {
	parts := make([]string, 0, len(want))
	for _, suffix := range slices.Sorted(maps.Keys(want)) {
		parts = append(parts, suffix+":"+string(want[suffix]))
	}
	return "malicious members " + strings.Join(parts, " ")
}

func describeEntriesMalicious(entries []datamodel.Report) string {
	var parts []string
	for _, e := range entries {
		for _, m := range flatten(e.MaliciousExtractedFiles) {
			parts = append(parts, m.FileName+":"+string(m.MalwareReason))
		}
	}
	return "malicious members " + strings.Join(parts, " ")
}

func describeMemberList(m *MemberList) string {
	if *m == (MemberList{}) {
		return "no member not analyzed"
	}
	s := "members not analyzed"
	if m.Reason != "" {
		s += " " + string(m.Reason)
	}
	if m.Count != 0 {
		s += " count=" + strconv.Itoa(m.Count)
	}
	if m.Includes != "" {
		s += " including " + strconv.Quote(m.Includes)
	}
	return s
}

func describeEntriesNotAnalyzed(entries []datamodel.Report) string {
	var parts []string
	for _, e := range entries {
		if len(e.NotAnalyzedExtractedFiles) == 0 && e.NotAnalyzedExtractedCount == 0 {
			parts = append(parts, "no member not analyzed")
			continue
		}
		reasons := map[datamodel.NotAnalyzedReason]bool{}
		for _, m := range e.NotAnalyzedExtractedFiles {
			reasons[m.Reason] = true
		}
		rs := make([]string, 0, len(reasons))
		for reason := range reasons {
			rs = append(rs, string(reason))
		}
		slices.Sort(rs)
		parts = append(parts, fmt.Sprintf("members not analyzed %s count=%d listed=%d", strings.Join(rs, ","), e.NotAnalyzedExtractedCount, len(e.NotAnalyzedExtractedFiles)))
	}
	return strings.Join(parts, ", ")
}
