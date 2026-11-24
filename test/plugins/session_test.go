//go:build linux && (e2e || e2e_plugins)

package plugins

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// P17: the folders a delivered file leaves empty in INPUT are removed once the
// session report is written.
func TestE2E_emptyFoldersRemoved(t *testing.T) {
	harness.Run(t, harness.Scenario{
		Plugins: map[string]map[string]any{"session": {"remove_empty_dirs": true}},
		Files:   []harness.File{{Path: "deep/er/a.txt", Content: []byte("in a subfolder")}},
		Want: map[string]harness.Outcome{
			"deep/er/a.txt": {In: harness.Output},
		},
		WantGone: []string{"deep"},
	})
}

// P3: a session that is closed gets its report, and the files that come later
// open a new session with its own report.
func TestE2E_sessionsCloseAndReopen(t *testing.T) {
	first, second := []byte("content of the first session"), []byte("content of the second session")
	in := harness.Run(t, harness.Scenario{
		Plugins: map[string]map[string]any{"session": {"delay": "2s"}},
		Files:   []harness.File{{Path: "one.txt", Content: first}},
		Steps: []harness.Step{
			harness.Await("one.txt", harness.Outcome{In: harness.Output}),
			harness.AddFileToInput(harness.File{Path: "two.txt", Content: second}),
		},
		Want: map[string]harness.Outcome{
			"one.txt": {In: harness.Output},
			"two.txt": {In: harness.Output},
		},
		WantSessionReports: 2,
	})
	for name, content := range map[string][]byte{"one.txt": first, "two.txt": second} {
		if got := in.ReportsOf(t, content); len(got) != 1 {
			t.Errorf("entries for %s = %d, want 1", name, len(got))
		}
	}
}

// spoolFiles lists the spool files of the open sessions.
func spoolFiles(t *testing.T, in *harness.Instance) []string {
	t.Helper()
	return harness.GlobOne(t, filepath.Join(in.Work, "gmhost-*", datamodel.SessionSpoolDir, "*"+datamodel.SessionSpoolExt))
}

// T20b: the reports of an open session wait on disk, in a private file; a
// session that has been open for max_duration is closed at once whatever its
// activity, with its report, and the next deposit opens a new session.
func TestE2E_aSessionIsClosedAtMaxDuration(t *testing.T) {
	gm := gmalware.New(t, false)
	in := harness.Start(t, gm, harness.Options{Plugins: map[string]map[string]any{"session": {"delay": "1h", "max_duration": "5s"}}})
	first, second := []byte("deposited in the first session"), []byte("deposited in the second session")
	in.Drop(t, "one.txt", first)
	var spool string
	in.WaitFor(t, "the spool of the open session", func() bool {
		files := spoolFiles(t, in)
		if len(files) != 1 {
			return false
		}
		spool = files[0]
		return true
	})
	info, err := os.Stat(spool)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the spool has the mode %o, want 600", mode)
	}
	if in.ReportCount() != 0 {
		t.Error("a session report was written before the session closed")
	}
	in.WaitFor(t, "the first session to be closed by max_duration", func() bool { return in.ReportCount() == 1 })
	if left := spoolFiles(t, in); len(left) != 0 {
		t.Errorf("spools left after the report: %v", left)
	}
	in.Drop(t, "two.txt", second)
	in.WaitFor(t, "the second session report", func() bool { return in.ReportCount() == 2 })
	if got := in.ReportsOf(t, first); len(got) != 1 {
		t.Errorf("entries for the first file = %d, want 1", len(got))
	}
	if got := in.ReportsOf(t, second); len(got) != 1 {
		t.Errorf("entries for the second file = %d, want 1", len(got))
	}
}

// T20b: a session whose reports reach max_spool_size (at least 1 MiB) is closed
// at once (that is the minimum the key accepts) and the next deposits open another: many reports in one run make
// several session reports, and not one report is lost.
func TestE2E_aSessionIsClosedAtMaxSpoolSize(t *testing.T) {
	long := strings.Repeat("n", 180)
	files := make([]harness.File, 0, 3000)
	paths := make([]string, 0, 3000)
	want := map[string]harness.Outcome{}
	for i := range 3000 {
		f := harness.File{Path: fmt.Sprintf("d%d/%s%05d.txt", i%20, long, i), Content: []byte(fmt.Sprintf("file number %d", i))}
		files = append(files, f)
		paths = append(paths, f.Path)
		want[f.Path] = harness.Outcome{In: harness.Output}
	}
	harness.Run(t, harness.Scenario{
		Config:  map[string]any{"workers": 8},
		Plugins: map[string]map[string]any{"session": {"delay": "1h", "max_spool_size": "1MiB"}},
		Steps: []harness.Step{
			harness.AddFileToInput(files...),
			harness.AwaitDelivered(paths...),
			harness.Stop(),
		},
		Want:               want,
		WantSessionReports: 2,
	})
}

// T20b: the spool of a session open when the connector crashed is not
// recovered: the next start removes it, with a warning that counts the session
// reports lost, and the work directory of the dead run goes with it.
func TestE2E_theSpoolOfACrashedRunIsRemovedWithAWarning(t *testing.T) {
	gm := gmalware.New(t, false)
	in := harness.Start(t, gm, harness.Options{Plugins: map[string]map[string]any{"session": {"delay": "1h"}}})
	content := []byte("deposited before the crash")
	in.Expect.CrashLost(content)
	in.Drop(t, "a.txt", content)
	in.WaitFor(t, "the delivery", func() bool { return in.InOutput("a.txt") })
	in.WaitFor(t, "the spool of the open session", func() bool { return len(spoolFiles(t, in)) == 1 })
	oldDirs := harness.GlobOne(t, filepath.Join(in.Work, "gmhost-*"))
	before := strings.Count(in.Stderr.String(), harness.MonitoringStarted)
	in.CrashAndRestart(t)
	in.WaitFor(t, "the connector to be back", func() bool { return strings.Count(in.Stderr.String(), harness.MonitoringStarted) > before })
	if !in.LogHas("1 session report(s) of a previous run were lost (crash)") {
		t.Error("the log does not warn that one session report was lost")
	}
	for _, dir := range oldDirs {
		if !in.Gone(dir) {
			t.Errorf("the work directory of the crashed run is still there: %s", dir)
		}
	}
	if left := spoolFiles(t, in); len(left) != 0 {
		t.Errorf("spools left: %v", left)
	}
}

// A SIGTERM with a session that holds a processed file: its report is written
// by the same path as the order of the console.
func TestShutdown_sigtermWritesTheReportOfAnOpenSession(t *testing.T) {
	g := gmalware.New(t, false)
	in := harness.Start(t, g, harness.Options{Plugins: map[string]map[string]any{"session": {"delay": "1h"}}})
	in.Drop(t, "a.txt", []byte("some content to analyze"))
	in.WaitFor(t, "the file to be delivered", func() bool { return in.InOutput("a.txt") })
	in.Signal(t, syscall.SIGTERM)
	if _, err := in.Wait(t, 6*time.Second); err != nil {
		t.Errorf("exit = %v, want code 0; log:\n%s", err, in.Stderr.String())
	}
	reports := harness.GlobOne(t, filepath.Join(in.Export, "tom", "*"))
	if len(reports) != 1 {
		t.Fatalf("reports = %v, want one; log:\n%s", reports, in.Stderr.String())
	}
	content, err := os.ReadFile(filepath.Clean(reports[0]))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "a.txt") {
		t.Errorf("the report does not mention the file:\n%s", content)
	}
}

// dropAs writes a file in INPUT below the owner folder of user.
func dropAs(t *testing.T, in *harness.Instance, user, rel string, content []byte) string {
	t.Helper()
	path := filepath.Join(in.Input, user, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	harness.Write(t, path, content)
	return path
}

// reportFiles lists the session reports of user.
func reportFiles(t *testing.T, in *harness.Instance, user string) []string {
	t.Helper()
	return harness.GlobOne(t, filepath.Join(in.Export, user, datamodel.SessionReportPrefix+"*"))
}

// entriesOf returns the entries of the session reports of user.
func entriesOf(t *testing.T, in *harness.Instance, user string) []datamodel.Report {
	t.Helper()
	reports, problems := harness.ReadSessionReports(filepath.Join(in.Export, user))
	if len(problems) != 0 {
		t.Fatalf("the session reports of %s are unreadable: %v", user, problems)
	}
	var all []datamodel.Report
	for _, entries := range reports {
		all = append(all, entries...)
	}
	return all
}

// T20a: a deposit of several hundred small files (a .git folder) split by a slow
// analysis of someone else's file, with the only worker saturated, is one
// session and one report: not one per burst, not one per file.
func TestE2E_aDepositOfSeveralHundredFilesBehindASaturatedWorkerIsOneSessionAndOneReport(t *testing.T) {
	tests := []struct {
		name string
		half int
		slow time.Duration
	}{
		{name: "150 files before the slow analysis and 150 during it", half: 150, slow: 8 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := gmalware.New(t, false)
			slow := []byte("jerry slow")
			gm.DelayResultOf(slow, tt.slow)
			in := harness.Start(t, gm, harness.Options{Config: map[string]any{"workers": 1}})
			for i := range tt.half {
				in.Drop(t, fmt.Sprintf(".git/objects/%02x/a%03d", i%256, i), []byte(fmt.Sprintf("tom blob %d", i)))
			}
			time.Sleep(300 * time.Millisecond)
			dropAs(t, in, "jerry", "slow.txt", slow)
			in.WaitFor(t, "the slow analysis of Jerry to hold the worker", func() bool { return len(gm.SubmittedNames(slow)) > 0 })
			for i := tt.half; i < 2*tt.half; i++ {
				in.Drop(t, fmt.Sprintf(".git/objects/%02x/b%03d", i%256, i), []byte(fmt.Sprintf("tom blob %d", i)))
			}

			in.WaitFor(t, "the report of Tom", func() bool { return len(reportFiles(t, in, "tom")) >= 1 })
			time.Sleep(2 * time.Second)
			files := reportFiles(t, in, "tom")
			if len(files) != 1 {
				t.Fatalf("Tom has %d reports %v, want one session and one report", len(files), files)
			}
			if got := len(entriesOf(t, in, "tom")); got != 2*tt.half {
				t.Errorf("the report has %d files, want %d", got, 2*tt.half)
			}
		})
	}
}

// T20a: a file waiting for a worker that is deleted, rewritten, or replaced by a
// refused one (a link, an empty file) before it is taken must not hold the
// session of its owner: the session closes after the delay and a report is
// written.
func TestE2E_aPendingFileThatChangesBeforeBeingTakenNeverBlocksTheSession(t *testing.T) {
	tests := []struct {
		name   string
		change func(t *testing.T, in *harness.Instance, p string)
	}{
		{"deleted", func(t *testing.T, _ *harness.Instance, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
		}},
		{"rewritten", func(t *testing.T, _ *harness.Instance, p string) {
			harness.Write(t, p, []byte("tom rewritten content"))
		}},
		{"replaced by a link", func(t *testing.T, in *harness.Instance, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(in.Input, "tom", "1.txt"), p); err != nil {
				t.Fatal(err)
			}
		}},
		{"emptied", func(t *testing.T, _ *harness.Instance, p string) {
			if err := os.Truncate(p, 0); err != nil {
				t.Fatal(err)
			}
		}},
		{"deleted then recreated", func(t *testing.T, _ *harness.Instance, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			time.Sleep(30 * time.Millisecond)
			harness.Write(t, p, []byte("tom recreated"))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := gmalware.New(t, false)
			slow := []byte("jerry slow")
			gm.DelayResultOf(slow, 10*time.Second)
			in := harness.Start(t, gm, harness.Options{Config: map[string]any{"workers": 1}})
			in.Drop(t, "1.txt", []byte("tom first"))
			in.WaitFor(t, "the session of Tom", func() bool { return len(spoolFiles(t, in)) == 1 })
			dropAs(t, in, "jerry", "slow.txt", slow)
			in.WaitFor(t, "the worker to be held", func() bool { return len(gm.SubmittedNames(slow)) > 0 })
			p := in.Drop(t, "2.txt", []byte("tom second"))
			time.Sleep(150 * time.Millisecond)
			tt.change(t, in, p)

			in.WaitFor(t, "the session of Tom to be closed", func() bool {
				return len(reportFiles(t, in, "tom")) >= 1
			})
			if len(entriesOf(t, in, "tom")) == 0 {
				t.Error("the reports of Tom are empty")
			}
		})
	}
}

// T20a: the queue is saturated for longer than inflight_timeout: the session of
// Tom is closed while files of its folder still wait, with a Warn that gives
// their number, and the files that waited open a new session with their own
// report: none is lost.
func TestE2E_aQueueSaturatedBeyondTheInflightTimeoutClosesTheSessionWithAWarn(t *testing.T) {
	tests := []struct {
		name     string
		inflight string
		slow     time.Duration
	}{
		{name: "a 3 s inflight timeout behind a 20 s analysis", inflight: "3s", slow: 20 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := gmalware.New(t, false)
			slow := []byte("jerry slow")
			gm.DelayResultOf(slow, tt.slow)
			in := harness.Start(t, gm, harness.Options{
				Config:  map[string]any{"workers": 1},
				Plugins: map[string]map[string]any{"session": {"delay": "1s", "inflight_timeout": tt.inflight}},
			})
			in.Drop(t, "1.txt", []byte("tom first"))
			in.WaitFor(t, "the session of Tom", func() bool { return len(spoolFiles(t, in)) == 1 })
			dropAs(t, in, "jerry", "slow.txt", slow)
			in.WaitFor(t, "the worker to be held", func() bool { return len(gm.SubmittedNames(slow)) > 0 })
			in.Drop(t, "2.txt", []byte("tom second"))
			in.Drop(t, "3.txt", []byte("tom third"))

			in.WaitFor(t, "the first report of Tom", func() bool { return len(reportFiles(t, in, "tom")) >= 1 })
			if _, done := gm.Given(gmalware.SHA256Hex(slow)); done {
				t.Fatal("the slow analysis ended before the session was closed: the saturation was not held long enough")
			}
			if !regexp.MustCompile(`"level":"WARN".*"pending":[1-9]`).MatchString(in.Stderr.String()) {
				t.Errorf("no Warn with the number of waiting files in the logs:\n%s", in.Stderr.String())
			}
			in.WaitFor(t, "the three files of Tom to be in a report", func() bool { return len(entriesOf(t, in, "tom")) >= 3 })
			seen := map[string]int{}
			for _, e := range entriesOf(t, in, "tom") {
				seen[filepath.Base(e.Filename)]++
			}
			for _, name := range []string{"1.txt", "2.txt", "3.txt"} {
				if seen[name] != 1 {
					t.Errorf("%s appears %d times in the reports of Tom %v, want once", name, seen[name], seen)
				}
			}
		})
	}
}
