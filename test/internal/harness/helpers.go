//go:build linux

package harness

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
)

func Write(t *testing.T, path string, data []byte) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := root.Close(); e != nil {
			t.Logf("close: %v", e)
		}
	}()
	if err = root.WriteFile(filepath.Base(path), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func GlobOne(t *testing.T, pattern string) []string {
	t.Helper()
	m, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// ReportCount counts the session reports written to the exports.
func (in *Instance) ReportCount() int {
	m, err := filepath.Glob(filepath.Join(in.Export, "*", datamodel.SessionReportPrefix+"*"))
	if err != nil {
		return 0
	}
	return len(m)
}

// Gone tells whether nothing is at the path any more: any other failure of the
// stat means the file may still be there.
func (in *Instance) Gone(path string) bool {
	_, err := os.Stat(path)
	return errors.Is(err, fs.ErrNotExist)
}

// ReportsOf returns the report entries of the session reports for a content.
func (in *Instance) ReportsOf(t *testing.T, content []byte) []datamodel.Report {
	t.Helper()
	reports, problems := ReadSessionReports(in.Export)
	if len(problems) != 0 {
		t.Fatalf("the session reports are unreadable: %v", problems)
	}
	return reports[gmalware.SHA256Hex(content)]
}

// Create makes a sparse file of the size below the owner folder of INPUT.
func (in *Instance) Create(t *testing.T, rel string, size int64) string {
	t.Helper()
	path := filepath.Join(in.Input, "tom", rel)
	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// WithConf returns a copy of the configuration of the run with the keys of
// change merged over it.
func (in *Instance) WithConf(t *testing.T, change map[string]any) map[string]any {
	t.Helper()
	return MergeMaps(cloneMap(t, in.conf), change)
}

// OutputHas tells whether a file with this content is delivered in OUTPUT: the
// staging folder of a copy in progress does not count.
func (in *Instance) OutputHas(t *testing.T, content []byte) bool {
	t.Helper()
	files, problems := listEntries(in.Output)
	if len(problems) != 0 {
		t.Fatalf("OUTPUT is unreadable: %v", problems)
	}
	for _, f := range files {
		if strings.Contains(f, string(filepath.Separator)+".gmhost-staging"+string(filepath.Separator)) {
			continue
		}
		sum, _, err := fileDigest(f)
		if err != nil {
			t.Fatal(err)
		}
		if sum == gmalware.SHA256Hex(content) {
			return true
		}
	}
	return false
}

// MonitoringStarted is the log line of a connector that is watching.
const MonitoringStarted = "monitoring successfully completed"

func (in *Instance) WaitMonitoring(t *testing.T) {
	t.Helper()
	in.WaitFor(t, "the monitoring to start", func() bool { return in.LogHas(MonitoringStarted) })
}

// Restart stops the connector with SIGTERM and starts it again on the same
// folders and quarantine, with change merged over its configuration, and waits
// for it to watch again. The registry of the quarantine is in memory, so the
// new run does not know what the previous one quarantined.
func (in *Instance) Restart(t *testing.T, change map[string]any) {
	t.Helper()
	in.Stop(t)
	if err := in.killGroup(); err != nil {
		t.Fatalf("the processes of the stopped connector: %v", err)
	}
	// The request for tasks of the dead process is still waiting in the fake
	// console, and would answer a poll later: it must be over before a task is
	// pushed.
	if in.Console != nil {
		if err := in.poll(time.Minute, nil, func() bool { return in.Console.PollsInFlight() == 0 }); err != nil {
			t.Fatalf("%v while waiting for the polls of the stopped process to end", err)
		}
	}
	conf := in.WithConf(t, change)
	in.conf = conf
	writeJSON(t, filepath.Join(in.Root, "config.yml"), conf)
	if in.Console != nil {
		in.Console.SetConfig(conf)
	}
	in.relaunch(t)
}

// relaunch starts the stopped connector again and waits for it to log that it
// watches more times than before.
func (in *Instance) relaunch(t *testing.T) {
	t.Helper()
	before := strings.Count(in.Stderr.String(), MonitoringStarted)
	in.launch(t, in.bin, in.args)
	in.WaitFor(t, "the monitoring to start again", func() bool { return strings.Count(in.Stderr.String(), MonitoringStarted) > before })
}

// NotDeliveredWindow is how long a file that must stay in INPUT is watched.
const NotDeliveredWindow = 12 * time.Second

// StaysInInput waits until the connector has looked at the file (the log names
// its path), then watches OUTPUT for the window: the file must never be
// delivered and must still be in INPUT.
func (in *Instance) StaysInInput(t *testing.T, path string, content []byte) {
	t.Helper()
	in.WaitFor(t, "the connector to look at "+filepath.Base(path), func() bool { return in.LogHas(path) })
	if in.poll(NotDeliveredWindow, in.exited, func() bool { return in.OutputHas(t, content) }) == nil {
		t.Fatalf("%s was delivered", filepath.Base(path))
	}
	if in.Gone(path) {
		t.Errorf("%s left INPUT", filepath.Base(path))
	}
}

// PathFilter is the filepath_filter section of the configuration.
func PathFilter(forbidden, skipped []string) map[string]any {
	return map[string]any{"filepath_filter": map[string]any{"forbidden_paths": forbidden, "skipped_paths": skipped}}
}

// CrashAndRestart kills the connector without warning, as a crash does, starts
// it again on the same folders, and waits for it to watch again.
func (in *Instance) CrashAndRestart(t *testing.T) {
	t.Helper()
	if err := in.killGroup(); err != nil {
		t.Fatal(err)
	}
	<-in.exited
	in.relaunch(t)
}

// NamesOf waits until the fake service has been sent the content, and returns
// the names it was sent under.
func (in *Instance) NamesOf(t *testing.T, content []byte) []string {
	t.Helper()
	in.WaitFor(t, "the content to be submitted to the service", func() bool { return len(in.gm.SubmittedNames(content)) > 0 })
	return in.gm.SubmittedNames(content)
}

// ReadReports reads the session reports, tolerating one being written.
func ReadReports(in *Instance) map[string][]datamodel.Report {
	reports, _ := ReadSessionReports(in.Export)
	return reports
}
