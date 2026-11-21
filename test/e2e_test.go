//go:build linux && e2e

// The end-to-end suite runs the real binary against a fake GLIMPS Malware
// Detect and a fake console. It is not part of `go test ./...`:
//
//	go test -tags e2e ./test/...
//	golangci-lint run --build-tags e2e ./test/...
//
// It needs the Go toolchain (the binary and the plugins are built once). The
// scenarios that need Chrome or the embedded 7-Zip skip with a message when
// they are absent. Every scenario ends with the OUTPUT invariant, which also
// runs when the scenario fails early.

package test

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	hcquarantine "github.com/glimps-re/host-connector/pkg/quarantine"
)

// Smoke test of the whole harness: a clean file is delivered, a malicious one
// is quarantined under its SHA256 and leaves INPUT, a detection report stands
// in OUTPUT, and the invariant holds.
func TestE2E_cleanDeliveredMaliciousQuarantined(t *testing.T) {
	gm := newGMalware(t, false)
	bad := []byte("this content is a malware for the fake service")
	gm.MarkMalicious(bad)
	in := startInstance(t, gm, options{})
	in.drop(t, "clean.txt", []byte("some harmless content"))
	badPath := in.drop(t, "bad.txt", bad)
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	if !in.inOutput("clean.txt") {
		t.Errorf("clean.txt was not delivered; log:\n%s", in.stderr.String())
	}
	if in.inOutput("bad.txt") {
		t.Error("the malware reached OUTPUT")
	}
	if _, err := os.Stat(badPath); !os.IsNotExist(err) {
		t.Errorf("the malware is still in INPUT: %v", err)
	}
	lock := filepath.Join(in.quarantine, hcquarantine.ComputeCacheID(badPath, sha256Hex(bad))+".lock")
	if _, err := os.Stat(lock); err != nil {
		t.Errorf("the malware is not quarantined as %s: %v", filepath.Base(lock), err)
	}
	if m := globOne(t, filepath.Join(in.quarantine, "*")); len(m) != 1 {
		t.Errorf("quarantine = %v, want only the malware", m)
	}
	if m := globOne(t, filepath.Join(in.output, "tom", "bad.txt-lockreport*.json")); len(m) != 1 {
		t.Errorf("detection reports = %v, want one", m)
	}
}

// While the service is down nothing is delivered and nothing is lost: once it
// answers again the file is analyzed and delivered.
func TestE2E_gmalwareOutageThenRecovery(t *testing.T) {
	gm := newGMalware(t, false)
	gm.FailWith(503)
	in := startInstance(t, gm, options{config: map[string]any{"monitoring": map[string]any{"period": "2s"}}})
	path := in.drop(t, "a.txt", []byte("content waiting for the service"))
	in.waitFor(t, "the connector to meet the outage", func() bool { return gm.failed.Load() > 0 })
	in.waitFor(t, "the failure to be reported", func() bool { return in.logHas("could not analyze file") })
	if in.inOutput("a.txt") {
		t.Error("a file was delivered without analysis during the outage")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the file left INPUT during the outage: %v", err)
	}
	gm.FailWith(0)
	in.waitFor(t, "the delivery after the recovery", func() bool { return in.inOutput("a.txt") })
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
}

// The console drives the agent: Stop and Start are executed and acknowledged
// without error, and files are analyzed again after Start.
func TestE2E_consoleStopThenStart(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{agent: true})
	in.drop(t, "first.txt", []byte("first content"))
	in.waitFor(t, "the first delivery", func() bool { return in.inOutput("first.txt") })
	for _, action := range []string{"stop", "start"} {
		if msg := in.console.WaitAck(t, in.console.Push(t, action, nil)); msg != "" {
			t.Fatalf("%s acknowledged with the error %q", action, msg)
		}
	}
	in.drop(t, "second.txt", []byte("second content"))
	in.waitFor(t, "the delivery after the restart", func() bool { return in.inOutput("second.txt") })
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
}

// reportCount counts the session reports written to the exports.
func (in *instance) reportCount() int {
	m, err := filepath.Glob(filepath.Join(in.export, "*", datamodel.SessionReportPrefix+"*"))
	if err != nil {
		return 0
	}
	return len(m)
}

// gone tells whether nothing is at the path any more: any other failure of the
// stat means the file may still be there.
func (in *instance) gone(path string) bool {
	_, err := os.Stat(path)
	return errors.Is(err, fs.ErrNotExist)
}

// reportsOf returns the report entries of the session reports for a content.
func (in *instance) reportsOf(t *testing.T, content []byte) []datamodel.Report {
	t.Helper()
	reports, problems := readSessionReports(in.export)
	if len(problems) != 0 {
		t.Fatalf("the session reports are unreadable: %v", problems)
	}
	return reports[sha256Hex(content)]
}

// create makes a sparse file of the size below the owner folder of INPUT.
func (in *instance) create(t *testing.T, rel string, size int64) string {
	t.Helper()
	path := filepath.Join(in.input, "tom", rel)
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

// P6: a file delivered under a name already taken in OUTPUT never overwrites
// it, with a copy or a rename: both contents are delivered, the second under
// another name that the report names. The second file is dropped once the
// first one left INPUT, so the scenario is a conflict in OUTPUT and not a
// rewrite in INPUT.
func TestE2E_destinationConflictKeepsBoth(t *testing.T) {
	for _, mode := range []string{"copy", "rename"} {
		t.Run(mode, func(t *testing.T) {
			gm := newGMalware(t, false)
			in := startInstance(t, gm, options{config: map[string]any{
				"move":                map[string]any{"mode": mode},
				"unanalyzable_policy": map[string]any{"empty": "skip"},
			}})
			first, second := []byte("first content"), []byte("second content, same name")
			firstPath := in.drop(t, "a.txt", first)
			in.waitFor(t, "the first delivery", func() bool { return in.inOutput("a.txt") })
			in.waitFor(t, "the first file to leave INPUT", func() bool { return in.gone(firstPath) })
			secondPath := in.drop(t, "a.txt", second)
			in.waitFor(t, "the second file to leave INPUT", func() bool { return in.gone(secondPath) })
			delivered := globOne(t, filepath.Join(in.output, "tom", "*"))
			if len(delivered) != 2 {
				t.Fatalf("OUTPUT = %v, want both files", delivered)
			}
			got, err := os.ReadFile(filepath.Join(in.output, "tom", "a.txt"))
			if err != nil || !bytes.Equal(got, first) {
				t.Errorf("a.txt in OUTPUT = %q, %v; want the first content untouched", got, err)
			}
			in.waitFor(t, "the report to name the conflict", func() bool {
				return slices.ContainsFunc(in.reportsOf(t, second), func(e datamodel.Report) bool { return e.MoveConflictOf != "" })
			})
		})
	}
}

// inotifyWatches counts the inotify watches the process holds.
func inotifyWatches(pid int) int {
	fds, err := filepath.Glob(filepath.Join("/proc", strconv.Itoa(pid), "fdinfo", "*"))
	if err != nil {
		return 0
	}
	n := 0
	for _, fd := range fds {
		raw, err := os.ReadFile(filepath.Clean(fd))
		if err == nil {
			n += strings.Count(string(raw), "inotify wd:")
		}
	}
	return n
}

// P11: with the filesystem watcher disabled the process holds no inotify watch
// and the periodic rescan finds and delivers the files. By default it watches,
// and the rescan is so far away (1 h) that only the watcher can deliver.
func TestE2E_watcherSwitch(t *testing.T) {
	for _, disabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("disabled=%v", disabled), func(t *testing.T) {
			period := "1h"
			if disabled {
				period = "2s"
			}
			gm := newGMalware(t, false)
			in := startInstance(t, gm, options{config: map[string]any{
				"monitoring": map[string]any{"disable_fs_watcher": disabled, "period": period},
			}})
			in.waitFor(t, "the monitoring to start", func() bool { return in.logHas("monitoring successfully completed") })
			if got := inotifyWatches(in.cmd.Process.Pid); (got == 0) != disabled {
				t.Errorf("inotify watches = %d with disable_fs_watcher=%v", got, disabled)
			}
			in.drop(t, "late.txt", []byte("written after the start"))
			in.waitFor(t, "the delivery", func() bool { return in.inOutput("late.txt") })
		})
	}
}

// P17: the folders a delivered file leaves empty in INPUT are removed once the
// session report is written.
func TestE2E_emptyFoldersRemoved(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{session: map[string]any{"remove_empty_dirs": true}})
	in.drop(t, "deep/er/a.txt", []byte("in a subfolder"))
	in.waitFor(t, "the delivery", func() bool { return in.inOutput("deep/er/a.txt") })
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	in.waitFor(t, "the empty folders to go", func() bool { return in.gone(filepath.Join(in.input, "tom", "deep")) })
}

// P15: a file above max_file_size and an empty file are delivered when the
// policy says pass, and the reports say they were not analyzed.
func TestE2E_unanalyzablePolicyPass(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{config: map[string]any{
		"max_file_size":       "1MiB",
		"unanalyzable_policy": map[string]any{"too_big": "pass", "empty": "pass"},
	}})
	in.create(t, "big.bin", 2<<20)
	in.drop(t, "empty.txt", nil)
	in.waitFor(t, "both files to be delivered", func() bool { return in.inOutput("big.bin") && in.inOutput("empty.txt") })
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	if gm.submitted.Load() != 0 {
		t.Errorf("%d submissions: neither file should have been analyzed", gm.submitted.Load())
	}
}

// withConf returns a copy of the configuration of the run with the keys of
// change merged over it.
func (in *instance) withConf(t *testing.T, change map[string]any) map[string]any {
	t.Helper()
	return mergeMaps(cloneMap(t, in.conf), change)
}

// errorTypes returns the types of the error events the console received.
func (c *fakeConsole) errorTypes() (types []string) {
	for _, raw := range c.EventsOfType("error") {
		var ev struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &ev) == nil {
			types = append(types, ev.Type)
		}
	}
	return types
}

// resolvedTypes returns the error types the console received a resolution for.
func (c *fakeConsole) resolvedTypes() (types []string) {
	for _, raw := range c.EventsOfType("resolution") {
		var ev struct {
			Types []string `json:"type"`
		}
		if json.Unmarshal(raw, &ev) == nil {
			types = append(types, ev.Types...)
		}
	}
	return types
}

// P18/P19/Q22: a configuration the connector cannot apply is refused, the task
// is acknowledged with the error, the old configuration keeps working, the
// console is told, and a valid configuration afterwards resolves the error.
func TestE2E_invalidConfigureKeepsTheOldConfiguration(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{agent: true})
	in.drop(t, "before.txt", []byte("before the bad configuration"))
	in.waitFor(t, "the first delivery", func() bool { return in.inOutput("before.txt") })

	in.console.SetConfig(in.withConf(t, map[string]any{"move": map[string]any{"mode": "bogus"}}))
	if msg := in.console.WaitAck(t, in.console.Push(t, "update-config", nil)); msg == "" {
		t.Error("an invalid configuration was acknowledged without error")
	}
	in.waitFor(t, "the console to be told of the rejection", func() bool { return slices.Contains(in.console.errorTypes(), "host-config-rejected") })
	in.drop(t, "during.txt", []byte("while the bad configuration is refused"))
	in.waitFor(t, "the old configuration to keep delivering", func() bool { return in.inOutput("during.txt") })

	in.console.SetConfig(in.withConf(t, nil))
	if msg := in.console.WaitAck(t, in.console.Push(t, "update-config", nil)); msg != "" {
		t.Fatalf("the valid configuration was refused: %s", msg)
	}
	in.waitFor(t, "the rejection to be resolved", func() bool { return slices.Contains(in.console.resolvedTypes(), "host-config-rejected") })
	in.drop(t, "after.txt", []byte("after the good configuration"))
	in.waitFor(t, "the delivery after the good configuration", func() bool { return in.inOutput("after.txt") })
}

// startFailure starts the connector with a configuration it must refuse, and
// returns its log and exit error.
func startFailure(t *testing.T, opt options) (log string, err error) {
	t.Helper()
	in := startInstance(t, newGMalware(t, false), opt)
	_, err = in.wait(t, 20*time.Second)
	return in.stderr.String(), err
}

// P14, P18: what the connector cannot work with is refused at start, with a
// message that says how to fix it, and not discovered at the first file.
func TestE2E_refusedAtStart(t *testing.T) {
	tests := []struct {
		name string
		opt  options
		want string
	}{
		{name: "work dir under a watched path (P14)", opt: options{config: map[string]any{"work_dir": "INPUT/work"}}, want: "is, or is under, the monitored path"},
		{name: "browser that does not exist (P19)", opt: options{more: map[string]map[string]any{"report": {"chrome_path": "/nonexistent/chromium"}}}, want: `plugin "report": browser /nonexistent/chromium: unsafe executable`},
		{name: "7-Zip that does not exist (P18)", opt: options{extract: true, plugins: map[string]any{"seven_zip_path": "/nonexistent/7z"}}, want: "install the binary or fix the configured path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := startFailure(t, tt.opt)
			if err == nil {
				t.Error("the connector started with a configuration it must refuse")
			}
			if !strings.Contains(log, tt.want) {
				t.Errorf("the log does not say %q:\n%s", tt.want, log)
			}
		})
	}
}

// P8/P9: an archive whose members are clean is delivered whole once every
// member was analyzed; one with a malicious member is quarantined whole and
// nothing of it reaches OUTPUT.
func TestE2E_archives(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true})
	badMember := []byte(strings.Repeat("this member is a malware ", 100))
	gm.MarkMalicious(badMember)
	goodMembers := [][]byte{[]byte(strings.Repeat("member one ", 200)), []byte(strings.Repeat("member two ", 200))}
	good := zipOf(t, map[string]string{"m1.txt": string(goodMembers[0]), "m2.txt": string(goodMembers[1])})
	bad := zipOf(t, map[string]string{"ok.txt": string(goodMembers[0]), "evil.exe": string(badMember)})
	in.expect.archive(good, goodMembers...)
	in.expect.archive(bad, goodMembers[0], badMember)
	in.drop(t, "good.zip", good)
	badPath := in.drop(t, "bad.zip", bad)
	in.waitFor(t, "the clean archive to be delivered", func() bool { return in.inOutput("good.zip") })
	in.waitFor(t, "the malicious archive to leave INPUT", func() bool { return in.gone(badPath) })
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	if in.inOutput("bad.zip") {
		t.Error("the archive with a malicious member reached OUTPUT")
	}
	if m := globOne(t, filepath.Join(in.quarantine, "*.lock")); len(m) != 1 {
		t.Errorf("quarantine = %v, want the malicious archive only", m)
	}
}

// outputWatch samples OUTPUT for a file that must not appear yet.
type outputWatch struct {
	found atomic.Bool
	quit  chan struct{}
	done  chan struct{}
	once  sync.Once
}

// watchOutput starts sampling for the file below the owner folder every 20 ms,
// until stop or the end of the test.
func watchOutput(t *testing.T, in *instance, rel string) *outputWatch {
	t.Helper()
	w := &outputWatch{quit: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		for {
			if in.inOutput(rel) {
				w.found.Store(true)
			}
			select {
			case <-w.quit:
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}()
	t.Cleanup(func() { w.stop() })
	return w
}

// stop ends the sampling and tells whether the file showed up while it ran.
func (w *outputWatch) stop() (found bool) {
	w.once.Do(func() { close(w.quit) })
	<-w.done
	return w.found.Load()
}

// P16: a quarantined malware is restorable by the console, in either container
// format. It was not delivered before the restore; what is restored comes back
// to INPUT, is not quarantined again, and is delivered once, with the restored
// mark of the report.
func TestE2E_quarantineRestore(t *testing.T) {
	for _, format := range []string{"tar", "zip"} {
		t.Run(format, func(t *testing.T) {
			gm := newGMalware(t, false)
			in := startInstance(t, gm, options{agent: true, config: map[string]any{"quarantine": map[string]any{"format": format}}})
			bad := []byte("this content is a malware, restored later " + format)
			gm.MarkMalicious(bad)
			in.expect.release(bad)
			early := watchOutput(t, in, "bad.txt")
			path := in.drop(t, "bad.txt", bad)
			id := hcquarantine.ComputeCacheID(path, sha256Hex(bad))
			lock := filepath.Join(in.quarantine, id+".lock")
			in.waitFor(t, "the quarantine", func() bool { return !in.gone(lock) })
			in.waitFor(t, "the malware to leave INPUT", func() bool { return in.gone(path) })
			head, err := os.ReadFile(filepath.Clean(lock))
			if err != nil {
				t.Fatal(err)
			}
			head = head[:min(4, len(head))]
			if isZip := bytes.HasPrefix(head, []byte("PK")); isZip != (format == "zip") {
				t.Errorf("container starts with %q for the format %s", head, format)
			}
			if early.stop() {
				t.Fatal("the malware was delivered before the restore")
			}
			if msg := in.console.WaitAck(t, in.console.Push(t, "restore", map[string]string{"id": id})); msg != "" {
				t.Fatalf("restore refused: %s", msg)
			}
			in.waitFor(t, "the restored file to be delivered", func() bool { return in.inOutput("bad.txt") })
			delivered, err := os.ReadFile(filepath.Join(in.output, "tom", "bad.txt"))
			if err != nil || !bytes.Equal(delivered, bad) {
				t.Errorf("delivered content = %q, %v", delivered, err)
			}
		})
	}
}

// P1: a file that is still being written is not analyzed, and what a depositor
// that keeps the file open writes after the delivery does not reach OUTPUT.
// The modification delay is 5 s against a writer that appends every 400 ms:
// with the 1 s default a stall of more than 600 ms is a legitimate delivery of
// a partial file, and the test would be red for no reason.
func TestE2E_slowUploadAndWriterThatKeepsTheFileOpen(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{config: map[string]any{"monitoring": map[string]any{"modification_delay": "5s"}}})
	path := filepath.Join(in.input, "tom", "upload.bin")
	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := f.Close(); e != nil {
			t.Logf("close: %v", e)
		}
	}()
	chunk := []byte("another slice of the upload\n")
	written := make([]byte, 0, len(chunk)*12)
	for range 12 {
		if _, err = f.Write(chunk); err != nil {
			t.Fatal(err)
		}
		written = append(written, chunk...)
		time.Sleep(400 * time.Millisecond)
		if gm.submitted.Load() != 0 || in.inOutput("upload.bin") {
			t.Fatal("a file still being written was analyzed or delivered")
		}
	}
	in.waitFor(t, "the delivery once the writer paused", func() bool { return in.inOutput("upload.bin") })
	delivered := filepath.Join(in.output, "tom", "upload.bin")
	got, err := os.ReadFile(filepath.Clean(delivered))
	if err != nil || !bytes.Equal(got, written) {
		t.Fatalf("delivered %d bytes, %v; want the %d bytes written", len(got), err, len(written))
	}
	if _, err = f.WriteString("written after the delivery"); err != nil {
		t.Fatal(err)
	}
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	after, err := os.ReadFile(filepath.Clean(delivered))
	if err != nil || !bytes.Equal(after, written) {
		t.Errorf("OUTPUT changed after the delivery: %d bytes, %v", len(after), err)
	}
}

// zeroReader reads zeros for ever.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// bombZip is a ZIP of one member of size zeros: tiny, and it inflates to size.
func bombZip(t *testing.T, size int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("zeros.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.CopyN(w, zeroReader{}, size); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// bombGzip is a gzip of size zeros.
func bombGzip(t *testing.T, size int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := io.CopyN(gz, zeroReader{}, size); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// P20: archives built to exhaust the extraction (a ZIP and a gzip that inflate
// to far more than the limit) are not extracted past the limit, are not
// delivered, and stay in INPUT with an error in the report.
func TestE2E_extractionBombsAreStopped(t *testing.T) {
	for _, tt := range []struct {
		name string
		make func(*testing.T, int64) []byte
	}{
		{name: "bomb.zip", make: bombZip},
		{name: "bomb.gz", make: bombGzip},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gm := newGMalware(t, false)
			in := startInstance(t, gm, options{extract: true, config: map[string]any{"recursive_extract_max_size": "4MiB"}})
			bomb := tt.make(t, 64<<20)
			path := in.drop(t, tt.name, bomb)
			in.waitFor(t, "the bomb to be reported", func() bool { return len(in.reportsOf(t, bomb)) > 0 })
			for _, e := range in.reportsOf(t, bomb) {
				if !strings.Contains(e.Error, "left out by the limits of the extraction") {
					t.Errorf("the error of the bomb = %q, want the limits of the extraction named", e.Error)
				}
			}
			if in.gone(path) {
				t.Error("the bomb left INPUT")
			}
			if in.inOutput(tt.name) {
				t.Error("the bomb was delivered")
			}
		})
	}
}

// P3: a session that is closed gets its report, and the files that come later
// open a new session with its own report.
func TestE2E_sessionsCloseAndReopen(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{session: map[string]any{"delay": "2s"}})
	first, second := []byte("content of the first session"), []byte("content of the second session")
	in.drop(t, "one.txt", first)
	in.waitFor(t, "the first session report", func() bool { return in.reportCount() == 1 })
	in.drop(t, "two.txt", second)
	in.waitFor(t, "the second session report", func() bool { return in.reportCount() == 2 })
	in.waitFor(t, "both deliveries", func() bool { return in.inOutput("one.txt") && in.inOutput("two.txt") })
	if got := in.reportsOf(t, first); len(got) != 1 {
		t.Errorf("entries for the first file = %d, want 1", len(got))
	}
	if got := in.reportsOf(t, second); len(got) != 1 {
		t.Errorf("entries for the second file = %d, want 1", len(got))
	}
	reports := globOne(t, filepath.Join(in.export, "tom", datamodel.SessionReportPrefix+"*"))
	if len(reports) != 2 {
		t.Errorf("reports = %v, want two distinct files", reports)
	}
}

// P4: with a table of tracked files too small for the load (the least the
// product accepts, 1 MiB, against files with long names), nothing is lost: the
// files that did not fit are found again by the rescan, and the process stays
// small.
func TestE2E_manyFilesWithATinyTable(t *testing.T) {
	const files = 3000
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{agent: true, config: map[string]any{
		"workers":    8,
		"monitoring": map[string]any{"max_tracked_memory": "1MiB", "period": "3s", "modification_delay": "1s"},
	}})
	long := strings.Repeat("n", 180)
	for i := range files {
		in.drop(t, fmt.Sprintf("d%d/%s%05d.txt", i%20, long, i), []byte(fmt.Sprintf("file number %d", i)))
	}
	in.waitFor(t, "every file to be delivered", func() bool { return deliveredBelow(in, 20) == files })
	// The pressure event is the guard: without it the table never overflowed, and
	// the scenario would prove nothing about the cap.
	if !slices.Contains(in.console.errorTypes(), "host-monitor-pressure") {
		t.Errorf("the table never overflowed (events %v): the scenario proves nothing", in.console.errorTypes())
	}
}

// deliveredBelow counts the files delivered in the folders d0 to d<n-1> of the
// owner folder of OUTPUT, without listing them all.
func deliveredBelow(in *instance, n int) (count int) {
	for i := range n {
		entries, err := os.ReadDir(filepath.Join(in.output, "tom", fmt.Sprintf("d%d", i)))
		if err == nil {
			count += len(entries)
		}
	}
	return count
}

// P10: the path filters judge the logical path: the real path of a file, and
// for a member of an archive the path of the archive followed by the member's.
// A forbidden path is treated as malware, a skipped one is delivered without
// analysis.
func TestE2E_pathFiltersJudgeTheLogicalPath(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true, more: map[string]map[string]any{
		"filepath_filter": {
			"forbidden_paths": []string{`/forbidden/`, `\.zip/secret/`},
			"skipped_paths":   []string{`/trusted/`},
		},
	}})
	in.expect.allow(datamodel.NotAnalyzedPolicySkipped)
	plain := []byte("an ordinary file")
	trusted := []byte("a file in a trusted folder")
	forbidden := []byte("a file in a forbidden folder")
	member := []byte(strings.Repeat("a member in a forbidden folder of an archive ", 40))
	other := []byte(strings.Repeat("another member, in an allowed folder ", 40))
	archive := zipOf(t, map[string]string{"secret/x.txt": string(member), "open/y.txt": string(other)})
	cleanMember := []byte(strings.Repeat("the only member of the clean archive ", 40))
	clean := zipOf(t, map[string]string{"open/z.txt": string(cleanMember)})
	in.expect.archive(clean, cleanMember)
	in.expect.archive(archive, member, other)
	in.expect.flag(forbidden, member)
	in.drop(t, "plain.txt", plain)
	in.drop(t, "trusted/t.txt", trusted)
	forbiddenPath := in.drop(t, "forbidden/f.txt", forbidden)
	archivePath := in.drop(t, "bad.zip", archive)
	in.drop(t, "clean.zip", clean)
	in.waitFor(t, "the ordinary files to be delivered", func() bool {
		return in.inOutput("plain.txt") && in.inOutput("trusted/t.txt") && in.inOutput("clean.zip")
	})
	in.waitFor(t, "the filtered files to leave INPUT", func() bool { return in.gone(forbiddenPath) && in.gone(archivePath) })
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	if in.inOutput("forbidden/f.txt") || in.inOutput("bad.zip") {
		t.Error("a file under a forbidden logical path reached OUTPUT")
	}
	if got := globOne(t, filepath.Join(in.quarantine, "*.lock")); len(got) != 2 {
		t.Errorf("quarantine = %v, want the forbidden file and the archive", got)
	}
	if _, ok := gm.Given(sha256Hex(trusted)); ok {
		t.Error("a file under a skipped path was analyzed")
	}
	for name, content := range map[string][]byte{"plain.txt": plain, "the member of clean.zip": cleanMember} {
		if _, ok := gm.Given(sha256Hex(content)); !ok {
			t.Errorf("%s was not analyzed", name)
		}
	}
	skipped := func(content []byte) bool {
		return slices.ContainsFunc(in.reportsOf(t, content), func(e datamodel.Report) bool {
			return e.NotAnalyzedReason == datamodel.NotAnalyzedPolicySkipped
		})
	}
	if !skipped(trusted) {
		t.Error("the file under a skipped path is not reported as skipped")
	}
	if skipped(plain) {
		t.Error("an ordinary file is reported as skipped")
	}
}

// requireChromium returns the path of a browser for the report plugin, or skips
// the test; with E2E_REQUIRE_BROWSER=1 a missing browser fails it instead.
func requireChromium(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	if os.Getenv("E2E_REQUIRE_BROWSER") == "1" {
		t.Fatal("no browser found and E2E_REQUIRE_BROWSER=1")
	}
	t.Skip("no browser found (chromium, chromium-browser, google-chrome)")
	return ""
}

// P13: with the report plugin and a real browser, the session report is a PDF
// that bears the reserved name in the exports, not a JSON file.
func TestE2E_sessionReportGeneratedByTheBrowser(t *testing.T) {
	chrome := requireChromium(t)
	gm := newGMalware(t, false)
	bad := []byte("a malware that makes a report")
	gm.MarkMalicious(bad)
	in := startInstance(t, gm, options{agent: true, more: map[string]map[string]any{"report": {"chrome_path": chrome}}})
	in.drop(t, "bad.txt", bad)
	pattern := filepath.Join(in.export, "tom", datamodel.SessionReportPrefix+"tom-*.pdf")
	in.waitFor(t, "the PDF report in the exports", func() bool { return len(globOne(t, pattern)) > 0 })
	reports := globOne(t, filepath.Join(in.export, "tom", "*"))
	if len(reports) != 1 {
		t.Fatalf("exports = %v, want the PDF report only", reports)
	}
	name := filepath.Base(reports[0])
	if !strings.HasPrefix(name, datamodel.SessionReportPrefix+"tom-") || filepath.Ext(name) != ".pdf" {
		t.Errorf("report name = %q, want %stom-<time>.pdf", name, datamodel.SessionReportPrefix)
	}
	raw, err := os.ReadFile(filepath.Clean(reports[0]))
	if err != nil || !bytes.HasPrefix(raw, []byte("%PDF")) {
		t.Errorf("the report is not a PDF: %v", err)
	}
	if slices.Contains(in.console.errorTypes(), "session-report-fallback") {
		t.Error("the connector fell back to JSON although the browser works")
	}
}

// browserStub is the source of a program that stands for the browser: it runs
// the real one until the file named broken exists, and then fails.
const browserStub = `package main

import (
	"fmt"
	"os"
	"syscall"
)

var chrome, broken string

func main() {
	if _, err := os.Stat(broken); err == nil {
		fmt.Fprintln(os.Stderr, "cannot render")
		os.Exit(1)
	}
	if err := syscall.Exec(chrome, append([]string{chrome}, os.Args[1:]...), os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
`

// buildBrowserStub builds the browser stub in dir and returns its path.
func buildBrowserStub(t *testing.T, dir, chrome, broken string) string {
	t.Helper()
	src := filepath.Join(dir, "stub.go")
	write(t, src, []byte(browserStub))
	out := filepath.Join(dir, "chromium")
	flags := fmt.Sprintf("-X main.chrome=%s -X main.broken=%s", chrome, broken)
	if err := goBuild(repoRoot(t), out, "-ldflags", flags, src); err != nil {
		t.Fatal(err)
	}
	return out
}

// P12: when the generator fails, the report is not lost: after its retries the
// session writes the JSON fallback under the reserved name, the console is
// told, and the delivered files are in that report. The browser is the real
// one until the test breaks it, once the connector has started.
func TestE2E_failingReportGeneratorFallsBackToJSON(t *testing.T) {
	chrome := requireChromium(t)
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken")
	wrapper := buildBrowserStub(t, dir, chrome, broken)
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{
		agent:   true,
		more:    map[string]map[string]any{"report": {"chrome_path": wrapper}},
		session: map[string]any{"report_retries": 1, "report_timeout": "30s"},
	})
	in.waitFor(t, "the monitoring to start", func() bool { return in.logHas("monitoring successfully completed") })
	write(t, broken, nil)
	content := []byte("a file whose report cannot be rendered")
	in.drop(t, "a.txt", content)
	in.waitFor(t, "the JSON fallback", func() bool {
		return len(globOne(t, filepath.Join(in.export, "tom", datamodel.SessionReportPrefix+"*.json"))) == 1
	})
	in.waitFor(t, "the console to be told", func() bool { return slices.Contains(in.console.errorTypes(), "session-report-fallback") })
	in.waitFor(t, "the delivery", func() bool { return in.inOutput("a.txt") })
	if got := in.reportsOf(t, content); len(got) != 1 {
		t.Errorf("entries for the file in the fallback = %d, want 1", len(got))
	}
	if m := globOne(t, filepath.Join(in.export, "tom", datamodel.SessionReportPrefix+"*.pdf")); len(m) != 0 {
		t.Errorf("a PDF report was written by a browser that fails: %v", m)
	}
}

// outputHas tells whether a file with this content is delivered in OUTPUT: the
// staging folder of a copy in progress does not count.
func (in *instance) outputHas(t *testing.T, content []byte) bool {
	t.Helper()
	files, problems := listEntries(in.output)
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
		if sum == sha256Hex(content) {
			return true
		}
	}
	return false
}

// T14b: a restore never replaces a file. With another file at the place the
// quarantined one came from, the restore is refused, the other file is
// untouched, the container is kept and the malware is not restored; once the
// place is free the same restore works.
func TestE2E_restoreNeverReplacesAFile(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{agent: true})
	bad := []byte("a malware that is restored onto an occupied place")
	gm.MarkMalicious(bad)
	in.expect.release(bad)
	path := in.drop(t, "bad.txt", bad)
	id := hcquarantine.ComputeCacheID(path, sha256Hex(bad))
	lock := filepath.Join(in.quarantine, id+".lock")
	in.waitFor(t, "the quarantine", func() bool { return !in.gone(lock) })
	in.waitFor(t, "the malware to leave INPUT", func() bool { return in.gone(path) })

	// A depositor keeps writing the file that now sits where the malware was: it
	// never gets stable, so it stays there while the restore is tried.
	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, e := f.WriteString("keeps growing\n"); e != nil {
				return
			}
			select {
			case <-stop:
				return
			case <-time.After(200 * time.Millisecond):
			}
		}
	}()
	stopWriter := sync.OnceFunc(func() {
		close(stop)
		<-done
		if e := f.Close(); e != nil {
			t.Logf("close: %v", e)
		}
	})
	defer stopWriter()

	msg := in.console.WaitAck(t, in.console.Push(t, "restore", map[string]string{"id": id}))
	if !strings.Contains(msg, "destination already exists") {
		t.Fatalf("refusal = %q, want the destination named as existing", msg)
	}
	if in.gone(lock) {
		t.Error("the container is gone although nothing was restored")
	}
	if got, err := os.ReadFile(filepath.Clean(path)); err != nil || bytes.Contains(got, bad) {
		t.Errorf("the file in the way was changed: %d bytes, %v", len(got), err)
	}
	if in.outputHas(t, bad) {
		t.Error("the malware reached OUTPUT although its restore was refused")
	}

	stopWriter()
	in.waitFor(t, "the file in the way to leave INPUT", func() bool { return in.gone(path) })
	if msg := in.console.WaitAck(t, in.console.Push(t, "restore", map[string]string{"id": id})); msg != "" {
		t.Fatalf("the restore was refused once the place was free: %s", msg)
	}
	in.waitFor(t, "the restored file to be delivered", func() bool { return in.outputHas(t, bad) })
}

// restart stops the connector with SIGTERM and starts it again on the same
// folders and quarantine, with change merged over its configuration. The
// registry of the quarantine is in memory, so the new run does not know what
// the previous one quarantined.
func (in *instance) restart(t *testing.T, change map[string]any) {
	t.Helper()
	in.signal(t, syscall.SIGTERM)
	if _, err := in.wait(t, 20*time.Second); err != nil {
		t.Fatalf("the connector did not stop cleanly: %v", err)
	}
	// The request for tasks of the dead process is still waiting in the fake
	// console, and answers a poll later: it must be over before a task is pushed.
	time.Sleep(2 * consolePollWait)
	conf := in.withConf(t, change)
	in.conf = conf
	writeJSON(t, filepath.Join(in.root, "config.yml"), conf)
	if in.console != nil {
		in.console.SetConfig(conf)
	}
	in.launch(t, in.bin, in.dir, in.args)
}

// quarantineThenRestart quarantines a malware, restarts the connector with
// change, and returns the malware, its path and the ID of its container.
func quarantineThenRestart(t *testing.T, change func(in *instance) map[string]any) (in *instance, bad []byte, path, id string) {
	t.Helper()
	gm := newGMalware(t, false)
	in = startInstance(t, gm, options{agent: true})
	bad = []byte("a malware whose registry entry is lost by a restart")
	gm.MarkMalicious(bad)
	in.expect.release(bad)
	path = in.drop(t, "bad.txt", bad)
	id = hcquarantine.ComputeCacheID(path, sha256Hex(bad))
	lock := filepath.Join(in.quarantine, id+".lock")
	in.waitFor(t, "the quarantine", func() bool { return !in.gone(lock) })
	in.waitFor(t, "the malware to leave INPUT", func() bool { return in.gone(path) })
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	in.restart(t, change(in))
	in.waitFor(t, "the connector to be back", func() bool { return strings.Count(in.stderr.String(), "monitoring successfully completed") >= 2 })
	return in, bad, path, id
}

// T14b, Q30: a container whose registry entry is lost (the registry is in
// memory and the connector restarted) is restored only under a watched folder.
// Outside the watched folders the restore is refused and nothing is written.
func TestE2E_restoreWithoutRegistryEntryOutsideWatchedFolders(t *testing.T) {
	in, bad, path, id := quarantineThenRestart(t, func(in *instance) map[string]any {
		other := filepath.Join(in.root, "elsewhere")
		if err := os.MkdirAll(other, 0o750); err != nil {
			t.Fatal(err)
		}
		return map[string]any{"paths": []string{other}}
	})
	if msg := in.console.WaitAck(t, in.console.Push(t, "restore", map[string]string{"id": id})); msg == "" {
		t.Fatal("a restore outside the watched folders was acknowledged without error")
	}
	if in.gone(filepath.Join(in.quarantine, id+".lock")) {
		t.Error("the container is gone although nothing was restored")
	}
	if !in.gone(path) {
		t.Error("a file was written where the malware came from")
	}
	if in.outputHas(t, bad) {
		t.Error("the malware reached OUTPUT")
	}
}

// T14b, Q30: under a watched folder the same restore is served, the console is
// told that the registry did not know the file, and the restored file is
// delivered once.
func TestE2E_restoreWithoutRegistryEntryUnderAWatchedFolder(t *testing.T) {
	in, bad, _, id := quarantineThenRestart(t, func(*instance) map[string]any { return nil })
	if msg := in.console.WaitAck(t, in.console.Push(t, "restore", map[string]string{"id": id})); msg != "" {
		t.Fatalf("the restore was refused: %s", msg)
	}
	in.waitFor(t, "the restored file to be delivered", func() bool { return in.outputHas(t, bad) })
	in.waitFor(t, "the console to be told", func() bool {
		return slices.Contains(in.console.errorTypes(), "quarantine-restore-unregistered")
	})
}
