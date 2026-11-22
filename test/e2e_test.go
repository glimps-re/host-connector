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
	le "encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"image"
	"image/png"
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
	in := startInstance(t, gm, options{extract: true, config: map[string]any{
		"filepath_filter": map[string]any{
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

// monitoringStarted is the log line of a connector that is watching.
const monitoringStarted = "monitoring successfully completed"

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
	if err := syscall.Kill(-in.cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("the processes of the stopped connector: %v", err)
	}
	// The request for tasks of the dead process is still waiting in the fake
	// console, and would answer a poll later: it must be over before a task is
	// pushed.
	if in.console != nil {
		waitFor(t, "the polls of the stopped process to end", func() bool { return in.console.PollsInFlight() == 0 })
	}
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
	started := strings.Count(in.stderr.String(), monitoringStarted)
	in.restart(t, change(in))
	in.waitFor(t, "the connector to be back", func() bool { return strings.Count(in.stderr.String(), monitoringStarted) > started })
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
	msg := in.console.WaitAck(t, in.console.Push(t, "restore", map[string]string{"id": id}))
	if !strings.Contains(msg, "below a watched path") {
		t.Fatalf("refusal = %q, want it to say the container is restored only below a watched path", msg)
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

// notDeliveredWindow is how long a file that must stay in INPUT is watched.
const notDeliveredWindow = 12 * time.Second

// fixtureOf reads a fixture of the extract plugin's tests.
func fixtureOf(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(filepath.Join(repoRoot(t), "cmd", "plugins", "extract", "testdata", "t17a", name)))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// T17b: a damaged archive that may hide an encryption, or a member path the
// extraction cannot handle, is never delivered as a plain file, whatever
// extract_error says: it stays in INPUT in error.
func TestE2E_extractErrorAsFile(t *testing.T) {
	plain := zipOf(t, map[string]string{"a.txt": strings.Repeat("a plain member ", 100)})
	enc := fixtureOf(t, "enc_zipcrypto.zip")
	longName := strings.Repeat("a", 300)
	deep := strings.Repeat("d/", 70) + "x.txt"
	huge := strings.Repeat("h", 4100)
	tests := []struct {
		name    string
		policy  string
		content []byte
	}{
		{name: "a cut plain archive stays under error", policy: "error", content: plain[:len(plain)*66/100]},
		{name: "a cut encrypted archive stays under as_file", policy: "as_file", content: enc[:len(enc)*66/100]},
		{name: "a cut encrypted archive stays under error", policy: "error", content: enc[:len(enc)*66/100]},
		{name: "a plain archive followed by an encrypted one stays under as_file", policy: "as_file", content: append(append([]byte(nil), plain...), enc...)},
		{name: "a member with a path component over 255 bytes stays under as_file", policy: "as_file", content: zipOf(t, map[string]string{"d/" + longName + "/x.txt": "member"})},
		{name: "a member with a path over 4096 bytes stays under as_file", policy: "as_file", content: zipOf(t, map[string]string{huge + "/x.txt": "member"})},
		{name: "a member 70 folders deep stays under as_file", policy: "as_file", content: zipOf(t, map[string]string{deep: "member"})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := newGMalware(t, false)
			in := startInstance(t, gm, options{extract: true, config: map[string]any{
				"unanalyzable_policy": map[string]any{"extract_error": tt.policy},
			}})
			in.expect.allow(datamodel.NotAnalyzedExtractError)
			path := in.drop(t, "a.zip", tt.content)
			// The log names the archive once the connector has looked at it: only then
			// does absence from OUTPUT mean something.
			in.waitFor(t, "the connector to look at the archive", func() bool { return in.logHas(path) })
			// Absence is judged over a window: the archive must never be delivered.
			deadline := time.Now().Add(notDeliveredWindow)
			for time.Now().Before(deadline) {
				if in.outputHas(t, tt.content) {
					t.Fatal("the archive was delivered")
				}
				time.Sleep(200 * time.Millisecond)
			}
			if in.gone(path) {
				t.Error("the archive left INPUT")
			}
		})
	}
}

// mitigationReasons returns the reasons of the mitigation events the console
// received.
func (c *fakeConsole) mitigationReasons() (reasons []string) {
	for _, raw := range c.EventsOfType("mitigation") {
		var ev struct {
			Reason string `json:"reason"`
		}
		if json.Unmarshal(raw, &ev) == nil {
			reasons = append(reasons, ev.Reason)
		}
	}
	return reasons
}

// D6: a detection always wins. A result that carries a detection and an
// analysis error is malware: quarantined, never delivered, never left as a plain
// error; the report says malicious with the reason malware-detected, and the
// console is told it is a malware. Same for an archive with a member in that
// case beside a member in analysis error.
func TestE2E_aDetectionWithAnAnalysisErrorIsMalware(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		gm := newGMalware(t, false)
		in := startInstance(t, gm, options{agent: true})
		bad := []byte("a malware the service also fails to finish analyzing")
		gm.MarkMaliciousWithError(bad, "an engine crashed")
		path := in.drop(t, "bad.txt", bad)
		lock := filepath.Join(in.quarantine, hcquarantine.ComputeCacheID(path, sha256Hex(bad))+".lock")
		in.waitFor(t, "the quarantine", func() bool { return !in.gone(lock) })
		in.waitFor(t, "the file to leave INPUT", func() bool { return in.gone(path) })
		in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
		if in.inOutput("bad.txt") {
			t.Error("the malware reached OUTPUT")
		}
		entries := in.reportsOf(t, bad)
		if len(entries) == 0 {
			t.Fatal("the file is in no session report")
		}
		for _, e := range entries {
			if !e.Malicious || e.MalwareReason != datamodel.MalwareDetected {
				t.Errorf("report entry: malicious=%v reason=%q error=%q, want a malware with the reason %q", e.Malicious, e.MalwareReason, e.Error, datamodel.MalwareDetected)
			}
		}
		in.waitFor(t, "the console mitigation", func() bool { return len(in.console.mitigationReasons()) > 0 })
		if got := in.console.mitigationReasons(); !slices.Equal(got, []string{"malware"}) {
			t.Errorf("console mitigation reasons = %q, want [malware]", got)
		}
	})
	t.Run("archive", func(t *testing.T) {
		gm := newGMalware(t, false)
		in := startInstance(t, gm, options{extract: true, agent: true})
		detected := []byte(strings.Repeat("a member that is a malware with an error ", 40))
		broken := []byte(strings.Repeat("a member whose analysis fails ", 40))
		gm.MarkMaliciousWithError(detected, "an engine crashed")
		gm.MarkAnalysisError(broken, "the analysis failed")
		archive := zipOf(t, map[string]string{"evil.exe": string(detected), "broken.txt": string(broken)})
		in.expect.archive(archive, detected, broken)
		path := in.drop(t, "a.zip", archive)
		in.waitFor(t, "the archive to leave INPUT", func() bool { return in.gone(path) })
		in.waitFor(t, "the quarantine", func() bool { return len(globOne(t, filepath.Join(in.quarantine, "*.lock"))) == 1 })
		in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
		if in.inOutput("a.zip") {
			t.Error("the archive reached OUTPUT")
		}
		entries := in.reportsOf(t, archive)
		if len(entries) == 0 {
			t.Fatal("the archive is in no session report")
		}
		for _, e := range entries {
			if !e.Malicious || e.MalwareReason != datamodel.MalwareDetected {
				t.Errorf("report entry of the archive: malicious=%v reason=%q error=%q, want a malware with the reason %q", e.Malicious, e.MalwareReason, e.Error, datamodel.MalwareDetected)
			}
		}
		in.waitFor(t, "the console mitigation", func() bool { return len(in.console.mitigationReasons()) > 0 })
		if got := in.console.mitigationReasons(); !slices.Equal(got, []string{"malware"}) {
			t.Errorf("console mitigation reasons = %q, want [malware]", got)
		}
	})
}

// realPNG is a small image the type detection recognizes.
func realPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for i := range img.Pix {
		img.Pix[i] = byte(i * 7)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A type the filter forbids is refused inside an archive too: the member is
// judged by its content, on the real path it has once extracted, and the whole
// archive is quarantined. An archive without such a member is delivered.
func TestE2E_aForbiddenTypeInsideAZipIsRefused(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true, more: map[string]map[string]any{
		"filetype_filter": {"forbidden_types": []string{"image/png"}},
	}})
	pic := realPNG(t)
	text := []byte(strings.Repeat("a text member beside an image ", 40))
	other := []byte(strings.Repeat("another text member ", 40))
	with := zipOf(t, map[string]string{"pic.png": string(pic), "a.txt": string(text)})
	without := zipOf(t, map[string]string{"a.txt": string(text), "b.txt": string(other)})
	in.expect.flag(pic)
	in.expect.archive(with, pic, text)
	in.expect.archive(without, text, other)
	withPath := in.drop(t, "with.zip", with)
	in.drop(t, "without.zip", without)
	in.waitFor(t, "the archive without the image to be delivered", func() bool { return in.inOutput("without.zip") })
	in.waitFor(t, "the archive with the image to leave INPUT", func() bool { return in.gone(withPath) })
	in.waitFor(t, "the quarantine", func() bool { return len(globOne(t, filepath.Join(in.quarantine, "*.lock"))) == 1 })
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	if in.inOutput("with.zip") {
		t.Error("the archive with a forbidden type reached OUTPUT")
	}
}

// spoolFiles lists the spool files of the open sessions.
func (in *instance) spoolFiles(t *testing.T) []string {
	t.Helper()
	return globOne(t, filepath.Join(in.work, "gmhost-*", datamodel.SessionSpoolDir, "*"+datamodel.SessionSpoolExt))
}

// T20b: the reports of an open session wait on disk, in a private file; a
// session that has been open for max_duration is closed at once whatever its
// activity, with its report, and the next deposit opens a new session.
func TestE2E_aSessionIsClosedAtMaxDuration(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{session: map[string]any{"delay": "1h", "max_duration": "5s"}})
	first, second := []byte("deposited in the first session"), []byte("deposited in the second session")
	in.drop(t, "one.txt", first)
	var spool string
	in.waitFor(t, "the spool of the open session", func() bool {
		files := in.spoolFiles(t)
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
	if in.reportCount() != 0 {
		t.Error("a session report was written before the session closed")
	}
	in.waitFor(t, "the first session to be closed by max_duration", func() bool { return in.reportCount() == 1 })
	if left := in.spoolFiles(t); len(left) != 0 {
		t.Errorf("spools left after the report: %v", left)
	}
	in.drop(t, "two.txt", second)
	in.waitFor(t, "the second session report", func() bool { return in.reportCount() == 2 })
	if got := in.reportsOf(t, first); len(got) != 1 {
		t.Errorf("entries for the first file = %d, want 1", len(got))
	}
	if got := in.reportsOf(t, second); len(got) != 1 {
		t.Errorf("entries for the second file = %d, want 1", len(got))
	}
}

// T20b: a session whose reports reach max_spool_size (at least 1 MiB) is closed
// at once (that is the minimum the key accepts) and the next deposits open another: many reports in one run make
// several session reports, and not one report is lost.
func TestE2E_aSessionIsClosedAtMaxSpoolSize(t *testing.T) {
	const files = 3000
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{config: map[string]any{"workers": 8}, session: map[string]any{"delay": "1h", "max_spool_size": "1MiB"}})
	long := strings.Repeat("n", 180)
	for i := range files {
		in.drop(t, fmt.Sprintf("d%d/%s%05d.txt", i%20, long, i), []byte(fmt.Sprintf("file number %d", i)))
	}
	in.waitFor(t, "every file to be delivered", func() bool { return deliveredBelow(in, 20) == files })
	in.waitFor(t, "the session to be closed by its size", func() bool { return in.reportCount() >= 1 })
	if !in.logHas("max_spool_size reached") {
		t.Error("the log does not say that max_spool_size closed a session")
	}
}

// crashAndRestart kills the connector without warning, as a crash does, and
// starts it again on the same folders.
func (in *instance) crashAndRestart(t *testing.T) {
	t.Helper()
	if err := syscall.Kill(-in.cmd.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	<-in.exited
	in.launch(t, in.bin, in.dir, in.args)
}

// T20b: the spool of a session open when the connector crashed is not
// recovered: the next start removes it, with a warning that counts the session
// reports lost, and the work directory of the dead run goes with it.
func TestE2E_theSpoolOfACrashedRunIsRemovedWithAWarning(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{session: map[string]any{"delay": "1h"}})
	content := []byte("deposited before the crash")
	in.expect.crashLost(content)
	in.drop(t, "a.txt", content)
	in.waitFor(t, "the delivery", func() bool { return in.inOutput("a.txt") })
	in.waitFor(t, "the spool of the open session", func() bool { return len(in.spoolFiles(t)) == 1 })
	oldDirs := globOne(t, filepath.Join(in.work, "gmhost-*"))
	before := strings.Count(in.stderr.String(), monitoringStarted)
	in.crashAndRestart(t)
	in.waitFor(t, "the connector to be back", func() bool { return strings.Count(in.stderr.String(), monitoringStarted) > before })
	if !in.logHas("1 session report(s) of a previous run were lost (crash)") {
		t.Error("the log does not warn that one session report was lost")
	}
	for _, dir := range oldDirs {
		if !in.gone(dir) {
			t.Errorf("the work directory of the crashed run is still there: %s", dir)
		}
	}
	if left := in.spoolFiles(t); len(left) != 0 {
		t.Errorf("spools left: %v", left)
	}
}

// D6, guard of shipped behaviour: a detection wins in an archive. A plugin that
// waives a nested archive (its logical path is a skipped path) does not discard
// the detection of a member beside it: the outer archive is quarantined, never
// delivered. The detected member sorts first and the waived archive last. This
// does not exercise the T55 race (a waiver judged after the detection of the
// waived archive's own members): with the shipped plugins the waiver is judged
// first, so no e2e ordering fails before T55; the race is covered by the unit
// regression tests of T55, with a slow plugin hook.
func TestE2E_aDetectionBesideAWaivedNestedArchiveWins(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true, config: map[string]any{
		"workers":         4,
		"filepath_filter": map[string]any{"skipped_paths": []string{`outer\.zip/z-inner\.zip$`}},
	}})
	in.expect.allow(datamodel.NotAnalyzedPolicySkipped)
	bad := []byte(strings.Repeat("a member that is a malware ", 40))
	gm.MarkMalicious(bad)
	inner := zipOf(t, map[string]string{"x.txt": strings.Repeat("a member of the waived archive ", 40)})
	outer := zipOf(t, map[string]string{"a-bad.bin": string(bad), "z-inner.zip": string(inner)})
	in.expect.archive(outer, bad, inner)
	path := in.drop(t, "outer.zip", outer)
	in.waitFor(t, "the archive to leave INPUT", func() bool { return in.gone(path) })
	in.waitFor(t, "the quarantine", func() bool { return len(globOne(t, filepath.Join(in.quarantine, "*.lock"))) == 1 })
	if in.inOutput("outer.zip") {
		t.Error("the archive with a detected member reached OUTPUT: the waiver of its nested archive discarded the detection")
	}
}

// D6, guard of shipped behaviour: a detection also outranks an archive that
// cannot be examined. An archive with a detected member and a nested encrypted
// archive (the policy of the encrypted files is error, which keeps a file in
// INPUT) is quarantined, not left in INPUT in error.
func TestE2E_aDetectionBeatsAnUnexaminableNestedArchive(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true})
	bad := []byte(strings.Repeat("a member that is a malware ", 40))
	gm.MarkMalicious(bad)
	enc := fixtureOf(t, "enc_zipcrypto.zip")
	outer := zipOf(t, map[string]string{"a-bad.bin": string(bad), "z-enc.zip": string(enc)})
	in.expect.archive(outer, bad, enc)
	path := in.drop(t, "outer.zip", outer)
	in.waitFor(t, "the archive to leave INPUT", func() bool { return in.gone(path) })
	in.waitFor(t, "the quarantine", func() bool { return len(globOne(t, filepath.Join(in.quarantine, "*.lock"))) == 1 })
	if in.inOutput("outer.zip") {
		t.Error("the archive with a detected member reached OUTPUT")
	}
}

// P7: a refusal beats an exemption. A file that the path rules let through (a
// skipped path) and a plugin refuses (a forbidden type) is refused.
// The same image is dropped outside the trusted folder (the control) and in it:
// each path gets its own container, so two are quarantined.
func TestE2E_aRefusalBeatsAnExemption(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{
		config: map[string]any{"filepath_filter": map[string]any{"skipped_paths": []string{`/trusted/`}}},
		more:   map[string]map[string]any{"filetype_filter": {"forbidden_types": []string{"image/png"}}},
	})
	in.expect.allow(datamodel.NotAnalyzedPolicySkipped)
	pic := realPNG(t)
	text := []byte("a text in a trusted folder")
	in.expect.flag(pic)
	control := in.drop(t, "control.png", pic)
	trusted := in.drop(t, "trusted/p.png", pic)
	in.drop(t, "trusted/t.txt", text)
	in.waitFor(t, "the trusted text to be delivered", func() bool { return in.inOutput("trusted/t.txt") })
	for _, path := range []string{control, trusted} {
		lock := filepath.Join(in.quarantine, hcquarantine.ComputeCacheID(path, sha256Hex(pic))+".lock")
		in.waitFor(t, "the quarantine of "+filepath.Base(path), func() bool { return !in.gone(lock) && in.gone(path) })
	}
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	if in.inOutput("control.png") || in.inOutput("trusted/p.png") {
		t.Error("the image reached OUTPUT: the exemption of its path beat the refusal of its type")
	}
	if _, ok := gm.Given(sha256Hex(text)); ok {
		t.Error("the file under a skipped path was analyzed")
	}
}

// T54: beyond what the type detection reads, a type never waives. A file whose
// type is in skipped_types is delivered without analysis when it is small, and
// analyzed when it is larger than what the detection reads (about 7 MiB): the
// type of such a file is judged from its head alone.
func TestE2E_aSkippedTypeIsNotWaivedForALargeFile(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{more: map[string]map[string]any{
		"filetype_filter": {"skipped_types": []string{"image/png"}},
	}})
	in.expect.allow(datamodel.NotAnalyzedPolicySkipped)
	small := realPNG(t)
	// A real image followed by zeros: still typed image/png, but past the size
	// the detection reads.
	large := append(realPNG(t), make([]byte, 9<<20)...)
	in.drop(t, "small.png", small)
	in.drop(t, "large.png", large)
	in.waitFor(t, "both images to be delivered", func() bool { return in.inOutput("small.png") && in.inOutput("large.png") })
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	if _, ok := gm.Given(sha256Hex(small)); ok {
		t.Error("the small image of a skipped type was analyzed")
	}
	if _, ok := gm.Given(sha256Hex(large)); !ok {
		t.Error("the large image of a skipped type was waived, not analyzed")
	}
	if !slices.ContainsFunc(in.reportsOf(t, small), func(e datamodel.Report) bool { return e.NotAnalyzedReason == datamodel.NotAnalyzedPolicySkipped }) {
		t.Error("the small image is not reported as skipped")
	}
}

// modeExecutable is the mode of the copy of the embedded 7-Zip.
const modeExecutable os.FileMode = 0o700

// sevenZip returns a copy of the embedded 7-Zip of the extract plugin that the
// tests can run, or skips the test when it is not there.
func sevenZip(t *testing.T) string {
	t.Helper()
	src := filepath.Join(repoRoot(t), "cmd", "plugins", "extract", "7zzs")
	in, err := os.Open(filepath.Clean(src))
	if err != nil {
		t.Skipf("embedded 7-Zip not available: %v", err)
	}
	defer func() {
		if e := in.Close(); e != nil {
			t.Logf("close: %v", e)
		}
	}()
	bin := filepath.Join(t.TempDir(), "7zzs")
	out, err := os.OpenFile(filepath.Clean(bin), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(bin, modeExecutable); err != nil {
		t.Fatal(err)
	}
	return bin
}

// headerEncrypted7z builds a 7z with the embedded 7-Zip whose headers and
// content are encrypted with "infected" (-mhe=on), the way samples are commonly
// shared. members maps a path in the archive to its content.
func headerEncrypted7z(t *testing.T, members map[string]string) []byte {
	t.Helper()
	bin := sevenZip(t)
	src := t.TempDir()
	paths := make([]string, 0, len(members))
	for name, content := range members {
		p := filepath.Join(src, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		write(t, p, []byte(content))
		paths = append(paths, name)
	}
	archive := filepath.Join(t.TempDir(), "he.7z")
	if out, err := runCommand(src, bin, append([]string{"a", "-t7z", "-mhe=on", "-pinfected", archive}, paths...)...); err != nil {
		t.Fatalf("cannot build the archive: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(filepath.Clean(archive))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A 7z with encrypted headers, whose password is a default one ("infected"), is
// extracted like any archive: with clean members it is delivered, after its members
// were analyzed; with a detected member it is quarantined.
func TestE2E_aHeaderEncryptedSevenZipWithADefaultPassword(t *testing.T) {
	for _, tt := range []struct {
		name     string
		detected bool
	}{{name: "clean members"}, {name: "a detected member", detected: true}} {
		t.Run(tt.name, func(t *testing.T) {
			gm := newGMalware(t, false)
			in := startInstance(t, gm, options{extract: true})
			clean := []byte(strings.Repeat("a clean member of the archive ", 40))
			other := []byte(strings.Repeat("a member that may be a malware ", 40))
			if tt.detected {
				gm.MarkMalicious(other)
				in.expect.flag(other)
			}
			archive := headerEncrypted7z(t, map[string]string{"d/clean.txt": string(clean), "other.bin": string(other)})
			in.expect.archive(archive, clean, other)
			path := in.drop(t, "he.7z", archive)
			if tt.detected {
				lock := filepath.Join(in.quarantine, hcquarantine.ComputeCacheID(path, sha256Hex(archive))+".lock")
				in.waitFor(t, "the quarantine of the archive", func() bool { return !in.gone(lock) && in.gone(path) })
				if in.outputHas(t, archive) {
					t.Error("the archive with a detected member was delivered")
				}
				return
			}
			in.waitFor(t, "the archive to be delivered", func() bool { return in.outputHas(t, archive) })
			for _, member := range [][]byte{clean, other} {
				if _, ok := gm.Given(sha256Hex(member)); !ok {
					t.Error("a member of the archive was not analyzed")
				}
			}
		})
	}
}

// staysInInput waits until the connector has looked at the file (the log names
// its path), then watches OUTPUT for the window: the file must never be
// delivered and must still be in INPUT.
func (in *instance) staysInInput(t *testing.T, path string, content []byte) {
	t.Helper()
	in.waitFor(t, "the connector to look at "+filepath.Base(path), func() bool { return in.logHas(path) })
	deadline := time.Now().Add(notDeliveredWindow)
	for time.Now().Before(deadline) {
		if in.outputHas(t, content) {
			t.Fatalf("%s was delivered", filepath.Base(path))
		}
		time.Sleep(200 * time.Millisecond)
	}
	if in.gone(path) {
		t.Errorf("%s left INPUT", filepath.Base(path))
	}
}

// quarantined waits for the file to leave INPUT into the quarantine and checks
// that it was not delivered.
func (in *instance) quarantinedFile(t *testing.T, path string, content []byte) {
	t.Helper()
	lock := filepath.Join(in.quarantine, hcquarantine.ComputeCacheID(path, sha256Hex(content))+".lock")
	in.waitFor(t, "the quarantine of "+filepath.Base(path), func() bool { return !in.gone(lock) && in.gone(path) })
	if in.outputHas(t, content) {
		t.Errorf("%s was delivered", filepath.Base(path))
	}
}

// pathFilter is the filepath_filter section of the configuration.
func pathFilter(forbidden, skipped []string) map[string]any {
	return map[string]any{"filepath_filter": map[string]any{"forbidden_paths": forbidden, "skipped_paths": skipped}}
}

// T51c: the paths rules of the core, with no plugin. A forbidden path (a file,
// a member of an archive) is malware and is quarantined; a skipped folder is
// delivered without analysis, marked policy-skipped; a refusal beats a skip.
func TestE2E_corePathRules(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true, config: pathFilter(
		[]string{`/forbidden/`, `\.zip/secret/`},
		[]string{`/tom/trusted/`},
	)})
	in.expect.allow(datamodel.NotAnalyzedPolicySkipped)
	plain := []byte("an ordinary file")
	trusted := []byte("a file in a skipped folder")
	forbidden := []byte("a file in a forbidden folder")
	both := []byte("forbidden and in a skipped folder")
	member := []byte(strings.Repeat("a member in a forbidden folder of an archive ", 40))
	other := []byte(strings.Repeat("another member, in an allowed folder ", 40))
	archive := zipOf(t, map[string]string{"secret/x.txt": string(member), "open/y.txt": string(other)})
	cleanMember := []byte(strings.Repeat("the only member of the clean archive ", 40))
	clean := zipOf(t, map[string]string{"open/z.txt": string(cleanMember)})
	in.expect.flag(forbidden, both, member)
	in.expect.archive(archive, member, other)
	in.expect.archive(clean, cleanMember)
	in.drop(t, "plain.txt", plain)
	in.drop(t, "trusted/t.txt", trusted)
	forbiddenPath := in.drop(t, "forbidden/f.txt", forbidden)
	bothPath := in.drop(t, "trusted/forbidden/b.txt", both)
	archivePath := in.drop(t, "bad.zip", archive)
	in.drop(t, "clean.zip", clean)
	in.waitFor(t, "the ordinary files to be delivered", func() bool {
		return in.inOutput("plain.txt") && in.inOutput("trusted/t.txt") && in.inOutput("clean.zip")
	})
	for path, content := range map[string][]byte{forbiddenPath: forbidden, bothPath: both} {
		in.quarantinedFile(t, path, content)
	}
	in.waitFor(t, "the archive with a forbidden member to be quarantined", func() bool { return in.gone(archivePath) })
	if in.inOutput("bad.zip") {
		t.Error("an archive with a member under a forbidden path was delivered")
	}
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	if _, ok := gm.Given(sha256Hex(trusted)); ok {
		t.Error("a file under a skipped path was analyzed")
	}
	if !slices.ContainsFunc(in.reportsOf(t, trusted), func(e datamodel.Report) bool { return e.NotAnalyzedReason == datamodel.NotAnalyzedPolicySkipped }) {
		t.Error("the file under a skipped path is not reported as skipped")
	}
}

// T51c: a newline inside the name of an archive does not make it escape a
// forbidden path. The rule `^/.*\.zip$` does not cross a newline with `.`, so the
// raw name "pack\nx.zip" would slip under it: the archive is refused all the same.
func TestE2E_aNewlineInAnArchiveNameDoesNotEscapeAForbiddenPath(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true, config: pathFilter([]string{`^/.*\.zip$`}, nil)})
	member := []byte(strings.Repeat("a member of an archive that a rule forbids ", 40))
	archive := zipOf(t, map[string]string{"a.txt": string(member)})
	in.expect.flag(archive)
	path := in.drop(t, "pack\nx.zip", archive)
	in.quarantinedFile(t, path, archive)
}

// T51c, Amendment 3 ("raw and sanitized names"): a path is matched in its raw
// form and in the form the core prints (control characters replaced). When the
// two differ, a forbidden rule is applied if either matches and a skip only if
// both do. A name ending in a newline is refused by `\.exe[^/]*$` (Go's `$` is
// the end of the text, so `\.exe$` alone would not match even the raw name). A
// control character makes the raw and the sanitized names differ: a file whose
// sanitized name matches the skip rule `a_b\.txt$` but whose raw name does not is
// analyzed. An invalid UTF-8 byte does not: RE2 reads it as U+FFFD, and so does
// the sanitized form, so both give the same verdict and the folder is skipped.
func TestE2E_pathRulesMatchTheRawAndTheSanitizedName(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{config: pathFilter(
		[]string{`\.exe[^/]*$`},
		[]string{"/tom/trusted[_\\x{FFFD}]/", `a_b\.txt$`},
	)})
	in.expect.allow(datamodel.NotAnalyzedPolicySkipped)
	exe := []byte("a file whose name ends in .exe and a newline")
	odd := []byte("a file in a folder whose name is not valid UTF-8")
	ctrl := []byte("a file whose name holds a control character")
	in.expect.flag(exe)
	exePath := in.drop(t, "run.exe\n", exe)
	in.drop(t, "trusted\xff/x.txt", odd)
	in.drop(t, "a\x01b.txt", ctrl)
	in.quarantinedFile(t, exePath, exe)
	in.waitFor(t, "the file of the odd folder to be delivered", func() bool { return in.inOutput("trusted\xff/x.txt") })
	in.waitFor(t, "the file with a control character to be delivered", func() bool { return in.inOutput("a\x01b.txt") })
	in.waitFor(t, "the file with a control character to have been analyzed", func() bool {
		_, ok := gm.Given(sha256Hex(ctrl))
		return ok
	})
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	skipped := func(content []byte) bool {
		return slices.ContainsFunc(in.reportsOf(t, content), func(e datamodel.Report) bool { return e.NotAnalyzedReason == datamodel.NotAnalyzedPolicySkipped })
	}
	if !skipped(odd) {
		t.Error("the file of the folder with an invalid UTF-8 byte is not reported as skipped")
	}
	if _, ok := gm.Given(sha256Hex(odd)); ok {
		t.Error("the file of the skipped folder was analyzed")
	}
	if skipped(ctrl) {
		t.Error("the file whose raw name does not match the skip rule was skipped")
	}
}

// T51c: a skipped archive refused because listed members match a forbidden path
// names those members in its report, as if it had been extracted: each appears
// among the malicious members of the archive.
func TestE2E_aRefusedSkippedArchiveNamesItsForbiddenMembers(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true, config: pathFilter([]string{`\.exe$`}, []string{`/tom/trusted/`})})
	a := []byte(strings.Repeat("the first executable ", 40))
	b := []byte(strings.Repeat("the second executable ", 40))
	archive := zipOf(t, map[string]string{"a.exe": string(a), "b.exe": string(b)})
	in.expect.flag(a, b)
	in.expect.archive(archive, a, b)
	path := in.drop(t, "trusted/x.zip", archive)
	in.quarantinedFile(t, path, archive)
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	entries := in.reportsOf(t, archive)
	if len(entries) == 0 {
		t.Fatal("the archive is in no session report")
	}
	for _, name := range []string{"a.exe", "b.exe"} {
		if !slices.ContainsFunc(entries, func(e datamodel.Report) bool {
			return slices.ContainsFunc(e.MaliciousExtractedFiles, func(m datamodel.ExtractedFile) bool {
				return strings.HasSuffix(m.FileName, "/"+name) || m.FileName == name
			})
		}) {
			t.Errorf("the report does not name %s among the malicious members: %+v", name, entries)
		}
	}
}

// T51c, Amendment 3: a skip waives the analysis, never a refusal. An archive in
// a skipped folder is listed, not extracted: a member under a forbidden path
// makes it malware; without such a member it is delivered, policy-skipped, and
// none of its members is analyzed.
func TestE2E_aSkippedArchiveIsStillCheckedAgainstTheForbiddenPaths(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true, config: pathFilter([]string{`\.exe$`}, []string{`/tom/trusted/`})})
	in.expect.allow(datamodel.NotAnalyzedPolicySkipped)
	exe := []byte(strings.Repeat("an executable member ", 40))
	doc := []byte(strings.Repeat("a document member ", 40))
	with := zipOf(t, map[string]string{"a.exe": string(exe), "b.txt": string(doc)})
	// c.txt does not reuse the bytes of a.exe: what the test flags is keyed by
	// content, and the archive without a forbidden member must not count as malware.
	plainMember := []byte(strings.Repeat("a document too, with other bytes ", 40))
	without := zipOf(t, map[string]string{"b.txt": string(doc), "c.txt": string(plainMember)})
	in.expect.flag(exe)
	in.expect.archive(with, exe, doc)
	in.expect.archive(without, doc, plainMember)
	withPath := in.drop(t, "trusted/with.zip", with)
	in.drop(t, "trusted/without.zip", without)
	in.waitFor(t, "the archive without a forbidden member to be delivered", func() bool { return in.inOutput("trusted/without.zip") })
	in.quarantinedFile(t, withPath, with)
	if _, ok := gm.Given(sha256Hex(doc)); ok {
		t.Error("a member of a skipped archive was analyzed")
	}
}

// analysisErrorCase is an analysis_error value and what must become of a file
// the service failed to analyze.
type analysisErrorCase struct {
	value string
	// mitigated: quarantined as a malware. delivered: in OUTPUT, marked. otherwise
	// the file stays in INPUT.
	mitigated, delivered bool
}

var analysisErrorCases = []analysisErrorCase{{value: "error"}, {value: "mitigate", mitigated: true}, {value: "pass", delivered: true}}

// T51b: analysis_error decides what becomes of a file whose analysis failed:
// error keeps it in INPUT, mitigate quarantines it as a malware (reason
// analysis-error), pass delivers it marked not analyzed. A detection always
// wins: with the error beside it, the file is a malware under every value.
func TestE2E_analysisErrorPolicy(t *testing.T) {
	for _, tt := range analysisErrorCases {
		t.Run(tt.value, func(t *testing.T) {
			gm := newGMalware(t, false)
			in := startInstance(t, gm, options{agent: true, config: map[string]any{"unanalyzable_policy": map[string]any{"analysis_error": tt.value}}})
			in.expect.allow(reasonAnalysisError)
			broken := []byte("a file whose analysis fails")
			gm.MarkAnalysisError(broken, "the analysis failed")
			if tt.mitigated {
				// mitigate turns the analysis error into a malware: it counts as one for
				// the checker (under error and pass it must not).
				in.expect.flag(broken)
			}
			detected := []byte("a malware whose analysis also fails")
			gm.MarkMaliciousWithError(detected, "an engine crashed")
			brokenPath := in.drop(t, "broken.txt", broken)
			detectedPath := in.drop(t, "detected.txt", detected)
			in.quarantinedFile(t, detectedPath, detected)
			switch {
			case tt.mitigated:
				in.quarantinedFile(t, brokenPath, broken)
			case tt.delivered:
				in.waitFor(t, "the delivery of the file whose analysis failed", func() bool { return in.outputHas(t, broken) })
				in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
				if !slices.ContainsFunc(in.reportsOf(t, broken), func(e datamodel.Report) bool { return e.NotAnalyzedReason == reasonAnalysisError }) {
					t.Error("the file delivered under pass is not marked analysis-error")
				}
			default:
				in.staysInInput(t, brokenPath, broken)
			}
		})
	}
}

// T51b: an archive with a member whose analysis failed follows the same value:
// under error it is counted in error (its report says members could not be
// analyzed) and stays in INPUT; under mitigate it is malware; under pass it is
// delivered, the member listed as not analyzed.
func TestE2E_analysisErrorInAnArchiveMember(t *testing.T) {
	for _, tt := range analysisErrorCases {
		t.Run(tt.value, func(t *testing.T) {
			gm := newGMalware(t, false)
			in := startInstance(t, gm, options{extract: true, config: map[string]any{"unanalyzable_policy": map[string]any{"analysis_error": tt.value}}})
			in.expect.allow(reasonAnalysisError)
			broken := []byte(strings.Repeat("a member whose analysis fails ", 40))
			fine := []byte(strings.Repeat("a member analyzed without problem ", 40))
			gm.MarkAnalysisError(broken, "the analysis failed")
			if tt.mitigated {
				// mitigate turns the member in error into a malware, and the archive with it.
				in.expect.flag(broken)
			}
			archive := zipOf(t, map[string]string{"broken.txt": string(broken), "fine.txt": string(fine)})
			in.expect.archive(archive, broken, fine)
			path := in.drop(t, "a.zip", archive)
			switch {
			case tt.mitigated:
				in.quarantinedFile(t, path, archive)
			case tt.delivered:
				in.waitFor(t, "the delivery of the archive", func() bool { return in.outputHas(t, archive) })
			default:
				in.staysInInput(t, path, archive)
				in.waitFor(t, "the report of the archive", func() bool { return len(in.reportsOf(t, archive)) > 0 })
				if !slices.ContainsFunc(in.reportsOf(t, archive), func(e datamodel.Report) bool { return e.Error != "" }) {
					t.Error("the archive with a member in analysis error is not reported in error")
				}
			}
		})
	}
}

// T51b: pass never bypasses another policy. With analysis_error pass, an
// encrypted archive and a file above max_file_size still follow encrypted and
// too_big (error: they stay in INPUT).
func TestE2E_passNeverBypassesTheOtherPolicies(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true, config: map[string]any{
		"max_file_size":       "1MiB",
		"unanalyzable_policy": map[string]any{"analysis_error": "pass", "encrypted": "error", "too_big": "error"},
	}})
	enc := fixtureOf(t, "enc_zipcrypto.zip")
	encPath := in.drop(t, "enc.zip", enc)
	bigPath := in.create(t, "big.bin", 2<<20)
	big, err := os.ReadFile(filepath.Clean(bigPath))
	if err != nil {
		t.Fatal(err)
	}
	in.staysInInput(t, encPath, enc)
	in.staysInInput(t, bigPath, big)
}

// quarantineThenRestore deposits a malware, waits for its quarantine, restores
// it through the console and returns the ID of the container. The caller waits
// for what follows.
func (in *instance) quarantineThenRestore(t *testing.T, rel string, content []byte) {
	t.Helper()
	path := in.drop(t, rel, content)
	id := hcquarantine.ComputeCacheID(path, sha256Hex(content))
	lock := filepath.Join(in.quarantine, id+".lock")
	in.waitFor(t, "the quarantine of "+rel, func() bool { return !in.gone(lock) && in.gone(path) })
	if msg := in.console.WaitAck(t, in.console.Push(t, "restore", map[string]string{"id": id})); msg != "" {
		t.Fatalf("restore refused: %s", msg)
	}
}

// quarantinedAt waits for the file at path to leave INPUT into the quarantine
// and checks that nothing was delivered at rel: the same content may have been
// delivered elsewhere, which is why this does not look at the content.
func (in *instance) quarantinedAt(t *testing.T, path, rel string, content []byte) {
	t.Helper()
	lock := filepath.Join(in.quarantine, hcquarantine.ComputeCacheID(path, sha256Hex(content))+".lock")
	in.waitFor(t, "the quarantine of "+rel, func() bool { return !in.gone(lock) && in.gone(path) })
	if in.inOutput(rel) {
		t.Errorf("%s was delivered", rel)
	}
}

// stillInInputAt is staysInInput for a content that is delivered elsewhere:
// it looks at the path, not at the content.
func (in *instance) stillInInputAt(t *testing.T, path, rel string) {
	t.Helper()
	in.waitFor(t, "the connector to look at "+rel, func() bool { return in.logHas(path) })
	deadline := time.Now().Add(notDeliveredWindow)
	for time.Now().Before(deadline) {
		if in.inOutput(rel) {
			t.Fatalf("%s was delivered", rel)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if in.gone(path) {
		t.Errorf("%s left INPUT", rel)
	}
}

// reportHas tells whether an entry of the reports for the content satisfies f.
func (in *instance) reportHas(t *testing.T, content []byte, f func(datamodel.Report) bool) bool {
	t.Helper()
	return slices.ContainsFunc(in.reportsOf(t, content), f)
}

// T56: "restored" waives the analysis, never a refusal. A content that an
// operator restored is delivered without analysis wherever it is deposited, but
// under a forbidden path it is refused: quarantined, with the reason of the
// path rule.
func TestE2E_aRestoredFileIsStillHeldToThePathRules(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{agent: true, config: pathFilter([]string{`/forbidden/`}, nil)})
	bad := []byte("a malware that an operator restores")
	gm.MarkMalicious(bad)
	in.expect.releaseCopies(bad, 2)
	in.quarantineThenRestore(t, "bad.txt", bad)
	in.waitFor(t, "the restored file to be delivered", func() bool { return in.inOutput("bad.txt") })

	refused := in.drop(t, "forbidden/y.txt", bad)
	in.quarantinedAt(t, refused, "forbidden/y.txt", bad)
	in.drop(t, "elsewhere/z.txt", bad)
	in.waitFor(t, "the same content to be delivered elsewhere", func() bool { return in.inOutput("elsewhere/z.txt") })
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	if !in.reportHas(t, bad, func(e datamodel.Report) bool {
		return e.Malicious && e.MalwareReason == datamodel.FilteredFilePath && strings.HasSuffix(e.Filename, "forbidden/y.txt")
	}) {
		t.Error("the report does not say the restored file was refused for its path")
	}
}

// T56: a restored file of a forbidden type is quarantined again, never
// delivered: the type rule is a refusal, which the restored mark does not waive.
func TestE2E_aRestoredFileOfAForbiddenTypeIsQuarantinedAgain(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{agent: true, more: map[string]map[string]any{
		"filetype_filter": {"forbidden_types": []string{"image/png"}},
	}})
	pic := realPNG(t)
	in.expect.flag(pic)
	path := in.drop(t, "pic.png", pic)
	id := hcquarantine.ComputeCacheID(path, sha256Hex(pic))
	lock := filepath.Join(in.quarantine, id+".lock")
	in.waitFor(t, "the quarantine of the image", func() bool { return !in.gone(lock) && in.gone(path) })
	if msg := in.console.WaitAck(t, in.console.Push(t, "restore", map[string]string{"id": id})); msg != "" {
		t.Fatalf("restore refused: %s", msg)
	}
	in.waitFor(t, "the restored image to be quarantined again", func() bool { return !in.gone(lock) && in.gone(path) })
	if in.outputHas(t, pic) {
		t.Error("the restored image of a forbidden type was delivered")
	}
}

// T56: with forbidden_paths set, a restored ARCHIVE is listed (never analyzed):
// a member that matches makes it malware again, with the member named; an
// archive with no match is delivered, unanalyzed. EXPECTED RED until T56 v2.
func TestE2E_aRestoredArchiveIsCheckedAgainstTheForbiddenPaths(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{agent: true, extract: true, config: pathFilter([]string{`\.exe$`}, nil)})
	detected := []byte(strings.Repeat("a member the service detects ", 40))
	other := []byte(strings.Repeat("an ordinary member ", 40))
	exe := []byte(strings.Repeat("an executable member ", 40))
	gm.MarkMalicious(detected)
	in.expect.flag(exe)
	with := zipOf(t, map[string]string{"run.exe": string(exe), "doc.txt": string(detected)})
	without := zipOf(t, map[string]string{"a.txt": string(detected), "b.txt": string(other)})
	in.expect.archive(with, exe, detected)
	in.expect.archive(without, detected, other)
	in.expect.release(without)

	in.quarantineThenRestore(t, "without.zip", without)
	in.waitFor(t, "the restored archive without a match to be delivered", func() bool { return in.outputHas(t, without) })

	path := in.drop(t, "with.zip", with)
	id := hcquarantine.ComputeCacheID(path, sha256Hex(with))
	lock := filepath.Join(in.quarantine, id+".lock")
	in.waitFor(t, "the quarantine of the archive with a forbidden member", func() bool { return !in.gone(lock) && in.gone(path) })
	if msg := in.console.WaitAck(t, in.console.Push(t, "restore", map[string]string{"id": id})); msg != "" {
		t.Fatalf("restore refused: %s", msg)
	}
	in.waitFor(t, "the restored archive to be quarantined again", func() bool { return !in.gone(lock) && in.gone(path) })
	if in.outputHas(t, with) {
		t.Error("the restored archive with a forbidden member was delivered")
	}
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	in.waitFor(t, "the report to name the forbidden member", func() bool {
		return in.reportHas(t, with, func(e datamodel.Report) bool {
			return slices.ContainsFunc(e.MaliciousExtractedFiles, func(m datamodel.ExtractedFile) bool { return strings.HasSuffix(m.FileName, "run.exe") })
		})
	})
}

// encrypted7z builds a 7z with the embedded 7-Zip whose headers and content are
// encrypted with the given password.
func encrypted7z(t *testing.T, password string, members map[string]string) []byte {
	t.Helper()
	bin := sevenZip(t)
	src := t.TempDir()
	paths := make([]string, 0, len(members))
	for name, content := range members {
		write(t, filepath.Join(src, name), []byte(content))
		paths = append(paths, name)
	}
	archive := filepath.Join(t.TempDir(), "enc.7z")
	if out, err := runCommand(src, bin, append([]string{"a", "-t7z", "-mhe=on", "-p" + password, archive}, paths...)...); err != nil {
		t.Fatalf("cannot build the archive: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(filepath.Clean(archive))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// T56: a restored 7z whose names cannot be listed (encrypted headers, no known
// password) with forbidden_paths set stays in INPUT with an error and is not
// submitted: a restore is the operator's decision, and analysis would only
// quarantine it again. It is not retried on the next pass. EXPECTED RED until
// T56 v2.
func TestE2E_aRestoredArchiveWhoseNamesCannotBeListedStaysInInput(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{agent: true, extract: true, config: mergeMaps(pathFilter([]string{`\.exe$`}, nil), map[string]any{
		"unanalyzable_policy": map[string]any{"encrypted": "mitigate"},
		"monitoring":          map[string]any{"period": "2s"},
	})})
	archive := encrypted7z(t, "not-a-default-password", map[string]string{"a.txt": strings.Repeat("a secret member ", 40)})
	in.expect.flag(archive)
	path := in.drop(t, "secret.7z", archive)
	id := hcquarantine.ComputeCacheID(path, sha256Hex(archive))
	lock := filepath.Join(in.quarantine, id+".lock")
	in.waitFor(t, "the quarantine of the encrypted archive", func() bool { return !in.gone(lock) && in.gone(path) })
	if msg := in.console.WaitAck(t, in.console.Push(t, "restore", map[string]string{"id": id})); msg != "" {
		t.Fatalf("restore refused: %s", msg)
	}
	// The restore removes the container, not the detection report written when
	// the archive was first mitigated: that report is history, and with its
	// container gone it would fail the invariant, so the test removes it.
	for _, report := range globOne(t, filepath.Join(in.output, "tom", "secret.7z-lockreport*.json")) {
		if err := os.Remove(report); err != nil {
			t.Fatal(err)
		}
	}
	before := gm.submitted.Load()
	in.staysInInput(t, path, archive)
	if got := gm.submitted.Load(); got != before {
		t.Errorf("the restored archive was submitted again (%d submissions, %d before)", got, before)
	}
}

// T56: with the quarantine and the deletion off, a refused restored file stays
// in INPUT, reported once and not retried at each pass. The restored mark is
// set while the quarantine is on, then the actions are turned off by the console
// and the content is deposited under a forbidden path.
func TestE2E_aRefusedRestoredFileStaysInInputWithoutRetry(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{agent: true, config: mergeMaps(pathFilter([]string{`/forbidden/`}, nil), map[string]any{
		"monitoring": map[string]any{"period": "2s"},
	})})
	bad := []byte("a malware that an operator restores, then is refused for its path")
	gm.MarkMalicious(bad)
	in.expect.release(bad)
	in.quarantineThenRestore(t, "bad.txt", bad)
	in.waitFor(t, "the restored file to be delivered", func() bool { return in.inOutput("bad.txt") })

	in.console.SetConfig(in.withConf(t, map[string]any{"actions": map[string]any{"quarantine": false, "delete": false}}))
	if msg := in.console.WaitAck(t, in.console.Push(t, "update-config", nil)); msg != "" {
		t.Fatalf("the configuration was refused: %s", msg)
	}
	in.expect.quarantineOff = true
	path := in.drop(t, "forbidden/y.txt", bad)
	in.stillInInputAt(t, path, "forbidden/y.txt")
	if n := len(globOne(t, filepath.Join(in.quarantine, "*.lock"))); n != 0 {
		t.Errorf("%d containers in the quarantine, want none: the quarantine is off", n)
	}
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	count := 0
	for _, e := range in.reportsOf(t, bad) {
		if strings.HasSuffix(e.Filename, "forbidden/y.txt") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("the refused file is reported %d times, want once", count)
	}
}

// rawEntry is one record of a hand-made ZIP: a file or a folder written stored,
// with the sizes it says (declared ones may lie), possibly never listed in the
// central directory, possibly followed by padding.
type rawEntry struct {
	name   string
	data   string
	folder bool
	// unlisted: the local record is written but the central directory does not
	// list it.
	unlisted bool
	// padAfter zero bytes follow the record.
	padAfter int
	// declared overrides the uncompressed size written in both headers (a lie
	// about a member whose packed size is zero), when not zero.
	declared uint32
}

// rawZip writes the entries as a ZIP, record by record, then the central
// directory of the listed ones. trailing follows the end of directory; decoy
// puts a copy of the directory and an end of directory that leads to it in the
// comment of the real one.
type rawZip struct {
	entries  []rawEntry
	trailing []byte
	decoy    bool
}

// u16 and u32 keep the low bits of a length for a header field: the hand-made
// archives of the tests are small.
func u16(n int) uint16 { return uint16(n & 0xFFFF) }

func u32(n int) uint32 { return uint32(n & 0xFFFFFFFF) }

func (z rawZip) bytes() []byte {
	var out, dir []byte
	listed := 0
	for _, e := range z.entries {
		offset := u32(len(out))
		data := []byte(e.data)
		crc := crc32.ChecksumIEEE(data)
		comp, uncomp := u32(len(data)), u32(len(data))
		if e.declared != 0 {
			uncomp = e.declared
		}
		name := e.name
		if e.folder && !strings.HasSuffix(name, "/") {
			name += "/"
		}
		out = le.LittleEndian.AppendUint32(out, 0x04034b50)
		out = le.LittleEndian.AppendUint16(out, 20)
		out = le.LittleEndian.AppendUint16(out, 0)
		out = le.LittleEndian.AppendUint16(out, 0)
		out = le.LittleEndian.AppendUint32(out, 0)
		out = le.LittleEndian.AppendUint32(out, crc)
		out = le.LittleEndian.AppendUint32(out, comp)
		out = le.LittleEndian.AppendUint32(out, uncomp)
		out = le.LittleEndian.AppendUint16(out, u16(len(name)))
		out = le.LittleEndian.AppendUint16(out, 0)
		out = append(out, name...)
		out = append(out, data...)
		out = append(out, make([]byte, e.padAfter)...)
		if e.unlisted {
			continue
		}
		listed++
		dir = le.LittleEndian.AppendUint32(dir, 0x02014b50)
		dir = le.LittleEndian.AppendUint16(dir, 20)
		dir = le.LittleEndian.AppendUint16(dir, 20)
		dir = le.LittleEndian.AppendUint16(dir, 0)
		dir = le.LittleEndian.AppendUint16(dir, 0)
		dir = le.LittleEndian.AppendUint32(dir, 0)
		dir = le.LittleEndian.AppendUint32(dir, crc)
		dir = le.LittleEndian.AppendUint32(dir, comp)
		dir = le.LittleEndian.AppendUint32(dir, uncomp)
		dir = le.LittleEndian.AppendUint16(dir, u16(len(name)))
		dir = le.LittleEndian.AppendUint16(dir, 0)
		dir = le.LittleEndian.AppendUint16(dir, 0)
		dir = le.LittleEndian.AppendUint16(dir, 0)
		dir = le.LittleEndian.AppendUint16(dir, 0)
		dir = le.LittleEndian.AppendUint32(dir, 0)
		dir = le.LittleEndian.AppendUint32(dir, offset)
		dir = append(dir, name...)
	}
	cdOffset := u32(len(out))
	eocd := func(offset uint32, comment []byte) []byte {
		b := le.LittleEndian.AppendUint32(nil, 0x06054b50)
		b = le.LittleEndian.AppendUint16(b, 0)
		b = le.LittleEndian.AppendUint16(b, 0)
		b = le.LittleEndian.AppendUint16(b, u16(listed))
		b = le.LittleEndian.AppendUint16(b, u16(listed))
		b = le.LittleEndian.AppendUint32(b, u32(len(dir)))
		b = le.LittleEndian.AppendUint32(b, offset)
		b = le.LittleEndian.AppendUint16(b, u16(len(comment)))
		return append(b, comment...)
	}
	var comment []byte
	if z.decoy {
		copyAt := cdOffset + u32(len(dir)) + 22
		comment = append(append([]byte(nil), dir...), eocd(copyAt, nil)...)
	}
	out = append(out, dir...)
	out = append(out, eocd(cdOffset, comment)...)
	return append(out, z.trailing...)
}

// T17d: the headers of a ZIP are walked. A record that the directory does not
// list (hidden between two entries, or after an empty folder) is an anomaly: the
// archive stays in INPUT, never delivered. The same archive without that record
// (the control), zero padding between entries, and a stored jar inside a jar are
// honest: the archive is delivered after each of its members was analyzed. A
// second end of directory that also ends the file, hidden in the comment of the
// real one, is a decoy: an anomaly, with or without a byte after the real end.
// One byte after the end of the archive is an anomaly too.
func TestE2E_theHeadersOfAZipAreWalked(t *testing.T) {
	member := []byte(strings.Repeat("a plain member of the archive ", 40))
	second := []byte(strings.Repeat("a plain member of the archive ", 40) + "!")
	evil := strings.Repeat("a record the directory does not list ", 40)
	manifest := []byte("Manifest-Version: 1.0\n")
	inner := rawZip{entries: []rawEntry{{name: "Inner.class", data: string(member)}}}.bytes()
	tests := []struct {
		name string
		zip  rawZip
		// delivered: the archive is delivered, and each of members was analyzed;
		// otherwise it stays in INPUT as damaged.
		delivered bool
		members   [][]byte
	}{
		{name: "an empty folder and a member, with no hidden record (the control)", zip: rawZip{entries: []rawEntry{
			{name: "d", folder: true}, {name: "a.txt", data: string(member)},
		}}, delivered: true, members: [][]byte{member}},
		{name: "a record hidden after an empty folder", zip: rawZip{entries: []rawEntry{
			{name: "d", folder: true}, {name: "evil.exe", data: evil, unlisted: true}, {name: "a.txt", data: string(member)},
		}}},
		{name: "a record hidden between two entries", zip: rawZip{entries: []rawEntry{
			{name: "a.txt", data: string(member)}, {name: "evil.exe", data: evil, unlisted: true}, {name: "b.txt", data: string(second)},
		}}},
		{name: "zero padding between entries", zip: rawZip{entries: []rawEntry{
			{name: "a.txt", data: string(member), padAfter: 64}, {name: "b.txt", data: string(second)},
		}}, delivered: true, members: [][]byte{member, second}},
		{name: "a stored jar inside a jar", zip: rawZip{entries: []rawEntry{
			{name: "inner.jar", data: string(inner)}, {name: "META-INF/MANIFEST.MF", data: string(manifest)},
		}}, delivered: true, members: [][]byte{member, manifest}},
		{name: "one byte after the end of the archive", zip: rawZip{trailing: []byte{0}, entries: []rawEntry{
			{name: "a.txt", data: string(member)},
		}}},
		{name: "a decoy end of directory alone", zip: rawZip{decoy: true, entries: []rawEntry{
			{name: "a.txt", data: string(member)},
		}}},
		{name: "a decoy end of directory and one byte after the real one", zip: rawZip{decoy: true, trailing: []byte{0}, entries: []rawEntry{
			{name: "a.txt", data: string(member)},
		}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := newGMalware(t, false)
			in := startInstance(t, gm, options{extract: true})
			archive := tt.zip.bytes()
			path := in.drop(t, "a.zip", archive)
			if tt.delivered {
				in.expect.archive(archive, tt.members...)
				in.waitFor(t, "the archive to be delivered", func() bool { return in.outputHas(t, archive) })
				for _, m := range tt.members {
					if _, ok := gm.Given(sha256Hex(m)); !ok {
						t.Errorf("a member (%d bytes) was not analyzed", len(m))
					}
				}
				return
			}
			in.staysInInput(t, path, archive)
			in.waitFor(t, "the report of the archive", func() bool { return len(in.reportsOf(t, archive)) > 0 })
			for _, e := range in.reportsOf(t, archive) {
				if !strings.Contains(e.Error, "damaged or inconsistent") {
					t.Errorf("the report of the archive says %q, want it damaged or inconsistent", e.Error)
				}
			}
		})
	}
}

// maxWorkBytes bounds what the work directory may hold at any moment while an
// archive that forges a bomb is judged: the embedded 7-Zip it holds is a few
// MiB, a bomb written out would be gigabytes.
const maxWorkBytes = 64 << 20

// bombJudgmentBound bounds the time to judge a bomb.
const bombJudgmentBound = 30 * time.Second

// treeSize adds up the sizes of the regular files below dir, as they are on the
// disk: a link (the plugin stages the archive it runs 7-Zip on as one) is not
// followed and counts for nothing. A folder that does not exist, or any other
// failure of the walk, is an error; an entry that goes away while it is
// measured (a clean-up in progress) is not, and a walk that ends early for that
// reason gives the partial total of that sample, which is harmless since only
// the largest sample counts.
func treeSize(dir string) (total int64, err error) {
	if _, err = os.Lstat(dir); err != nil {
		return 0, err
	}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if path != dir && errors.Is(walkErr, fs.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, infoErr := d.Info()
		switch {
		case errors.Is(infoErr, fs.ErrNotExist):
			return nil
		case infoErr != nil:
			return infoErr
		}
		total += info.Size()
		return nil
	})
	return total, err
}

// sizeWatch samples the size of a folder from its start to its stop, so that a
// file written and removed within one judgment is still seen.
type sizeWatch struct {
	max  atomic.Int64
	mu   sync.Mutex
	err  error
	quit chan struct{}
	done chan struct{}
	once sync.Once
}

// watchSize samples the work directory of the run every 50 ms until stop or the end of the test.
func watchSize(t *testing.T, in *instance) *sizeWatch {
	t.Helper()
	w := &sizeWatch{quit: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		for {
			size, err := treeSize(in.work)
			switch {
			case err != nil:
				w.mu.Lock()
				if w.err == nil {
					w.err = err
				}
				w.mu.Unlock()
			case size > w.max.Load():
				w.max.Store(size)
			}
			select {
			case <-w.quit:
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()
	t.Cleanup(func() { _, _ = w.stop() })
	return w
}

// stop ends the sampling and returns the largest size seen, and the first
// failure of the walk if any.
func (w *sizeWatch) stop() (largest int64, err error) {
	w.once.Do(func() { close(w.quit) })
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.max.Load(), w.err
}

// assertNoBigWrite fails when the work directory was ever bigger than
// maxWorkBytes, when it could not be measured, or when nothing was ever seen
// there (the sampling would then prove nothing).
func assertNoBigWrite(t *testing.T, w *sizeWatch) {
	t.Helper()
	largest, err := w.stop()
	if err != nil {
		t.Errorf("the work directory could not be measured: %v", err)
	}
	if largest == 0 {
		t.Error("nothing was ever seen in the work directory: the sampling proves nothing")
	}
	if largest > maxWorkBytes {
		t.Errorf("the work directory held %d bytes at some point: the archive was written out", largest)
	}
}

// T48c: a ZIP that forges a bomb is refused, under the default limits, within a
// bounded time and without being written out: 40 members of 90 MB, each declared
// with no packed byte, stay under the per-member and total limits but cannot be
// real.
func TestE2E_aForgedZipOfEmptyPackedMembersIsABomb(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true})
	work := watchSize(t, in)
	entries := make([]rawEntry, 0, 40)
	for i := range 40 {
		entries = append(entries, rawEntry{name: fmt.Sprintf("zeros%02d.bin", i), declared: 90_000_000})
	}
	archive := rawZip{entries: entries}.bytes()
	start := time.Now()
	path := in.drop(t, "bomb.zip", archive)
	in.waitFor(t, "the connector to call the archive a bomb", func() bool { return in.logHas("potential ZipBomb") })
	if judged := time.Since(start); judged > bombJudgmentBound {
		t.Errorf("the bomb was judged in %s, want at most %s", judged, bombJudgmentBound)
	}
	in.staysInInput(t, path, archive)
	assertNoBigWrite(t, work)
}

// T48c: a solid 7z whose first member is larger than the limit for a member and
// made of zeros (23 KB packed for 150 MiB) is left out by the limits of the
// extraction: it stays in INPUT in error and the member is not written out. It
// is not called a bomb: its members within the limit do not declare 3 GB.
func TestE2E_aSolidSevenZipWithAHugeFirstMemberIsLeftOutAndNotWrittenOut(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true})
	work := watchSize(t, in)
	bin := sevenZip(t)
	src := t.TempDir()
	f, err := os.OpenFile(filepath.Clean(filepath.Join(src, "a-zeros.bin")), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(150 << 20); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(src, "b-small.txt"), []byte(strings.Repeat("a small member after the bomb ", 40)), 0o600); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "bomb.7z")
	if out, runErr := runCommand(src, bin, "a", "-t7z", "-ms=on", archivePath, "a-zeros.bin", "b-small.txt"); runErr != nil {
		t.Fatalf("cannot build the archive: %v\n%s", runErr, out)
	}
	archive, err := os.ReadFile(filepath.Clean(archivePath))
	if err != nil {
		t.Fatal(err)
	}
	path := in.drop(t, "bomb.7z", archive)
	in.staysInInput(t, path, archive)
	if !in.logHas("left out by the limits of the extraction") {
		t.Error("the log does not say the member was left out by the limits of the extraction")
	}
	assertNoBigWrite(t, work)
}

// treeSize counts regular files only: a link is no failure and no size, a
// missing folder is an error.
func TestTreeSize(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.bin"), make([]byte, 1000))
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "sub", "b.bin"), make([]byte, 24))
	if err := os.Symlink(filepath.Join(dir, "a.bin"), filepath.Join(dir, "link-to-file")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "sub"), filepath.Join(dir, "link-to-dir")); err != nil {
		t.Fatal(err)
	}
	total, err := treeSize(dir)
	if err != nil || total != 1024 {
		t.Errorf("treeSize = %d, %v; want 1024 and no error: links count for nothing and are no failure", total, err)
	}
	if _, err = treeSize(filepath.Join(dir, "missing")); err == nil {
		t.Error("treeSize of a missing folder is not an error")
	}
}
