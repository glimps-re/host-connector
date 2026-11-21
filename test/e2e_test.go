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
	"path/filepath"
	"slices"
	"strconv"
	"strings"
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
	waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
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
	waitFor(t, "the connector to meet the outage", func() bool { return gm.failed.Load() > 0 })
	waitFor(t, "the failure to be reported", func() bool { return in.logHas("could not analyze file") })
	if in.inOutput("a.txt") {
		t.Error("a file was delivered without analysis during the outage")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the file left INPUT during the outage: %v", err)
	}
	gm.FailWith(0)
	waitFor(t, "the delivery after the recovery", func() bool { return in.inOutput("a.txt") })
	waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
}

// The console drives the agent: Stop and Start are executed and acknowledged
// without error, and files are analyzed again after Start.
func TestE2E_consoleStopThenStart(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{agent: true})
	in.drop(t, "first.txt", []byte("first content"))
	waitFor(t, "the first delivery", func() bool { return in.inOutput("first.txt") })
	for _, action := range []string{"stop", "start"} {
		if msg := in.console.WaitAck(t, in.console.Push(t, action, nil)); msg != "" {
			t.Fatalf("%s acknowledged with the error %q", action, msg)
		}
	}
	in.drop(t, "second.txt", []byte("second content"))
	waitFor(t, "the delivery after the restart", func() bool { return in.inOutput("second.txt") })
	waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
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
			waitFor(t, "the first delivery", func() bool { return in.inOutput("a.txt") })
			waitFor(t, "the first file to leave INPUT", func() bool { return in.gone(firstPath) })
			secondPath := in.drop(t, "a.txt", second)
			waitFor(t, "the second file to leave INPUT", func() bool { return in.gone(secondPath) })
			delivered := globOne(t, filepath.Join(in.output, "tom", "*"))
			if len(delivered) != 2 {
				t.Fatalf("OUTPUT = %v, want both files", delivered)
			}
			got, err := os.ReadFile(filepath.Join(in.output, "tom", "a.txt"))
			if err != nil || !bytes.Equal(got, first) {
				t.Errorf("a.txt in OUTPUT = %q, %v; want the first content untouched", got, err)
			}
			waitFor(t, "the report to name the conflict", func() bool {
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
			waitFor(t, "the monitoring to start", func() bool { return in.logHas("monitoring successfully completed") })
			if got := inotifyWatches(in.cmd.Process.Pid); (got == 0) != disabled {
				t.Errorf("inotify watches = %d with disable_fs_watcher=%v", got, disabled)
			}
			in.drop(t, "late.txt", []byte("written after the start"))
			waitFor(t, "the delivery", func() bool { return in.inOutput("late.txt") })
		})
	}
}

// P17: the folders a delivered file leaves empty in INPUT are removed once the
// session report is written.
func TestE2E_emptyFoldersRemoved(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{session: map[string]any{"remove_empty_dirs": true}})
	in.drop(t, "deep/er/a.txt", []byte("in a subfolder"))
	waitFor(t, "the delivery", func() bool { return in.inOutput("deep/er/a.txt") })
	waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	waitFor(t, "the empty folders to go", func() bool { return in.gone(filepath.Join(in.input, "tom", "deep")) })
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
	waitFor(t, "both files to be delivered", func() bool { return in.inOutput("big.bin") && in.inOutput("empty.txt") })
	waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
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
	waitFor(t, "the first delivery", func() bool { return in.inOutput("before.txt") })

	in.console.SetConfig(in.withConf(t, map[string]any{"move": map[string]any{"mode": "bogus"}}))
	if msg := in.console.WaitAck(t, in.console.Push(t, "update-config", nil)); msg == "" {
		t.Error("an invalid configuration was acknowledged without error")
	}
	waitFor(t, "the console to be told of the rejection", func() bool { return slices.Contains(in.console.errorTypes(), "host-config-rejected") })
	in.drop(t, "during.txt", []byte("while the bad configuration is refused"))
	waitFor(t, "the old configuration to keep delivering", func() bool { return in.inOutput("during.txt") })

	in.console.SetConfig(in.withConf(t, nil))
	if msg := in.console.WaitAck(t, in.console.Push(t, "update-config", nil)); msg != "" {
		t.Fatalf("the valid configuration was refused: %s", msg)
	}
	waitFor(t, "the rejection to be resolved", func() bool { return slices.Contains(in.console.resolvedTypes(), "host-config-rejected") })
	in.drop(t, "after.txt", []byte("after the good configuration"))
	waitFor(t, "the delivery after the good configuration", func() bool { return in.inOutput("after.txt") })
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
	waitFor(t, "the clean archive to be delivered", func() bool { return in.inOutput("good.zip") })
	waitFor(t, "the malicious archive to leave INPUT", func() bool { return in.gone(badPath) })
	waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	if in.inOutput("bad.zip") {
		t.Error("the archive with a malicious member reached OUTPUT")
	}
	if m := globOne(t, filepath.Join(in.quarantine, "*.lock")); len(m) != 1 {
		t.Errorf("quarantine = %v, want the malicious archive only", m)
	}
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
			path := in.drop(t, "bad.txt", bad)
			id := hcquarantine.ComputeCacheID(path, sha256Hex(bad))
			lock := filepath.Join(in.quarantine, id+".lock")
			waitFor(t, "the quarantine", func() bool { return !in.gone(lock) })
			waitFor(t, "the malware to leave INPUT", func() bool { return in.gone(path) })
			if in.inOutput("bad.txt") {
				t.Fatal("the malware was delivered before the restore")
			}
			head, err := os.ReadFile(filepath.Clean(lock))
			if err != nil {
				t.Fatal(err)
			}
			head = head[:min(4, len(head))]
			if isZip := bytes.HasPrefix(head, []byte("PK")); isZip != (format == "zip") {
				t.Errorf("container starts with %q for the format %s", head, format)
			}
			if msg := in.console.WaitAck(t, in.console.Push(t, "restore", map[string]string{"id": id})); msg != "" {
				t.Fatalf("restore refused: %s", msg)
			}
			waitFor(t, "the restored file to be delivered", func() bool { return in.inOutput("bad.txt") })
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
	waitFor(t, "the delivery once the writer paused", func() bool { return in.inOutput("upload.bin") })
	delivered := filepath.Join(in.output, "tom", "upload.bin")
	got, err := os.ReadFile(filepath.Clean(delivered))
	if err != nil || !bytes.Equal(got, written) {
		t.Fatalf("delivered %d bytes, %v; want the %d bytes written", len(got), err, len(written))
	}
	if _, err = f.WriteString("written after the delivery"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
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
			waitFor(t, "the bomb to be reported", func() bool { return len(in.reportsOf(t, bomb)) > 0 })
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
