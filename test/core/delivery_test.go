//go:build linux && (e2e || e2e_core)

package core

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// Smoke test of the whole harness: a clean file is delivered, a malicious one
// is quarantined under its SHA256 and leaves INPUT, a detection report stands
// in OUTPUT, and the invariant holds.
func TestE2E_cleanDeliveredMaliciousQuarantined(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a clean file and a malware",
			scenario: harness.Scenario{
				Files: []harness.File{
					{Path: "clean.txt", Content: []byte("some harmless content")},
					{Path: "bad.txt", Content: []byte("this content is a malware for the fake service"), Verdict: harness.Malicious},
				},
				Want: map[string]harness.Outcome{
					"clean.txt": {In: harness.Output},
					"bad.txt":   {In: harness.Quarantine, Malware: datamodel.MalwareDetected},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// While the service is down nothing is delivered and nothing is lost: once it
// answers again the file is analyzed and delivered.
func TestE2E_gmalwareOutageThenRecovery(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a 503 outage",
			scenario: harness.Scenario{
				Config: map[string]any{"monitoring": map[string]any{"period": "2s"}},
				Steps: []harness.Step{
					harness.ServiceDown(503),
					harness.AddFileToInput(harness.File{Path: "a.txt", Content: []byte("content waiting for the service")}),
					harness.AwaitServiceFailure(),
					harness.Await("a.txt", harness.Outcome{In: harness.Input, Error: "injected failure"}),
					harness.ServiceUp(),
				},
				Want: map[string]harness.Outcome{
					"a.txt": {In: harness.Output},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// P6: a file delivered under a name already taken in OUTPUT never overwrites
// it, with a copy or a rename: both contents are delivered, the second under
// another name that the report names. The second file is dropped once the
// first one left INPUT, so the scenario is a conflict in OUTPUT and not a
// rewrite in INPUT.
func TestE2E_destinationConflictKeepsBoth(t *testing.T) {
	for _, mode := range []string{"copy", "rename"} {
		t.Run(mode, func(t *testing.T) {
			gm := gmalware.New(t)
			in := harness.Start(t, gm, harness.Options{Config: map[string]any{
				"move":                map[string]any{"mode": mode},
				"unanalyzable_policy": map[string]any{"empty": "skip"},
			}})
			first, second := []byte("first content"), []byte("second content, same name")
			firstPath := in.Drop(t, "a.txt", first)
			in.WaitFor(t, "the first delivery", func() bool { return in.InOutput("a.txt") })
			in.WaitFor(t, "the first file to leave INPUT", func() bool { return in.Gone(firstPath) })
			secondPath := in.Drop(t, "a.txt", second)
			in.WaitFor(t, "the second file to leave INPUT", func() bool { return in.Gone(secondPath) })
			delivered := harness.GlobOne(t, filepath.Join(in.Output, "tom", "*"))
			if len(delivered) != 2 {
				t.Fatalf("OUTPUT = %v, want both files", delivered)
			}
			got, err := os.ReadFile(filepath.Join(in.Output, "tom", "a.txt"))
			if err != nil || !bytes.Equal(got, first) {
				t.Errorf("a.txt in OUTPUT = %q, %v; want the first content untouched", got, err)
			}
			if !in.OutputHas(t, second) {
				t.Error("the second content was not delivered")
			}
			in.WaitFor(t, "the report to name the conflict", func() bool {
				return slices.ContainsFunc(in.ReportsOf(t, second), func(e datamodel.Report) bool { return e.MoveConflictOf != "" })
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
			gm := gmalware.New(t)
			in := harness.Start(t, gm, harness.Options{Config: map[string]any{
				"monitoring": map[string]any{"disable_fs_watcher": disabled, "period": period},
			}})
			in.WaitMonitoring(t)
			if got := inotifyWatches(in.Cmd.Process.Pid); (got == 0) != disabled {
				t.Errorf("inotify watches = %d with disable_fs_watcher=%v", got, disabled)
			}
			in.Drop(t, "late.txt", []byte("written after the start"))
			in.WaitFor(t, "the delivery", func() bool { return in.InOutput("late.txt") })
		})
	}
}

// P1: a file that is still being written is not analyzed, and what a depositor
// that keeps the file open writes after the delivery does not reach OUTPUT.
// The modification delay is 5 s against a writer that appends every 400 ms:
// with the 1 s default a stall of more than 600 ms is a legitimate delivery of
// a partial file, and the test would be red for no reason.
func TestE2E_slowUploadAndWriterThatKeepsTheFileOpen(t *testing.T) {
	tests := []struct {
		name              string
		modificationDelay string
		chunks            int
		every             time.Duration
	}{
		{name: "12 chunks every 400 ms under a 5 s delay", modificationDelay: "5s", chunks: 12, every: 400 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := gmalware.New(t)
			in := harness.Start(t, gm, harness.Options{Config: map[string]any{"monitoring": map[string]any{"modification_delay": tt.modificationDelay}}})
			path := filepath.Join(in.Input, "tom", "upload.bin")
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
			written := make([]byte, 0, len(chunk)*tt.chunks)
			for range tt.chunks {
				if _, err = f.Write(chunk); err != nil {
					t.Fatal(err)
				}
				written = append(written, chunk...)
				time.Sleep(tt.every)
				if gm.Submitted.Load() != 0 || in.InOutput("upload.bin") {
					t.Fatal("a file still being written was analyzed or delivered")
				}
			}
			in.WaitFor(t, "the delivery once the writer paused", func() bool { return in.InOutput("upload.bin") })
			delivered := filepath.Join(in.Output, "tom", "upload.bin")
			got, err := os.ReadFile(filepath.Clean(delivered))
			if err != nil || !bytes.Equal(got, written) {
				t.Fatalf("delivered %d bytes, %v; want the %d bytes written", len(got), err, len(written))
			}
			if _, err = f.WriteString("written after the delivery"); err != nil {
				t.Fatal(err)
			}
			in.WaitFor(t, "the session report", func() bool { return in.ReportCount() > 0 })
			after, err := os.ReadFile(filepath.Clean(delivered))
			if err != nil || !bytes.Equal(after, written) {
				t.Errorf("OUTPUT changed after the delivery: %d bytes, %v", len(after), err)
			}
		})
	}
}

// P4: with a table of tracked files too small for the load (the least the
// product accepts, 1 MiB, against files with long names), nothing is lost: the
// files that did not fit are found again by the rescan. The pressure event is
// the guard: without it the table never overflowed, and the scenario would
// prove nothing about the cap.
func TestE2E_manyFilesWithATinyTable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		files int
	}{
		{name: "3000 files with long names", files: 3000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := harness.Scenario{
				Agent: true,
				Config: map[string]any{
					"workers":    8,
					"monitoring": map[string]any{"max_tracked_memory": "1MiB", "period": "3s", "modification_delay": "1s"},
				},
				Want:              map[string]harness.Outcome{},
				WantConsoleErrors: []string{"host-monitor-pressure"},
			}
			long := strings.Repeat("n", 180)
			for i := range tt.files {
				f := harness.File{Path: fmt.Sprintf("d%d/%s%05d.txt", i%20, long, i), Content: []byte(fmt.Sprintf("file number %d", i))}
				s.Files = append(s.Files, f)
				s.Want[f.Path] = harness.Outcome{In: harness.Output}
			}
			harness.Run(t, s)
		})
	}
}

// rescanPeriod is the rescan period of the T11 scenarios: the watcher is off, so
// only the rescans find the files.
const rescanPeriod = time.Second

// rescanConfig leaves the files in INPUT (the move is off) and rescans them every
// rescanPeriod.
func rescanConfig() map[string]any {
	return map[string]any{
		"actions":    map[string]any{"move": false},
		"monitoring": map[string]any{"disable_fs_watcher": true, "period": rescanPeriod.String()},
	}
}

// T11: an unchanged file left in INPUT is analyzed once over many rescans (the
// file is watched in INPUT for harness.NotDeliveredWindow, about 12 rescans).
func TestE2E_anUnchangedFileLeftInInputIsAnalyzedOnceOverManyRescans(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		content []byte
	}{
		{name: "about 12 rescans", content: []byte("stays in INPUT, the action does not move it")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Config: rescanConfig(),
				Files:  []harness.File{{Path: "left-behind.bin", Content: tt.content}},
				Want: map[string]harness.Outcome{
					"left-behind.bin": {In: harness.Input, Submissions: 1},
				},
			})
		})
	}
}

// T11: a file left in INPUT that is modified is analyzed again, once per
// version.
func TestE2E_aModifiedFileIsAnalyzedAgain(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		one, two []byte
	}{
		{name: "a longer second version", one: []byte("version one"), two: []byte("version two, longer")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Config: rescanConfig(),
				Files:  []harness.File{{Path: "changing.bin", Content: tt.one}},
				Steps: []harness.Step{
					harness.Await("changing.bin", harness.Outcome{In: harness.Input, Submissions: 1}),
					harness.AddFileToInput(harness.File{Path: "changing.bin", Content: tt.two}),
				},
				Want: map[string]harness.Outcome{
					"changing.bin": {In: harness.Input, Submissions: 1},
				},
			})
		})
	}
}

// T11: while the service fails, a file is retried with growing delays and
// never more often than its backoff allows. Each attempt starts with a search
// of its SHA256, which the outage fails.
func TestE2E_aTransientFailureIsRetriedWithGrowingDelaysAndNeverTooOften(t *testing.T) {
	tests := []struct {
		name     string
		attempts int
	}{
		{name: "three attempts", attempts: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := gmalware.New(t)
			gm.FailWith(503)
			in := harness.Start(t, gm, harness.Options{Config: rescanConfig()})
			in.Drop(t, "flaky.bin", []byte("the service is down"))
			in.WaitFor(t, "the attempts", func() bool { return len(gm.Searches()) >= tt.attempts })
			at := gm.Searches()
			for i := 1; i < len(at); i++ {
				gap := at[i].Sub(at[i-1])
				minimum := time.Duration(float64(rescanPeriod) * float64(uint(1)<<min(i-1, 6)) * 0.8 * 0.8)
				if gap < minimum {
					t.Errorf("attempt %d came %v after the previous one, want at least about %v: a retry must wait for its backoff", i+1, gap, minimum)
				}
			}
			if len(at) >= 3 && at[2].Sub(at[1]) <= at[1].Sub(at[0])/2 {
				t.Errorf("delays %v then %v: the backoff must grow", at[1].Sub(at[0]), at[2].Sub(at[1]))
			}
		})
	}
}
