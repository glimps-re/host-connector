//go:build linux && (e2e || e2e_core)

package core

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	hcquarantine "github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// P16: a quarantined malware is restorable by the console, in either container
// format. It was not delivered before the restore; what is restored comes back
// to INPUT, is not quarantined again, and is delivered once, with the restored
// mark of the report.
func TestE2E_quarantineRestore(t *testing.T) {
	t.Parallel()
	for _, format := range []harness.Format{harness.Tar, harness.Zip} {
		t.Run(string(format), func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Agent:  true,
				Config: map[string]any{"quarantine": map[string]any{"format": string(format)}},
				Files:  []harness.File{{Path: "bad.txt", Content: []byte("this content is a malware, restored later " + string(format)), Verdict: harness.Malicious}},
				Steps: []harness.Step{
					harness.Await("bad.txt", harness.Outcome{In: harness.Quarantine, Malware: datamodel.MalwareDetected, Container: format}),
					harness.Restore("bad.txt", ""),
				},
				Want: map[string]harness.Outcome{
					"bad.txt": {In: harness.Output, Restored: true},
				},
				WantMitigations: []string{"malware"},
			})
		})
	}
}

// T14b: a restore never replaces a file. With another file at the place the
// quarantined one came from, the restore is refused, the other file is
// untouched, the container is kept and the malware is not restored; once the
// place is free the same restore works.
func TestE2E_restoreNeverReplacesAFile(t *testing.T) {
	tests := []struct {
		name string
		bad  []byte
	}{
		{name: "a file kept growing where the malware was", bad: []byte("a malware that is restored onto an occupied place")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := gmalware.New(t)
			in := harness.Start(t, gm, harness.Options{Agent: true})
			gm.MarkMalicious(tt.bad)
			path := in.Drop(t, "bad.txt", tt.bad)
			in.Expect.Release(path, tt.bad)
			id := hcquarantine.ComputeCacheID(path, gmalware.SHA256Hex(tt.bad))
			lock := filepath.Join(in.Quarantine, id+".lock")
			in.WaitFor(t, "the quarantine", func() bool { return !in.Gone(lock) })
			in.WaitFor(t, "the malware to leave INPUT", func() bool { return in.Gone(path) })

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

			msg := in.WaitAck(t, in.Console.Push(t, "restore", map[string]string{"id": id}))
			if !strings.Contains(msg, "destination already exists") {
				t.Fatalf("refusal = %q, want the destination named as existing", msg)
			}
			if in.Gone(lock) {
				t.Error("the container is gone although nothing was restored")
			}
			if got, err := os.ReadFile(filepath.Clean(path)); err != nil || bytes.Contains(got, tt.bad) {
				t.Errorf("the file in the way was changed: %d bytes, %v", len(got), err)
			}
			if in.OutputHas(t, tt.bad) {
				t.Error("the malware reached OUTPUT although its restore was refused")
			}

			stopWriter()
			in.WaitFor(t, "the file in the way to leave INPUT", func() bool { return in.Gone(path) })
			if msg := in.WaitAck(t, in.Console.Push(t, "restore", map[string]string{"id": id})); msg != "" {
				t.Fatalf("the restore was refused once the place was free: %s", msg)
			}
			in.WaitFor(t, "the restored file to be delivered", func() bool { return in.OutputHas(t, tt.bad) })
		})
	}
}

// T14b, Q30: a container whose registry entry is lost (the registry is in
// memory and the connector restarted) is restored only under a watched folder.
// Outside the watched folders the restore is refused and nothing is written.
func TestE2E_restoreWithoutRegistryEntryOutsideWatchedFolders(t *testing.T) {
	t.Parallel()
	elsewhere := t.TempDir()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a restart that watches another folder",
			scenario: harness.Scenario{
				Agent: true,
				Files: []harness.File{{Path: "bad.txt", Content: []byte("a malware whose registry entry is lost by a restart"), Verdict: harness.Malicious}},
				Steps: []harness.Step{
					harness.Await("bad.txt", harness.Outcome{In: harness.Quarantine, Malware: datamodel.MalwareDetected}),
					harness.Restart(map[string]any{"paths": []string{elsewhere}}),
					harness.Restore("bad.txt", "below a watched path"),
				},
				Want: map[string]harness.Outcome{
					"bad.txt": {In: harness.Quarantine, Malware: datamodel.MalwareDetected},
				},
				WantMitigations: []string{"malware"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// T14b, Q30: under a watched folder the same restore is served, the console is
// told that the registry did not know the file, and the restored file is
// delivered once.
func TestE2E_restoreWithoutRegistryEntryUnderAWatchedFolder(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a restart on the same folders",
			scenario: harness.Scenario{
				Agent: true,
				Files: []harness.File{{Path: "bad.txt", Content: []byte("a malware whose registry entry is lost by a restart"), Verdict: harness.Malicious}},
				Steps: []harness.Step{
					harness.Await("bad.txt", harness.Outcome{In: harness.Quarantine, Malware: datamodel.MalwareDetected}),
					harness.Restart(nil),
					harness.Restore("bad.txt", ""),
				},
				Want: map[string]harness.Outcome{
					"bad.txt": {In: harness.Output, Restored: true},
				},
				WantMitigations:   []string{"malware"},
				WantConsoleErrors: []string{"quarantine-restore-unregistered"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// p3/T61: a restored file that is delivered is listed as not analyzed with the
// reason "restored": it was not analyzed, so it must not pass for analyzed.
// The detection that quarantined it earlier stays in the reports, and an
// ordinary file of the same run carries no reason.
func TestE2E_aRestoredFileIsListedAsNotAnalyzed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		bad  []byte
	}{
		{name: "a restored malware beside an ordinary file", bad: []byte("this content is a malware, restored then reported as not analyzed")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := harness.Run(t, harness.Scenario{
				Agent: true,
				Files: []harness.File{{Path: "bad.txt", Content: tt.bad, Verdict: harness.Malicious}},
				Steps: []harness.Step{
					harness.Await("bad.txt", harness.Outcome{In: harness.Quarantine, Malware: datamodel.MalwareDetected}),
					harness.Restore("bad.txt", ""),
					harness.AddFileToInput(harness.File{Path: "clean.txt", Content: []byte("an ordinary file that is analyzed")}),
				},
				Want: map[string]harness.Outcome{
					"bad.txt":   {In: harness.Output, Restored: true},
					"clean.txt": {In: harness.Output},
				},
				WantMitigations: []string{"malware"},
			})
			if !slices.ContainsFunc(harness.ReadReports(in)[gmalware.SHA256Hex(tt.bad)], func(e datamodel.Report) bool { return e.Malicious }) {
				t.Error("the detection that quarantined the file is gone from the reports")
			}
		})
	}
}

// T56: a release is per file. A content that an operator restored, deposited
// again at other paths, is a new file there: refused under a forbidden path,
// with the reason of the path rule, and analyzed and quarantined elsewhere.
func TestE2E_aRestoredContentAtOtherPathsIsANewFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		bad  []byte
	}{
		{name: "deposited under a forbidden path and elsewhere", bad: []byte("a malware that an operator restores")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Agent:  true,
				Config: harness.PathFilter([]string{`/forbidden/`}, nil),
				Files:  []harness.File{{Path: "bad.txt", Content: tt.bad, Verdict: harness.Malicious}},
				Steps: []harness.Step{
					harness.Await("bad.txt", harness.Outcome{In: harness.Quarantine, Malware: datamodel.MalwareDetected}),
					harness.Restore("bad.txt", ""),
					harness.AddFileToInput(
						harness.File{Path: "forbidden/y.txt", Content: tt.bad, Verdict: harness.Malicious},
						harness.File{Path: "elsewhere/z.txt", Content: tt.bad, Verdict: harness.Malicious},
					),
				},
				Want: map[string]harness.Outcome{
					"bad.txt":         {In: harness.Output, Restored: true},
					"forbidden/y.txt": {In: harness.Quarantine, Malware: datamodel.FilteredFilePath},
					"elsewhere/z.txt": {In: harness.Quarantine, Malware: datamodel.MalwareDetected},
				},
				WantMitigations: []string{"malware", "filepath", "malware"},
			})
		})
	}
}

// T56: with the quarantine and the deletion off, a refused restored file stays
// in INPUT, reported once and not retried at each pass. The restored mark is
// set while the quarantine is on, then the actions are turned off by the console
// and the content is deposited under a forbidden path.
func TestE2E_aRefusedRestoredFileStaysInInputWithoutRetry(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		bad  []byte
	}{
		{name: "quarantine and deletion off", bad: []byte("a malware that an operator restores, then is refused for its path")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := harness.Run(t, harness.Scenario{
				Agent: true,
				Config: harness.MergeMaps(harness.PathFilter([]string{`/forbidden/`}, nil), map[string]any{
					"monitoring": map[string]any{"period": "2s"},
				}),
				Files: []harness.File{{Path: "bad.txt", Content: tt.bad, Verdict: harness.Malicious}},
				Steps: []harness.Step{
					harness.Await("bad.txt", harness.Outcome{In: harness.Quarantine, Malware: datamodel.MalwareDetected}),
					harness.Restore("bad.txt", ""),
					harness.Await("bad.txt", harness.Outcome{In: harness.Output, Restored: true}),
					harness.UpdateConfig(map[string]any{"actions": map[string]any{"quarantine": false, "delete": false}}, ""),
					harness.AddFileToInput(harness.File{Path: "forbidden/y.txt", Content: tt.bad, Verdict: harness.Malicious}),
				},
				Want: map[string]harness.Outcome{
					"bad.txt":         {In: harness.Output, Restored: true},
					"forbidden/y.txt": {In: harness.Input, Malware: datamodel.FilteredFilePath},
				},
				WantMitigations: []string{"malware", "filepath"},
			})
			count := 0
			for _, e := range harness.ReadReports(in)[gmalware.SHA256Hex(tt.bad)] {
				if e.Filename == filepath.Join(in.Input, "tom", "forbidden/y.txt") {
					count++
				}
			}
			if count != 1 {
				t.Errorf("the refused file is reported %d times, want once", count)
			}
		})
	}
}
