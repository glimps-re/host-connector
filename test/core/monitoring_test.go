//go:build linux && (e2e || e2e_core)

package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// From TestMonitor_processDue ("a vanished file is forgotten without
// callback"): a file removed before the end of its modification delay is never
// submitted and is in no report; a file dropped after it, whose report closes
// the window, is. harness.Start: a step cannot remove a file.
func TestE2E_aFileRemovedBeforeTheEndOfItsDelayIsForgotten(t *testing.T) {
	tests := []struct {
		name          string
		delay         string
		gone, control []byte
	}{
		{name: "removed 1 s into a 5 s delay", delay: "5s", gone: []byte("removed while it waits"), control: []byte("dropped after the removal")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := gmalware.New(t, false)
			in := harness.Start(t, gm, harness.Options{Config: map[string]any{"monitoring": map[string]any{"modification_delay": tt.delay}}})
			in.WaitFor(t, "the monitoring to start", func() bool { return in.LogHas(harness.MonitoringStarted) })
			path := in.Drop(t, "gone.txt", tt.gone)
			time.Sleep(time.Second)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			in.Drop(t, "control.txt", tt.control)
			in.WaitFor(t, "the report of the file dropped after", func() bool { return len(harness.ReadReports(in)[gmalware.SHA256Hex(tt.control)]) > 0 })
			if names := gm.SubmittedNames(tt.gone); len(names) != 0 {
				t.Errorf("the removed file was submitted as %q", names)
			}
			if got := in.ReportsOf(t, tt.gone); len(got) != 0 {
				t.Errorf("the removed file has %d report entries, want none", len(got))
			}
		})
	}
}

// From TestMonitor_mkdirOfTwoHundredLevelsAskForBoundedWalks: a file at the
// bottom of 200 levels of folders made at once is delivered.
func TestE2E_aFileAtTheBottomOfTwoHundredLevelsIsDelivered(t *testing.T) {
	t.Parallel()
	deep := strings.Repeat("d/", 200) + "f.bin"
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "200 levels",
			scenario: harness.Scenario{
				Files: []harness.File{{Path: deep, Content: []byte("at the bottom of 200 folders")}},
				Want: map[string]harness.Outcome{
					deep: {In: harness.Output},
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

// From TestMonitor_walkRootCapsTheUnreadableFolders: folders that cannot be
// read do not stop the rescan, which finds and delivers the readable file after
// them. harness.Start: a scenario cannot make a folder unreadable.
func TestE2E_unreadableFoldersDoNotHideTheFileBesideThem(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission denied cannot be triggered as root")
	}
	tests := []struct {
		name    string
		locked  int
		content []byte
	}{
		{name: "120 folders in mode 000", locked: 120, content: []byte("readable beside the locked folders")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := gmalware.New(t, false)
			in := harness.Start(t, gm, harness.Options{Config: map[string]any{"monitoring": map[string]any{"disable_fs_watcher": true, "period": "1s"}}})
			for i := range tt.locked {
				dir := filepath.Join(in.Input, "tom", fmt.Sprintf("locked%03d", i))
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dir, 0o000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Chmod(dir, 0o700); err != nil {
						t.Errorf("could not restore %s: %v", dir, err)
					}
				})
			}
			in.Drop(t, "ok.txt", tt.content)
			in.WaitFor(t, "the delivery of the readable file", func() bool { return in.InOutput("ok.txt") })
		})
	}
}
