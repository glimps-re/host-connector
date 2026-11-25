//go:build linux && (e2e || e2e_plugins)

package plugins

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	hcquarantine "github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// sessionStart returns the start of the session of user, read from the log line
// that opens it.
func sessionStart(in *harness.Instance, user string) (time.Time, bool) {
	for line := range strings.SplitSeq(in.Stderr.String(), "\n") {
		var l struct {
			Msg     string `json:"msg"`
			Session string `json:"session_id"`
			Start   string `json:"start_time"`
		}
		if json.Unmarshal([]byte(line), &l) != nil || l.Msg != "new session created" || l.Session != user {
			continue
		}
		start, err := time.Parse(time.RFC3339, l.Start)
		return start, err == nil
	}
	return time.Time{}, false
}

// From TestReportGeneration_anExistingFileAtTheNameOfTheReportIsLeftIntact: a
// file, a link or a dangling link already at the name of the session report is
// left as it is, and what a link points to is not written through: the report
// is written under another name, with an error in the log, and no temporary
// file is left. harness.Start: the name holds the start of the session, known
// once the session is open.
func TestE2E_aFileAtTheNameOfTheSessionReportIsLeftIntact(t *testing.T) {
	precious := []byte("PRECIOUS")
	tests := []struct {
		name string
		// setup puts something at the name of the report; outside is a path out
		// of the exports.
		setup func(t *testing.T, at, outside string)
		link  bool
		// wantOutside is what outside holds afterwards, nil for nothing.
		wantOutside []byte
	}{
		{
			name:  "regular file",
			setup: func(t *testing.T, at, _ string) { harness.Write(t, at, precious) },
		},
		{
			name: "link to a file elsewhere",
			setup: func(t *testing.T, at, outside string) {
				harness.Write(t, outside, precious)
				if err := os.Symlink(outside, at); err != nil {
					t.Fatal(err)
				}
			},
			link:        true,
			wantOutside: precious,
		},
		{
			name: "dangling link",
			setup: func(t *testing.T, at, outside string) {
				if err := os.Symlink(outside, at); err != nil {
					t.Fatal(err)
				}
			},
			link: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := gmalware.New(t, false)
			in := harness.Start(t, gm, harness.Options{Plugins: map[string]map[string]any{"session": {"delay": "1h"}}})
			in.Drop(t, "a.txt", []byte("a file whose session report finds its name taken"))
			var start time.Time
			in.WaitFor(t, "the session of tom to open", func() bool {
				var ok bool
				start, ok = sessionStart(in, "tom")
				return ok
			})
			dir := filepath.Join(in.Export, "tom")
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			at := filepath.Join(dir, fmt.Sprintf("%stom-%d.json", datamodel.SessionReportPrefix, start.Unix()))
			outside := filepath.Join(t.TempDir(), "outside.json")
			tt.setup(t, at, outside)
			// The harness reads every file of the exports as a session report:
			// what the test put there goes before the end of the test.
			t.Cleanup(func() {
				if err := os.Remove(at); err != nil {
					t.Error(err)
				}
			})
			in.WaitFor(t, "the delivery", func() bool { return in.InOutput("a.txt") })
			in.Signal(t, syscall.SIGTERM)
			if _, err := in.Wait(t, 20*time.Second); err != nil {
				t.Fatalf("the connector did not stop cleanly: %v", err)
			}

			info, err := os.Lstat(at)
			switch {
			case err != nil:
				t.Fatalf("what was at the name of the report is gone: %v", err)
			case tt.link && info.Mode()&os.ModeSymlink == 0:
				t.Error("the link was replaced")
			case !tt.link:
				if got, _ := os.ReadFile(filepath.Clean(at)); !bytes.Equal(got, precious) {
					t.Errorf("the file at the name of the report holds %q, want it intact", got)
				}
			}
			got, err := os.ReadFile(filepath.Clean(outside))
			switch {
			case tt.wantOutside == nil && err == nil:
				t.Errorf("the target of the link was created through it, holding %q", got)
			case tt.wantOutside != nil && !bytes.Equal(got, tt.wantOutside):
				t.Errorf("the target of the link holds %q (%v), want it intact", got, err)
			}
			var written []string
			for _, p := range harness.GlobOne(t, filepath.Join(dir, "*")) {
				switch {
				case strings.HasPrefix(filepath.Base(p), hcquarantine.TempPrefix):
					t.Errorf("temporary file %s left behind", filepath.Base(p))
				case p != at && filepath.Base(p) != hcquarantine.StagingDir:
					written = append(written, p)
				}
			}
			if len(written) != 1 {
				t.Fatalf("reports written beside it: %v, want one under another name", written)
			}
			raw, err := os.ReadFile(filepath.Clean(written[0]))
			if err != nil || !strings.Contains(string(raw), "a.txt") {
				t.Errorf("the report written under another name does not name a.txt (%v): %s", err, raw)
			}
			if !in.LogHas("already existed: written as") {
				t.Error("the log has no error about the name already taken")
			}
		})
	}
}
