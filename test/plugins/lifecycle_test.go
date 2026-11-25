//go:build linux && (e2e || e2e_plugins)

package plugins

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// P14, P18: what the connector cannot work with is refused at start, with a
// message that says how to fix it, and not discovered at the first file.
func TestE2E_aPluginMisconfigurationIsRefusedAtStart(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		plugins map[string]map[string]any
		want    string
	}{
		{name: "browser that does not exist (P19)", plugins: map[string]map[string]any{"report": {"chrome_path": "/nonexistent/chromium"}}, want: `plugin "report": browser /nonexistent/chromium: unsafe executable`},
		{name: "7-Zip that does not exist (P18)", plugins: map[string]map[string]any{"extract": {"seven_zip_path": "/nonexistent/7z"}}, want: "install the binary or fix the configured path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Plugins:     tt.plugins,
				WantRefused: tt.want,
			})
		})
	}
}

// processesUnder lists the processes whose command line mentions dir.
func processesUnder(dir string) (found []string) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err == nil && strings.Contains(string(raw), dir) {
			found = append(found, e.Name()+" "+strings.ReplaceAll(string(raw), "\x00", " "))
		}
	}
	return found
}

// A SIGTERM while an archive is being analyzed (the service never answers): the
// process leaves within the shutdown time, with code 0, the work directory is
// gone, no 7-Zip is left and the archive stays in INPUT.
func TestShutdown_sigtermDuringTheAnalysisOfAnArchive(t *testing.T) {
	tests := []struct {
		name    string
		members map[string]string
	}{
		{name: "a zip of two members", members: map[string]string{"m1.txt": strings.Repeat("member one ", 200), "m2.txt": strings.Repeat("member two ", 200)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gmalware.New(t, true)
			in := harness.Start(t, g, harness.Options{Plugins: map[string]map[string]any{"extract": nil}, Timeout: "4s"})
			archive := filepath.Join(in.Input, "tom", "a.zip")
			harness.Write(t, archive, zipOf(t, tt.members))
			in.WaitFor(t, "the analysis of a member to start", func() bool { return g.Submitted.Load() > 0 })
			in.Signal(t, syscall.SIGTERM)
			took, err := in.Wait(t, 4*time.Second+2*time.Second)
			if err != nil {
				t.Errorf("exit = %v, want code 0; log:\n%s", err, in.Stderr.String())
			}
			t.Logf("stopped in %s", took)
			if m := harness.GlobOne(t, filepath.Join(in.Work, "gmhost-*")); len(m) != 0 {
				t.Errorf("work directory left: %v", m)
			}
			if p := processesUnder(in.Work); len(p) != 0 {
				t.Errorf("processes left under the work directory: %v", p)
			}
			if _, err := os.Stat(archive); err != nil {
				t.Errorf("the archive is not in INPUT any more: %v", err)
			}
		})
	}
}
