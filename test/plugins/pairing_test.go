//go:build linux && (e2e || e2e_plugins)

package plugins

import (
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// From TestPipeline_everyOnStartScanFileIsFollowedByExactlyOneOnFileScanned: a file waived by a plugin, a damaged archive or a plain file under extraction closes its session with one report.
func TestE2E_everyWayOutOfThePipelineWithPluginsClosesTheSession(t *testing.T) {
	t.Parallel()
	plain := zipOf(t, map[string]string{"a.txt": strings.Repeat("a plain member ", 100)})
	for _, tt := range []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a file waived by filetype_filter",
			scenario: harness.Scenario{
				Plugins:            map[string]map[string]any{"filetype_filter": {"skipped_types": []string{"image/png"}}},
				Files:              []harness.File{{Path: "p.png", Content: realPNG(t)}},
				Want:               map[string]harness.Outcome{"p.png": {In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedPolicySkipped}},
				WantSessionReports: 1,
			},
		},
		{
			name: "a damaged archive",
			scenario: harness.Scenario{
				Plugins:            map[string]map[string]any{"extract": nil},
				Files:              []harness.File{{Path: "a.zip", Content: plain[:len(plain)*66/100]}},
				Want:               map[string]harness.Outcome{"a.zip": {In: harness.Input, Error: "damaged or inconsistent"}},
				WantSessionReports: 1,
			},
		},
		{
			name: "a file that is not an archive",
			scenario: harness.Scenario{
				Plugins:            map[string]map[string]any{"extract": nil},
				Files:              []harness.File{{Path: "f.txt", Content: []byte(strings.Repeat("plain text, not an archive ", 100))}},
				Want:               map[string]harness.Outcome{"f.txt": {In: harness.Output}},
				WantSessionReports: 1,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}
