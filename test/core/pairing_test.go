//go:build linux && (e2e || e2e_core)

package core

import (
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// From TestPipeline_everyOnStartScanFileIsFollowedByExactlyOneOnFileScanned: whatever way a file leaves the pipeline, its session closes with one report.
func TestE2E_everyWayOutOfThePipelineClosesTheSession(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a clean file",
			scenario: harness.Scenario{
				Files:              []harness.File{{Path: "f.bin", Content: []byte("a clean file")}},
				Want:               map[string]harness.Outcome{"f.bin": {In: harness.Output}},
				WantSessionReports: 1,
			},
		},
		{
			name: "a malware",
			scenario: harness.Scenario{
				Files:              []harness.File{{Path: "f.bin", Content: []byte("a malware"), Verdict: harness.Malicious}},
				Want:               map[string]harness.Outcome{"f.bin": {In: harness.Quarantine, Malware: datamodel.MalwareDetected}},
				WantSessionReports: 1,
			},
		},
		{
			name: "a submission failure",
			scenario: harness.Scenario{
				Steps: []harness.Step{
					harness.ServiceDown(503),
					harness.AddFileToInput(harness.File{Path: "f.bin", Content: []byte("a file the service fails to take")}),
					harness.AwaitServiceFailure(),
				},
				Want:               map[string]harness.Outcome{"f.bin": {In: harness.Input, Error: "injected failure"}},
				WantSessionReports: 1,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}
