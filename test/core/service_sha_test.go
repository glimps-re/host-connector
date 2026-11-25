//go:build linux && (e2e || e2e_core)

package core

import (
	"testing"

	"github.com/glimps-re/host-connector/test/internal/harness"
)

// From TestPipeline_aShaReturnedByTheServiceThatDiffersIsAnErrorWithoutAction: a verdict about another SHA256 is an error, and the file stays in INPUT without action.
func TestE2E_aVerdictOnAnotherSHA256IsAnErrorWithoutAction(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a clean verdict on another SHA256",
			scenario: harness.Scenario{
				Files: []harness.File{{Path: "f.bin", Content: []byte("the service answers about another file"), Verdict: harness.OtherSHA256}},
				Want:  map[string]harness.Outcome{"f.bin": {In: harness.Input, Error: "analysis of another content"}},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}
