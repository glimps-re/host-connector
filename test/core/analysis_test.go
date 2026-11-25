//go:build linux && (e2e || e2e_core)

package core

import (
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// P15: a file above max_file_size and an empty file are delivered when the
// policy says pass, and the reports say they were not analyzed.
func TestE2E_unanalyzablePolicyPass(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a too big and an empty file",
			scenario: harness.Scenario{
				Config: map[string]any{
					"max_file_size":       "1MiB",
					"unanalyzable_policy": map[string]any{"too_big": "pass", "empty": "pass"},
				},
				Files: []harness.File{
					{Path: "big.bin", Content: make([]byte, 2<<20)},
					{Path: "empty.txt"},
				},
				Want: map[string]harness.Outcome{
					"big.bin":   {In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedTooBig, ServiceVerdict: harness.NotGiven},
					"empty.txt": {In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedEmpty, ServiceVerdict: harness.NotGiven},
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

// The empty policy beside P15: with no empty key an empty file is delivered,
// marked empty; with skip it stays in INPUT, unreported. Mirrors
// TestPipeline_anEmptyFileIsDeliveredByDefault.
func TestE2E_emptyFilePolicy(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		config map[string]any
		want   harness.Outcome
	}{
		{name: "no empty key", want: harness.Outcome{In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedEmpty}},
		{name: "skip", config: map[string]any{"unanalyzable_policy": map[string]any{"empty": "skip"}}, want: harness.Outcome{In: harness.Input, NoReport: true}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Config: tt.config,
				Files:  []harness.File{{Path: "empty.txt"}},
				Want:   map[string]harness.Outcome{"empty.txt": tt.want},
			})
		})
	}
}

// D6: a detection always wins. A result that carries a detection and an
// analysis error is malware: quarantined, never delivered, never left as a plain
// error; the report says malicious with the reason malware-detected, and the
// console is told it is a malware.
func TestE2E_aDetectionWithAnAnalysisErrorIsMalware(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a plain file",
			scenario: harness.Scenario{
				Agent: true,
				Files: []harness.File{
					{Path: "bad.txt", Content: []byte("a malware the service also fails to finish analyzing"), Verdict: harness.MaliciousWithError},
				},
				Want: map[string]harness.Outcome{
					"bad.txt": {In: harness.Quarantine, Malware: datamodel.MalwareDetected, Error: "could not be analyzed"},
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

// T51b: analysis_error decides what becomes of a file whose analysis failed:
// error keeps it in INPUT, mitigate quarantines it as a malware (reason
// analysis-error), pass delivers it marked not analyzed. A detection always
// wins: with the error beside it, the file is a malware under every value.
func TestE2E_analysisErrorPolicy(t *testing.T) {
	t.Parallel()
	detected := harness.Outcome{In: harness.Quarantine, Malware: datamodel.MalwareDetected, Error: "could not be analyzed"}
	for _, tt := range []struct {
		value       string
		broken      harness.Outcome
		mitigations []string
	}{
		{value: "error", broken: harness.Outcome{In: harness.Input, Error: "could not be analyzed"}, mitigations: []string{"malware"}},
		{value: "mitigate", broken: harness.Outcome{In: harness.Quarantine, Malware: datamodel.AnalysisError, Error: "could not be analyzed"}, mitigations: []string{"malware", "error"}},
		{value: "pass", broken: harness.Outcome{In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedAnalysisError}, mitigations: []string{"malware"}},
	} {
		t.Run(tt.value, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Agent:  true,
				Config: map[string]any{"unanalyzable_policy": map[string]any{"analysis_error": tt.value}},
				Files: []harness.File{
					{Path: "broken.txt", Content: []byte("a file whose analysis fails"), Verdict: harness.AnalysisError},
					{Path: "detected.txt", Content: []byte("a malware whose analysis also fails"), Verdict: harness.MaliciousWithError},
				},
				Want: map[string]harness.Outcome{
					"broken.txt":   tt.broken,
					"detected.txt": detected,
				},
				WantMitigations: tt.mitigations,
			})
		})
	}
}
