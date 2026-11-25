//go:build linux && (e2e || e2e_core)

package core

import (
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// From TestMoveAction_copyModeEveryClassOfFileReachesOutputAsAVerifiedPrivateCopy: in copy mode every file reaches OUTPUT as a private copy, except a file too big to be analyzed that the policy lets through, which goes by path.
func TestE2E_copyModeDeliversAPrivateCopy(t *testing.T) {
	t.Parallel()
	copyMode := map[string]any{"move": map[string]any{"mode": "copy"}}
	large := []byte(strings.Repeat("L", 4096))
	restored := []byte("content restored from quarantine")
	for _, tt := range []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a plain file analyzed",
			scenario: harness.Scenario{
				Config: copyMode,
				Files:  []harness.File{{Path: "d/file.bin", Content: []byte("plain analysed content")}},
				Want:   map[string]harness.Outcome{"d/file.bin": {In: harness.Output, Delivery: harness.Copied}},
			},
		},
		{
			name: "a large file analyzed",
			scenario: harness.Scenario{
				Config: copyMode,
				Files:  []harness.File{{Path: "d/file.bin", Content: large}},
				Want:   map[string]harness.Outcome{"d/file.bin": {In: harness.Output, Delivery: harness.Copied}},
			},
		},
		{
			name: "a restored file",
			scenario: harness.Scenario{
				Agent:  true,
				Config: copyMode,
				Files:  []harness.File{{Path: "d/file.bin", Content: restored, Verdict: harness.Malicious}},
				Steps: []harness.Step{
					harness.Await("d/file.bin", harness.Outcome{In: harness.Quarantine, Malware: datamodel.MalwareDetected}),
					harness.Restore("d/file.bin", ""),
				},
				Want:            map[string]harness.Outcome{"d/file.bin": {In: harness.Output, Restored: true, Delivery: harness.Copied}},
				WantMitigations: []string{"malware"},
			},
		},
		{
			name: "an empty file",
			scenario: harness.Scenario{
				Config: copyMode,
				Files:  []harness.File{{Path: "d/file.bin"}},
				Want:   map[string]harness.Outcome{"d/file.bin": {In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedEmpty, Delivery: harness.Copied}},
			},
		},
		{
			name: "a file too big not analyzed, passed by path",
			scenario: harness.Scenario{
				Config: harness.MergeMaps(map[string]any{
					"max_file_size":       "1KiB",
					"unanalyzable_policy": map[string]any{"too_big": "pass"},
				}, copyMode),
				Files: []harness.File{{Path: "d/file.bin", Content: large}},
				Want:  map[string]harness.Outcome{"d/file.bin": {In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedTooBig, Delivery: harness.SameFile}},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}
