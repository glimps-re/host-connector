//go:build linux && (e2e || e2e_core)

package core

import (
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// emptyPassWithRename is the start of the refusal of unanalyzable_policy.empty
// at pass with move.mode at rename: it names both keys.
const emptyPassWithRename = "unanalyzable_policy.empty: pass delivers an empty file as a new empty file, which needs move.mode copy"

// From TestConfigure_emptyPassWithRenameIsRefusedAndTheRunningOneKept: the
// console sends empty at pass with the move in rename mode; the task is
// acknowledged with the refusal and the running configuration keeps
// delivering.
func TestE2E_anEmptyPassWithRenameIsRefusedAndTheRunningOneKept(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "move on, rename, pass",
			scenario: harness.Scenario{
				Agent: true,
				Files: []harness.File{{Path: "before.txt", Content: []byte("before the refused configuration")}},
				Steps: []harness.Step{
					harness.Await("before.txt", harness.Outcome{In: harness.Output}),
					harness.UpdateConfig(map[string]any{
						"move":                map[string]any{"mode": "rename"},
						"unanalyzable_policy": map[string]any{"empty": "pass"},
					}, emptyPassWithRename),
					harness.AddFileToInput(harness.File{Path: "after.txt", Content: []byte("after the refused configuration")}),
				},
				Want: map[string]harness.Outcome{
					"before.txt": {In: harness.Output},
					"after.txt":  {In: harness.Output, Delivery: harness.Copied},
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

// From TestPrepare_theEmptyPolicyAndTheMoveMode: the mode of the move counts
// only while the move is on, and only empty at pass with rename is refused at
// start. Without the empty key, rename skips the empty files.
func TestE2E_theEmptyPolicyAndTheMoveMode(t *testing.T) {
	t.Parallel()
	content := []byte("a file delivered whatever the empty policy")
	tests := []struct {
		name        string
		config      map[string]any
		want        harness.Outcome
		wantEmpty   harness.Outcome
		wantRefused string
	}{
		{
			name:      "move on, copy, pass",
			config:    map[string]any{"move": map[string]any{"mode": "copy"}, "unanalyzable_policy": map[string]any{"empty": "pass"}},
			want:      harness.Outcome{In: harness.Output},
			wantEmpty: harness.Outcome{In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedEmpty},
		},
		{
			name:      "move on, no mode, absent",
			want:      harness.Outcome{In: harness.Output},
			wantEmpty: harness.Outcome{In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedEmpty},
		},
		{
			name:      "move on, rename, absent",
			config:    map[string]any{"move": map[string]any{"mode": "rename"}},
			want:      harness.Outcome{In: harness.Output},
			wantEmpty: harness.Outcome{In: harness.Input, NoReport: true},
		},
		{
			name:      "move on, rename, skip",
			config:    map[string]any{"move": map[string]any{"mode": "rename"}, "unanalyzable_policy": map[string]any{"empty": "skip"}},
			want:      harness.Outcome{In: harness.Output},
			wantEmpty: harness.Outcome{In: harness.Input, NoReport: true},
		},
		{
			name:      "move on, rename, mitigate",
			config:    map[string]any{"move": map[string]any{"mode": "rename"}, "unanalyzable_policy": map[string]any{"empty": "mitigate"}},
			want:      harness.Outcome{In: harness.Output},
			wantEmpty: harness.Outcome{In: harness.Quarantine, Malware: datamodel.Empty},
		},
		{
			name:        "move on, rename, pass",
			config:      map[string]any{"move": map[string]any{"mode": "rename"}, "unanalyzable_policy": map[string]any{"empty": "pass"}},
			wantRefused: emptyPassWithRename,
		},
		{
			name:      "move off, rename, pass",
			config:    map[string]any{"actions": map[string]any{"move": false}, "move": map[string]any{"mode": "rename"}, "unanalyzable_policy": map[string]any{"empty": "pass"}},
			want:      harness.Outcome{In: harness.Input},
			wantEmpty: harness.Outcome{In: harness.Input, NotAnalyzed: datamodel.NotAnalyzedEmpty},
		},
		{
			name:      "move off, rename, absent",
			config:    map[string]any{"actions": map[string]any{"move": false}, "move": map[string]any{"mode": "rename"}},
			want:      harness.Outcome{In: harness.Input},
			wantEmpty: harness.Outcome{In: harness.Input, NotAnalyzed: datamodel.NotAnalyzedEmpty},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := harness.Scenario{Config: tt.config, WantRefused: tt.wantRefused}
			if tt.wantRefused == "" {
				s.Files = []harness.File{{Path: "a.txt", Content: content}, {Path: "empty.txt"}}
				s.Want = map[string]harness.Outcome{"a.txt": tt.want, "empty.txt": tt.wantEmpty}
			}
			harness.Run(t, s)
		})
	}
}
