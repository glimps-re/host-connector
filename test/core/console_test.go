//go:build linux && (e2e || e2e_core)

package core

import (
	"testing"

	"github.com/glimps-re/host-connector/test/internal/harness"
)

// The console drives the agent: Stop and Start are executed and acknowledged
// without error. A file dropped while stopped stays in INPUT, and is delivered
// by the prescan of Start.
func TestE2E_consoleStopThenStart(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a file before the stop, one while stopped and one after the start",
			scenario: harness.Scenario{
				Agent: true,
				Files: []harness.File{{Path: "first.txt", Content: []byte("first content")}},
				Steps: []harness.Step{
					harness.Await("first.txt", harness.Outcome{In: harness.Output}),
					harness.Task("stop", ""),
					harness.AddFileToInput(harness.File{Path: "while-stopped.txt", Content: []byte("dropped while stopped")}),
					harness.Await("while-stopped.txt", harness.Outcome{In: harness.Input, NoReport: true}),
					harness.Task("start", ""),
					harness.AddFileToInput(harness.File{Path: "second.txt", Content: []byte("second content")}),
				},
				Want: map[string]harness.Outcome{
					"first.txt":         {In: harness.Output},
					"while-stopped.txt": {In: harness.Output},
					"second.txt":        {In: harness.Output},
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

// P18/P19/Q22: a configuration the connector cannot apply is refused, the task
// is acknowledged with the error, the old configuration keeps working, the
// console is told, and a valid configuration afterwards resolves the error.
func TestE2E_invalidConfigureKeepsTheOldConfiguration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a bogus move mode then a valid configuration",
			scenario: harness.Scenario{
				Agent: true,
				Files: []harness.File{{Path: "before.txt", Content: []byte("before the bad configuration")}},
				Steps: []harness.Step{
					harness.Await("before.txt", harness.Outcome{In: harness.Output}),
					harness.UpdateConfig(map[string]any{"move": map[string]any{"mode": "bogus"}}, "invalid configuration: move"),
					harness.AwaitConsoleError("host-config-rejected"),
					harness.AddFileToInput(harness.File{Path: "during.txt", Content: []byte("while the bad configuration is refused")}),
					harness.Await("during.txt", harness.Outcome{In: harness.Output}),
					harness.UpdateConfig(nil, ""),
					harness.AddFileToInput(harness.File{Path: "after.txt", Content: []byte("after the good configuration")}),
				},
				Want: map[string]harness.Outcome{
					"before.txt": {In: harness.Output},
					"during.txt": {In: harness.Output},
					"after.txt":  {In: harness.Output},
				},
				WantConsoleErrors:   []string{"host-config-rejected"},
				WantConsoleResolved: []string{"host-config-rejected"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// P14, P18: what the connector cannot work with is refused at start, with a
// message that says how to fix it, and not discovered at the first file.
func TestE2E_refusedAtStart(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		config map[string]any
		want   string
	}{
		{name: "work dir under a watched path (P14)", config: map[string]any{"work_dir": "INPUT/work"}, want: "is, or is under, the monitored path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Config:      tt.config,
				WantRefused: tt.want,
			})
		})
	}
}
