//go:build linux && (e2e || e2e_plugins)

package plugins

import (
	"path/filepath"
	"testing"

	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// From TestReportGeneration_theFallbackEventIsRaisedOnceForSeveralSessions: the
// sessions of several owners whose report cannot be generated each get their
// JSON report, and the console is told once.
func TestE2E_theFallbackIsToldOnceForSeveralSessions(t *testing.T) {
	tests := []struct {
		name  string
		users []string
	}{
		{name: "tom, jerry and spike", users: []string{"tom", "jerry", "spike"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := gmalware.New(t)
			in := harness.Start(t, gm, harness.Options{
				Agent: true,
				Plugins: map[string]map[string]any{
					"report":  {"template_path": failingTemplate(t)},
					"session": {"report_retries": 0},
				},
			})
			for _, user := range tt.users {
				dropAs(t, in, user, "a.txt", []byte("a file of "+user))
			}
			for _, user := range tt.users {
				in.WaitFor(t, "the JSON report of "+user, func() bool {
					files := reportFiles(t, in, user)
					return len(files) == 1 && filepath.Ext(files[0]) == ".json"
				})
			}
			if got := fallbackEvents(in); got != 1 {
				t.Errorf("%d session-report-fallback events, want 1", got)
			}
		})
	}
}
