//go:build linux && (e2e || e2e_plugins)

package plugins

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// chromePathDeprecated is the warning of the report plugin for a chrome_path
// left in the configuration.
const chromePathDeprecated = "chrome_path is deprecated and ignored: the report plugin renders PDFs without a browser; remove it from the configuration"

// P13: with the report plugin, the session report is a PDF that bears the
// reserved name in the exports, not a JSON file. A chrome_path left in the
// configuration is ignored with a warning.
func TestE2E_sessionReportIsAPDF(t *testing.T) {
	gm := gmalware.New(t)
	bad := []byte("a malware that makes a report")
	gm.MarkMalicious(bad)
	in := harness.Start(t, gm, harness.Options{Agent: true, Plugins: map[string]map[string]any{"report": {"chrome_path": "/nonexistent/chromium"}}})
	in.Drop(t, "bad.txt", bad)
	pattern := filepath.Join(in.Export, "tom", datamodel.SessionReportPrefix+"tom-*.pdf")
	in.WaitFor(t, "the PDF report in the exports", func() bool { return len(harness.GlobOne(t, pattern)) > 0 })
	reports := harness.GlobOne(t, filepath.Join(in.Export, "tom", "*"))
	if len(reports) != 1 {
		t.Fatalf("exports = %v, want the PDF report only", reports)
	}
	name := filepath.Base(reports[0])
	if !strings.HasPrefix(name, datamodel.SessionReportPrefix+"tom-") || filepath.Ext(name) != ".pdf" {
		t.Errorf("report name = %q, want %stom-<time>.pdf", name, datamodel.SessionReportPrefix)
	}
	raw, err := os.ReadFile(filepath.Clean(reports[0]))
	if err != nil || !bytes.HasPrefix(raw, []byte("%PDF")) {
		t.Errorf("the report is not a PDF: %v", err)
	}
	if slices.Contains(in.Console.ErrorTypes(), "session-report-fallback") {
		t.Error("the connector fell back to JSON although the renderer works")
	}
	if !in.LogHas(chromePathDeprecated) {
		t.Error("the log does not warn that chrome_path is deprecated")
	}
}

// fallbackEvents counts the session-report-fallback errors the console was
// sent.
func fallbackEvents(in *harness.Instance) (n int) {
	for _, typ := range in.Console.ErrorTypes() {
		if typ == "session-report-fallback" {
			n++
		}
	}
	return n
}

// failingTemplate writes a report template that parses at start and fails at
// every execution, and returns its path.
func failingTemplate(t *testing.T) string {
	t.Helper()
	templ := filepath.Join(t.TempDir(), "report.html.tmpl")
	harness.Write(t, templ, []byte("<html>{{ .NoSuchField }}</html>"))
	return templ
}

// failedAttempt is logged by the session plugin for each failed generation of
// a report.
const failedAttempt = "failed to write the session report, it will be tried again"

// P12, and from
// TestReportGeneration_aGeneratorThatFailsNTimesGivesTheReportOrTheJSONFallback:
// a generator that fails is tried again report_retries times, once per tick of
// the session monitor; when it fails once more the report is not lost: the
// session writes the JSON fallback under the reserved name, the console is
// told, and the delivered files are in that report. The template parses at
// start and fails at every execution; the cases where a later attempt succeeds
// are covered by the session plugin test above.
func TestE2E_failingReportGeneratorFallsBackToJSON(t *testing.T) {
	tests := []struct {
		name         string
		retries      int
		wantAttempts int
	}{
		{name: "one retry", retries: 1, wantAttempts: 2},
		{name: "3 retries", retries: 3, wantAttempts: 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := gmalware.New(t)
			in := harness.Start(t, gm, harness.Options{
				Agent: true,
				Plugins: map[string]map[string]any{
					"report":  {"template_path": failingTemplate(t)},
					"session": {"report_retries": tt.retries, "report_timeout": "30s"},
				},
			})
			content := []byte("a file whose report cannot be rendered")
			in.Drop(t, "a.txt", content)
			in.WaitFor(t, "the JSON fallback", func() bool {
				return len(harness.GlobOne(t, filepath.Join(in.Export, "tom", datamodel.SessionReportPrefix+"*.json"))) == 1
			})
			in.WaitFor(t, "the console to be told", func() bool { return slices.Contains(in.Console.ErrorTypes(), "session-report-fallback") })
			in.WaitFor(t, "the delivery", func() bool { return in.InOutput("a.txt") })
			if reports := harness.GlobOne(t, filepath.Join(in.Export, "tom", "*")); len(reports) != 1 {
				t.Errorf("exports = %v, want the JSON report only", reports)
			}
			if got := fallbackEvents(in); got != 1 {
				t.Errorf("%d session-report-fallback events, want 1", got)
			}
			if got := in.ReportsOf(t, content); len(got) != 1 {
				t.Errorf("entries for the file in the fallback = %d, want 1", len(got))
			}
			if got := strings.Count(in.Stderr.String(), failedAttempt); got != tt.wantAttempts {
				t.Errorf("%d failed attempts, want %d: a failure is tried again report_retries times", got, tt.wantAttempts)
			}
		})
	}
}
