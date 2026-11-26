//go:build linux && (e2e || e2e_plugins) && realbrowser

package plugins

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// requireChromium returns the path of a browser for the report plugin. The
// realbrowser tag asks for these scenarios, so it fails the test as root
// (Chrome refuses its sandbox) or when no browser is found.
func requireChromium(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatal("Chrome refuses its sandbox as root: run the browser scenarios as a regular user")
	}
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	t.Fatal("no browser found (chromium, chromium-browser, google-chrome)")
	return ""
}

// P13: with the report plugin and a real browser, the session report is a PDF
// that bears the reserved name in the exports, not a JSON file.
func TestE2E_sessionReportGeneratedByTheBrowser(t *testing.T) {
	tests := []struct {
		name string
		bad  []byte
	}{
		{name: "the report of a malware", bad: []byte("a malware that makes a report")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chrome := requireChromium(t)
			gm := gmalware.New(t)
			gm.MarkMalicious(tt.bad)
			in := harness.Start(t, gm, harness.Options{Agent: true, Plugins: map[string]map[string]any{"report": {"chrome_path": chrome}}})
			in.Drop(t, "bad.txt", tt.bad)
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
				t.Error("the connector fell back to JSON although the browser works")
			}
		})
	}
}

// browserStub is the source of a program that stands for the browser: it runs
// the real one until the file named broken exists; from then on it counts its
// launches in that file and fails the first failures of them.
const browserStub = `package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

var chrome, broken, failures string

func main() {
	if raw, err := os.ReadFile(broken); err == nil {
		n, _ := strconv.Atoi(string(raw))
		n++
		if err = os.WriteFile(broken, []byte(strconv.Itoa(n)), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if limit, _ := strconv.Atoi(failures); n <= limit {
			fmt.Fprintln(os.Stderr, "cannot render")
			os.Exit(1)
		}
	}
	if err := syscall.Exec(chrome, append([]string{chrome}, os.Args[1:]...), os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
`

// alwaysFails is a number of failures of the browser stub that no run reaches.
const alwaysFails = 1 << 30

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

// buildBrowserStub builds the browser stub in dir and returns its path.
func buildBrowserStub(t *testing.T, dir, chrome, broken string, failures int) string {
	t.Helper()
	src := filepath.Join(dir, "stub.go")
	harness.Write(t, src, []byte(browserStub))
	out := filepath.Join(dir, "chromium")
	flags := fmt.Sprintf("-X main.chrome=%s -X main.broken=%s -X main.failures=%d", chrome, broken, failures)
	if err := harness.GoBuild(harness.RepoRoot(t), out, "-ldflags", flags, src); err != nil {
		t.Fatal(err)
	}
	return out
}

// P12, and from
// TestReportGeneration_aGeneratorThatFailsNTimesGivesTheReportOrTheJSONFallback:
// a generator that fails is tried again report_retries times, once per tick of
// the session monitor; when it fails once more the report is not lost: the
// session writes the JSON fallback under the reserved name, the console is
// told, and the delivered files are in that report. The browser is the real
// one until the test breaks it, once the connector has started; the stub then
// counts the attempts. The OUTPUT invariant cannot read a PDF report: the file
// of the rows that end with one is a malware, which is not delivered.
func TestE2E_failingReportGeneratorFallsBackToJSON(t *testing.T) {
	tests := []struct {
		name          string
		session       map[string]any
		failures      int
		malware       bool
		wantExt       string
		wantFallbacks int
		wantAttempts  int
	}{
		{name: "one retry, always failing", session: map[string]any{"report_retries": 1, "report_timeout": "30s"}, failures: alwaysFails, wantExt: ".json", wantFallbacks: 1, wantAttempts: 2},
		{name: "3 retries, 2 failures", session: map[string]any{"report_retries": 3, "report_timeout": "30s"}, failures: 2, malware: true, wantExt: ".pdf", wantFallbacks: 0, wantAttempts: 3},
		{name: "3 retries, 3 failures", session: map[string]any{"report_retries": 3, "report_timeout": "30s"}, failures: 3, malware: true, wantExt: ".pdf", wantFallbacks: 0, wantAttempts: 4},
		{name: "3 retries, 4 failures", session: map[string]any{"report_retries": 3, "report_timeout": "30s"}, failures: 4, wantExt: ".json", wantFallbacks: 1, wantAttempts: 4},
		{name: "3 retries, always failing", session: map[string]any{"report_retries": 3, "report_timeout": "30s"}, failures: alwaysFails, wantExt: ".json", wantFallbacks: 1, wantAttempts: 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chrome := requireChromium(t)
			dir := t.TempDir()
			broken := filepath.Join(dir, "broken")
			wrapper := buildBrowserStub(t, dir, chrome, broken, tt.failures)
			content := []byte("a file whose report fails to be rendered")
			gm := gmalware.New(t)
			if tt.malware {
				gm.MarkMalicious(content)
			}
			in := harness.Start(t, gm, harness.Options{
				Agent: true,
				Plugins: map[string]map[string]any{
					"report":  {"chrome_path": wrapper},
					"session": tt.session,
				},
			})
			in.WaitMonitoring(t)
			harness.Write(t, broken, nil)
			in.Drop(t, "a.txt", content)
			in.WaitFor(t, "the "+tt.wantExt+" report", func() bool {
				return len(harness.GlobOne(t, filepath.Join(in.Export, "tom", datamodel.SessionReportPrefix+"*"+tt.wantExt))) == 1
			})
			if !tt.malware {
				in.WaitFor(t, "the delivery", func() bool { return in.InOutput("a.txt") })
			}
			if reports := harness.GlobOne(t, filepath.Join(in.Export, "tom", "*")); len(reports) != 1 {
				t.Errorf("exports = %v, want the %s report only", reports, tt.wantExt)
			}
			if tt.wantFallbacks > 0 {
				in.WaitFor(t, "the console to be told", func() bool { return slices.Contains(in.Console.ErrorTypes(), "session-report-fallback") })
			}
			if got := fallbackEvents(in); got != tt.wantFallbacks {
				t.Errorf("%d session-report-fallback events, want %d", got, tt.wantFallbacks)
			}
			if tt.wantExt == ".json" {
				if got := in.ReportsOf(t, content); len(got) != 1 {
					t.Errorf("entries for the file in the fallback = %d, want 1", len(got))
				}
			}
			raw, err := os.ReadFile(filepath.Clean(broken))
			if attempts, _ := strconv.Atoi(string(raw)); err != nil || attempts != tt.wantAttempts {
				t.Errorf("the browser was launched %s times (%v), want %d: a failure is tried again report_retries times", raw, err, tt.wantAttempts)
			}
		})
	}
}
