//go:build linux && (e2e || e2e_plugins) && realbrowser

package plugins

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
	chrome := requireChromium(t)
	gm := gmalware.New(t, false)
	bad := []byte("a malware that makes a report")
	gm.MarkMalicious(bad)
	in := harness.Start(t, gm, harness.Options{Agent: true, Plugins: map[string]map[string]any{"report": {"chrome_path": chrome}}})
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
		t.Error("the connector fell back to JSON although the browser works")
	}
}

// browserStub is the source of a program that stands for the browser: it runs
// the real one until the file named broken exists, and then fails.
const browserStub = `package main

import (
	"fmt"
	"os"
	"syscall"
)

var chrome, broken string

func main() {
	if _, err := os.Stat(broken); err == nil {
		fmt.Fprintln(os.Stderr, "cannot render")
		os.Exit(1)
	}
	if err := syscall.Exec(chrome, append([]string{chrome}, os.Args[1:]...), os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
`

// buildBrowserStub builds the browser stub in dir and returns its path.
func buildBrowserStub(t *testing.T, dir, chrome, broken string) string {
	t.Helper()
	src := filepath.Join(dir, "stub.go")
	harness.Write(t, src, []byte(browserStub))
	out := filepath.Join(dir, "chromium")
	flags := fmt.Sprintf("-X main.chrome=%s -X main.broken=%s", chrome, broken)
	if err := harness.GoBuild(harness.RepoRoot(t), out, "-ldflags", flags, src); err != nil {
		t.Fatal(err)
	}
	return out
}

// P12: when the generator fails, the report is not lost: after its retries the
// session writes the JSON fallback under the reserved name, the console is
// told, and the delivered files are in that report. The browser is the real
// one until the test breaks it, once the connector has started.
func TestE2E_failingReportGeneratorFallsBackToJSON(t *testing.T) {
	chrome := requireChromium(t)
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken")
	wrapper := buildBrowserStub(t, dir, chrome, broken)
	gm := gmalware.New(t, false)
	in := harness.Start(t, gm, harness.Options{
		Agent: true,
		Plugins: map[string]map[string]any{
			"report":  {"chrome_path": wrapper},
			"session": {"report_retries": 1, "report_timeout": "30s"},
		},
	})
	in.WaitFor(t, "the monitoring to start", func() bool { return in.LogHas("monitoring successfully completed") })
	harness.Write(t, broken, nil)
	content := []byte("a file whose report cannot be rendered")
	in.Drop(t, "a.txt", content)
	in.WaitFor(t, "the JSON fallback", func() bool {
		return len(harness.GlobOne(t, filepath.Join(in.Export, "tom", datamodel.SessionReportPrefix+"*.json"))) == 1
	})
	in.WaitFor(t, "the console to be told", func() bool { return slices.Contains(in.Console.ErrorTypes(), "session-report-fallback") })
	in.WaitFor(t, "the delivery", func() bool { return in.InOutput("a.txt") })
	if got := in.ReportsOf(t, content); len(got) != 1 {
		t.Errorf("entries for the file in the fallback = %d, want 1", len(got))
	}
	if m := harness.GlobOne(t, filepath.Join(in.Export, "tom", datamodel.SessionReportPrefix+"*.pdf")); len(m) != 0 {
		t.Errorf("a PDF report was written by a browser that fails: %v", m)
	}
}
