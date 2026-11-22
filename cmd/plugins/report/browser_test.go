package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

func runner(t *testing.T, execPath string) *browserRunner {
	t.Helper()
	return &browserRunner{execPath: execPath, workDir: t.TempDir(), logger: slog.New(slog.DiscardHandler)}
}

func TestLocateBrowser(t *testing.T) {
	if got, err := locateBrowser("/opt/chrome/chrome"); err != nil || got != "/opt/chrome/chrome" {
		t.Errorf("locateBrowser(configured) = %q, %v", got, err)
	}
	if got, err := locateBrowser(""); err != nil || filepath.Base(got) != "chromium" || !filepath.IsAbs(got) {
		t.Errorf("locateBrowser(\"\") = %q, %v, want the absolute path of chromium found in PATH", got, err)
	}
	t.Setenv("PATH", t.TempDir())
	if _, err := locateBrowser(""); !errors.Is(err, errNoBrowser) {
		t.Errorf("locateBrowser with an empty PATH error = %v, want errNoBrowser", err)
	}
}

func TestDeclareBrowser_refusalLaunchesNothing(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "launched")
	path := fakeBrowser(t, "touch "+marker)
	vc := mock.NewMockHCContext()
	vc.DeclareExecutableErr = errors.New("owned by another account")
	for _, configured := range []string{path, ""} {
		if _, err := declareBrowser(configured, vc); err == nil || !strings.Contains(err.Error(), "owned by another account") {
			t.Errorf("declareBrowser(%q) error = %v, want the refusal", configured, err)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("a refused browser must never be launched")
	}
	if len(vc.Executables) != 2 {
		t.Errorf("declared %v, want the configured and the found browser", vc.Executables)
	}
}

func TestSelfTest_failures(t *testing.T) {
	prev := renderTestTimeout
	renderTestTimeout = 3 * time.Second
	t.Cleanup(func() { renderTestTimeout = prev })

	tests := map[string]string{
		"exits with an error":      "echo boom >&2; exit 1",
		"prints no endpoint":       "echo hello",
		"endpoint nobody listens":  "echo 'DevTools listening on ws://127.0.0.1:1/devtools/browser/x'; sleep 30",
		"never answers":            "sleep 30",
		"output without any lines": "head -c 100000 /dev/zero | tr '\\0' x; sleep 30",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			b := runner(t, fakeBrowser(t, body))
			start := time.Now()
			err := b.selfTest(t.Context())
			if err == nil {
				t.Fatal("selfTest() error = nil, want a failure")
			}
			if time.Since(start) > 15*time.Second {
				t.Errorf("selfTest() took %v, must be bounded", time.Since(start))
			}
			if !strings.Contains(err.Error(), b.execPath) {
				t.Errorf("error %q must name the browser", err)
			}
		})
	}
}

func TestRender_profileIsUnderTheWorkDir(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args")
	b := runner(t, fakeBrowser(t, `printf '%s\n' "$@" > `+argsFile+"; exit 1"))
	_ = b.selfTest(t.Context())
	raw, err := os.ReadFile(filepath.Clean(argsFile))
	if err != nil {
		t.Fatal(err)
	}
	want := "--user-data-dir=" + filepath.Join(b.workDir, "report", "profile-")
	if !strings.Contains(string(raw), want) {
		t.Errorf("browser arguments %q do not contain %q", raw, want)
	}
	entries, err := os.ReadDir(filepath.Join(b.workDir, "report"))
	if err != nil || len(entries) != 0 {
		t.Errorf("profiles left behind: %v, %v", entries, err)
	}
	if strings.Contains(string(raw), "--no-sandbox") {
		t.Error("the sandbox must stay on")
	}
}

func TestStartBrowser_disappearedBrowserFailsRender(t *testing.T) {
	b := runner(t, filepath.Join(t.TempDir(), "gone"))
	if _, err := b.render(t.Context(), "<html></html>", page.PrintToPDF(), maxTestPDFSize); err == nil {
		t.Error("render() error = nil, want an error once the browser is gone")
	}
}

func TestValidateAndInit_browserFailureRefuses(t *testing.T) {
	prev := checkBrowser
	t.Cleanup(func() { checkBrowser = prev })
	checkBrowser = func(context.Context, *browserRunner) error { return errors.New("no PDF") }

	var p ReportPlugin
	if err := p.Validate(&Config{}, mock.NewMockHCContext()); err == nil || !strings.Contains(err.Error(), "no PDF") {
		t.Errorf("Validate() error = %v, want the browser failure", err)
	}
	if p.browser != nil || p.templ != nil {
		t.Error("Validate must not change the plugin state")
	}
	hcc := mock.NewMockHCContext()
	if err := p.Init(&Config{}, hcc); err == nil {
		t.Error("Init() error = nil, want the browser failure")
	}
	if hcc.GenerateReportFunc != nil {
		t.Error("a plugin that failed to start must not register its generator")
	}
}

func TestInit_noBrowserFoundRefuses(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	var p ReportPlugin
	err := p.Init(&Config{}, mock.NewMockHCContext())
	if !errors.Is(err, errNoBrowser) {
		t.Errorf("Init() error = %v, want errNoBrowser", err)
	}
}

func TestRealBrowser_rendersAPDF(t *testing.T) {
	skipWithoutBrowser(t)
	b := runner(t, realBrowser)
	if err := b.selfTest(t.Context()); err != nil {
		t.Fatalf("the installed browser does not render a PDF: %v", err)
	}
}

func TestRealBrowser_pageCannotScriptOrLoadResources(t *testing.T) {
	skipWithoutBrowser(t)
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	var logs bytes.Buffer
	b := runner(t, realBrowser)
	b.logger = slog.New(slog.NewTextHandler(&logs, nil))
	if err := b.selfTest(t.Context()); err != nil {
		t.Fatalf("the installed browser does not render a PDF: %v", err)
	}
	logs.Reset()
	b.settle = time.Second
	html := `<html><head>
<title>STATIC</title><script>document.title = "SCRIPT-RAN"; new Image().src = "` + srv.URL + `/script"; fetch("` + srv.URL + `/fetch")</script>
<link rel="stylesheet" href="` + srv.URL + `/style.css">
<link rel="stylesheet" href="file:///etc/hostname">
</head><body><img src="` + srv.URL + `/image.png"><iframe src="file:///etc/passwd"></iframe></body></html>`
	ctx, cancel := context.WithTimeout(t.Context(), renderTestTimeout)
	defer cancel()
	pdf, err := b.render(ctx, html, page.PrintToPDF(), maxTestPDFSize)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(pdf), pdfMagic) {
		t.Error("the result is not a PDF")
	}
	if !strings.Contains(string(pdf), "/Title (STATIC)") {
		t.Error("the script of the page ran")
	}
	if !strings.Contains(logs.String(), "refused") || !strings.Contains(logs.String(), "requests=2") {
		t.Errorf("log %q must say that the 2 remote requests were refused", logs.String())
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the page made %d outgoing requests, want none", n)
	}
}

func TestRealBrowser_pageCannotReadLocalFiles(t *testing.T) {
	skipWithoutBrowser(t)
	css := filepath.Join(t.TempDir(), "witness.css")
	if err := os.WriteFile(css, []byte("body{background:#f00}"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := runner(t, realBrowser)
	b.settle = 500 * time.Millisecond
	render := func(html string) []byte {
		pdf, err := b.render(t.Context(), html, page.PrintToPDF().WithPrintBackground(true), maxTestPDFSize)
		if err != nil {
			t.Fatalf("the installed browser does not render a PDF: %v", err)
		}
		return pdf
	}
	base := render("<html><body>x</body></html>")
	// The same style, inline, changes the PDF: the comparison can see it.
	if inline := render("<html><head><style>body{background:#f00}</style></head><body>x</body></html>"); len(inline) == len(base) {
		t.Skip("this browser renders the control style like the base page: the comparison proves nothing here")
	}
	linked := render(`<html><head><link rel="stylesheet" href="file://` + css + `"></head><body>x</body></html>`)
	if len(linked) != len(base) {
		t.Errorf("the PDF of a page linking a local style (%d bytes) differs from the base (%d): the file was read", len(linked), len(base))
	}
}

func TestRender_pdfLargerThanTheCapIsRefused(t *testing.T) {
	skipWithoutBrowser(t)
	b := runner(t, realBrowser)
	_, err := b.render(t.Context(), "<html><body>x</body></html>", page.PrintToPDF(), 100)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("render() error = %v, want the size cap refusal", err)
	}
}

func TestRender_rootIsRefusedBeforeAnyLaunch(t *testing.T) {
	prev := effectiveUID
	t.Cleanup(func() { effectiveUID = prev })
	effectiveUID = func() int { return 0 }

	marker := filepath.Join(t.TempDir(), "launched")
	path := fakeBrowser(t, "touch "+marker)
	b := runner(t, path)
	if _, err := b.render(t.Context(), "<html></html>", page.PrintToPDF(), maxTestPDFSize); !errors.Is(err, errRunningAsRoot) {
		t.Errorf("render() error = %v, want errRunningAsRoot", err)
	}
	var p ReportPlugin
	if err := p.Validate(&Config{ChromePath: path}, mock.NewMockHCContext()); !errors.Is(err, errRunningAsRoot) {
		t.Errorf("Validate() error = %v, want errRunningAsRoot", err)
	}
	if err := p.Init(&Config{ChromePath: path}, mock.NewMockHCContext()); !errors.Is(err, errRunningAsRoot) {
		t.Errorf("Init() error = %v, want errRunningAsRoot", err)
	}
	if !strings.Contains(errRunningAsRoot.Error(), "dedicated service account") {
		t.Error("the refusal must name the remedy")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the browser was launched as root")
	}
}

func TestRender_hardeningFlagsAndNoSandboxOption(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args")
	b := runner(t, fakeBrowser(t, `printf '%s\n' "$@" > `+argsFile+"; exit 1"))
	_ = b.selfTest(t.Context())
	raw, err := os.ReadFile(filepath.Clean(argsFile))
	if err != nil {
		t.Fatal(err)
	}
	args := string(raw)
	for _, want := range []string{
		"--host-resolver-rules=MAP * ~NOTFOUND", "--proxy-server=127.0.0.1:9", "--proxy-bypass-list=<-loopback>",
		"--dns-prefetch-disable", "--disable-remote-fonts", "--disable-plugins",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("browser arguments lack %q", want)
		}
	}
	if strings.Contains(args, "no-sandbox") {
		t.Error("the sandbox must stay on")
	}
}

func TestRenderTimeout_defaultIsFiveMinutes(t *testing.T) {
	if renderTimeout != 300*time.Second {
		t.Errorf("renderTimeout = %s, want 5m0s", renderTimeout)
	}
}

func TestRender_hungBrowserFailsWithinTheRenderTimeout(t *testing.T) {
	prev := renderTimeout
	renderTimeout = 2 * time.Second
	t.Cleanup(func() { renderTimeout = prev })
	b := runner(t, fakeBrowser(t, "sleep 60"))
	start := time.Now()
	if _, err := b.render(t.Context(), "<html></html>", page.PrintToPDF(), maxTestPDFSize); err == nil {
		t.Fatal("render() error = nil")
	}
	if time.Since(start) > 15*time.Second {
		t.Errorf("render() took %v, want the render timeout to apply", time.Since(start))
	}
	if entries, err := os.ReadDir(filepath.Join(b.workDir, "report")); err != nil || len(entries) != 0 {
		t.Errorf("profiles left behind after the timeout: %v, %v", entries, err)
	}
}

func TestRender_waitsForASlotAndGivesUp(t *testing.T) {
	for range cap(renderSlots) {
		renderSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for range cap(renderSlots) {
			<-renderSlots
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	b := runner(t, fakeBrowser(t, "exit 1"))
	if _, err := b.render(ctx, "<html></html>", page.PrintToPDF(), maxTestPDFSize); err == nil || !strings.Contains(err.Error(), "slot") {
		t.Errorf("render() error = %v, want a refusal while every slot is taken", err)
	}
}

func TestInit_failureKeepsThePreviousState(t *testing.T) {
	var p ReportPlugin
	hcc := mock.NewMockHCContext()
	if err := p.Init(&Config{}, hcc); err != nil {
		t.Fatal(err)
	}
	templ, runner, logger := p.templ, p.browser, p.logger
	prev := checkBrowser
	t.Cleanup(func() { checkBrowser = prev })
	checkBrowser = func(context.Context, *browserRunner) error { return errors.New("no PDF") }
	if err := p.Init(&Config{}, mock.NewMockHCContext()); err == nil {
		t.Fatal("Init() error = nil")
	}
	if p.templ != templ || p.browser != runner || p.logger != logger {
		t.Error("a failed Init changed the running plugin")
	}
}

func TestBrowserEnv(t *testing.T) {
	d := browserDirs{tmp: "/w/tmp", home: "/w/home", tmpLink: "/t/gmhc-x"}
	for _, tt := range []struct {
		name, goos string
		dirs       browserDirs
		want       []string
		not        string
	}{
		{"linux with link", "linux", d, []string{"TMPDIR=/t/gmhc-x", "HOME=/w/home", "XDG_CONFIG_HOME=/w/home/.config", "XDG_CACHE_HOME=/w/home/.cache", "XDG_DATA_HOME=/w/home/.local/share"}, "TMP="},
		{"darwin", "darwin", d, []string{"TMPDIR=/t/gmhc-x", "HOME=/w/home"}, "TEMP="},
		{"linux without link", "linux", browserDirs{tmp: "/w/tmp", home: "/w/home"}, []string{"TMPDIR=/w/tmp"}, "gmhc"},
		{"windows", "windows", browserDirs{tmp: `C:\w\tmp`, home: `C:\w\home`}, []string{`TMP=C:\w\tmp`, `TEMP=C:\w\tmp`, `USERPROFILE=C:\w\home`}, "TMPDIR"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := browserEnv(tt.dirs, tt.goos)
			for _, want := range tt.want {
				if !slices.Contains(got, want) {
					t.Errorf("env %q lacks %q", got, want)
				}
			}
			for _, e := range got {
				if strings.HasPrefix(e, tt.not) {
					t.Errorf("env has %q, want no %s", e, tt.not)
				}
			}
		})
	}
}
