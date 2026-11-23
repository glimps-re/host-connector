//go:build linux && realbrowser

package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/page"
)

// realBrowser is the browser installed on the machine, "" when there is none.
// Initialised with the package: TestMain has not yet put the fake chromium first in PATH.
var realBrowser = findRealBrowser()

// findRealBrowser returns the path of chromium, else google-chrome, found in PATH, or "".
func findRealBrowser() string {
	if p, err := exec.LookPath("chromium"); err == nil {
		return p
	}
	if p, err := exec.LookPath("google-chrome"); err == nil {
		return p
	}
	return ""
}

// requireBrowser fails the test when no real browser can run it: as root (Chrome
// refuses its sandbox) or when realBrowser is "". The realbrowser tag is an explicit
// request for these tests, so a missing browser is a failure, not a skip.
func requireBrowser(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatal("Chrome refuses its sandbox as root: run the realbrowser tests as a regular user")
	}
	if realBrowser == "" {
		t.Fatal("no chromium or google-chrome in PATH: the realbrowser tests need one")
	}
}

func TestRealBrowser_rendersAPDF(t *testing.T) {
	requireBrowser(t)
	b := runner(t, realBrowser)
	if err := b.selfTest(t.Context()); err != nil {
		t.Fatalf("the installed browser does not render a PDF: %v", err)
	}
}

func TestRealBrowser_pageCannotScriptOrLoadResources(t *testing.T) {
	requireBrowser(t)
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
	requireBrowser(t)
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
		t.Fatal("this browser renders the control style like the base page: the comparison proves nothing here")
	}
	linked := render(`<html><head><link rel="stylesheet" href="file://` + css + `"></head><body>x</body></html>`)
	if len(linked) != len(base) {
		t.Errorf("the PDF of a page linking a local style (%d bytes) differs from the base (%d): the file was read", len(linked), len(base))
	}
}

func TestRealBrowser_pdfLargerThanTheCapIsRefused(t *testing.T) {
	requireBrowser(t)
	b := runner(t, realBrowser)
	_, err := b.render(t.Context(), "<html><body>x</body></html>", page.PrintToPDF(), 100)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("render() error = %v, want the size cap refusal", err)
	}
}

// confinedRun runs run with a browser whose TMPDIR and HOME are empty folders
// owned by the test, and checks that nothing is left in them, nor in the work
// directory, once it returns.
func confinedRun(t *testing.T, work string, run func(b *browserRunner)) {
	t.Helper()
	tmp, home := emptyDir(t), emptyDir(t)
	t.Setenv("TMPDIR", tmp)
	t.Setenv("HOME", home)
	run(&browserRunner{execPath: realBrowser, workDir: work, logger: slog.New(slog.DiscardHandler)})
	assertNothingIn(t, tmp, "the temporary folder")
	assertNothingIn(t, home, "HOME")
	assertNothingIn(t, filepath.Join(work, profilesDir), "the work directory")
}

// watchBrowser polls the work directory until the browser has made its folders
// there and calls onSeen the first time. The returned function stops the poll
// and tells whether the browser was seen.
func watchBrowser(t *testing.T, work string, onSeen func()) (stop func() bool) {
	t.Helper()
	var seen atomic.Bool
	quit, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-quit:
				return
			case <-time.After(5 * time.Millisecond):
				m, err := filepath.Glob(filepath.Join(work, profilesDir, "profile-*", "tmp", "org.chromium.*"))
				if err != nil {
					t.Error(err)
					return
				}
				if len(m) > 0 && seen.CompareAndSwap(false, true) {
					onSeen()
				}
			}
		}
	}()
	return func() bool {
		close(quit)
		<-done
		return seen.Load()
	}
}

// Everything the browser creates goes under the folders of its rendering, which
// go with it: the temporary folder and the home of the connector stay empty.
func TestRealBrowser_leavesNothingOutsideTheWorkDirWhateverTheOutcome(t *testing.T) {
	requireBrowser(t)
	for name, run := range map[string]func(t *testing.T, b *browserRunner){
		"pdf": func(t *testing.T, b *browserRunner) {
			if err := b.selfTest(t.Context()); err != nil {
				t.Fatal(err)
			}
		},
		"timeout": func(t *testing.T, b *browserRunner) {
			prev := renderTimeout
			renderTimeout = time.Millisecond
			t.Cleanup(func() { renderTimeout = prev })
			if _, err := b.render(t.Context(), "<html></html>", page.PrintToPDF(), maxTestPDFSize); err == nil {
				t.Error("render() succeeded, want the timeout")
			}
		},
		"browser killed once started": func(t *testing.T, b *browserRunner) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			stop := watchBrowser(t, b.workDir, cancel)
			_, err := b.render(ctx, "<html></html>", page.PrintToPDF(), maxTestPDFSize)
			stop()
			if err == nil {
				t.Error("render() succeeded, want the cancellation")
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			confinedRun(t, t.TempDir(), func(b *browserRunner) { run(t, b) })
		})
	}
}

// The browser starts whatever the length of the work directory, and what it
// creates is physically under it (never at the other end of the link, nor in the
// temporary folder).
func TestRealBrowser_startsWithAnyWorkDirLengthAndKeepsItsFilesInIt(t *testing.T) {
	requireBrowser(t)
	for _, n := range []int{64, 200} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			work := filepath.Join(t.TempDir(), strings.Repeat("p", n), "gmhost-0000000000")
			if err := os.MkdirAll(work, 0o700); err != nil {
				t.Fatal(err)
			}
			confinedRun(t, work, func(b *browserRunner) {
				stop := watchBrowser(t, work, func() {})
				err := b.selfTest(t.Context())
				seen := stop()
				if err != nil {
					t.Fatalf("the browser does not start with a work directory of %d bytes: %v", len(work), err)
				}
				if !seen {
					t.Error("no folder of the browser was seen under the work directory")
				}
			})
		})
	}
}
