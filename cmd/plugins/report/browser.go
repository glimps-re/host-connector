package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/fetch"
	cdpio "github.com/chromedp/cdproto/io"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// renderTestTimeout bounds the start-up rendering test; a variable for tests.
var renderTestTimeout = 30 * time.Second

const (
	// maxTestPDFSize caps the PDF accepted from the rendering test.
	maxTestPDFSize = 1 << 20
	pdfMagic       = "%PDF-"
	// browserWaitDelay bounds the wait for the browser pipes after it is killed.
	browserWaitDelay = 2 * time.Second
	// maxBrowserOutput bounds the browser output quoted in an error.
	maxBrowserOutput = 1024
)

// browserNames are the executables looked up in PATH when chrome_path is empty.
var browserNames = []string{
	"headless_shell", "headless-shell", "chromium", "chromium-browser",
	"google-chrome", "google-chrome-stable", "google-chrome-beta",
	"google-chrome-unstable", "chrome", "chrome-headless-shell",
}

// effectiveUID is the account the connector runs as; a variable for tests.
var effectiveUID = os.Geteuid

// errNoBrowser is wrapped by the error returned when no browser is found.
var errNoBrowser = errors.New("no browser found")

// locateBrowser returns the browser to use: chromePath, or the first known
// browser found in PATH. The result is absolute.
func locateBrowser(chromePath string) (string, error) {
	if chromePath != "" {
		return chromePath, nil
	}
	for _, name := range browserNames {
		found, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		return filepath.Abs(found)
	}
	return "", fmt.Errorf("%w: looked for %s in PATH; install Chrome or Chromium, or set chrome_path", errNoBrowser, strings.Join(browserNames, ", "))
}

// declareBrowser locates the browser and has the core check it before anything
// runs it, whether it was configured or found.
func declareBrowser(chromePath string, vc plugins.ValidationContext) (string, error) {
	path, err := locateBrowser(chromePath)
	if err != nil {
		return "", err
	}
	if err := vc.DeclareExecutable(path); err != nil {
		return "", fmt.Errorf("browser %s: %w", path, err)
	}
	return path, nil
}

// errRunningAsRoot is returned instead of launching a browser as root: Chrome's
// sandbox is kept, and it cannot run as root.
var errRunningAsRoot = errors.New("the connector runs as root: the report browser keeps its sandbox, which Chrome refuses as root; run the connector under a dedicated service account")

// refuseRoot returns errRunningAsRoot when the connector runs as root.
func refuseRoot() error {
	if effectiveUID() == 0 {
		return errRunningAsRoot
	}
	return nil
}

const (
	// maxReportPDF caps the PDF of a report, kept in memory.
	maxReportPDF = 64 << 20
	// streamChunk is the size asked from the browser for each read of a PDF.
	streamChunk = 1 << 20
)

// renderTimeout bounds one rendering; a variable for tests.
var renderTimeout = 2 * time.Minute

// renderSlots bounds the browsers running at the same time.
var renderSlots = make(chan struct{}, 2)

// browserFlags harden the browser beyond the request interception: nothing
// resolves, connects or prefetches.
var browserFlags = []chromedp.ExecAllocatorOption{
	// chromedp adds --no-sandbox by itself for uid 0: say no.
	chromedp.Flag("no-sandbox", false),
	chromedp.Flag("host-resolver-rules", "MAP * ~NOTFOUND"),
	chromedp.Flag("proxy-server", "127.0.0.1:9"),
	chromedp.Flag("proxy-bypass-list", "<-loopback>"),
	chromedp.Flag("dns-prefetch-disable", true),
	chromedp.Flag("disable-remote-fonts", true),
	chromedp.Flag("disable-plugins", true),
}

const (
	// profilesDir and profilePrefix name the folder of the renderings inside the
	// work directory.
	profilesDir   = "report"
	profilePrefix = "profile-"
)

// browserDirs are the folders of one rendering, all inside its profile folder.
type browserDirs struct {
	data, tmp, home string
	// tmpLink is the short name the browser is given as its temporary folder:
	// a Unix socket path is limited to about 100 bytes, a work directory is not.
	// Empty where the real folder is used.
	tmpLink string
}

func (d browserDirs) tmpDir() string {
	if d.tmpLink != "" {
		return d.tmpLink
	}
	return d.tmp
}

func createBrowserDirs(profile string) (browserDirs, error) {
	d := browserDirs{data: filepath.Join(profile, "data"), tmp: filepath.Join(profile, "tmp"), home: filepath.Join(profile, "home")}
	for _, dir := range []string{d.data, d.tmp, d.home} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return browserDirs{}, fmt.Errorf("cannot create a browser folder: %w", err)
		}
	}
	return d, nil
}

// browserEnv is what the browser is given on top of the environment of the
// connector (which it keeps): everything it would write under the temporary
// folder, the home or the XDG folders goes under the folders of its rendering.
func browserEnv(d browserDirs, goos string) []string {
	if goos == "windows" {
		return []string{"TMP=" + d.tmpDir(), "TEMP=" + d.tmpDir(), "USERPROFILE=" + d.home}
	}
	return []string{
		"TMPDIR=" + d.tmpDir(),
		"HOME=" + d.home,
		"XDG_CONFIG_HOME=" + filepath.Join(d.home, ".config"),
		"XDG_CACHE_HOME=" + filepath.Join(d.home, ".cache"),
		"XDG_DATA_HOME=" + filepath.Join(d.home, ".local", "share"),
	}
}

// browserOptions are the options of every launch of the browser by the plugin:
// the restrictions, the profile, and the confinement of what it creates.
func browserOptions(execPath string, d browserDirs) []chromedp.ExecAllocatorOption {
	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts, browserFlags...)
	return append(opts,
		chromedp.ExecPath(execPath),
		chromedp.UserDataDir(d.data),
		chromedp.Env(browserEnv(d, runtime.GOOS)...),
		chromedp.ModifyCmdFunc(confineBrowser),
	)
}

// browserRunner renders HTML to PDF with a restricted browser.
type browserRunner struct {
	execPath string
	// workDir is the private directory the browser profiles are created in.
	workDir string
	logger  *slog.Logger
	// settle is how long the page is left to load before printing; tests use
	// it to give a forbidden request time to show.
	settle time.Duration
}

// render converts the HTML document to a PDF of at most maxPDF bytes. JavaScript
// is off and every network or file request of the page is refused: the document
// is injected, never loaded by URL. The browser has exited and its profile is
// gone when it returns.
func (b *browserRunner) render(ctx context.Context, html string, params *page.PrintToPDFParams, maxPDF int) (pdf []byte, err error) {
	if err = refuseRoot(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, renderTimeout)
	defer cancel()
	select {
	case renderSlots <- struct{}{}:
		defer func() { <-renderSlots }()
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for a browser slot: %w", ctx.Err())
	}

	if !filepath.IsAbs(b.workDir) {
		return nil, fmt.Errorf("the work directory %q is not absolute", b.workDir)
	}
	profileRoot := filepath.Join(b.workDir, profilesDir)
	if err = os.MkdirAll(profileRoot, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create the browser profile directory: %w", err)
	}
	profile, err := os.MkdirTemp(profileRoot, profilePrefix)
	if err != nil {
		return nil, fmt.Errorf("cannot create the browser profile: %w", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(profile); rmErr != nil {
			b.logger.Warn("cannot remove the browser profile", slog.String("dir", profile), slog.String("error", rmErr.Error()))
		}
	}()

	dirs, err := createBrowserDirs(profile)
	if err != nil {
		return nil, err
	}
	if dirs.tmpLink, err = linkTemp(dirs.tmp); err != nil {
		return nil, err
	}
	// Removed once the browser has exited, before the folder it points to.
	defer func() {
		if rmErr := removeTempLink(dirs.tmpLink); rmErr != nil {
			b.logger.Warn("cannot remove the temporary link of the browser", slog.String("link", dirs.tmpLink), slog.String("error", rmErr.Error()))
		}
	}()
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, browserOptions(b.execPath, dirs)...)
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	// The profile is removed only once the browser has exited.
	defer func() {
		cancelBrowser()
		if c := chromedp.FromContext(browserCtx); c != nil && c.Allocator != nil {
			c.Allocator.Wait()
		}
		cancelAlloc()
	}()

	var blocked atomic.Int64
	chromedp.ListenTarget(browserCtx, func(ev any) {
		paused, ok := ev.(*fetch.EventRequestPaused)
		if !ok {
			return
		}
		blocked.Add(1)
		go func() {
			c := chromedp.FromContext(browserCtx)
			if c == nil || c.Target == nil {
				return
			}
			// A request that cannot be failed stays paused: nothing leaves.
			if e := fetch.FailRequest(paused.RequestID, network.ErrorReasonBlockedByClient).Do(cdp.WithExecutor(browserCtx, c.Target)); e != nil {
				b.logger.Debug("cannot refuse a request of the report page", slog.String("error", e.Error()))
			}
		}()
	})

	err = chromedp.Run(browserCtx,
		emulation.SetScriptExecutionDisabled(true),
		fetch.Enable(),
		chromedp.Navigate("about:blank"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			frameTree, err := page.GetFrameTree().Do(ctx)
			if err != nil {
				return err
			}
			return page.SetDocumentContent(frameTree.Frame.ID, html).Do(ctx)
		}),
		chromedp.Sleep(b.settle),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, stream, err := params.WithTransferMode(page.PrintToPDFTransferModeReturnAsStream).Do(ctx)
			if err != nil {
				return err
			}
			pdf, err = readStream(ctx, stream, maxPDF)
			return err
		}),
	)
	if n := blocked.Load(); n > 0 {
		b.logger.Warn("the report page tried to load external resources, refused", slog.Int64("requests", n))
	}
	if err != nil {
		return nil, b.explain(err)
	}
	return pdf, nil
}

// readStream reads a browser stream of at most limit bytes and closes it.
func readStream(ctx context.Context, handle cdpio.StreamHandle, limit int) ([]byte, error) {
	var out []byte
	for {
		data, eof, err := cdpio.Read(handle).WithSize(streamChunk).Do(ctx)
		if err != nil {
			return nil, err
		}
		// A binary stream is sent base64 encoded, chunk by chunk.
		chunk, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return nil, fmt.Errorf("the browser sent an unreadable PDF chunk: %w", err)
		}
		if len(out)+len(chunk) > limit {
			return nil, fmt.Errorf("the PDF is larger than %d bytes", limit)
		}
		out = append(out, chunk...)
		if eof {
			break
		}
	}
	if err := cdpio.Close(handle).Do(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// explain adds the cause and the remedy a browser failure deserves.
func (b *browserRunner) explain(err error) error {
	msg := err.Error()
	if len(msg) > maxBrowserOutput {
		msg = strings.ToValidUTF8(msg[:maxBrowserOutput], "") + "..."
	}
	return fmt.Errorf("the report browser %s failed: %s (check that it starts for this account)", b.execPath, msg)
}

// selfTest renders an empty page within renderTestTimeout and checks the
// result is a PDF.
func (b *browserRunner) selfTest(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, renderTestTimeout)
	defer cancel()
	pdf, err := b.render(ctx, "<html><body></body></html>", page.PrintToPDF(), maxTestPDFSize)
	if err != nil {
		return err
	}
	if len(pdf) == 0 || len(pdf) > maxTestPDFSize || !bytes.HasPrefix(pdf, []byte(pdfMagic)) {
		return fmt.Errorf("the report browser %s did not produce a PDF (%d bytes)", b.execPath, len(pdf))
	}
	return nil
}

// checkBrowser is the start-up check of Validate and Init; a variable so the
// tests of the rest of the plugin do not need a browser.
var checkBrowser = func(ctx context.Context, b *browserRunner) error {
	return b.selfTest(ctx)
}
