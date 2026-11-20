//go:build !windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

// Modes of the folders the tests make: named constants, they are test fixtures.
const (
	privateDir       os.FileMode = 0o700
	readOnlyDir      os.FileMode = 0o500
	worldWritableDir os.FileMode = 0o777
)

// shortDirs numbers the folders of shortDirIn.
var shortDirs atomic.Int64

// shortDirIn creates a folder named after prefix and a counter in parent,
// removed when the test ends: a folder whose path is short, which the links of
// the browser may be made in (t.TempDir() carries the name of the test).
func shortDirIn(t *testing.T, parent, prefix string) string {
	t.Helper()
	for range 10 {
		dir := filepath.Join(parent, prefix+strconv.FormatInt(shortDirs.Add(1), 10))
		err := os.Mkdir(dir, 0o700)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if e := os.RemoveAll(dir); e != nil {
				t.Error(e)
			}
		})
		return dir
	}
	t.Fatal("no free folder name")
	return ""
}

// emptyDir is a new empty folder with a short path, inside the private folder
// the links of the tests are made in.
func emptyDir(t *testing.T) string {
	t.Helper()
	return shortDirIn(t, testLinkBase, "w")
}

// useLinkBase makes the links of the browser go to base for the test.
func useLinkBase(t *testing.T, base string) {
	t.Helper()
	prev := systemTempDir
	t.Cleanup(func() { systemTempDir = prev })
	systemTempDir = func() string { return base }
}

// unsafeDir is an empty folder any account can rename entries in.
func unsafeDir(t *testing.T) string {
	t.Helper()
	dir := emptyDir(t)
	if err := os.Chmod(dir, worldWritableDir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func assertNothingIn(t *testing.T, dir, what string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 0 {
		t.Errorf("%s: %v left by the browser, want nothing", what, names)
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
	skipWithoutBrowser(t)
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

// The browser gets the folders of its rendering in its environment, keeps the
// rest of it, and ours win over a variable already set.
func TestRender_browserEnvironmentIsConfinedAndKeepsTheRest(t *testing.T) {
	work := t.TempDir()
	envFile := filepath.Join(work, "env")
	browser := fakeBrowser(t, "env > "+envFile+"; readlink \"$TMPDIR\" > "+envFile+".link; exit 1")
	t.Setenv("T35_KEEP", "yes")
	linkDir := emptyDir(t)
	useLinkBase(t, linkDir)
	t.Setenv("TMPDIR", "/must/be/overridden")
	t.Setenv("HOME", "/must/be/overridden")
	b := &browserRunner{execPath: browser, workDir: work, logger: slog.New(slog.DiscardHandler)}
	if err := b.selfTest(t.Context()); err == nil {
		t.Fatal("selfTest() succeeded with a browser that exits at once")
	}
	raw, err := os.ReadFile(filepath.Clean(envFile))
	if err != nil {
		t.Fatal(err)
	}
	env := string(raw)
	profile := regexp.QuoteMeta(filepath.Join(work, profilesDir)) + `/profile-[0-9]+`
	for _, pattern := range []string{
		`(?m)^TMPDIR=` + regexp.QuoteMeta(linkDir) + `/gmhc-[0-9a-f]{12}$`,
		`(?m)^HOME=` + profile + `/home$`,
		`(?m)^XDG_CONFIG_HOME=` + profile + `/home/\.config$`,
		`(?m)^XDG_CACHE_HOME=` + profile + `/home/\.cache$`,
		`(?m)^XDG_DATA_HOME=` + profile + `/home/\.local/share$`,
		`(?m)^T35_KEEP=yes$`,
	} {
		if !regexp.MustCompile(pattern).MatchString(env) {
			t.Errorf("the environment of the browser lacks %s:\n%s", pattern, env)
		}
	}
	if strings.Contains(env, "/must/be/overridden") {
		t.Error("a TMPDIR or HOME of the connector reached the browser")
	}
	target, err := os.ReadFile(filepath.Clean(envFile + ".link"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^` + profile + `/tmp\n$`).Match(target) {
		t.Errorf("the link of the browser points to %q, want the tmp folder of its rendering", target)
	}
	assertNothingIn(t, linkDir, "the temporary folder")
}

// A link that cannot be made fails the rendering with the reason, and leaves
// neither a profile nor a link.
func TestRender_failsCleanlyWhenTheLinkCannotBeMade(t *testing.T) {
	for name, tt := range map[string]struct {
		setup func(t *testing.T, base string)
		want  string
	}{
		"no random name": {
			setup: func(t *testing.T, _ string) {
				prev := newLinkName
				t.Cleanup(func() { newLinkName = prev })
				newLinkName = func() (string, error) { return "", errors.New("no entropy") }
			},
			want: "no entropy",
		},
		"every name taken": {
			setup: func(t *testing.T, base string) {
				if err := os.Symlink(base, filepath.Join(base, "gmhc-taken")); err != nil {
					t.Fatal(err)
				}
				prev := newLinkName
				t.Cleanup(func() { newLinkName = prev })
				newLinkName = func() (string, error) { return "gmhc-taken", nil }
			},
			want: "no free name",
		},
		"folder not writable": {
			setup: func(t *testing.T, base string) {
				if os.Geteuid() == 0 {
					t.Skip("root writes anywhere")
				}
				if err := os.Chmod(base, readOnlyDir); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Chmod(base, privateDir); err != nil {
						t.Error(err)
					}
				})
			},
			want: "cannot make the temporary link",
		},
	} {
		t.Run(name, func(t *testing.T) {
			base := emptyDir(t)
			useLinkBase(t, base)
			b := &browserRunner{execPath: fakeBrowser(t, "exit 1"), workDir: t.TempDir(), logger: slog.New(slog.DiscardHandler)}
			tt.setup(t, base)
			err := b.selfTest(t.Context())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("selfTest() = %v, want an error with %q", err, tt.want)
			}
			assertNothingIn(t, filepath.Join(b.workDir, profilesDir), "the work directory")
		})
	}
}

func TestBrowserFolders_areWritableOnlyByTheOwner(t *testing.T) {
	d, err := createBrowserDirs(emptyDir(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{d.data, d.tmp, d.home} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Errorf("%s mode = %o, want 700", dir, got)
		}
	}
}

func TestSafeLinkBase(t *testing.T) {
	mkdir := func(t *testing.T, mode os.FileMode) string {
		dir := emptyDir(t)
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	paddedTo := func(t *testing.T, length int) string {
		parent := emptyDir(t)
		n := length - len(parent) - 1
		if n < 1 {
			t.Fatalf("%s is too long to build a folder of %d bytes", parent, length)
		}
		dir := filepath.Join(parent, strings.Repeat("d", n))
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	file := filepath.Join(emptyDir(t), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tt := range map[string]struct {
		dir  string
		want bool
	}{
		"private folder":                     {mkdir(t, 0o700), true},
		"readable by all, writable by owner": {mkdir(t, 0o755), true},
		"world-writable with the sticky bit": {mkdir(t, os.ModeSticky|0o777), true},
		"world-writable without the sticky":  {mkdir(t, 0o777), false},
		"group-writable":                     {mkdir(t, 0o770), false},
		"group-writable, readable by all":    {mkdir(t, 0o775), false},
		"group-writable with the sticky bit": {mkdir(t, os.ModeSticky|0o770), true},
		"owned by root, not writable":        {"/", true},
		"missing":                            {filepath.Join(emptyDir(t), "missing"), false},
		"a file":                             {file, false},
		"relative":                           {"tmp", false},
		"as long as the limit":               {paddedTo(t, maxLinkBase), true},
		"one byte longer than the limit":     {paddedTo(t, maxLinkBase+1), false},
		"empty":                              {"", false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := safeLinkBase(tt.dir); got != tt.want {
				t.Errorf("safeLinkBase(%q) = %v, want %v", tt.dir, got, tt.want)
			}
		})
	}
}

func TestPickLinkBase(t *testing.T) {
	unsafe := unsafeDir(t)
	good := emptyDir(t)
	if got, err := pickLinkBase(unsafe, good); err != nil || got != good {
		t.Errorf("pickLinkBase(unsafe, good) = %q, %v, want %q", got, err, good)
	}
	if got, err := pickLinkBase(good, unsafe); err != nil || got != good {
		t.Errorf("pickLinkBase(good, unsafe) = %q, %v, want %q", got, err, good)
	}
	if got, err := pickLinkBase(unsafe, "relative"); err == nil {
		t.Errorf("pickLinkBase(unsafe, relative) = %q, want an error", got)
	}
}

func TestLinkBase_isPinnedToThePrivateFolderOfTheTests(t *testing.T) {
	if got, err := linkBase(); err != nil || got != testLinkBase {
		t.Fatalf("linkBase() = %q, %v, want %q: a test could reach the real temporary folder", got, err, testLinkBase)
	}
}

func TestLinkBase_usesTheTemporaryFolderWhenSafe(t *testing.T) {
	base := emptyDir(t)
	useLinkBase(t, base)
	if got, err := linkBase(); err != nil || got != base {
		t.Errorf("linkBase() = %q, %v, want %q", got, err, base)
	}
}

func TestLinkBase_fallsBackWhenTheTemporaryFolderIsNotUsable(t *testing.T) {
	unsafe := unsafeDir(t)
	for name, tmpdir := range map[string]string{
		"too long":       "/" + strings.Repeat("l", maxLinkBase),
		"world-writable": unsafe,
		"missing":        filepath.Join(unsafe, "missing"),
	} {
		t.Run(name, func(t *testing.T) {
			fallback := emptyDir(t)
			useLinkBase(t, tmpdir)
			prev := fallbackLinkBase
			t.Cleanup(func() { fallbackLinkBase = prev })
			fallbackLinkBase = fallback
			if got, err := linkBase(); err != nil || got != fallback {
				t.Errorf("linkBase() = %q, %v, want %q", got, err, fallback)
			}
		})
	}
}

// The browser starts whatever the length of the work directory, and what it
// creates is physically under it (never at the other end of the link, nor in the
// temporary folder).
func TestRealBrowser_startsWithAnyWorkDirLengthAndKeepsItsFilesInIt(t *testing.T) {
	skipWithoutBrowser(t)
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

func TestPurgeTempLinks_removesOnlyOurDanglingLinks(t *testing.T) {
	base := emptyDir(t)
	useLinkBase(t, base)
	live := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Symlink(filepath.Join(base, "gone"), filepath.Join(base, "gmhc-dangling")))
	must(os.Symlink(live, filepath.Join(base, "gmhc-live")))
	must(os.Symlink(filepath.Join(base, "gmhc-loop-b"), filepath.Join(base, "gmhc-loop-a")))
	must(os.Symlink(filepath.Join(base, "gmhc-loop-a"), filepath.Join(base, "gmhc-loop-b")))
	must(os.Symlink(filepath.Join(base, "gone"), filepath.Join(base, "other-dangling")))
	must(os.WriteFile(filepath.Join(base, "gmhc-file"), []byte("x"), 0o600))
	must(os.Mkdir(filepath.Join(base, "gmhc-dir"), 0o700))
	removed, err := purgeTempLinks()
	if err != nil || removed != 1 {
		t.Fatalf("purgeTempLinks() = %d, %v, want 1", removed, err)
	}
	for name, want := range map[string]bool{"gmhc-dangling": false, "gmhc-live": true, "gmhc-loop-a": true, "gmhc-loop-b": true, "other-dangling": true, "gmhc-file": true, "gmhc-dir": true} {
		_, lerr := os.Lstat(filepath.Join(base, name))
		if (lerr == nil) != want {
			t.Errorf("%s present = %v, want %v", name, lerr == nil, want)
		}
	}
}

// The folder is read in batches: entries beyond the first batch are still seen.
func TestPurgeTempLinks_readsTheFolderInBatches(t *testing.T) {
	base := emptyDir(t)
	useLinkBase(t, base)
	const dangling = 3*purgeBatch + 7
	for i := range dangling {
		if err := os.Symlink(filepath.Join(base, "gone"), filepath.Join(base, fmt.Sprintf("gmhc-%04d", i))); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, fmt.Sprintf("file-%04d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := purgeTempLinks()
	if err != nil || removed != dangling {
		t.Fatalf("purgeTempLinks() = %d, %v, want %d", removed, err, dangling)
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != dangling {
		t.Errorf("%d entries left, want the %d files", len(entries), dangling)
	}
}

// A name that is no longer a link is never removed, a missing one is not an
// error.
func TestRemoveTempLink(t *testing.T) {
	base := emptyDir(t)
	link := filepath.Join(base, "gmhc-x")
	if err := os.Symlink(filepath.Join(base, "gone"), link); err != nil {
		t.Fatal(err)
	}
	if err := removeTempLink(link); err != nil {
		t.Fatal(err)
	}
	if err := removeTempLink(link); err != nil {
		t.Errorf("removeTempLink(missing) = %v, want nil", err)
	}
	if err := os.Mkdir(link, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := removeTempLink(link); err == nil {
		t.Error("removeTempLink(empty folder) = nil, want an error")
	}
	if _, err := os.Lstat(link); err != nil {
		t.Errorf("the empty folder was removed: %v", err)
	}
}

func TestInit_purgesTheLinksOfAPreviousRun(t *testing.T) {
	base := emptyDir(t)
	useLinkBase(t, base)
	if err := os.Symlink(filepath.Join(base, "gone"), filepath.Join(base, "gmhc-old")); err != nil {
		t.Fatal(err)
	}
	var p ReportPlugin
	if err := p.Init(&Config{ChromePath: fakeBrowser(t, "exit 1")}, mock.NewMockHCContext()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(base, "gmhc-old")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the link of a previous run is still there: %v", err)
	}
}
