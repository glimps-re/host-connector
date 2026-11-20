package scanner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/glimps-re/host-connector/internal/pathutil"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
)

func cleanSubmitter() *gdetectMock.MockGDetectSubmitter {
	return echoReader(&gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForFileMock: func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) {
			return gdetect.Result{}, nil
		},
	})
}

// swapDirForLink replaces dir by a link to target, keeping dir's content aside.
func swapDirForLink(t *testing.T, dir, target string) {
	t.Helper()
	if err := os.Rename(dir, dir+".real"); err != nil {
		t.Error(err)
		return
	}
	if err := os.Symlink(target, dir); err != nil {
		t.Error(err)
	}
}

func newPathCheckFixture(t *testing.T, follow bool) (c *Connector, in, file string, handled *[]string) {
	t.Helper()
	in = t.TempDir()
	dir := filepath.Join(in, "alice")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	file = filepath.Join(dir, "f.bin")
	if err := os.WriteFile(file, []byte("some content"), 0o600); err != nil {
		t.Fatal(err)
	}
	var err error
	c, err = NewConnector(Config{Roots: []string{in}, FollowSymlinks: follow, WorkDir: t.TempDir(), Workers: 2}, nil, cleanSubmitter())
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	paths := []string{}
	handled = &paths
	c.action = &MockAction{HandleMock: func(_ context.Context, p Source, _ datamodel.Result, _ *datamodel.Report) error {
		mu.Lock()
		defer mu.Unlock()
		paths = append(paths, p.Path)
		return nil
	}}
	return
}

func TestPrepareFile_refusesPathThroughLink(t *testing.T) {
	c, in, file, _ := newPathCheckFixture(t, false)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "f.bin"), []byte("other user's data"), 0o600); err != nil {
		t.Fatal(err)
	}
	swapDirForLink(t, filepath.Join(in, "alice"), outside)
	if _, skip := c.prepareFile(file, FileIdentity{}, nil); !skip {
		t.Error("prepareFile() must skip a path that crosses a link: the file of another tree would be read")
	}
}

func TestProcessFile_parentSwappedBetweenAnalysisAndActionTakesNoAction(t *testing.T) {
	c, in, file, handled := newPathCheckFixture(t, false)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "f.bin"), []byte("some content"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.RegisterOnScanFile(func(_, _, _ string, _ bool) *datamodel.Result {
		swapDirForLink(t, filepath.Join(in, "alice"), outside)
		return nil
	})
	var scanned []datamodel.Result
	c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
		scanned = append(scanned, r)
		return nil
	})
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.ScanFile(t.Context(), file); err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}
	c.Close(t.Context())
	if len(*handled) != 0 {
		t.Errorf("an action ran on %v after the parent was swapped for a link", *handled)
	}
	if len(scanned) != 1 {
		t.Errorf("OnFileScanned calls = %d, want 1: the plugins are told, only the action is refused", len(scanned))
	}
}

func TestProcessFile_parentSwappedBeforeQueueIsDropped(t *testing.T) {
	c, in, file, handled := newPathCheckFixture(t, false)
	swapDirForLink(t, filepath.Join(in, "alice"), t.TempDir())
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.ScanFile(t.Context(), file); err != nil {
		t.Logf("ScanFile() error = %v", err)
	}
	c.Close(t.Context())
	if len(*handled) != 0 {
		t.Errorf("an action ran on %v", *handled)
	}
}

func TestHandleRestoredFile_refusesPathThroughLink(t *testing.T) {
	c, in, file, handled := newPathCheckFixture(t, false)
	swapDirForLink(t, filepath.Join(in, "alice"), t.TempDir())
	if err := c.handleRestoredFile(file, "sha", 10, FileIdentity{}, nil, nil); !errors.Is(err, pathutil.ErrSymlinkInPath) {
		t.Errorf("handleRestoredFile() error = %v, want pathutil.ErrSymlinkInPath", err)
	}
	if len(*handled) != 0 {
		t.Errorf("an action ran on %v", *handled)
	}
}

func TestFinishArchiveAnalysis_refusesPathThroughLink(t *testing.T) {
	c, in, file, handled := newPathCheckFixture(t, false)
	sha, err := getFileSHA256(file)
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	id := c.archiveStatus.addStatus(archiveStatus{
		started: true, archiveLocation: file, tmpFolder: tmp, total: 1, analyzed: 1, finished: true,
		result: datamodel.Result{SHA256: sha},
	})
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "f.bin"), []byte("some content"), 0o600); err != nil {
		t.Fatal(err)
	}
	swapDirForLink(t, filepath.Join(in, "alice"), outside)
	if err := c.finishArchiveAnalysis(id); err != nil {
		t.Fatalf("finishArchiveAnalysis() error = %v", err)
	}
	if len(*handled) != 0 {
		t.Errorf("an action ran on an archive behind a link: %v", *handled)
	}
	if _, ok := c.archiveStatus.getStatus(id); ok {
		t.Error("status must still be cleaned up")
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Errorf("temporary folder must still be removed: %v", err)
	}
}

func TestCheckPath_followSymlinksDisablesTheCheck(t *testing.T) {
	c, in, file, _ := newPathCheckFixture(t, true)
	swapDirForLink(t, filepath.Join(in, "alice"), t.TempDir())
	if err := c.checkPath(file); err != nil {
		t.Errorf("checkPath() = %v, want nil: the operator enabled follow_symlinks", err)
	}
}

func TestCheckPath_linkAboveTheRootIsAccepted(t *testing.T) {
	realBase := t.TempDir()
	in := filepath.Join(realBase, "in")
	if err := os.MkdirAll(filepath.Join(in, "alice"), 0o750); err != nil {
		t.Fatal(err)
	}
	linkBase := filepath.Join(t.TempDir(), "var-run")
	if err := os.Symlink(realBase, linkBase); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in, "alice", "f.bin"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Connector{config: Config{Roots: []string{filepath.Join(linkBase, "in")}}}
	if err := c.checkPath(filepath.Join(linkBase, "in", "alice", "f.bin")); err != nil {
		t.Errorf("checkPath() = %v, want nil: a link above the monitored path is the operator's", err)
	}
}

func TestRootFor(t *testing.T) {
	in := t.TempDir()
	nested := filepath.Join(in, "nested")
	other := t.TempDir()
	c := &Connector{config: Config{Roots: []string{in, nested}}}
	scanArg := filepath.Join(other, "arg")
	c.noteScanRoot(scanArg)
	c.noteScanRoot(filepath.Join(scanArg, "deeper", "file"))
	c.noteScanRoot(filepath.Join(in, "x"))

	tests := []struct{ path, want string }{
		{filepath.Join(nested, "a", "f"), in},
		{filepath.Join(in, "a", "f"), in},
		{filepath.Join(scanArg, "deeper", "file"), scanArg},
		{filepath.Join(other, "unknown", "f"), filepath.Join(other, "unknown")},
	}
	for _, tt := range tests {
		if got := c.rootFor(tt.path); got != tt.want {
			t.Errorf("rootFor(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
	n := 0
	c.scanRoots.Range(func(_, _ any) bool { n++; return true })
	if n != 1 {
		t.Errorf("scan roots = %d, want only the operator's argument", n)
	}
}

func TestScanFile_commandLineScanChecksBelowTheArgument(t *testing.T) {
	arg := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "f.bin"), []byte("outside data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(arg, "link")); err != nil {
		t.Fatal(err)
	}
	c, err := NewConnector(Config{WorkDir: t.TempDir()}, nil, cleanSubmitter())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(t.Context()) })
	c.noteScanRoot(arg)
	if _, skip := c.prepareFile(filepath.Join(arg, "link", "f.bin"), FileIdentity{}, nil); !skip {
		t.Error("a file reached through a link below the scan argument must be skipped")
	}
}

func BenchmarkCheckPath(b *testing.B) {
	in := b.TempDir()
	dir := filepath.Join(in, "a", "b", "c", "d", "e", "f", "g", "h")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		b.Fatal(err)
	}
	file := filepath.Join(dir, "report.pdf")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		b.Fatal(err)
	}
	c := &Connector{config: Config{Roots: []string{in}}}
	b.ReportAllocs()
	for b.Loop() {
		if err := c.checkPath(file); err != nil {
			b.Fatal(err)
		}
	}
}

func TestCheckPath_nestedRootsUseTheOutermost(t *testing.T) {
	in := t.TempDir()
	inner := filepath.Join(in, "alice")
	if err := os.Mkdir(inner, 0o750); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(inner, "f.bin")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Connector{config: Config{Roots: []string{in, inner}}}
	swapDirForLink(t, inner, t.TempDir())
	if err := c.checkPath(file); !errors.Is(err, pathutil.ErrSymlinkInPath) {
		t.Errorf("checkPath() = %v, want a refusal: the inner root was swapped for a link", err)
	}
}

func TestRefusePath_onlyALinkIsAnAlert(t *testing.T) {
	buf := captureLogs(t)
	refusePath("/in/gone.bin", fs.ErrNotExist)
	if buf.Len() != 0 {
		t.Errorf("a vanished file raised a warning: %s", buf.String())
	}
	refusePath("/in/link/f.bin", fmt.Errorf("%w: %q", pathutil.ErrSymlinkInPath, "/in/link"))
	if !strings.Contains(buf.String(), `"level":"WARN"`) {
		t.Errorf("a link raised no warning: %q", buf.String())
	}
}
