package scanner

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"

	"github.com/glimps-re/host-connector/internal/safepath"
)

func newVerified(t *testing.T) (root, path string, src Source) {
	t.Helper()
	root = t.TempDir()
	path = filepath.Join(root, "dir", "f.bin")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("verified content"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	sha, err := getFileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	return root, path, Source{Path: path, Root: root, Identity: IdentityOf(info), SHA256: sha}
}

func readAll(t *testing.T, f *os.File) string {
	t.Helper()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func withHandle(t *testing.T, root, path string, src Source) Source {
	t.Helper()
	rel, err := filepath.Rel(root, path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := safepath.Open(root, rel)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := h.Close(); e != nil {
			t.Error(e)
		}
	})
	return src.withHandle(h)
}

func TestSource_openWithoutHandleReadsTheVerifiedFile(t *testing.T) {
	_, _, src := newVerified(t)
	f, release, err := src.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if got := readAll(t, f); got != "verified content" {
		t.Errorf("read %q", got)
	}
}

func TestSource_openWithHandleGivesAFreshOffsetEachTime(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the handle is only kept on Linux")
	}
	root, path, src := newVerified(t)
	src = withHandle(t, root, path, src)
	for range 2 {
		f, release, err := src.Open()
		if err != nil {
			t.Fatal(err)
		}
		if got := readAll(t, f); got != "verified content" {
			t.Errorf("read %q, want the whole content again: each Open starts at the beginning", got)
		}
		release()
	}
}

func TestSource_openRefusesAChangedFile(t *testing.T) {
	root, path, src := newVerified(t)
	handled := withHandle(t, root, path, src)
	if err := os.WriteFile(path, []byte("modified after the verification"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]Source{"without handle": src, "with handle": handled} {
		if f, _, err := s.Open(); !errors.Is(err, ErrSourceChanged) {
			if err == nil {
				_ = f.Close()
			}
			t.Errorf("%s: Open() error = %v, want ErrSourceChanged", name, err)
		}
	}
}

func TestSource_openWithoutHandleRefusesAFolderTurnedIntoALink(t *testing.T) {
	root, path, src := newVerified(t)
	victim := t.TempDir()
	if err := os.WriteFile(filepath.Join(victim, "f.bin"), []byte("verified content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Dir(path), filepath.Join(root, "dir.moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(root, "dir")); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if f, _, err := src.Open(); err == nil {
		_ = f.Close()
		t.Error("Open() followed the link that replaced the folder")
	}
}

func TestSource_removeDeletesTheVerifiedFileOnly(t *testing.T) {
	root, path, src := newVerified(t)
	handled := withHandle(t, root, path, src)
	if runtime.GOOS == "linux" {
		if err := handled.Remove(); err != nil {
			t.Fatal(err)
		}
	} else if err := src.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the file is still there (%v)", err)
	}
}

func TestSource_removeRefusesAChangedFile(t *testing.T) {
	root, path, src := newVerified(t)
	handled := withHandle(t, root, path, src)
	if err := os.WriteFile(path, []byte("appended since the analysis, not analysed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := handled.Remove(); !errors.Is(err, ErrSourceChanged) {
		t.Errorf("with handle: Remove() error = %v, want ErrSourceChanged", err)
	}
	want := ErrSourceChanged
	if holdsHandle {
		want = errNoHandle
	}
	if err := src.Remove(); !errors.Is(err, want) {
		t.Errorf("without handle: Remove() error = %v, want %v", err, want)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("a modified file was deleted: %v", err)
	}
}

func TestSource_removeWithHandleActsOnTheOriginalFolderWhenItIsRedirected(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the handle is only kept on Linux")
	}
	root, path, src := newVerified(t)
	handled := withHandle(t, root, path, src)
	victim := t.TempDir()
	victimFile := filepath.Join(victim, "f.bin")
	if err := os.WriteFile(victimFile, []byte("verified content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Dir(path), filepath.Join(root, "dir.moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(root, "dir")); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if err := handled.Remove(); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if _, err := os.Stat(victimFile); err != nil {
		t.Errorf("the file behind the redirected folder was deleted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "dir.moved", "f.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the verified file is still there (%v)", err)
	}
}

func TestSource_aSourceThePipelineDidNotVerifyIsNeverDeletedNorMoved(t *testing.T) {
	root, path, src := newVerified(t)
	handled := withHandle(t, root, path, src)
	noIdentity := handled
	noIdentity.Identity = FileIdentity{}
	noHash := handled
	noHash.SHA256 = ""
	dest := t.TempDir()
	a, err := NewMoveAction(dest, root)
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]Source{"no identity": noIdentity, "no SHA256": noHash} {
		if err := s.Remove(); err == nil {
			t.Errorf("%s: Remove() succeeded", name)
		}
		if err := a.Handle(t.Context(), s, datamodel.Result{}, &datamodel.Report{}); err == nil {
			t.Errorf("%s: the move succeeded", name)
		}
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the file is gone: %v", err)
	}
	if entries, _ := os.ReadDir(dest); len(entries) != 0 {
		t.Errorf("the destination holds %v", entries)
	}
}

// The SHA256 of the source is the one the pipeline computed, not the one a
// plugin put in the result.
func TestPipeline_theSourceCarriesTheHashThePipelineComputed(t *testing.T) {
	noOpenInputs(t)
	c, _, file, _ := newPathCheckFixture(t, false)
	want, err := getFileSHA256(file)
	if err != nil {
		t.Fatal(err)
	}
	c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
		r.SHA256 = "replaced-by-a-plugin"
		return &r
	})
	var got atomic.Pointer[string]
	c.action = &MockAction{HandleMock: func(_ context.Context, src Source, _ datamodel.Result, _ *datamodel.Report) error {
		s := src.SHA256
		got.Store(&s)
		return nil
	}}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.ScanFile(t.Context(), file); err != nil {
		t.Fatal(err)
	}
	c.Close(t.Context())
	if p := got.Load(); p == nil || *p != want {
		t.Errorf("Source.SHA256 = %v, want the hash of the file %s", p, want)
	}
}
