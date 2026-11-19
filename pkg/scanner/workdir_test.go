package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewWorkDir(t *testing.T) {
	base := t.TempDir()
	w, err := newWorkDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(w.path) != base || !strings.HasPrefix(filepath.Base(w.path), workDirPrefix) {
		t.Errorf("work dir = %q, want gmhost-* directly under %q", w.path, base)
	}
	fi, err := os.Stat(w.path)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("work dir mode = %v (err %v), want 0700", fi.Mode().Perm(), err)
	}
	if _, err := os.Stat(filepath.Join(w.path, workDirLock)); err != nil {
		t.Errorf("lock file missing: %v", err)
	}
	if fi, err := os.Stat(w.extractDir()); err != nil || !fi.IsDir() {
		t.Errorf("extract dir missing: %v", err)
	}
	if err := w.close(); err != nil {
		t.Errorf("close() error = %v", err)
	}
	if _, err := os.Stat(w.path); !os.IsNotExist(err) {
		t.Errorf("work dir still there after close: %v", err)
	}
}

func TestNewWorkDir_createsMissingBase(t *testing.T) {
	base := filepath.Join(t.TempDir(), "a", "b")
	w, err := newWorkDir(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := w.close(); err != nil {
			t.Errorf("close() error = %v", err)
		}
	})
	if filepath.Dir(w.path) != base {
		t.Errorf("work dir = %q, want under %q", w.path, base)
	}
}

func TestWorkDir_contains(t *testing.T) {
	base := t.TempDir()
	w, err := newWorkDir(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := w.close(); err != nil {
			t.Errorf("close() error = %v", err)
		}
	})
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(w.path, link); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"itself", w.path, true},
		{"file inside", filepath.Join(w.path, "extract", "x-1", "a"), true},
		{"not yet existing inside", filepath.Join(w.path, "later"), true},
		{"sibling with the same prefix", w.path + "x", false},
		{"sibling file", filepath.Join(base, "a.txt"), false},
		{"parent", base, false},
		{"dotdot escape", filepath.Join(w.path, "..", "a"), false},
		{"through a symlink", filepath.Join(link, "extract"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := w.contains(tt.path); got != tt.want {
				t.Errorf("contains(%q) = %t, want %t", tt.path, got, tt.want)
			}
		})
	}
	for _, p := range []string{filepath.Join(link, "extract"), filepath.Join(link, "not", "yet")} {
		if !w.containsResolved(p) {
			t.Errorf("containsResolved(%q) = false, want true: the link points into the work directory", p)
		}
	}
	if w.containsResolved(w.path + "x") {
		t.Error("containsResolved() compared by prefix")
	}
}

func TestConnector_IsInternalPathAndGetWorkDir(t *testing.T) {
	var zero Connector
	if zero.IsInternalPath("/tmp/x") || zero.GetWorkDir() != "" {
		t.Error("a connector without work directory must report none")
	}
	c, err := NewConnector(Config{WorkDir: t.TempDir()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(t.Context()) })
	wd := c.GetWorkDir()
	if wd == "" || !c.IsInternalPath(filepath.Join(wd, "extract")) || c.IsInternalPath(wd+"x") {
		t.Errorf("IsInternalPath wrong for work dir %q", wd)
	}
	c.Close(t.Context())
	if _, err := os.Stat(wd); !os.IsNotExist(err) {
		t.Errorf("Close must remove the work directory: %v", err)
	}
}

func TestConnector_internalPathsAreNeverScanned(t *testing.T) {
	c, err := NewConnector(Config{WorkDir: t.TempDir(), Extract: true}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(t.Context()) })
	var started []string
	c.RegisterOnStartScanFile(func(location, _ string) { started = append(started, location) })

	inside := filepath.Join(c.GetWorkDir(), "extract", "x-1", "a.bin")
	if err := os.MkdirAll(filepath.Dir(inside), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inside, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.ScanFile(t.Context(), inside); err != nil {
		t.Errorf("ScanFile(internal file) error = %v, want nil", err)
	}
	if err := c.ScanFile(t.Context(), c.GetWorkDir()); err != nil {
		t.Errorf("ScanFile(work dir) error = %v, want nil", err)
	}
	if len(started) != 0 {
		t.Errorf("OnStartScanFile reached plugins for internal paths: %v", started)
	}
}

func TestConnector_scanDirSkipsWorkDirUnderScannedFolder(t *testing.T) {
	root := t.TempDir()
	c, err := NewConnector(Config{WorkDir: root}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(t.Context()) })
	if err := os.WriteFile(filepath.Join(c.GetWorkDir(), "extract", "inside.bin"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var started []string
	c.RegisterOnStartScanFile(func(location, _ string) { started = append(started, location) })
	if err := c.ScanFile(t.Context(), root); err != nil {
		t.Fatalf("ScanFile(root) error = %v", err)
	}
	if len(started) != 0 {
		t.Errorf("files under the work directory were scanned: %v", started)
	}
}

func newTestWorkDir(t *testing.T) *workDir {
	t.Helper()
	w, err := newWorkDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := w.close(); err != nil {
			t.Errorf("close() error = %v", err)
		}
	})
	return w
}

func TestConnector_ScanFileSkipsLinkToWorkDir(t *testing.T) {
	c, err := NewConnector(Config{WorkDir: t.TempDir(), FollowSymlinks: true}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(t.Context()) })
	inside := filepath.Join(c.GetWorkDir(), "extract", "a.bin")
	if err := os.WriteFile(inside, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link.bin")
	if err := os.Symlink(inside, link); err != nil {
		t.Fatal(err)
	}
	var started []string
	c.RegisterOnStartScanFile(func(location, _ string) { started = append(started, location) })
	if err := c.ScanFile(t.Context(), link); err != nil {
		t.Fatalf("ScanFile(link) error = %v", err)
	}
	c.Close(t.Context())
	if len(started) != 0 {
		t.Errorf("a link into the work directory was scanned: %v", started)
	}
}

func BenchmarkIsInternalPath(b *testing.B) {
	c, err := NewConnector(Config{WorkDir: b.TempDir()}, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { c.Close(context.Background()) })
	outside := filepath.Join(b.TempDir(), "deposits", "team", "report.pdf")
	inside := filepath.Join(c.GetWorkDir(), "extract", "x-1", "a.bin")
	b.ReportAllocs()
	for b.Loop() {
		if c.IsInternalPath(outside) || !c.IsInternalPath(inside) {
			b.Fatal("wrong classification")
		}
	}
}
