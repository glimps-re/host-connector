package pathutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestUnder(t *testing.T) {
	tests := []struct {
		root, p string
		want    bool
	}{
		{"/a/b", "/a/b", true},
		{"/a/b", "/a/b/c/d", true},
		{"/a/b/", "/a/b/c", true},
		{"/a/b", "/a/bc", false},
		{"/a/b", "/a", false},
		{"/a/b", "/a/b/../c", false},
		{"/a/b", "/a/b/..x/c", true},
		{"/a/b", "/other", false},
	}
	for _, tt := range tests {
		if got := Under(tt.root, tt.p); got != tt.want {
			t.Errorf("Under(%q, %q) = %t, want %t", tt.root, tt.p, got, tt.want)
		}
	}
}

func TestResolvedForms(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if !Same(target, link) || Same(target, dir) {
		t.Error("Same() must resolve links and only links")
	}
	if !UnderResolved(target, filepath.Join(link, "sub")) {
		t.Error("UnderResolved() must follow the link")
	}
	if UnderResolved(target, target+"x") {
		t.Error("UnderResolved() compared by prefix")
	}
	if Under(target, filepath.Join(link, "sub")) {
		t.Error("Under() is lexical and must not follow links")
	}
	if got := Forms(filepath.Join(dir, "missing")); len(got) != 1 {
		t.Errorf("Forms(missing) = %v, want only the absolute form", got)
	}
}

func TestCheckNoSymlink(t *testing.T) {
	root := t.TempDir()
	mk := func(rel string) string {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(p, 0o750); err != nil {
			t.Fatal(err)
		}
		return p
	}
	file := filepath.Join(mk("a/b"), "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(file, filepath.Join(root, "a", "filelink")); err != nil {
		t.Fatal(err)
	}
	above := filepath.Join(t.TempDir(), "above")
	if err := os.Symlink(root, above); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		root, path  string
		wantSymlink bool
		wantErr     bool
	}{
		{name: "plain file", root: root, path: file},
		{name: "root itself", root: root, path: root},
		{name: "intermediate link", root: root, path: filepath.Join(root, "link", "x"), wantSymlink: true},
		{name: "last component is a link", root: root, path: filepath.Join(root, "a", "filelink"), wantSymlink: true},
		{name: "link above the root is trusted", root: above, path: filepath.Join(above, "a", "b", "f.txt")},
		{name: "path outside root", root: root, path: outside, wantSymlink: true},
		{name: "missing component", root: root, path: filepath.Join(root, "a", "missing", "f"), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckNoSymlink(tt.root, tt.path)
			wantErr := tt.wantSymlink || tt.wantErr
			if (err != nil) != wantErr {
				t.Fatalf("CheckNoSymlink() error = %v, wantErr %t", err, wantErr)
			}
			if tt.wantSymlink && !errors.Is(err, ErrSymlinkInPath) {
				t.Errorf("CheckNoSymlink() error = %v, want ErrSymlinkInPath", err)
			}
		})
	}

	if err := CheckExistingNoSymlink(root, filepath.Join(root, "a", "missing", "deeper")); err != nil {
		t.Errorf("CheckExistingNoSymlink(missing tail) = %v, want nil", err)
	}
	if err := CheckExistingNoSymlink(root, filepath.Join(root, "link", "missing")); !errors.Is(err, ErrSymlinkInPath) {
		t.Errorf("CheckExistingNoSymlink(link then missing) = %v, want ErrSymlinkInPath", err)
	}
}

func BenchmarkCheckNoSymlink(b *testing.B) {
	root := b.TempDir()
	dir := filepath.Join(root, "alice", "reports", "2026", "11")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		b.Fatal(err)
	}
	file := filepath.Join(dir, "report.pdf")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := CheckNoSymlink(root, file); err != nil {
			b.Fatal(err)
		}
	}
}

func TestCheckTrustedPath(t *testing.T) {
	base := t.TempDir()
	plain := filepath.Join(base, "a", "b")
	if err := os.MkdirAll(plain, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(plain, link); err != nil {
		t.Fatal(err)
	}
	userLink := filepath.Join(plain, "userlink")
	if err := os.Symlink(base, userLink); err != nil {
		t.Fatal(err)
	}
	relLink := filepath.Join(base, "rel")
	if err := os.Symlink(filepath.Join("a", "b"), relLink); err != nil {
		t.Fatal(err)
	}
	never := func(_, _ fs.FileInfo) bool { return false }
	onlyNamed := func(name string) func(_, _ fs.FileInfo) bool {
		return func(l, _ fs.FileInfo) bool { return l.Name() == name }
	}

	if err := CheckTrustedPath(plain, never); err != nil {
		t.Errorf("plain path: %v", err)
	}
	if err := CheckTrustedPath(link, never); !errors.Is(err, ErrSymlinkInPath) {
		t.Errorf("untrusted link: error = %v, want ErrSymlinkInPath", err)
	}
	if err := CheckTrustedPath(link, onlyNamed("link")); err != nil {
		t.Errorf("trusted link: %v", err)
	}
	if err := CheckTrustedPath(relLink, onlyNamed("rel")); err != nil {
		t.Errorf("trusted relative link: %v", err)
	}
	if err := CheckTrustedPath(filepath.Join(link, "userlink", "a"), onlyNamed("link")); !errors.Is(err, ErrSymlinkInPath) {
		t.Errorf("link found after a trusted one: error = %v, want ErrSymlinkInPath", err)
	}
	if err := CheckTrustedPath(filepath.Join(base, "missing", "x"), never); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing component: error = %v, want ErrNotExist", err)
	}
	if err := CheckTrustedPath(filepath.Join(plain, "..", "b"), never); err != nil {
		t.Errorf("dotdot: %v", err)
	}

	chain := plain
	holder := t.TempDir()
	for i := range MaxLinks {
		l := filepath.Join(holder, "c"+strconv.Itoa(i))
		if err := os.Symlink(chain, l); err != nil {
			t.Fatal(err)
		}
		chain = l
	}
	all := func(_, _ fs.FileInfo) bool { return true }
	if err := CheckTrustedPath(chain, all); err != nil {
		t.Errorf("%d links: %v", MaxLinks, err)
	}
	l := filepath.Join(holder, "last")
	if err := os.Symlink(chain, l); err != nil {
		t.Fatal(err)
	}
	if err := CheckTrustedPath(l, all); !errors.Is(err, ErrSymlinkInPath) {
		t.Errorf("%d links: error = %v, want ErrSymlinkInPath", MaxLinks+1, err)
	}
}

func TestIsLinkLike(t *testing.T) {
	if !IsLinkLike(fs.ModeSymlink) || !IsLinkLike(fs.ModeIrregular|fs.ModeDir) {
		t.Error("symlinks and irregular entries (Windows junctions) are links")
	}
	if IsLinkLike(fs.ModeDir) || IsLinkLike(0) {
		t.Error("plain directories and files are not links")
	}
}
