package pathutil

import (
	"os"
	"path/filepath"
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
