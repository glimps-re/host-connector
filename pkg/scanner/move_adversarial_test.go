package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMoveAction_destinationSymlinkIsNeverFollowed(t *testing.T) {
	tests := []struct {
		name      string
		linkTo    func(outside string) string
		wantExist bool
	}{
		{"dangling link", func(outside string) string { return filepath.Join(outside, "created-through-link") }, false},
		{"link to an existing file", func(outside string) string {
			p := filepath.Join(outside, "victim")
			if err := os.WriteFile(p, []byte("victim"), 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newMoveFixture(t)
			outside := t.TempDir()
			target := tt.linkTo(outside)
			if err := os.MkdirAll(filepath.Join(f.dst, "u"), 0o750); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(f.dst, "u", "a.bin")
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			rep, err := f.move(t, f.deposit(t, "u/a.bin", "payload"), false)
			if err != nil {
				t.Fatalf("move error = %v", err)
			}
			if _, statErr := os.Stat(target); (statErr == nil) != tt.wantExist {
				t.Errorf("target through the link exists = %t, want %t: the link was followed", statErr == nil, tt.wantExist)
			}
			if tt.wantExist && read(t, target) != "victim" {
				t.Error("the file behind the link was overwritten")
			}
			if fi, lerr := os.Lstat(link); lerr != nil || fi.Mode()&os.ModeSymlink == 0 {
				t.Errorf("the link at the destination must be left alone: %v", lerr)
			}
			if !strings.Contains(rep.MovedTo, ".conflict-") || read(t, rep.MovedTo) != "payload" {
				t.Errorf("MovedTo = %q, want a conflict name holding the payload", rep.MovedTo)
			}
		})
	}
}

func TestMoveAction_reservedPrefixOnlyAppliesToTheBaseName(t *testing.T) {
	f := newMoveFixture(t)
	for _, rel := range []string{"report-session-dir/file.pdf", "u/Report-Session-dir/inner/file.pdf"} {
		p := f.deposit(t, rel, "ok")
		rep, err := f.move(t, p, false)
		if err != nil || read(t, rep.MovedTo) != "ok" {
			t.Errorf("move of %q = %+v, %v: only the base name is reserved", rel, rep, err)
		}
	}
}
