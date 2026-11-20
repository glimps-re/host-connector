package quarantine

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"testing"
	"time"
)

var testNow = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }

func TestMoveVerifiedCopy_aRemovalThatFailsTakesTheCopyBack(t *testing.T) {
	content := "analyzed content"
	f := newCopyFixture(t, content, 0o600)
	removeErr := syscall.EROFS
	_, err := MoveVerifiedCopy(t.Context(), f.src, func() error { return removeErr }, f.dst("x.bin"), f.staging, shaHex(content), testNow, 3)
	if !errors.Is(err, ErrSourceNotRemovable) || !errors.Is(err, removeErr) {
		t.Fatalf("error = %v, want ErrSourceNotRemovable wrapping the cause", err)
	}
	if got := treeOf(t, f.out); len(got) != 1 {
		t.Errorf("destination tree = %v, want only the transit folder", got)
	}
}

func TestMoveVerifiedCopy_aSourceNameThatChangedIsLeftAloneAndTheCopyStays(t *testing.T) {
	for name, removeErr := range map[string]error{
		"changed":  ErrSourceChanged,
		"replaced": errors.Join(errors.New("x"), fs.ErrNotExist),
	} {
		t.Run(name, func(t *testing.T) {
			content := "analyzed content"
			f := newCopyFixture(t, content, 0o600)
			got, err := MoveVerifiedCopy(t.Context(), f.src, func() error { return removeErr }, f.dst("x.bin"), f.staging, shaHex(content), testNow, 3)
			if err != nil || got != f.dst("x.bin") {
				t.Fatalf("MoveVerifiedCopy() = %q, %v", got, err)
			}
			if readFile(t, f.dst("x.bin")) != content {
				t.Error("the copy must stay")
			}
		})
	}
}

func TestMoveEmpty(t *testing.T) {
	t.Run("creates a new empty file and removes the source", func(t *testing.T) {
		f := newCopyFixture(t, "", 0o640)
		removed := false
		got, err := MoveEmpty(func() error { removed = true; return os.Remove(f.srcPath) }, f.srcPath, 0o640, f.dst("e"), testNow, 3)
		if err != nil || got != f.dst("e") || !removed {
			t.Fatalf("MoveEmpty() = %q, %v, removed %v", got, err, removed)
		}
		info, err := os.Lstat(got)
		if err != nil || info.Size() != 0 || !info.Mode().IsRegular() {
			t.Fatalf("destination = %v, %v", info, err)
		}
		if _, err := os.Lstat(f.srcPath); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("source still there: %v", err)
		}
	})
	t.Run("never replaces and takes a conflict name", func(t *testing.T) {
		f := newCopyFixture(t, "", 0o600)
		writeFixture(t, f.dst("e"), "taken")
		got, err := MoveEmpty(func() error { return nil }, "src", 0o600, f.dst("e"), testNow, 3)
		if err != nil || got != ConflictName(f.dst("e"), testNow(), 0) {
			t.Fatalf("MoveEmpty() = %q, %v", got, err)
		}
		if readFile(t, f.dst("e")) != "taken" {
			t.Error("the existing file was replaced")
		}
	})
	t.Run("all names taken", func(t *testing.T) {
		f := newCopyFixture(t, "", 0o600)
		writeFixture(t, f.dst("e"), "x")
		for i := range 2 {
			writeFixture(t, ConflictName(f.dst("e"), testNow(), i), "x")
		}
		if _, err := MoveEmpty(func() error { return nil }, "src", 0o600, f.dst("e"), testNow, 2); !errors.Is(err, ErrDestinationExists) {
			t.Errorf("error = %v, want ErrDestinationExists", err)
		}
	})
	t.Run("a removal that fails takes the file back", func(t *testing.T) {
		f := newCopyFixture(t, "", 0o600)
		_, err := MoveEmpty(func() error { return syscall.EACCES }, "src", 0o600, f.dst("e"), testNow, 3)
		if !errors.Is(err, ErrSourceNotRemovable) {
			t.Fatalf("error = %v", err)
		}
		if _, err := os.Lstat(f.dst("e")); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("destination must be removed: %v", err)
		}
	})
}
