//go:build linux

package quarantine

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"syscall"
	"testing"
)

func TestMoveResolvingConflicts_aCopyMadeWhenLinksAreRefusedIsVerifiedAgainstTheAnalyzedHash(t *testing.T) {
	refuse := func(t *testing.T) {
		t.Helper()
		prev := linkFD
		t.Cleanup(func() { linkFD = prev })
		linkFD = func(*os.File, string) error { return syscall.EXDEV }
	}
	t.Run("same content: published", func(t *testing.T) {
		src, dst, staging := newMoveDirs(t)
		writeFile(t, src, "analyzed", 0o640)
		ms := verifiedSource(t, src)
		ms.SHA256 = shaHex("analyzed")
		refuse(t)
		got, err := MoveResolvingConflicts(t.Context(), ms, dst, staging, testNow, 3)
		if err != nil || readFile(t, got) != "analyzed" {
			t.Fatalf("MoveResolvingConflicts() = %q, %v", got, err)
		}
	})
	t.Run("rewritten since the analysis: nothing published, source kept", func(t *testing.T) {
		src, dst, staging := newMoveDirs(t)
		writeFile(t, src, "analyzed", 0o640)
		ms := verifiedSource(t, src)
		ms.SHA256 = shaHex("something else")
		refuse(t)
		_, err := MoveResolvingConflicts(t.Context(), ms, dst, staging, testNow, 3)
		if !errors.Is(err, ErrContentChanged) {
			t.Fatalf("error = %v, want ErrContentChanged", err)
		}
		if _, statErr := os.Lstat(dst); !errors.Is(statErr, fs.ErrNotExist) {
			t.Errorf("destination published: %v", statErr)
		}
		if readFile(t, src) != "analyzed" {
			t.Error("the source must stay")
		}
		if entries, _ := os.ReadDir(staging); len(entries) != 0 {
			t.Errorf("%d leftovers in the transit directory", len(entries))
		}
	})
}

func TestRunPublication_byDescriptorTakesTheDestinationBackWhenTheSourceStays(t *testing.T) {
	src, dst, staging := newMoveDirs(t)
	writeFile(t, src, "verified", 0o640)
	ms := verifiedSource(t, src)
	ms.Remove = func() error { return syscall.EACCES }
	_, err := MoveResolvingConflicts(t.Context(), ms, dst, staging, testNow, 3)
	if !errors.Is(err, ErrSourceNotRemovable) {
		t.Fatalf("error = %v", err)
	}
	if _, statErr := os.Lstat(dst); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("destination must be taken back: %v", statErr)
	}
}

func TestMoveResolvingConflicts_aCopyWithoutAHashIsRefused(t *testing.T) {
	src, dst, staging := newMoveDirs(t)
	writeFile(t, src, "analyzed", 0o640)
	ms := verifiedSource(t, src)
	ms.SHA256 = ""
	prev := linkFD
	t.Cleanup(func() { linkFD = prev })
	linkFD = func(*os.File, string) error { return syscall.EXDEV }
	if _, err := MoveResolvingConflicts(t.Context(), ms, dst, staging, testNow, 3); !errors.Is(err, ErrNoExpectedHash) {
		t.Fatalf("error = %v, want ErrNoExpectedHash", err)
	}
	if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("destination published: %v", err)
	}
}

func TestMoveResolvingConflicts_aCopyMadeWhenLinksAreRefusedStopsWithTheContext(t *testing.T) {
	src, dst, staging := newMoveDirs(t)
	writeFile(t, src, "analyzed", 0o640)
	ms := verifiedSource(t, src)
	prev := linkFD
	t.Cleanup(func() { linkFD = prev })
	linkFD = func(*os.File, string) error { return syscall.EXDEV }
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := MoveResolvingConflicts(ctx, ms, dst, staging, testNow, 3); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	assertEmptyDir(t, staging)
	if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("destination published: %v", err)
	}
}
