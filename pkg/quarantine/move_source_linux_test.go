//go:build linux

package quarantine

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/internal/safepath"
)

// verifiedSource opens src like the pipeline does and returns the MoveSource
// whose Remove goes through the handle.
func verifiedSource(t *testing.T, src string) MoveSource {
	t.Helper()
	h, err := safepath.Open(filepath.Dir(src), filepath.Base(src))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := h.Close(); e != nil {
			t.Error(e)
		}
	})
	return MoveSource{Path: src, File: h.OS(), Remove: h.Remove}
}

func fixedNow() func() time.Time {
	return func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
}

func TestMoveResolvingConflicts_aNameSwappedBeforeTheMoveLeavesTheFileInPlace(t *testing.T) {
	src, dst, staging := newMoveDirs(t)
	writeFile(t, src, "verified content", 0o640)
	ms := verifiedSource(t, src)
	// The name is swapped for another file after the verification.
	if err := os.Rename(src, src+".verified"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, src, "UNVERIFIED content", 0o640)
	_, err := MoveResolvingConflicts(ms, dst, staging, fixedNow(), 3)
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("error = %v, want ErrSourceChanged: the verified inode keeps a name in the source folder", err)
	}
	if _, statErr := os.Stat(dst); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("the destination is kept (%v)", statErr)
	}
	if readFile(t, src) != "UNVERIFIED content" {
		t.Error("the file that replaced the name was removed: it is not ours")
	}
}

func TestMoveResolvingConflicts_sourceWithoutDescriptorIsRefused(t *testing.T) {
	src, dst, staging := newMoveDirs(t)
	writeFile(t, src, "x", 0o640)
	_, err := MoveResolvingConflicts(MoveSource{Path: src}, dst, staging, fixedNow(), 3)
	if !errors.Is(err, ErrNoVerifiedSource) {
		t.Errorf("error = %v, want ErrNoVerifiedSource: no move by name on Linux", err)
	}
	if readFile(t, src) != "x" {
		t.Error("the source was touched")
	}
}

func TestMoveResolvingConflicts_takenNamesGetConflictNames(t *testing.T) {
	src, dst, staging := newMoveDirs(t)
	writeFile(t, dst, "already there", 0o640)
	writeFile(t, src, "verified", 0o640)
	got, err := MoveResolvingConflicts(verifiedSource(t, src), dst, staging, fixedNow(), 3)
	if err != nil {
		t.Fatal(err)
	}
	if got == dst || readFile(t, dst) != "already there" || readFile(t, got) != "verified" {
		t.Errorf("moved to %q, destination holds %q: a taken name must never be overwritten", got, readFile(t, dst))
	}
}

func TestMoveResolvingConflicts_linkRefusedFallsBackToACopyReadFromTheDescriptor(t *testing.T) {
	for _, errno := range []error{syscall.EXDEV, syscall.EPERM, syscall.ENOTSUP, syscall.EMLINK} {
		t.Run(errno.Error(), func(t *testing.T) {
			src, dst, staging := newMoveDirs(t)
			writeFile(t, src, "verified content", 0o640)
			ms := verifiedSource(t, src)
			prev := linkFD
			t.Cleanup(func() { linkFD = prev })
			linkFD = func(*os.File, string) error { return errno }
			// The name is swapped: only the descriptor holds the verified content.
			if err := os.Rename(src, src+".verified"); err != nil {
				t.Fatal(err)
			}
			writeFile(t, src, "UNVERIFIED", 0o640)
			got, err := MoveResolvingConflicts(ms, dst, staging, fixedNow(), 3)
			if err != nil {
				t.Fatal(err)
			}
			if readFile(t, got) != "verified content" {
				t.Errorf("destination holds %q, want the content of the descriptor", readFile(t, got))
			}
			if entries, _ := os.ReadDir(staging); len(entries) != 0 {
				t.Errorf("%d leftovers in the transit directory", len(entries))
			}
		})
	}
}

func TestMoveResolvingConflicts_failedRemovalTakesTheDestinationBack(t *testing.T) {
	for name, tc := range map[string]struct {
		cause     error
		permanent bool
	}{
		"permission": {syscall.EACCES, true},
		"read-only":  {syscall.EROFS, true},
		"other":      {syscall.EIO, false},
	} {
		t.Run(name, func(t *testing.T) {
			src, dst, staging := newMoveDirs(t)
			writeFile(t, src, "verified", 0o640)
			ms := verifiedSource(t, src)
			ms.Remove = func() error { return &os.PathError{Op: "remove", Path: src, Err: tc.cause} }
			_, err := MoveResolvingConflicts(ms, dst, staging, fixedNow(), 3)
			if err == nil || errors.Is(err, ErrSourceNotRemovable) != tc.permanent {
				t.Fatalf("error = %v, want ErrSourceNotRemovable = %t", err, tc.permanent)
			}
			if _, statErr := os.Stat(dst); !errors.Is(statErr, fs.ErrNotExist) {
				t.Errorf("the destination is kept (%v): the file would be in two places", statErr)
			}
			if readFile(t, src) != "verified" {
				t.Error("the source is gone")
			}
		})
	}
}

func TestMoveResolvingConflicts_aFileWrittenAfterTheCopyIsNotMoved(t *testing.T) {
	src, dst, staging := newMoveDirs(t)
	writeFile(t, src, "verified content", 0o640)
	ms := verifiedSource(t, src)
	prevLink, prevCopy := linkFD, copyData
	t.Cleanup(func() { linkFD, copyData = prevLink, prevCopy })
	linkFD = func(*os.File, string) error { return syscall.EXDEV }
	copyData = func(w io.Writer, r io.Reader) (int64, error) {
		n, err := io.Copy(w, r)
		// The depositor keeps writing while the copy is made.
		if e := os.WriteFile(src, []byte("verified content, then more"), 0o600); e != nil {
			t.Error(e)
		}
		return n, err
	}
	if _, err := MoveResolvingConflicts(ms, dst, staging, fixedNow(), 3); !errors.Is(err, ErrSourceChanged) {
		t.Errorf("error = %v, want ErrSourceChanged", err)
	}
	if _, err := os.Stat(dst); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the destination exists (%v)", err)
	}
}

func TestMoveResolvingConflicts_aSiblingHardLinkGetsACopy(t *testing.T) {
	src, dst, staging := newMoveDirs(t)
	writeFile(t, src, "verified content", 0o640)
	sibling := src + ".sibling"
	if err := os.Link(src, sibling); err != nil {
		t.Fatal(err)
	}
	got, err := MoveResolvingConflicts(verifiedSource(t, src), dst, staging, fixedNow(), 3)
	if err != nil {
		t.Fatal(err)
	}
	// What was published must not be an inode the depositor can still write.
	if err := os.WriteFile(sibling, []byte("rewritten through the sibling"), 0o600); err != nil {
		t.Fatal(err)
	}
	if readFile(t, got) != "verified content" {
		t.Errorf("the published file holds %q after a write through the sibling link: it must be a copy", readFile(t, got))
	}
}

func TestMoveResolvingConflicts_aLinkMadeAfterThePublicationTakesTheDestinationBack(t *testing.T) {
	src, dst, staging := newMoveDirs(t)
	writeFile(t, src, "verified content", 0o640)
	ms := verifiedSource(t, src)
	remove := ms.Remove
	sibling := src + ".late"
	ms.Remove = func() error {
		if err := os.Link(src, sibling); err != nil {
			t.Error(err)
		}
		return remove()
	}
	_, err := MoveResolvingConflicts(ms, dst, staging, fixedNow(), 3)
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("error = %v, want ErrSourceChanged", err)
	}
	if _, statErr := os.Stat(dst); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("the destination is kept (%v): its inode has another name", statErr)
	}
}

func TestMoveResolvingConflicts_aRenameDuringTheMoveTakesTheDestinationBack(t *testing.T) {
	src, dst, staging := newMoveDirs(t)
	writeFile(t, src, "verified content", 0o640)
	ms := verifiedSource(t, src)
	remove := ms.Remove
	ms.Remove = func() error {
		if err := os.Rename(src, src+".renamed"); err != nil {
			t.Error(err)
		}
		return remove()
	}
	_, err := MoveResolvingConflicts(ms, dst, staging, fixedNow(), 3)
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("error = %v, want ErrSourceChanged", err)
	}
	if _, statErr := os.Stat(dst); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("the destination is kept (%v): its inode kept a name in the source folder", statErr)
	}
}

func TestMoveResolvingConflicts_copyFallbackWithoutExchangeMovesTheFile(t *testing.T) {
	for _, errno := range []error{syscall.EXDEV, syscall.EPERM} {
		t.Run(errno.Error(), func(t *testing.T) {
			src, dst, staging := newMoveDirs(t)
			writeFile(t, src, "verified content", 0o640)
			ms := verifiedSource(t, src)
			prev := linkFD
			t.Cleanup(func() { linkFD = prev })
			linkFD = func(*os.File, string) error { return errno }
			got, err := MoveResolvingConflicts(ms, dst, staging, fixedNow(), 3)
			if err != nil {
				t.Fatal(err)
			}
			if readFile(t, got) != "verified content" {
				t.Errorf("destination holds %q", readFile(t, got))
			}
			if _, statErr := os.Stat(src); !errors.Is(statErr, fs.ErrNotExist) {
				t.Errorf("the source is still there (%v)", statErr)
			}
		})
	}
}

func TestMoveResolvingConflicts_copyFallbackKeepsTheCopyWhenTheSourceHasAnotherName(t *testing.T) {
	src, dst, staging := newMoveDirs(t)
	writeFile(t, src, "verified content", 0o640)
	ms := verifiedSource(t, src)
	prev := linkFD
	t.Cleanup(func() { linkFD = prev })
	linkFD = func(*os.File, string) error { return syscall.EXDEV }
	sibling := src + ".sibling"
	if err := os.Link(src, sibling); err != nil {
		t.Fatal(err)
	}
	got, err := MoveResolvingConflicts(ms, dst, staging, fixedNow(), 3)
	if err != nil {
		t.Fatal(err)
	}
	if readFile(t, got) != "verified content" {
		t.Errorf("destination holds %q", readFile(t, got))
	}
}

func TestMoveResolvingConflicts_unreadableLinkCountTakesTheDestinationBack(t *testing.T) {
	src, dst, staging := newMoveDirs(t)
	writeFile(t, src, "verified content", 0o640)
	ms := verifiedSource(t, src)
	own, err := os.Open(filepath.Clean(src))
	if err != nil {
		t.Fatal(err)
	}
	remove := ms.Remove
	ms.File = own
	ms.Remove = func() error {
		err := remove()
		if e := own.Close(); e != nil {
			t.Error(e)
		}
		return err
	}
	_, err = MoveResolvingConflicts(ms, dst, staging, fixedNow(), 3)
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("error = %v, want ErrSourceChanged", err)
	}
	if _, statErr := os.Stat(dst); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("the destination is kept (%v)", statErr)
	}
}
