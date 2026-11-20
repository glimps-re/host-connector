//go:build linux

package quarantine

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// H1: the verified file is renamed elsewhere in INPUT after it was published and
// before the source is removed. The published inode must then have no name left
// in INPUT (or the publication is taken back): otherwise its owner could rewrite
// what was delivered.
func TestH1_aRenameBetweenThePublicationAndTheRemovalNeverLeavesTheDeliveredFileReachable(t *testing.T) {
	for name, rename := range map[string]func(src, other string) error{
		"renamed to another name": os.Rename,
		"exchanged with another file": func(src, other string) error {
			if err := os.WriteFile(other, []byte("some other file"), 0o600); err != nil {
				return err
			}
			return exchange(src, other)
		},
	} {
		t.Run(name, func(t *testing.T) {
			src, dst, staging := newMoveDirs(t)
			writeFile(t, src, "verified content", 0o640)
			ms := verifiedSource(t, src)
			other := src + ".elsewhere"

			prev := linkFD
			t.Cleanup(func() { linkFD = prev })
			linkFD = func(f *os.File, target string) error {
				if err := prev(f, target); err != nil {
					return err
				}
				// The depositor acts right after the publication.
				if err := rename(src, other); err != nil {
					t.Errorf("could not race the move: %v", err)
				}
				return nil
			}
			final, err := MoveResolvingConflicts(t.Context(), ms, dst, staging, fixedNow(), 3)

			published, statErr := os.Lstat(dst)
			if err != nil || final == "" {
				// A refusal is a correct answer provided nothing stays published.
				if statErr == nil {
					t.Fatalf("the move failed (%v) but %s is published", err, dst)
				}
				return
			}
			if statErr != nil {
				t.Fatalf("the move succeeded but %s is missing: %v", dst, statErr)
			}
			st, ok := published.Sys().(*syscall.Stat_t)
			if !ok {
				t.Fatalf("no stat for %s", dst)
			}
			if st.Nlink != 1 {
				t.Errorf("the delivered file has %d names (one in INPUT is still reachable): rewriting it there changes OUTPUT", st.Nlink)
			}
			before := readFile(t, dst)
			if err := os.WriteFile(other, []byte("REWRITTEN BY THE DEPOSITOR"), 0o600); err == nil {
				if after := readFile(t, dst); after != before {
					t.Errorf("writing through the INPUT name changed the delivered file: %q became %q", before, after)
				}
			}
		})
	}
}

func exchange(a, b string) error {
	tmp := filepath.Join(filepath.Dir(a), ".h1-swap")
	if err := os.Rename(a, tmp); err != nil {
		return err
	}
	if err := os.Rename(b, a); err != nil {
		return err
	}
	return os.Rename(tmp, b)
}

// The copy fallback: the link is refused (EXDEV, then EPERM) and the verified
// content is copied from the descriptor. Nothing is raced here, so the move must
// simply succeed: the copy is published, the source is removed, nothing is left
// in the transit folder. A published copy is never taken back because the
// source, which was removed, has no link left.
func TestH1_theCopyFallbackPublishesTheContentAndRemovesTheSource(t *testing.T) {
	for name, refusal := range map[string]error{"EXDEV": syscall.EXDEV, "EPERM": syscall.EPERM} {
		for variant, secondName := range map[string]bool{"single name": false, "a second name of the source stays in INPUT": true} {
			t.Run(name+"/"+variant, func(t *testing.T) {
				src, dst, staging := newMoveDirs(t)
				writeFile(t, src, "verified content", 0o640)
				if secondName {
					if err := os.Link(src, src+".second"); err != nil {
						t.Fatal(err)
					}
				}
				ms := verifiedSource(t, src)
				prev := linkFD
				t.Cleanup(func() { linkFD = prev })
				linkFD = func(*os.File, string) error {
					return &os.LinkError{Op: "linkat", Old: src, New: dst, Err: refusal}
				}
				final, err := MoveResolvingConflicts(t.Context(), ms, dst, staging, fixedNow(), 3)
				if err != nil {
					t.Fatalf("MoveResolvingConflicts() error = %v, want the move to succeed", err)
				}
				if final != dst {
					t.Errorf("published at %q, want %q", final, dst)
				}
				if got := readFile(t, dst); got != "verified content" {
					t.Errorf("the destination holds %q, want the content of the source: the copy was lost", got)
				}
				if _, statErr := os.Lstat(src); !os.IsNotExist(statErr) {
					t.Errorf("the source is still there (%v): it must be removed once the copy is published", statErr)
				}
				if secondName {
					if got := readFile(t, src+".second"); got != "verified content" {
						t.Errorf("the other name of the source holds %q: it is not ours to touch", got)
					}
				}
				if entries, readErr := os.ReadDir(staging); readErr == nil && len(entries) != 0 {
					t.Errorf("the transit folder holds %d file(s) after the move", len(entries))
				}
			})
		}
	}
}
