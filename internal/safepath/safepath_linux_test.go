//go:build linux

package safepath

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestOpen_fallbackWithoutOpenat2StillRefusesLinks(t *testing.T) {
	prev := useOpenat2
	useOpenat2 = false
	t.Cleanup(func() { useOpenat2 = prev })

	root := t.TempDir()
	outside := t.TempDir()
	write(t, filepath.Join(outside, "secret"), "secret")
	write(t, filepath.Join(root, "real", "f"), "x")
	symlink(t, outside, filepath.Join(root, "dirlink"))
	symlink(t, filepath.Join(outside, "secret"), filepath.Join(root, "filelink"))

	f, err := Open(root, "real/f")
	if err != nil {
		t.Fatalf("Open() without openat2 error = %v", err)
	}
	if err := f.Remove(); err != nil {
		t.Errorf("Remove() without openat2 error = %v", err)
	}
	if err := f.Close(); err != nil {
		t.Error(err)
	}
	for _, rel := range []string{"dirlink/secret", "filelink"} {
		if g, err := Open(root, rel); err == nil {
			_ = g.Close()
			t.Errorf("Open(%q) without openat2 followed a link", rel)
		} else if !errors.Is(err, ErrSymlink) {
			t.Errorf("Open(%q) without openat2 error = %v, want ErrSymlink", rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(outside, "secret")); err != nil {
		t.Errorf("a file behind a link was reached: %v", err)
	}
}

func TestOpen_fallbackWithoutOpenat2RefusesANamedPipeWithoutBlocking(t *testing.T) {
	prev := useOpenat2
	useOpenat2 = false
	t.Cleanup(func() { useOpenat2 = prev })
	TestOpen_refusesANamedPipeWithoutBlocking(t)
}

// A symbolic link at each level of the path is refused, with openat2 and with
// the fallback for kernels older than 5.6.
func TestOpen_aLinkAtAnyLevelIsRefusedInBothModes(t *testing.T) {
	for _, mode := range []bool{true, false} {
		t.Run(map[bool]string{true: "openat2", false: "fallback"}[mode], func(t *testing.T) {
			prev := useOpenat2
			useOpenat2 = mode
			t.Cleanup(func() { useOpenat2 = prev })

			root := t.TempDir()
			outside := t.TempDir()
			write(t, filepath.Join(outside, "b", "c", "f.bin"), "secret")
			write(t, filepath.Join(root, "real", "b", "c", "f.bin"), "x")
			// A link at the first, second, third level and on the file itself.
			symlink(t, outside, filepath.Join(root, "l1"))
			symlink(t, filepath.Join(outside, "b"), filepath.Join(root, "real", "l2"))
			symlink(t, filepath.Join(outside, "b", "c"), filepath.Join(root, "real", "b", "l3"))
			symlink(t, filepath.Join(outside, "b", "c", "f.bin"), filepath.Join(root, "real", "b", "c", "lf"))
			for _, rel := range []string{"l1/b/c/f.bin", "real/l2/c/f.bin", "real/b/l3/f.bin", "real/b/c/lf"} {
				if f, err := Open(root, rel); err == nil {
					_ = f.Close()
					t.Errorf("Open(%q) followed a link", rel)
				} else if !errors.Is(err, ErrSymlink) {
					t.Errorf("Open(%q) error = %v, want ErrSymlink", rel, err)
				}
			}
			f, err := Open(root, "real/b/c/f.bin")
			if err != nil {
				t.Fatalf("Open() of the real file error = %v", err)
			}
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestFile_closeIsSafeFromTwoGoroutines(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "f"), "x")
	f, err := Open(root, "f")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { _ = f.Close() })
	}
	wg.Wait()
	if err := f.Close(); err != nil {
		t.Errorf("Close() after the others error = %v", err)
	}
}
