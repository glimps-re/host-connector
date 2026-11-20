//go:build !windows

package scanner

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A deposited file replaced by a FIFO after its stability check must not block
// a worker: opening a FIFO for reading waits for a writer forever.
func TestPrepareFile_fifoReplacingTheFileDoesNotBlock(t *testing.T) {
	noOpenInputs(t)
	c, _, file, _ := newPathCheckFixture(t, false)
	want := idOf(t, file)
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(file, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	done := make(chan bool, 1)
	go func() {
		_, skip := c.prepareFile(file, want, nil)
		done <- skip
	}()
	select {
	case skip := <-done:
		if !skip {
			t.Error("prepareFile() must refuse a FIFO")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("prepareFile() blocked on a FIFO")
	}
}

func TestGetFileSHA256_refusesAFifoWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := getFileSHA256(path)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errNotRegular) {
			t.Errorf("getFileSHA256() error = %v, want errNotRegular", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("getFileSHA256() blocked on a FIFO")
	}
}

func TestOpenRegular_doesNotFollowALinkUnlessAsked(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if f, err := openRegular(link, false); err == nil {
		_ = f.Close()
		t.Error("openRegular() followed a link it must not follow")
	}
	f, err := openRegular(link, true)
	if err != nil {
		t.Fatalf("openRegular() error = %v", err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStatInput(t *testing.T) {
	c, in, file, _ := newPathCheckFixture(t, true)
	link := filepath.Join(in, "link.bin")
	if err := os.Symlink(file, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	intoWork := filepath.Join(in, "work.bin")
	workFile := filepath.Join(c.work.path, "private.bin")
	if err := os.WriteFile(workFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(workFile, intoWork); err != nil {
		t.Fatal(err)
	}
	t.Run("a followed link describes its target", func(t *testing.T) {
		info, err := c.statInput(link)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Size() != int64(len("some content")) {
			t.Errorf("statInput() = %v, %v; want the target", info, err)
		}
	})
	t.Run("a link to the work directory is refused", func(t *testing.T) {
		if _, err := c.statInput(intoWork); !errors.Is(err, errSkippedLink) {
			t.Errorf("statInput() error = %v, want errSkippedLink", err)
		}
	})
	t.Run("a link is refused unless followed", func(t *testing.T) {
		c.config.FollowSymlinks = false
		t.Cleanup(func() { c.config.FollowSymlinks = true })
		if _, err := c.statInput(link); !errors.Is(err, errSkippedLink) {
			t.Errorf("statInput() error = %v, want errSkippedLink", err)
		}
	})
	t.Run("a missing file is an error", func(t *testing.T) {
		if _, err := c.statInput(filepath.Join(in, "missing")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("statInput() error = %v, want ErrNotExist", err)
		}
	})
}
