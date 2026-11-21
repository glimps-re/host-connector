//go:build unix

package quarantine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A named pipe swapped in for a container must not block the restoration, which
// holds locks, nor the listing.
func TestRestore_aFIFOCalledLikeAContainerIsRefusedAtOnce(t *testing.T) {
	q, dir := newE2EHandler(t, FormatTar)
	_, id := quarantined(t, q, "f.bin", "content")
	if err := removeContainer(dir, id); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, id+".lock"), 0o600); err != nil {
		t.Skip("named pipes not available:", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := q.Restore(t.Context(), id); err == nil {
			t.Error("Restore() accepted a named pipe")
		}
		for f, err := range q.ListQuarantinedFiles(t.Context()) {
			if err != nil || f != nil {
				t.Errorf("a named pipe is listed: %+v, %v", f, err)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Restore or the listing blocked on a named pipe")
	}
}

// A named pipe swapped in for the container after its name was examined must not
// block the opening (O_NONBLOCK) and is refused.
func TestRestore_aFIFOSwappedInAfterTheExaminationIsRefusedWithoutBlocking(t *testing.T) {
	q, dir := newE2EHandler(t, FormatTar)
	_, id := quarantined(t, q, "f.bin", "content")
	lock := filepath.Join(dir, id+".lock")
	prev := betweenLstatAndOpen
	betweenLstatAndOpen = func() {
		betweenLstatAndOpen = prev
		if err := removeContainer(dir, id); err != nil {
			t.Error(err)
		}
		if err := syscall.Mkfifo(lock, 0o600); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { betweenLstatAndOpen = prev })
	done := make(chan error, 1)
	go func() { done <- q.Restore(t.Context(), id) }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Restore() accepted a named pipe")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Restore() blocked on a named pipe swapped in after the examination of its name")
	}
}

func TestIsLinkRefused(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{syscall.EPERM, true},
		{syscall.ENOTSUP, true},
		{syscall.EMLINK, true},
		{syscall.ENOSYS, true},
		{fmt.Errorf("link: %w", &os.LinkError{Op: "link", Err: syscall.EPERM}), true},
		{syscall.EEXIST, false},
		{syscall.ENOENT, false},
		{syscall.EACCES, false},
		{nil, false},
	}
	for _, tt := range tests {
		if got := isLinkRefused(tt.err); got != tt.want {
			t.Errorf("isLinkRefused(%v) = %t, want %t", tt.err, got, tt.want)
		}
	}
}

// The real renameat2 path, with the links refused: an existing destination is
// refused by the kernel and left intact.
func TestRestore_withRenameNoReplaceAndNoLinkAnExistingDestinationIsRefused(t *testing.T) {
	prev := rootLink
	rootLink = func(*os.Root, string, string) error { return syscall.EPERM }
	t.Cleanup(func() { rootLink = prev })
	q, _ := newE2EHandler(t, FormatTar)
	path, id := quarantined(t, q, "f.bin", "content")
	if err := os.WriteFile(path, []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	if handled, _ := rootRenameNoReplaceOS(mustRoot(t, filepath.Dir(path)), "absent-a", "absent-b"); !handled {
		t.Skip("this file system does not support RENAME_NOREPLACE")
	}
	if err := q.Restore(t.Context(), id); !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("Restore() = %v, want ErrDestinationExists", err)
	}
	assertContent(t, path, "in the way")
	assertNoTemp(t, filepath.Dir(path))
}

func mustRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := root.Close(); e != nil {
			t.Error(e)
		}
	})
	return root
}
