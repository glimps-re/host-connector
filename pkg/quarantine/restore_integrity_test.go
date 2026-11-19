package quarantine

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newIntegrityHandler(t *testing.T, password string, format Format) (*QuarantineHandler, string) {
	t.Helper()
	dir := t.TempDir()
	q, err := NewQuarantineHandler(t.Context(), Config{Location: dir, LockPassword: password, Format: format})
	if err != nil {
		t.Fatalf("NewQuarantineHandler() error = %v", err)
	}
	t.Cleanup(func() {
		if e := q.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	return q, dir
}

func TestRestore_wrongPasswordAfterReconfigure(t *testing.T) {
	for _, format := range []Format{FormatTar, FormatZip} {
		t.Run(string(format), func(t *testing.T) {
			q, dir := newIntegrityHandler(t, "infected", format)
			content := []byte("content to protect, long enough to look like a file")
			src := filepath.Join(t.TempDir(), "sample.bin")
			if err := os.WriteFile(src, content, 0o600); err != nil {
				t.Fatal(err)
			}
			_, id, err := q.Quarantine(t.Context(), src, sha256Hex(content), []string{"m"})
			if err != nil {
				t.Fatalf("Quarantine() error = %v", err)
			}
			if err = os.Remove(src); err != nil {
				t.Fatal(err)
			}
			if err = q.Reconfigure(t.Context(), Config{Location: dir, LockPassword: "another password", Format: format}); err != nil {
				t.Fatalf("Reconfigure() error = %v", err)
			}

			err = q.Restore(t.Context(), id)
			if err == nil {
				t.Fatal("Restore() with a wrong password succeeded")
			}
			if format == FormatTar && !errors.Is(err, ErrRestoreContentMismatch) {
				t.Errorf("Restore() error = %v, want ErrRestoreContentMismatch", err)
			}
			if _, e := os.Stat(src); !errors.Is(e, os.ErrNotExist) {
				t.Errorf("destination must not exist after a failed restore (stat error = %v)", e)
			}
			if _, e := os.Stat(filepath.Join(dir, id+".lock")); e != nil {
				t.Errorf(".lock must be kept: %v", e)
			}
			entries, e := os.ReadDir(filepath.Dir(src))
			if e != nil {
				t.Fatal(e)
			}
			if len(entries) != 0 {
				t.Errorf("temporary file left behind: %v", entries)
			}
		})
	}
}

func TestRestore_registryHashMismatch(t *testing.T) {
	q, dir := newIntegrityHandler(t, "infected", FormatTar)
	content := []byte("real content")
	src := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}
	_, id, err := q.Quarantine(t.Context(), src, sha256Hex(content), []string{"m"})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := q.registry.Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	entry.SHA256 = sha256Hex([]byte("another content"))
	if err = q.registry.Set(t.Context(), entry); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(src); err != nil {
		t.Fatal(err)
	}
	if err = q.Restore(t.Context(), id); !errors.Is(err, ErrRestoreContentMismatch) {
		t.Errorf("Restore() error = %v, want ErrRestoreContentMismatch", err)
	}
	if _, e := os.Stat(filepath.Join(dir, id+".lock")); e != nil {
		t.Errorf(".lock must be kept: %v", e)
	}
}

func TestQuarantine_fileSizeChangedDuringRead(t *testing.T) {
	tests := []struct {
		name string
		lock func(path string, in io.Reader, out io.Writer) error
	}{
		{
			name: "container reads less than the stat size",
			lock: func(_ string, in io.Reader, _ io.Writer) error {
				_, err := io.CopyN(io.Discard, in, 3)
				return err
			},
		},
		{
			name: "file grows while being read",
			lock: func(path string, in io.Reader, _ io.Writer) error {
				f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_WRONLY, 0o600)
				if err != nil {
					return err
				}
				if _, err = f.WriteString(" grown"); err != nil {
					return errors.Join(err, f.Close())
				}
				if err = f.Close(); err != nil {
					return err
				}
				_, err = io.Copy(io.Discard, in)
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			locker := &lockerMock{LockFileMock: func(file string, in io.Reader, _ os.FileInfo, _ string, out io.Writer) error {
				return tt.lock(file, in, out)
			}}
			q := &QuarantineHandler{location: dir, locker: locker, registry: &registryMock{SetMock: func(_ context.Context, _ *Entry) error {
				t.Error("registry must not be updated for a changed file")
				return nil
			}}}
			src := filepath.Join(t.TempDir(), "sample.bin")
			if err := os.WriteFile(src, []byte("0123456789"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, id, err := q.Quarantine(t.Context(), src, "sha", []string{"m"})
			if !errors.Is(err, ErrFileChanged) {
				t.Fatalf("Quarantine() error = %v, want ErrFileChanged", err)
			}
			if _, e := os.Stat(filepath.Join(dir, ComputeCacheID(src, "sha")+".lock")); !errors.Is(e, os.ErrNotExist) {
				t.Errorf(".lock must be removed (stat error = %v, id=%q)", e, id)
			}
		})
	}
}

func TestRestore_invalidID(t *testing.T) {
	q, dir := newIntegrityHandler(t, "infected", FormatTar)
	outside := filepath.Join(t.TempDir(), "outside.lock")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, testRestoreID+".lock")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for name, id := range map[string]string{
		"empty":     "",
		"traversal": "../" + testRestoreID,
		"too short": "abcd",
		"uppercase": strings.ToUpper(testRestoreID),
		"suffix":    testRestoreID + ".lock",
	} {
		t.Run(name, func(t *testing.T) {
			if err := q.Restore(t.Context(), id); !errors.Is(err, errInvalidQuarantineID) {
				t.Errorf("Restore(%q) error = %v, want errInvalidQuarantineID", id, err)
			}
		})
	}
	t.Run("symlinked container", func(t *testing.T) {
		if err := q.Restore(t.Context(), testRestoreID); err == nil {
			t.Error("Restore() followed a symlink out of the quarantine directory")
		}
	})
}

func TestRestore_nonUTF8Path(t *testing.T) {
	for _, format := range []Format{FormatTar, FormatZip} {
		t.Run(string(format), func(t *testing.T) {
			q, _ := newIntegrityHandler(t, "infected", format)
			content := []byte("content")
			src := filepath.Join(t.TempDir(), "bad\xffname.bin")
			if err := os.WriteFile(src, content, 0o600); err != nil {
				t.Skipf("file system refuses non UTF-8 names: %v", err)
			}
			_, id, err := q.Quarantine(t.Context(), src, sha256Hex(content), []string{"m"})
			if err != nil {
				t.Fatalf("Quarantine() error = %v", err)
			}
			if err = os.Remove(src); err != nil {
				t.Fatal(err)
			}
			if err = q.Restore(t.Context(), id); err != nil {
				t.Fatalf("Restore() error = %v", err)
			}
			got, err := os.ReadFile(filepath.Clean(src))
			if err != nil || string(got) != "content" {
				t.Errorf("restored file = %q (err=%v), want the original name and content", got, err)
			}
		})
	}
}

func TestRestore_cancelledContext(t *testing.T) {
	q, dir := newIntegrityHandler(t, "infected", FormatTar)
	content := []byte("some content")
	src := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}
	_, id, err := q.Quarantine(t.Context(), src, sha256Hex(content), []string{"m"})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(src); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err = q.Restore(ctx, id); !errors.Is(err, context.Canceled) {
		t.Errorf("Restore() error = %v, want context.Canceled", err)
	}
	if _, e := os.Stat(src); !errors.Is(e, os.ErrNotExist) {
		t.Errorf("destination must not exist (stat error = %v)", e)
	}
	if _, e := os.Stat(filepath.Join(dir, id+".lock")); e != nil {
		t.Errorf(".lock must be kept: %v", e)
	}
}

func TestQuarantine_contentChangedAtSameSize(t *testing.T) {
	for _, format := range []Format{FormatTar, FormatZip} {
		t.Run(string(format), func(t *testing.T) {
			q, dir := newIntegrityHandler(t, "infected", format)
			src := filepath.Join(t.TempDir(), "sample.bin")
			if err := os.WriteFile(src, []byte("bbbb"), 0o600); err != nil {
				t.Fatal(err)
			}
			analysedSHA := sha256Hex([]byte("aaaa"))
			_, _, err := q.Quarantine(t.Context(), src, analysedSHA, []string{"m"})
			if !errors.Is(err, ErrQuarantineSHA256Mismatch) {
				t.Fatalf("Quarantine() error = %v, want ErrQuarantineSHA256Mismatch", err)
			}
			if matches, e := filepath.Glob(filepath.Join(dir, "*.lock")); e != nil || len(matches) != 0 {
				t.Errorf("no .lock must be kept, got %v (err %v)", matches, e)
			}
			if _, e := q.registry.GetBySHA256(t.Context(), analysedSHA); !errors.Is(e, errEntryNotFound) {
				t.Errorf("registry must have no entry (error = %v)", e)
			}
		})
	}
}
