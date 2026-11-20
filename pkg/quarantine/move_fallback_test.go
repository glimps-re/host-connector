package quarantine

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
)

func withoutAtomicRename(t *testing.T) {
	t.Helper()
	prev := atomicRename
	atomicRename = func(string, string) (bool, error) { return false, nil }
	t.Cleanup(func() { atomicRename = prev })
}

func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRenameNoReplace_fallback(t *testing.T) {
	withoutAtomicRename(t)
	t.Run("free destination", func(t *testing.T) {
		dir := t.TempDir()
		src, dst := filepath.Join(dir, "src"), filepath.Join(dir, "dst")
		writeFixture(t, src, "data")
		if err := renameNoReplace(src, dst); err != nil {
			t.Fatalf("renameNoReplace() error = %v", err)
		}
		if got := readFile(t, dst); got != "data" {
			t.Errorf("destination = %q, want data", got)
		}
		if _, err := os.Lstat(src); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("source must be gone (error = %v)", err)
		}
	})
	t.Run("existing file", func(t *testing.T) {
		dir := t.TempDir()
		src, dst := filepath.Join(dir, "src"), filepath.Join(dir, "dst")
		writeFixture(t, src, "new")
		writeFixture(t, dst, "old")
		if err := renameNoReplace(src, dst); !errors.Is(err, ErrDestinationExists) {
			t.Fatalf("renameNoReplace() error = %v, want ErrDestinationExists", err)
		}
		if got := readFile(t, dst); got != "old" {
			t.Errorf("destination = %q, want it untouched", got)
		}
		if got := readFile(t, src); got != "new" {
			t.Errorf("source = %q, want it kept", got)
		}
	})
	t.Run("dangling link", func(t *testing.T) {
		dir := t.TempDir()
		src, dst := filepath.Join(dir, "src"), filepath.Join(dir, "dst")
		writeFixture(t, src, "new")
		if err := os.Symlink(filepath.Join(dir, "nowhere"), dst); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if err := renameNoReplace(src, dst); !errors.Is(err, ErrDestinationExists) {
			t.Fatalf("renameNoReplace() error = %v, want ErrDestinationExists", err)
		}
		if target, err := os.Readlink(dst); err != nil || target != filepath.Join(dir, "nowhere") {
			t.Errorf("link = %q (%v), want it untouched", target, err)
		}
	})
	t.Run("examination error is returned as is", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows reports a missing path instead of ENOTDIR")
		}
		dir := t.TempDir()
		src := filepath.Join(dir, "src")
		writeFixture(t, src, "data")
		dst := filepath.Join(src, "child")
		err := renameNoReplace(src, dst)
		if err == nil || errors.Is(err, ErrDestinationExists) || errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("renameNoReplace() error = %v, want a not-a-directory error", err)
		}
	})
}

func TestRenameNoReplace_atomicResults(t *testing.T) {
	tests := []struct {
		name    string
		result  error
		wantErr error
	}{
		{name: "destination taken", result: fs.ErrExist, wantErr: ErrDestinationExists},
		{name: "other error", result: syscall.EACCES, wantErr: syscall.EACCES},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prev := atomicRename
			atomicRename = func(string, string) (bool, error) { return true, tt.result }
			t.Cleanup(func() { atomicRename = prev })
			if err := renameNoReplace("a", "b"); !errors.Is(err, tt.wantErr) {
				t.Errorf("renameNoReplace() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestRenameNoReplace_concurrentFallbacksOneWins(t *testing.T) {
	withoutAtomicRename(t)
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst")
	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		src := filepath.Join(dir, "src"+string(rune('a'+i)))
		writeFixture(t, src, string(rune('a'+i)))
		wg.Go(func() { errs[i] = renameNoReplace(src, dst) })
	}
	wg.Wait()
	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, ErrDestinationExists):
			t.Errorf("unexpected error: %v", err)
		}
	}
	if wins != 1 {
		t.Errorf("%d renames succeeded, want exactly 1", wins)
	}
}

func TestRollback(t *testing.T) {
	cause := errors.New("cause")
	dir := t.TempDir()
	t.Run("removes the destination", func(t *testing.T) {
		dst := filepath.Join(dir, "dst")
		writeFixture(t, dst, "x")
		if err := rollback(dst, cause); !errors.Is(err, cause) {
			t.Errorf("rollback() = %v, want the cause", err)
		}
		if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("destination must be removed (error = %v)", err)
		}
	})
	t.Run("already gone", func(t *testing.T) {
		if err := rollback(filepath.Join(dir, "missing"), cause); !errors.Is(err, cause) {
			t.Errorf("rollback() = %v, want the cause", err)
		}
	})
	t.Run("removal failure still returns the cause", func(t *testing.T) {
		notEmpty := filepath.Join(dir, "notEmpty")
		if err := os.Mkdir(notEmpty, 0o750); err != nil {
			t.Fatal(err)
		}
		writeFixture(t, filepath.Join(notEmpty, "child"), "x")
		if err := rollback(notEmpty, cause); !errors.Is(err, cause) {
			t.Errorf("rollback() = %v, want the cause", err)
		}
		if _, err := os.Lstat(notEmpty); err != nil {
			t.Errorf("directory must be kept: %v", err)
		}
	})
}

func TestCreateStaged(t *testing.T) {
	prev := stagedNameSuffix
	t.Cleanup(func() { stagedNameSuffix = prev })
	t.Run("collisions are retried", func(t *testing.T) {
		dir := t.TempDir()
		writeFixture(t, filepath.Join(dir, "taken"), "x")
		calls := 0
		stagedNameSuffix = func(int) (string, error) {
			calls++
			if calls < 3 {
				return "taken", nil
			}
			return "free", nil
		}
		name, f, err := createStaged(dir)
		if err != nil {
			t.Fatalf("createStaged() error = %v", err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
		if name != filepath.Join(dir, "free") || calls != 3 {
			t.Errorf("name = %q after %d draws, want free after 3", name, calls)
		}
	})
	t.Run("five collisions give up", func(t *testing.T) {
		dir := t.TempDir()
		writeFixture(t, filepath.Join(dir, "taken"), "x")
		stagedNameSuffix = func(int) (string, error) { return "taken", nil }
		if _, _, err := createStaged(dir); !errors.Is(err, fs.ErrExist) {
			t.Errorf("createStaged() error = %v, want fs.ErrExist", err)
		}
	})
	t.Run("random source failure", func(t *testing.T) {
		boom := errors.New("no entropy")
		stagedNameSuffix = func(int) (string, error) { return "", boom }
		if _, _, err := createStaged(t.TempDir()); !errors.Is(err, boom) {
			t.Errorf("createStaged() error = %v, want %v", err, boom)
		}
	})
	t.Run("other creation error", func(t *testing.T) {
		stagedNameSuffix = func(int) (string, error) { return "x", nil }
		if _, _, err := createStaged(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("createStaged() error = %v, want fs.ErrNotExist", err)
		}
	})
}
