package quarantine

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func refuseLinks(t *testing.T) {
	t.Helper()
	stubLink(t, func(oldname, newname string) error {
		return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: syscall.EPERM}
	})
}

func TestMoveFileNoReplace_refusedLinksNeverOverwrite(t *testing.T) {
	t.Run("existing destination is kept and the source stays", func(t *testing.T) {
		src, dst, staging := newMoveDirs(t)
		refuseLinks(t)
		writeFile(t, src, "new", 0o640)
		writeFile(t, dst, "original", 0o640)
		err := MoveFileNoReplace(src, dst, staging)
		if !errors.Is(err, ErrDestinationExists) {
			t.Fatalf("error = %v, want ErrDestinationExists", err)
		}
		if readFile(t, dst) != "original" || readFile(t, src) != "new" {
			t.Error("a refused move must leave both files untouched")
		}
	})
	t.Run("destination that is a dangling link is not written through", func(t *testing.T) {
		src, dst, staging := newMoveDirs(t)
		refuseLinks(t)
		writeFile(t, src, "new", 0o640)
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.Symlink(victim, dst); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		err := MoveFileNoReplace(src, dst, staging)
		if !errors.Is(err, ErrDestinationExists) {
			t.Fatalf("error = %v, want ErrDestinationExists", err)
		}
		if _, statErr := os.Lstat(victim); !errors.Is(statErr, fs.ErrNotExist) {
			t.Errorf("the link was followed: %v", statErr)
		}
	})
	t.Run("missing destination directory is a plain failure", func(t *testing.T) {
		src, dst, staging := newMoveDirs(t)
		refuseLinks(t)
		writeFile(t, src, "new", 0o640)
		missing := filepath.Join(filepath.Dir(dst), "nodir", "f.txt")
		err := MoveFileNoReplace(src, missing, staging)
		if err == nil || errors.Is(err, ErrDestinationExists) {
			t.Fatalf("error = %v, want a failure that is not ErrDestinationExists", err)
		}
		if readFile(t, src) != "new" {
			t.Error("source must be kept")
		}
	})
	t.Run("free destination is published and the source is gone", func(t *testing.T) {
		src, dst, staging := newMoveDirs(t)
		refuseLinks(t)
		writeFile(t, src, "new", 0o640)
		if err := MoveFileNoReplace(src, dst, staging); err != nil {
			t.Fatalf("error = %v", err)
		}
		if readFile(t, dst) != "new" {
			t.Error("destination content differs")
		}
		if _, err := os.Lstat(src); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("source must be gone: %v", err)
		}
	})
}

func TestMoveFileNoReplace_linkFailureThatIsNotARefusal(t *testing.T) {
	src, dst, staging := newMoveDirs(t)
	stubLink(t, func(oldname, newname string) error {
		return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: syscall.EIO}
	})
	writeFile(t, src, "new", 0o640)
	err := MoveFileNoReplace(src, dst, staging)
	if !errors.Is(err, syscall.EIO) {
		t.Fatalf("error = %v, want the I/O error returned as is", err)
	}
	if readFile(t, src) != "new" {
		t.Error("source must be kept")
	}
	if _, statErr := os.Lstat(dst); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("nothing must appear at the destination: %v", statErr)
	}
}

func TestStageCopy_failuresKeepTheSource(t *testing.T) {
	t.Run("staging directory that is a link", func(t *testing.T) {
		src, dst, staging := newMoveDirs(t)
		stubLink(t, exdevFor(src))
		if err := os.Symlink(t.TempDir(), staging); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		writeFile(t, src, "content", 0o640)
		err := MoveFileNoReplace(src, dst, staging)
		if !errors.Is(err, ErrStagingUnsafe) {
			t.Fatalf("error = %v, want ErrStagingUnsafe", err)
		}
		if readFile(t, src) != "content" {
			t.Error("source must be kept")
		}
	})
	t.Run("source that is not a regular file", func(t *testing.T) {
		src, dst, staging := newMoveDirs(t)
		stubLink(t, func(oldname, newname string) error {
			return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: syscall.EXDEV}
		})
		if err := os.Mkdir(src, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := MoveFileNoReplace(src, dst, staging); err == nil {
			t.Fatal("error = nil, want a refusal to copy a directory")
		}
		assertEmptyDir(t, staging)
	})
	t.Run("source vanished before the copy", func(t *testing.T) {
		src, dst, staging := newMoveDirs(t)
		if _, _, err := stageCopy(src, staging); err == nil {
			t.Fatal("stageCopy of a missing source: error = nil")
		}
		if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("nothing must appear at the destination: %v", err)
		}
	})
}

func TestCreateStaged_failsInAMissingDirectory(t *testing.T) {
	if _, f, err := createStaged(filepath.Join(t.TempDir(), "missing")); err == nil {
		if e := f.Close(); e != nil {
			t.Error(e)
		}
		t.Fatal("createStaged in a missing directory: error = nil")
	}
}

func TestRollback_keepsTheCauseWhenTheRemovalFails(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-empty")
	if err := os.MkdirAll(filepath.Join(dir, "child"), 0o750); err != nil {
		t.Fatal(err)
	}
	cause := errors.New("original failure")
	if got := rollback(dir, cause); !errors.Is(got, cause) {
		t.Errorf("rollback() = %v, want the original cause", got)
	}
	if got := rollback(filepath.Join(t.TempDir(), "already-gone"), cause); !errors.Is(got, cause) {
		t.Errorf("rollback() of a missing file = %v, want the original cause", got)
	}
}

func TestRemoveSource_unreadableSourceRollsTheDestinationBack(t *testing.T) {
	root := t.TempDir()
	notADir := filepath.Join(root, "file")
	writeFile(t, notADir, "x", 0o640)
	dst := filepath.Join(root, "dst")
	writeFile(t, dst, "published", 0o640)
	if err := removeSource(filepath.Join(notADir, "src"), dst, true); err == nil {
		t.Fatal("removeSource() error = nil, want the Lstat failure")
	}
	if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the destination must be rolled back when the source cannot be examined: %v", err)
	}
}

func TestPurgeStaging_ignoresWhatIsNotAnOldFile(t *testing.T) {
	purgeStaging(filepath.Join(t.TempDir(), "missing"))
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, "old")
	writeFile(t, old, "x", 0o600)
	past := time.Now().Add(-2 * stagingTTL)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(sub, past, past); err != nil {
		t.Fatal(err)
	}
	purgeStaging(dir)
	if _, err := os.Lstat(old); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("an old file must be purged: %v", err)
	}
	if _, err := os.Lstat(sub); err != nil {
		t.Errorf("a directory is never purged: %v", err)
	}
}
