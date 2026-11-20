package quarantine

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"testing"
)

// Whatever way a file is published, a source that cannot be removed takes the
// destination back and stays: the file is never in two places.
func TestRunPublication_everyStrategyTakesTheDestinationBackWhenTheSourceStays(t *testing.T) {
	content := "analyzed content"
	strategies := map[string]func(t *testing.T, f *copyFixture) error{
		"by path": func(t *testing.T, f *copyFixture) error {
			prev := osRemove
			t.Cleanup(func() { osRemove = prev })
			osRemove = func(string) error { return syscall.EACCES }
			_, err := moveFile(f.srcPath, f.dst("x.bin"), f.staging, func(int) (string, bool) { return "", false })
			return err
		},
		"verified copy": func(t *testing.T, f *copyFixture) error {
			_, err := MoveVerifiedCopy(t.Context(), f.src, func() error { return syscall.EACCES }, f.dst("x.bin"), f.staging, shaHex(content), testNow, 1)
			return err
		},
		"empty file": func(t *testing.T, f *copyFixture) error {
			_, err := MoveEmpty(func() error { return syscall.EACCES }, f.srcPath, 0o600, f.dst("x.bin"), testNow, 1)
			return err
		},
	}
	for name, run := range strategies {
		t.Run(name, func(t *testing.T) {
			f := newCopyFixture(t, content, 0o600)
			if err := run(t, f); !errors.Is(err, ErrSourceNotRemovable) {
				t.Fatalf("error = %v, want ErrSourceNotRemovable", err)
			}
			if _, err := os.Lstat(f.dst("x.bin")); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("destination must be taken back: %v", err)
			}
			if _, err := os.Lstat(f.srcPath); err != nil {
				t.Errorf("the source must stay: %v", err)
			}
		})
	}
}

func TestSyncDir_aDirectoryThatCannotBeMadeDurableKeepsTheSourceAndTheDestinationOut(t *testing.T) {
	prev := syncDir
	t.Cleanup(func() { syncDir = prev })
	syncDir = func(string) error { return syscall.EIO }
	content := "analyzed content"
	t.Run("verified copy", func(t *testing.T) {
		f := newCopyFixture(t, content, 0o600)
		removed := false
		_, err := MoveVerifiedCopy(t.Context(), f.src, func() error { removed = true; return nil }, f.dst("x.bin"), f.staging, shaHex(content), testNow, 1)
		if !errors.Is(err, syscall.EIO) || removed {
			t.Fatalf("error = %v, removed %v: the source must be kept", err, removed)
		}
		if _, err := os.Lstat(f.dst("x.bin")); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("destination must be taken back: %v", err)
		}
	})
	t.Run("empty file", func(t *testing.T) {
		f := newCopyFixture(t, "", 0o600)
		removed := false
		_, err := MoveEmpty(func() error { removed = true; return nil }, f.srcPath, 0o600, f.dst("x.bin"), testNow, 1)
		if !errors.Is(err, syscall.EIO) || removed {
			t.Fatalf("error = %v, removed %v", err, removed)
		}
	})
}

func TestCopies_dropWriteForOthersAndNeverKeepSetuid(t *testing.T) {
	content := "analyzed content"
	t.Run("verified copy", func(t *testing.T) {
		f := newCopyFixture(t, content, 0o666)
		if err := CopyVerified(t.Context(), f.src, f.dst("x.bin"), f.staging, shaHex(content)); err != nil {
			t.Fatal(err)
		}
		if got := modeOf(t, f.dst("x.bin")); got != 0o664 {
			t.Errorf("mode = %o, want 664: write for others is dropped, write for the group kept", got)
		}
	})
	t.Run("empty file", func(t *testing.T) {
		f := newCopyFixture(t, "", 0o666)
		if _, err := MoveEmpty(nil, f.srcPath, 0o666, f.dst("e"), testNow, 1); err != nil {
			t.Fatal(err)
		}
		if got := modeOf(t, f.dst("e")); got != 0o664 {
			t.Errorf("mode = %o, want 664 whatever the umask", got)
		}
	})
}

func modeOf(t *testing.T, path string) fs.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestCopyVerified_aFileThatGrowsByOneByteAfterTheLastBlockIsNeverPublished(t *testing.T) {
	content := string(make([]byte, 2*copyBlockSize))
	f := newCopyFixture(t, content, 0o600)
	withHooks(t, func(copied int64) {
		if copied == int64(len(content)) {
			if _, err := f.src.WriteAt([]byte("x"), copied); err != nil {
				t.Error(err)
			}
		}
	}, nil)
	err := CopyVerified(t.Context(), f.src, f.dst("x.bin"), f.staging, shaHex(content))
	if !errors.Is(err, ErrContentChanged) {
		t.Errorf("error = %v, want ErrContentChanged: the size is a multiple of the block, the probe byte tells", err)
	}
	if got := treeOf(t, f.out); len(got) > 1 {
		t.Errorf("published something: %v", got)
	}
}

func TestPathMove_aCopyAcrossDevicesIsVerifiedWhenTheHashIsKnown(t *testing.T) {
	content := "analyzed content"
	tests := []struct {
		name, sha string
		want      error
	}{
		{"same content", shaHex(content), nil},
		{"rewritten since the analysis", shaHex("other"), ErrContentChanged},
		{"no hash: a copy that cannot be verified is refused", "", ErrNoExpectedHash},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newCopyFixture(t, content, 0o600)
			stubLink(t, exdevFor(f.srcPath))
			p := &pathMove{ctx: t.Context(), src: f.srcPath, cur: f.srcPath, stagingDir: f.staging, sha256: tt.sha, verified: true}
			_, err := runPublication(p, f.dst("x.bin"), func(int) (string, bool) { return "", false })
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			if tt.want != nil {
				if _, statErr := os.Lstat(f.dst("x.bin")); !errors.Is(statErr, fs.ErrNotExist) {
					t.Errorf("destination published: %v", statErr)
				}
				if entries, _ := os.ReadDir(f.staging); len(entries) != 0 {
					t.Errorf("%d leftovers in the transit directory", len(entries))
				}
			}
		})
	}
}
