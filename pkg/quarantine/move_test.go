package quarantine

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func writeFile(t *testing.T, path, content string, mode fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func stubLink(t *testing.T, f func(oldname, newname string) error) {
	t.Helper()
	prev := osLink
	osLink = f
	t.Cleanup(func() { osLink = prev })
}

func exdevFor(src string) func(string, string) error {
	return func(oldname, newname string) error {
		if oldname == src {
			return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: syscall.EXDEV}
		}
		return os.Link(oldname, newname)
	}
}

func newMoveDirs(t *testing.T) (src, dst, staging string) {
	t.Helper()
	root := t.TempDir()
	src = filepath.Join(root, "in", "f.txt")
	if err := os.MkdirAll(filepath.Dir(src), 0o750); err != nil {
		t.Fatal(err)
	}
	dstDir := filepath.Join(root, "out")
	if err := os.MkdirAll(dstDir, 0o750); err != nil {
		t.Fatal(err)
	}
	return src, filepath.Join(dstDir, "f.txt"), filepath.Join(dstDir, StagingDir)
}

func TestMoveFileNoReplace(t *testing.T) {
	t.Run("moves to a free destination", func(t *testing.T) {
		src, dst, staging := newMoveDirs(t)
		writeFile(t, src, "content", 0o640)
		if err := MoveFileNoReplace(src, dst, staging); err != nil {
			t.Fatalf("MoveFileNoReplace() error = %v", err)
		}
		if readFile(t, dst) != "content" {
			t.Error("content lost")
		}
		if _, err := os.Stat(src); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("source must be gone: %v", err)
		}
	})
	t.Run("never overwrites", func(t *testing.T) {
		src, dst, staging := newMoveDirs(t)
		writeFile(t, src, "new", 0o640)
		writeFile(t, dst, "original", 0o640)
		err := MoveFileNoReplace(src, dst, staging)
		if !errors.Is(err, ErrDestinationExists) {
			t.Fatalf("error = %v, want ErrDestinationExists", err)
		}
		if readFile(t, dst) != "original" || readFile(t, src) != "new" {
			t.Error("a file was lost or replaced")
		}
	})
	t.Run("links refused: Lstat and rename fallback never overwrites", func(t *testing.T) {
		src, dst, staging := newMoveDirs(t)
		stubLink(t, func(string, string) error { return &os.LinkError{Op: "link", Err: syscall.EPERM} })
		writeFile(t, src, "new", 0o640)
		writeFile(t, dst, "original", 0o640)
		if err := MoveFileNoReplace(src, dst, staging); !errors.Is(err, ErrDestinationExists) {
			t.Fatalf("error = %v, want ErrDestinationExists", err)
		}
		if readFile(t, dst) != "original" {
			t.Error("destination overwritten")
		}
		if err := os.Remove(dst); err != nil {
			t.Fatal(err)
		}
		if err := MoveFileNoReplace(src, dst, staging); err != nil {
			t.Fatalf("fallback move error = %v", err)
		}
		if readFile(t, dst) != "new" {
			t.Error("fallback did not move the file")
		}
	})
}

func TestMoveFileNoReplace_acrossDevices(t *testing.T) {
	t.Run("copies through the staging directory", func(t *testing.T) {
		src, dst, staging := newMoveDirs(t)
		stubLink(t, exdevFor(src))
		writeFile(t, src, "content", 0o640)
		if err := MoveFileNoReplace(src, dst, staging); err != nil {
			t.Fatalf("error = %v", err)
		}
		if readFile(t, dst) != "content" {
			t.Error("content lost")
		}
		if _, err := os.Stat(src); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("source must be gone: %v", err)
		}
		assertEmptyDir(t, staging)
		fi, err := os.Stat(staging)
		if err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("staging directory = %v, %v; want mode 0700", fi, err)
		}
	})
	t.Run("existing destination: intact, staging emptied, source kept", func(t *testing.T) {
		src, dst, staging := newMoveDirs(t)
		stubLink(t, exdevFor(src))
		writeFile(t, src, "new", 0o640)
		writeFile(t, dst, "original", 0o640)
		if err := MoveFileNoReplace(src, dst, staging); !errors.Is(err, ErrDestinationExists) {
			t.Fatalf("error = %v, want ErrDestinationExists", err)
		}
		if readFile(t, dst) != "original" || readFile(t, src) != "new" {
			t.Error("a file was lost or replaced")
		}
		assertEmptyDir(t, staging)
	})
	t.Run("interrupted copy leaves nothing under the final name", func(t *testing.T) {
		src, dst, staging := newMoveDirs(t)
		stubLink(t, exdevFor(src))
		if err := os.Mkdir(src, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := MoveFileNoReplace(src, dst, staging); err == nil {
			t.Fatal("copying a directory must fail")
		}
		if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a partial file appeared at the final name: %v", err)
		}
		assertEmptyDir(t, staging)
	})
	t.Run("setuid and setgid are not copied", func(t *testing.T) {
		src, dst, staging := newMoveDirs(t)
		stubLink(t, exdevFor(src))
		writeFile(t, src, "content", 0o755)
		if err := os.Chmod(src, 0o755|fs.ModeSetuid|fs.ModeSetgid); err != nil {
			t.Fatal(err)
		}
		if err := MoveFileNoReplace(src, dst, staging); err != nil {
			t.Fatalf("error = %v", err)
		}
		fi, err := os.Stat(dst)
		if err != nil || fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid) != 0 || fi.Mode().Perm() != 0o755 {
			t.Errorf("destination mode = %v, %v; want 0755 without setuid/setgid", fi.Mode(), err)
		}
	})
}

func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("%s holds %v, want it empty", dir, entries)
	}
}

func TestCopyAndDelete_neverOverwritesNorKeepsSetuid(t *testing.T) {
	src, dst, _ := newMoveDirs(t)
	writeFile(t, src, "new", 0o755)
	writeFile(t, dst, "original", 0o640)
	if err := copyAndDelete(src, dst); err == nil {
		t.Fatal("copyAndDelete over an existing file must fail")
	}
	if readFile(t, dst) != "original" || readFile(t, src) != "new" {
		t.Error("a file was lost or replaced")
	}
	if err := os.Remove(dst); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src, 0o755|fs.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	if err := copyAndDelete(src, dst); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dst); err != nil || fi.Mode()&fs.ModeSetuid != 0 {
		t.Errorf("destination mode = %v, %v; want no setuid", fi.Mode(), err)
	}
}

func TestConflictName(t *testing.T) {
	ts := time.Date(2026, 11, 19, 20, 30, 15, 0, time.UTC)
	tests := []struct {
		name string
		dst  string
		n    int
		want string
	}{
		{"with extension", "/out/u/report.pdf", 0, "/out/u/report.conflict-20261119T203015Z.pdf"},
		{"numbered", "/out/u/report.pdf", 2, "/out/u/report.conflict-20261119T203015Z-2.pdf"},
		{"no extension", "/out/u/notes", 0, "/out/u/notes.conflict-20261119T203015Z"},
		{"double extension keeps the last", "/out/a.tar.gz", 0, "/out/a.tar.conflict-20261119T203015Z.gz"},
		{"local time converted", "/out/f.txt", 0, "/out/f.conflict-20261119T203015Z.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := ts
			if tt.name == "local time converted" {
				in = ts.In(time.FixedZone("x", 3600))
			}
			if got := ConflictName(tt.dst, in, tt.n); got != tt.want {
				t.Errorf("ConflictName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConflictName_longNamesKeepTheirSuffix(t *testing.T) {
	ts := time.Date(2026, 11, 19, 20, 30, 15, 0, time.UTC)
	for _, base := range []string{strings.Repeat("a", 255-len(".pdf")), strings.Repeat("é", 200)} {
		got := ConflictName("/out/"+base+".pdf", ts, 3)
		name := filepath.Base(got)
		if len(name) > 255 {
			t.Errorf("name is %d bytes long, want at most 255", len(name))
		}
		if !strings.HasSuffix(name, ".conflict-20261119T203015Z-3.pdf") {
			t.Errorf("name = %q, the suffix must never be cut", name)
		}
		if strings.ContainsRune(name, '�') {
			t.Errorf("name = %q: a character was cut", name)
		}
	}
}

func TestFitName(t *testing.T) {
	got := FitName("/d/", strings.Repeat("x", 300), "-lockreport0101_1200.json")
	if len(filepath.Base(got)) != 255 || !strings.HasSuffix(got, "-lockreport0101_1200.json") {
		t.Errorf("FitName() = %q (%d bytes)", filepath.Base(got), len(filepath.Base(got)))
	}
	if got := FitName("/d/", "short", ".x"); got != "/d/short.x" {
		t.Errorf("FitName(short) = %q", got)
	}
}

func TestMoveFileResolvingConflicts(t *testing.T) {
	fixed := func() time.Time { return time.Date(2026, 11, 19, 20, 0, 0, 0, time.UTC) }
	t.Run("same file system: conflict names, original untouched", func(t *testing.T) {
		src, dst, staging := newMoveDirs(t)
		writeFile(t, dst, "original", 0o640)
		writeFile(t, strings.TrimSuffix(dst, ".txt")+".conflict-20261119T200000Z.txt", "other", 0o640)
		writeFile(t, src, "new", 0o640)
		got, err := MoveFileResolvingConflicts(src, dst, staging, fixed, 5)
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		if !strings.HasSuffix(got, ".conflict-20261119T200000Z-1.txt") || readFile(t, got) != "new" || readFile(t, dst) != "original" {
			t.Errorf("moved to %q", got)
		}
	})
	t.Run("across devices: the copy is made once for all the names tried", func(t *testing.T) {
		src, dst, staging := newMoveDirs(t)
		stubLink(t, exdevFor(src))
		copies := 0
		prev := copyData
		copyData = func(w io.Writer, r io.Reader) (int64, error) { copies++; return io.Copy(w, r) }
		t.Cleanup(func() { copyData = prev })
		writeFile(t, dst, "original", 0o640)
		writeFile(t, strings.TrimSuffix(dst, ".txt")+".conflict-20261119T200000Z.txt", "x", 0o640)
		writeFile(t, strings.TrimSuffix(dst, ".txt")+".conflict-20261119T200000Z-1.txt", "y", 0o640)
		writeFile(t, src, "new", 0o640)
		got, err := MoveFileResolvingConflicts(src, dst, staging, fixed, 5)
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		if copies != 1 || readFile(t, got) != "new" || !strings.HasSuffix(got, "-2.txt") {
			t.Errorf("copies = %d, moved to %q", copies, got)
		}
		assertEmptyDir(t, staging)
		if _, err := os.Stat(src); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("source must be gone: %v", err)
		}
	})
	t.Run("names exhausted: ErrDestinationExists, source and staging intact", func(t *testing.T) {
		src, dst, staging := newMoveDirs(t)
		stubLink(t, exdevFor(src))
		writeFile(t, dst, "original", 0o640)
		writeFile(t, src, "new", 0o640)
		_, err := MoveFileResolvingConflicts(src, dst, staging, time.Now, 0)
		if !errors.Is(err, ErrDestinationExists) {
			t.Fatalf("error = %v, want ErrDestinationExists", err)
		}
		if readFile(t, src) != "new" {
			t.Error("source lost")
		}
		assertEmptyDir(t, staging)
	})
}

func TestStageCopy_realCopyErrorLeavesNothing(t *testing.T) {
	src, dst, staging := newMoveDirs(t)
	stubLink(t, exdevFor(src))
	prev := copyData
	copyData = func(w io.Writer, _ io.Reader) (int64, error) {
		n, _ := w.Write([]byte("par"))
		return int64(n), errors.New("disk failure")
	}
	t.Cleanup(func() { copyData = prev })
	writeFile(t, src, "partial content", 0o640)
	if err := MoveFileNoReplace(src, dst, staging); err == nil {
		t.Fatal("a failing copy must fail the move")
	}
	assertEmptyDir(t, staging)
	if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("something appeared at the final name: %v", err)
	}
	if readFile(t, src) != "partial content" {
		t.Error("source must be kept")
	}
}

func TestStageCopy_sourceChangedDuringTheCopy(t *testing.T) {
	src, dst, staging := newMoveDirs(t)
	stubLink(t, exdevFor(src))
	prev := copyData
	copyData = func(w io.Writer, r io.Reader) (int64, error) {
		n, err := io.Copy(w, r)
		writeFile(t, src, "content that grew while it was copied", 0o640)
		return n, err
	}
	t.Cleanup(func() { copyData = prev })
	writeFile(t, src, "content", 0o640)
	err := MoveFileNoReplace(src, dst, staging)
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("error = %v, want ErrSourceChanged", err)
	}
	assertEmptyDir(t, staging)
	if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a copy of a changed file was published: %v", err)
	}
	if !strings.Contains(readFile(t, src), "grew") {
		t.Error("source must be kept")
	}
}

func TestMoveFileNoReplace_sourceNotARegularFile(t *testing.T) {
	src, dst, staging := newMoveDirs(t)
	stubLink(t, exdevFor(src))
	if err := os.Mkdir(src, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := MoveFileNoReplace(src, dst, staging); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("error = %v, want a refusal of a non regular source", err)
	}
}

func TestRemoveSource(t *testing.T) {
	t.Run("source already gone is a success", func(t *testing.T) {
		src, dst, _ := newMoveDirs(t)
		writeFile(t, dst, "x", 0o640)
		if err := removeSource(src, dst, true); err != nil {
			t.Errorf("error = %v", err)
		}
		if readFile(t, dst) != "x" {
			t.Error("destination rolled back for nothing")
		}
	})
	t.Run("a source that is no longer the linked file is kept and the destination taken back", func(t *testing.T) {
		src, dst, _ := newMoveDirs(t)
		writeFile(t, src, "replaced by someone", 0o640)
		writeFile(t, dst, "moved", 0o640)
		if err := removeSource(src, dst, true); !errors.Is(err, ErrSourceChanged) {
			t.Errorf("error = %v, want ErrSourceChanged", err)
		}
		if readFile(t, src) != "replaced by someone" {
			t.Error("the file that replaced the source was removed")
		}
		if _, err := os.Stat(dst); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the destination is kept (%v): it is not what was verified", err)
		}
	})
	t.Run("a linked source is removed", func(t *testing.T) {
		src, dst, _ := newMoveDirs(t)
		writeFile(t, src, "x", 0o640)
		if err := os.Link(src, dst); err != nil {
			t.Fatal(err)
		}
		if err := removeSource(src, dst, true); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(src); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("source still there: %v", err)
		}
	})
}

func TestPrepareStaging(t *testing.T) {
	t.Run("a directory open to others is refused", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("permission bits do not apply")
		}
		dir := filepath.Join(t.TempDir(), StagingDir)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, stagingTooOpen); err != nil {
			t.Fatal(err)
		}
		if err := prepareStaging(dir); !errors.Is(err, ErrStagingUnsafe) {
			t.Errorf("error = %v, want ErrStagingUnsafe", err)
		}
	})
	t.Run("a link is refused", func(t *testing.T) {
		base := t.TempDir()
		target := filepath.Join(base, "elsewhere")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(base, StagingDir)
		if err := os.Symlink(target, dir); err != nil {
			t.Fatal(err)
		}
		if err := prepareStaging(dir); !errors.Is(err, ErrStagingUnsafe) {
			t.Errorf("error = %v, want ErrStagingUnsafe", err)
		}
	})
	t.Run("old leftovers are purged once, recent ones kept", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), StagingDir)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		old, recent := filepath.Join(dir, "old"), filepath.Join(dir, "recent")
		writeFile(t, old, "x", 0o600)
		writeFile(t, recent, "x", 0o600)
		past := time.Now().Add(-48 * time.Hour)
		if err := os.Chtimes(old, past, past); err != nil {
			t.Fatal(err)
		}
		if err := prepareStaging(dir); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(old); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("old leftover kept: %v", err)
		}
		if _, err := os.Stat(recent); err != nil {
			t.Errorf("recent file removed: %v", err)
		}
	})
}

func TestConflictName_neverExceeds255Bytes(t *testing.T) {
	ts := time.Date(2026, 11, 19, 20, 30, 15, 0, time.UTC)
	for _, dst := range []string{
		"/out/" + strings.Repeat("a", 250) + ".txt",
		"/out/" + strings.Repeat("a", 251) + ".txt",
		"/out/" + strings.Repeat("a", 10) + "." + strings.Repeat("e", 244),
		"/out/." + strings.Repeat("e", 253),
	} {
		for _, n := range []int{0, 5} {
			if got := filepath.Base(ConflictName(dst, ts, n)); len(got) > 255 || !strings.Contains(got, ".conflict-20261119T203015Z") {
				t.Errorf("ConflictName(%.20q..., %d) = %d bytes %q", dst, n, len(got), got)
			}
		}
	}
}

func TestStageCopy_sneakyChangesAreCaught(t *testing.T) {
	const content = "0123456789"
	cases := []struct {
		name string
		do   func(t *testing.T, src string, mtime time.Time)
	}{
		{"same-size rewrite with the modification time reset (change time moves)", func(t *testing.T, src string, mtime time.Time) {
			if runtime.GOOS != "linux" {
				t.Skip("change time is only read on Linux")
			}
			writeFile(t, src, "ABCDEFGHIJ", 0o640)
			if err := os.Chtimes(src, mtime, mtime); err != nil {
				t.Fatal(err)
			}
		}},
		{"swap for another file of the same size and modification time", func(t *testing.T, src string, mtime time.Time) {
			other := src + ".other"
			writeFile(t, other, "ABCDEFGHIJ", 0o640)
			if err := os.Chtimes(other, mtime, mtime); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(other, src); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			src, dst, staging := newMoveDirs(t)
			stubLink(t, exdevFor(src))
			writeFile(t, src, content, 0o640)
			fi, err := os.Stat(src)
			if err != nil {
				t.Fatal(err)
			}
			mtime := fi.ModTime()
			prev := copyData
			copyData = func(w io.Writer, r io.Reader) (int64, error) {
				n, err := io.Copy(w, r)
				tt.do(t, src, mtime)
				return n, err
			}
			t.Cleanup(func() { copyData = prev })
			if err := MoveFileNoReplace(src, dst, staging); !errors.Is(err, ErrSourceChanged) {
				t.Fatalf("error = %v, want ErrSourceChanged", err)
			}
			assertEmptyDir(t, staging)
			if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("a copy of a changed file was published: %v", err)
			}
			if _, err := os.Stat(src); err != nil {
				t.Errorf("the source must be kept: %v", err)
			}
		})
	}
}

func TestRemoveCopiedSource_sneakyChangesKeepTheSource(t *testing.T) {
	t.Run("swapped for another file of the same size and modification time", func(t *testing.T) {
		src, dst, _ := newMoveDirs(t)
		writeFile(t, src, "0123456789", 0o640)
		copied, err := os.Stat(src)
		if err != nil {
			t.Fatal(err)
		}
		other := src + ".other"
		writeFile(t, other, "ABCDEFGHIJ", 0o640)
		if err := os.Chtimes(other, copied.ModTime(), copied.ModTime()); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(other, src); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dst, "copy", 0o640)
		if err := removeCopiedSource(src, dst, copied); !errors.Is(err, ErrSourceChanged) {
			t.Fatalf("error = %v, want ErrSourceChanged", err)
		}
		if readFile(t, src) != "ABCDEFGHIJ" {
			t.Error("the swapped source must be kept")
		}
		if _, err := os.Stat(dst); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the copy must be rolled back: %v", err)
		}
	})
	t.Run("rewritten with the modification time reset", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("change time is only read on Linux")
		}
		src, dst, _ := newMoveDirs(t)
		writeFile(t, src, "0123456789", 0o640)
		copied, err := os.Stat(src)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, src, "ABCDEFGHIJ", 0o640)
		if err := os.Chtimes(src, copied.ModTime(), copied.ModTime()); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dst, "copy", 0o640)
		if err := removeCopiedSource(src, dst, copied); !errors.Is(err, ErrSourceChanged) {
			t.Fatalf("error = %v, want ErrSourceChanged", err)
		}
		if readFile(t, src) != "ABCDEFGHIJ" {
			t.Error("the rewritten source must be kept")
		}
	})
	t.Run("untouched source is removed", func(t *testing.T) {
		src, dst, _ := newMoveDirs(t)
		writeFile(t, src, "0123456789", 0o640)
		copied, err := os.Stat(src)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, dst, "copy", 0o640)
		if err := removeCopiedSource(src, dst, copied); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(src); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("source still there: %v", err)
		}
	})
}
