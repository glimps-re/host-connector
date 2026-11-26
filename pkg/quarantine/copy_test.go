package quarantine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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

func shaHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

type copyFixture struct {
	out     string // destination folder
	staging string
	src     *os.File
	srcPath string
}

func newCopyFixture(t *testing.T, content string, mode os.FileMode) *copyFixture {
	t.Helper()
	root := t.TempDir()
	out := filepath.Join(root, "out")
	if err := os.Mkdir(out, 0o750); err != nil {
		t.Fatal(err)
	}
	srcPath := filepath.Join(root, "in.bin")
	if err := os.WriteFile(srcPath, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(srcPath, mode); err != nil {
		t.Fatal(err)
	}
	src, err := os.OpenFile(filepath.Clean(srcPath), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = src.Close() })
	return &copyFixture{out: out, staging: filepath.Join(out, StagingDir), src: src, srcPath: srcPath}
}

func (f *copyFixture) dst(name string) string { return filepath.Join(f.out, name) }

// treeOf lists everything under dir, relative, to check what is visible where.
func treeOf(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	if err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p != dir {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, rel)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func withHooks(t *testing.T, after func(int64), wrap func(io.Writer) io.Writer) {
	t.Helper()
	prevAfter, prevWrap := afterCopyBlock, wrapCopyWriter
	t.Cleanup(func() { afterCopyBlock, wrapCopyWriter = prevAfter, prevWrap })
	if after != nil {
		afterCopyBlock = after
	}
	if wrap != nil {
		wrapCopyWriter = wrap
	}
}

func TestCopyVerified_copiesTheAnalyzedContent(t *testing.T) {
	content := strings.Repeat("analyzed content ", 20_000) // several blocks
	f := newCopyFixture(t, content, 0o640)
	if err := CopyVerified(t.Context(), f.src, f.dst("a.bin"), f.staging, shaHex(content)); err != nil {
		t.Fatalf("CopyVerified() error = %v", err)
	}
	if got := readFile(t, f.dst("a.bin")); got != content {
		t.Error("the destination does not hold the analyzed content")
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(f.dst("a.bin")); err != nil || info.Mode().Perm() != 0o640 {
			t.Errorf("mode = %v (%v), want 0640", info.Mode(), err)
		}
	}
	if entries := treeOf(t, f.staging); len(entries) != 0 {
		t.Errorf("transit folder not empty: %v", entries)
	}
	if got := readFile(t, f.srcPath); got != content {
		t.Error("the source must be left untouched: it is not removed here")
	}
	if upper := strings.ToUpper(shaHex(content)); CopyVerified(t.Context(), f.src, f.dst("b.bin"), f.staging, upper) != nil {
		t.Error("an upper-case SHA256 must be accepted")
	}
}

func TestCopyVerified_refusesWhenTheHashIsMissingOrMalformed(t *testing.T) {
	f := newCopyFixture(t, "content", 0o600)
	for name, sha := range map[string]string{"empty": "", "short": "abc", "not hex": strings.Repeat("z", 64), "too long": shaHex("content") + "0"} {
		t.Run(name, func(t *testing.T) {
			err := CopyVerified(t.Context(), f.src, f.dst("x.bin"), f.staging, sha)
			if !errors.Is(err, ErrNoExpectedHash) {
				t.Errorf("CopyVerified(%q) error = %v, want ErrNoExpectedHash", sha, err)
			}
			if entries := treeOf(t, f.out); len(entries) != 0 {
				t.Errorf("nothing may be created without a hash to verify: %v", entries)
			}
		})
	}
}

// What was analyzed is not what the source holds now: nothing is published.
func TestCopyVerified_aDifferentContentIsNeverPublished(t *testing.T) {
	f := newCopyFixture(t, "what the source holds now", 0o600)
	err := CopyVerified(t.Context(), f.src, f.dst("x.bin"), f.staging, shaHex("what was analyzed"))
	if !errors.Is(err, ErrContentChanged) {
		t.Fatalf("CopyVerified() error = %v, want ErrContentChanged", err)
	}
	if entries := treeOf(t, f.out); len(entries) != 1 || entries[0] != StagingDir {
		t.Errorf("tree = %v, want only the empty transit folder", entries)
	}
	if got := readFile(t, f.srcPath); got != "what the source holds now" {
		t.Error("the source must be left in place")
	}
}

// The writer keeps its descriptor and writes after the copy: the destination
// keeps the content that was verified.
func TestCopyVerified_aLateWriterCannotChangeTheDestination(t *testing.T) {
	content := "content verified at copy time"
	f := newCopyFixture(t, content, 0o600)
	if err := CopyVerified(t.Context(), f.src, f.dst("x.bin"), f.staging, shaHex(content)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.src.WriteAt([]byte("REWRITTEN AFTER THE MOVE!!!!!"), 0); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, f.dst("x.bin")); got != content {
		t.Errorf("destination = %q after a late write, want the verified content: the inode must not be shared", got)
	}
}

func TestCopyVerified_aSourceRewrittenDuringTheCopyIsNeverPublished(t *testing.T) {
	content := strings.Repeat("0123456789abcdef", 100_000) // 1.6 MB, 13 blocks
	f := newCopyFixture(t, content, 0o600)
	rewritten := false
	withHooks(t, func(copied int64) {
		if !rewritten && copied >= copyBlockSize {
			rewritten = true
			// in place, behind the blocks already copied and read by position
			if _, err := f.src.WriteAt([]byte("XXXX"), int64(len(content))-8); err != nil {
				t.Error(err)
			}
		}
	}, nil)
	err := CopyVerified(t.Context(), f.src, f.dst("x.bin"), f.staging, shaHex(content))
	if !errors.Is(err, ErrContentChanged) {
		t.Fatalf("CopyVerified() error = %v, want ErrContentChanged", err)
	}
	if entries := treeOf(t, f.out); len(entries) != 1 || entries[0] != StagingDir {
		t.Errorf("tree = %v, want nothing published and the transit folder empty", entries)
	}
}

func TestCopyVerified_aFileThatGrewOrShrankIsNeverPublished(t *testing.T) {
	for name, mutate := range map[string]func(t *testing.T, f *copyFixture){
		"grew": func(t *testing.T, f *copyFixture) {
			if _, err := f.src.WriteAt([]byte("more"), int64(len("original content"))); err != nil {
				t.Fatal(err)
			}
		},
		"shrank": func(t *testing.T, f *copyFixture) {
			if err := f.src.Truncate(4); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newCopyFixture(t, "original content", 0o600)
			// the analyzed hash is the original's; the size read at the start of the
			// copy is the current one, so the hash tells
			mutate(t, f)
			err := CopyVerified(t.Context(), f.src, f.dst("x.bin"), f.staging, shaHex("original content"))
			if !errors.Is(err, ErrContentChanged) {
				t.Errorf("CopyVerified() error = %v, want ErrContentChanged", err)
			}
			if entries := treeOf(t, f.out); len(entries) > 1 {
				t.Errorf("published something: %v", entries)
			}
		})
	}
}

// While the copy runs, nothing appears in the tree of the destination: the
// partial file lives in the transit folder only.
func TestCopyVerified_noPartialFileIsVisibleOutsideTheTransitFolder(t *testing.T) {
	content := strings.Repeat("x", 4*copyBlockSize)
	f := newCopyFixture(t, content, 0o600)
	var seen [][]string
	withHooks(t, func(int64) { seen = append(seen, treeOf(t, f.out)) }, nil)
	if err := CopyVerified(t.Context(), f.src, f.dst("x.bin"), f.staging, shaHex(content)); err != nil {
		t.Fatal(err)
	}
	if len(seen) == 0 {
		t.Fatal("the hook never ran")
	}
	for _, tree := range seen {
		for _, e := range tree {
			if e != StagingDir && !strings.HasPrefix(e, StagingDir+string(filepath.Separator)) {
				t.Errorf("%q is visible in the destination tree during the copy", e)
			}
		}
	}
}

func TestCopyVerified_neverReplacesAFileAtTheDestination(t *testing.T) {
	f := newCopyFixture(t, "new", 0o600)
	if err := os.WriteFile(f.dst("x.bin"), []byte("already there"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CopyVerified(t.Context(), f.src, f.dst("x.bin"), f.staging, shaHex("new")); !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("CopyVerified() error = %v, want ErrDestinationExists", err)
	}
	if got := readFile(t, f.dst("x.bin")); got != "already there" {
		t.Errorf("destination = %q, want it untouched", got)
	}
	if entries := treeOf(t, f.staging); len(entries) != 0 {
		t.Errorf("transit folder not empty: %v", entries)
	}
}

func TestMoveVerifiedCopy_publishesUnderAConflictName(t *testing.T) {
	f := newCopyFixture(t, "new", 0o600)
	if err := os.WriteFile(f.dst("x.bin"), []byte("already there"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC) }
	got, err := MoveVerifiedCopy(t.Context(), f.src, nil, f.dst("x.bin"), f.staging, shaHex("new"), now, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got == f.dst("x.bin") || readFile(t, got) != "new" || readFile(t, f.dst("x.bin")) != "already there" {
		t.Errorf("published as %q, want a conflict name holding the new content, the original untouched", got)
	}
	if _, err = MoveVerifiedCopy(t.Context(), f.src, nil, f.dst("x.bin"), f.staging, shaHex("new"), now, 0); !errors.Is(err, ErrDestinationExists) {
		t.Errorf("without conflict names allowed, error = %v, want ErrDestinationExists", err)
	}
}

func TestCopyVerified_aCancelledCopyLeavesNothing(t *testing.T) {
	content := strings.Repeat("x", 6*copyBlockSize)
	f := newCopyFixture(t, content, 0o600)
	ctx, cancel := context.WithCancel(t.Context())
	withHooks(t, func(copied int64) {
		if copied >= 2*copyBlockSize {
			cancel()
		}
	}, nil)
	err := CopyVerified(ctx, f.src, f.dst("x.bin"), f.staging, shaHex(content))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CopyVerified() error = %v, want context.Canceled", err)
	}
	if entries := treeOf(t, f.out); len(entries) != 1 || entries[0] != StagingDir {
		t.Errorf("tree = %v, want only the empty transit folder", entries)
	}
}

func TestCopyVerified_aDeadlineIsReportedAsSuch(t *testing.T) {
	content := strings.Repeat("x", 6*copyBlockSize)
	f := newCopyFixture(t, content, 0o600)
	ctx, cancel := context.WithTimeout(t.Context(), time.Nanosecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond)
	if err := CopyVerified(ctx, f.src, f.dst("x.bin"), f.staging, shaHex(content)); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("CopyVerified() error = %v, want context.DeadlineExceeded", err)
	}
	if entries := treeOf(t, f.staging); len(entries) != 0 {
		t.Errorf("transit folder not empty: %v", entries)
	}
}

// A full disk ends the copy with the error of the system, the transit folder
// emptied.
type failingWriter struct {
	w    io.Writer
	left int
}

func (f *failingWriter) Write(p []byte) (int, error) {
	if len(p) > f.left {
		n, _ := f.w.Write(p[:f.left])
		f.left = 0
		return n, &fs.PathError{Op: "write", Path: "staged", Err: syscall.ENOSPC}
	}
	f.left -= len(p)
	return f.w.Write(p)
}

func TestCopyVerified_aFullDiskEndsTheCopyAndEmptiesTheTransitFolder(t *testing.T) {
	content := strings.Repeat("x", 4*copyBlockSize)
	f := newCopyFixture(t, content, 0o600)
	withHooks(t, nil, func(w io.Writer) io.Writer { return &failingWriter{w: w, left: 2 * copyBlockSize} })
	err := CopyVerified(t.Context(), f.src, f.dst("x.bin"), f.staging, shaHex(content))
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("CopyVerified() error = %v, want ENOSPC", err)
	}
	if entries := treeOf(t, f.out); len(entries) != 1 || entries[0] != StagingDir {
		t.Errorf("tree = %v, want only the empty transit folder", entries)
	}
}

func TestCopyVerified_setuidAndSetgidDoNotFollowTheCopy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no permission bits")
	}
	f := newCopyFixture(t, "program", 0o755)
	if err := os.Chmod(f.srcPath, 0o755|os.ModeSetuid|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	if err := CopyVerified(t.Context(), f.src, f.dst("x.bin"), f.staging, shaHex("program")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(f.dst("x.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || info.Mode().Perm() != 0o755 {
		t.Errorf("mode = %v, want 0755 without setuid or setgid", info.Mode())
	}
}

func TestCopyVerified_refusesAnythingButARegularFile(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	out := t.TempDir()
	if err = CopyVerified(t.Context(), dir, filepath.Join(out, "x"), filepath.Join(out, StagingDir), shaHex("")); err == nil {
		t.Error("CopyVerified() accepted a directory")
	}
}

// The copy is read by position: the offset of the descriptor does not matter.
func TestCopyVerified_readsFromTheStartWhateverTheOffsetOfTheDescriptor(t *testing.T) {
	f := newCopyFixture(t, "0123456789", 0o600)
	if _, err := f.src.Seek(6, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if err := CopyVerified(t.Context(), f.src, f.dst("x.bin"), f.staging, shaHex("0123456789")); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, f.dst("x.bin")); got != "0123456789" {
		t.Errorf("destination = %q, want the whole content", got)
	}
}

func BenchmarkCopyVerified(b *testing.B) {
	for _, size := range []int64{1 << 20, 64 << 20} {
		b.Run(fmt.Sprintf("%dMiB", size>>20), func(b *testing.B) {
			dir := b.TempDir()
			f, err := os.Create(filepath.Clean(filepath.Join(dir, "big.bin")))
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() {
				if e := f.Close(); e != nil {
					b.Error(e)
				}
			})
			h := sha256.New()
			block := make([]byte, 1<<20)
			for range size >> 20 {
				if _, err = f.Write(block); err != nil {
					b.Fatal(err)
				}
				h.Write(block)
			}
			want := hex.EncodeToString(h.Sum(nil))
			out := filepath.Join(dir, "out")
			if err = os.Mkdir(out, 0o750); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(size)
			b.ReportAllocs()
			dst := filepath.Join(out, "copy.bin")
			for b.Loop() {
				if err = CopyVerified(b.Context(), f, dst, filepath.Join(out, StagingDir), want); err != nil {
					b.Fatal(err)
				}
				if err = os.Remove(dst); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
