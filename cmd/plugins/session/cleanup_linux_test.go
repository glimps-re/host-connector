//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Modes of folders made read-only on purpose: named constants.
const (
	readOnlyDir os.FileMode = 0o500
	ownerDir    os.FileMode = 0o700
)

func mkdirs(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if err := os.MkdirAll(p, 0o750); err != nil {
			t.Fatal(err)
		}
	}
}

func age(t *testing.T, path string, by time.Duration) {
	t.Helper()
	old := time.Now().Add(-by)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func TestRemoveEmptyDirs_removesTheOldEmptyOnesDeepestFirstAndKeepsTheRest(t *testing.T) {
	root := t.TempDir()
	session := filepath.Join(root, "tom")
	mkdirs(t,
		filepath.Join(session, "a", "b", "c"),   // all empty and old: gone
		filepath.Join(session, "kept", "empty"), // a file in kept: only empty goes
		filepath.Join(session, "recent"),
		filepath.Join(session, "protected", "x"),
	) // the work directory is kept whole, and never entered
	if err := os.WriteFile(filepath.Join(session, "kept", "f.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"a/b/c", "a/b", "a", "kept/empty", "kept", "protected/x", "protected"} {
		age(t, filepath.Join(session, filepath.FromSlash(p)), time.Hour)
	}
	st, err := removeEmptyDirs(t.Context(), root, "tom", time.Minute, filepath.Join(session, "protected"))
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{
		"a": false, "a/b": false, "a/b/c": false, "kept": true, "kept/empty": false,
		"recent": true, "protected": true, "protected/x": true,
	} {
		if got := exists(filepath.Join(session, filepath.FromSlash(p))); got != want {
			t.Errorf("%s present = %v, want %v", p, got, want)
		}
	}
	if !exists(session) {
		t.Error("the session folder itself must stay")
	}
	if st.removed != 4 || st.kept != 3 || st.failed != 0 {
		t.Errorf("stats = %+v, want 4 removed, 3 kept, no failure", st)
	}
}

func TestRemoveEmptyDirs_neverFollowsALinkNorRemovesIt(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "empty-outside")
	mkdirs(t, outside, filepath.Join(root, "tom"))
	link := filepath.Join(root, "tom", "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := removeEmptyDirs(t.Context(), root, "tom", 0, ""); err != nil {
		t.Fatal(err)
	}
	if !exists(outside) || !exists(link) {
		t.Errorf("target present = %v, link present = %v: neither may be touched", exists(outside), exists(link))
	}
}

func TestRemoveEmptyDirs_aSessionFolderThatIsALinkIsRefused(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	mkdirs(t, filepath.Join(outside, "victim"))
	if err := os.Symlink(outside, filepath.Join(root, "tom")); err != nil {
		t.Fatal(err)
	}
	if _, err := removeEmptyDirs(t.Context(), root, "tom", 0, ""); err == nil {
		t.Fatal("a session folder that is a link must be refused")
	}
	if !exists(filepath.Join(outside, "victim")) {
		t.Error("a folder outside the tree was removed")
	}
}

func TestRemoveEmptyDirs_aFolderSwappedAfterTheListingIsNeverRemovedNorFollowed(t *testing.T) {
	for name, tt := range map[string]struct {
		replace func(t *testing.T, at, outside string)
		check   func(t *testing.T, at string)
	}{
		"link": {
			replace: func(t *testing.T, at, outside string) {
				if err := os.Symlink(outside, at); err != nil {
					t.Error(err)
				}
			},
			check: func(t *testing.T, at string) {
				if info, err := os.Lstat(at); err != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Errorf("the link that replaced the folder is gone or changed: %v", err)
				}
			},
		},
		"file": {
			replace: func(t *testing.T, at, _ string) {
				if err := os.WriteFile(at, []byte("data"), 0o600); err != nil {
					t.Error(err)
				}
			},
			check: func(t *testing.T, at string) {
				if b, err := os.ReadFile(filepath.Clean(at)); err != nil || string(b) != "data" {
					t.Errorf("the file was removed or changed: %q, %v", b, err)
				}
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			session := filepath.Join(root, "tom")
			swap := filepath.Join(session, "swap")
			outside := filepath.Join(t.TempDir(), "outside")
			mkdirs(t, swap, filepath.Join(outside, "victim"))
			prev := afterList
			t.Cleanup(func() { afterList = prev })
			var swapped bool
			afterList = func(path string) {
				if path != session || swapped {
					return
				}
				swapped = true
				if err := os.Remove(swap); err != nil {
					t.Error(err)
				}
				tt.replace(t, swap, outside)
			}
			if _, err := removeEmptyDirs(t.Context(), root, "tom", 0, ""); err != nil {
				t.Fatal(err)
			}
			if !exists(filepath.Join(outside, "victim")) {
				t.Error("something outside the tree was removed")
			}
			tt.check(t, swap)
		})
	}
}

func TestRemoveEmptyDirs_theWorkDirIsKeptWhateverTheSpellingOfThePaths(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "in")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	session := filepath.Join(target, "tom")
	work := filepath.Join(session, ".work")
	mkdirs(t, filepath.Join(work, "extract", "empty"), filepath.Join(session, "old", "empty"))
	for _, p := range []string{filepath.Join(work, "extract", "empty"), filepath.Join(work, "extract"), work, filepath.Join(session, "old", "empty"), filepath.Join(session, "old")} {
		age(t, p, time.Hour)
	}
	st, err := removeEmptyDirs(t.Context(), link, "tom", time.Minute, work)
	if err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(work, "extract", "empty")) {
		t.Error("the work directory was entered")
	}
	if exists(filepath.Join(session, "old")) {
		t.Error("an old empty folder next to the work directory was left")
	}
	if st.removed != 2 || st.failed != 0 {
		t.Errorf("stats = %+v, want 2 removed", st)
	}
	if _, err := removeEmptyDirs(t.Context(), link, "tom", time.Minute, filepath.Join(session, "missing")); err != nil {
		t.Errorf("a work directory that does not exist must not fail the cleanup: %v", err)
	}
}

func TestRemoveEmptyDirs_countsTheFailuresAndNotTheVanishedFolders(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes anywhere")
	}
	root := t.TempDir()
	session := filepath.Join(root, "tom")
	locked := filepath.Join(session, "locked")
	mkdirs(t, filepath.Join(locked, "empty"), filepath.Join(session, "gone"))
	if err := os.Chmod(locked, readOnlyDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(locked, ownerDir); err != nil {
			t.Error(err)
		}
	})
	prev := afterList
	t.Cleanup(func() { afterList = prev })
	afterList = func(path string) {
		if path == session {
			if err := os.Remove(filepath.Join(session, "gone")); err != nil {
				t.Error(err)
			}
		}
	}
	st, err := removeEmptyDirs(t.Context(), root, "tom", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if st.failed != 1 || st.firstErr == nil || !strings.Contains(st.firstErr.Error(), "empty") {
		t.Errorf("stats = %+v, want one failure about locked/empty", st)
	}
	if st.removed != 0 || st.kept != 1 {
		t.Errorf("stats = %+v, want only locked kept (its child could not go)", st)
	}
}

func closeTest(t *testing.T, fd int) {
	t.Helper()
	if err := unix.Close(fd); err != nil {
		t.Error(err)
	}
}

func openFds(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc")
	}
	return len(entries)
}

// A tree of 2000 levels, built with relative calls (no path can hold it): the
// walk holds at most 129 descriptors (the session folder and 128 levels), ends without EMFILE, and says it left the
// deeper part.
func TestRemoveEmptyDirs_aTreeOf2000LevelsUsesBoundedDescriptors(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "tom"), 0o750); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(filepath.Clean(filepath.Join(root, "tom")), unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	for range 2000 {
		if err = unix.Mkdirat(fd, "d", 0o750); err != nil {
			t.Fatal(err)
		}
		next, oerr := unix.Openat(fd, "d", unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if oerr != nil {
			t.Fatal(oerr)
		}
		closeTest(t, fd)
		fd = next
	}
	closeTest(t, fd)
	base := openFds(t)
	peak := 0
	prev := afterList
	t.Cleanup(func() { afterList = prev })
	afterList = func(string) { peak = max(peak, openFds(t)-base) }
	st, err := removeEmptyDirs(t.Context(), root, "tom", 0, "")
	if !errors.Is(err, errTooDeep) {
		t.Fatalf("error = %v, want errTooDeep", err)
	}
	if limit := maxCleanupDepth + 1 + 1; peak > limit { // +1: the listing of /proc/self/fd
		t.Errorf("%d descriptors open at once, want at most %d", peak, limit)
	}
	if st.removed != 0 {
		t.Errorf("removed %d: a part that was cut off keeps its ancestors", st.removed)
	}
	if got := openFds(t); got != base {
		t.Errorf("%d descriptors leaked", got-base)
	}
}

func TestRemoveEmptyDirs_aHugeFolderIsWalkedWithBoundedMemory(t *testing.T) {
	root := t.TempDir()
	session := filepath.Join(root, "tom")
	mkdirs(t, filepath.Join(session, "big"))
	for i := range 100_000 {
		f, err := os.Create(filepath.Clean(filepath.Join(session, "big", fmt.Sprintf("f%06d", i))))
		if err != nil {
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var peak uint64
	prev := afterList
	t.Cleanup(func() { afterList = prev })
	afterList = func(string) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		peak = max(peak, m.HeapAlloc)
	}
	if st, err := removeEmptyDirs(t.Context(), root, "tom", 0, ""); err != nil || st.kept != 1 {
		t.Fatalf("kept %d, error %v, want the folder kept", st.kept, err)
	}
	runtime.ReadMemStats(&after)
	if growth := after.TotalAlloc - before.TotalAlloc; growth > 64<<20 {
		t.Errorf("%d MiB allocated to walk a folder of 100 000 entries", growth>>20)
	}
	if peak > before.HeapAlloc+64<<20 {
		t.Errorf("the heap grew to %d MiB during the walk", peak>>20)
	}
}

func TestRemoveEmptyDirs_stopsCleanlyWhenTheBudgetEnds(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, filepath.Join(root, "tom", "a"))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	st, err := removeEmptyDirs(ctx, root, "tom", 0, "")
	if !errors.Is(err, context.Canceled) || st.removed != 0 {
		t.Errorf("removed %d, error %v, want nothing and context.Canceled", st.removed, err)
	}
	if !exists(filepath.Join(root, "tom", "a")) {
		t.Error("nothing may be removed once the budget ended")
	}
}

func TestRemoveEmptyDirs_aMissingSessionFolderIsNotAnError(t *testing.T) {
	st, err := removeEmptyDirs(t.Context(), t.TempDir(), "gone", 0, "")
	if err != nil || st != (cleanupStats{}) {
		t.Errorf("removeEmptyDirs() = %+v, %v, want nothing and no error", st, err)
	}
}

func TestRemoveEmptyDirs_aSessionFolderLeavingTheRootIsRefused(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	mkdirs(t, filepath.Join(root, "in"), filepath.Join(outside, "empty"))
	if _, err := removeEmptyDirs(t.Context(), filepath.Join(root, "in"), "../outside", 0, ""); err == nil {
		t.Error("a session folder with .. must be refused")
	}
	if !exists(filepath.Join(outside, "empty")) {
		t.Error("a folder outside the root was removed")
	}
}
