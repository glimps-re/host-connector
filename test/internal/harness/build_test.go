//go:build linux

package harness

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// keys returns a key function that answers the keys in order, the last one for
// ever after.
func keys(ks ...string) func() (string, error) {
	i := 0
	return func() (string, error) {
		k := ks[min(i, len(ks)-1)]
		i++
		return k, nil
	}
}

func fakeBuild(builds *int) func(dir string) error {
	return func(dir string) error {
		*builds++
		return os.WriteFile(filepath.Join(dir, "GMHost"), []byte("binary"), 0o600)
	}
}

// runBuild runs buildIn and releases the build at the end of the test.
func runBuild(t *testing.T, cache string, key func() (string, error), b func(string) error) (string, *os.File, error) {
	t.Helper()
	dir, inUse, err := buildIn(cache, key, b)
	if inUse != nil {
		t.Cleanup(func() { releaseBuild(t, inUse) })
	}
	return dir, inUse, err
}

func releaseBuild(t *testing.T, inUse *os.File) {
	t.Helper()
	if err := inUse.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		t.Error(err)
	}
}

// A tree that changes while the binaries compile leaves no complete build
// behind: the build fails, its folder is removed, and the next run builds again
// under the key of the tree it finds.
func TestBuildIn_aTreeChangedDuringTheBuildIsNeverKept(t *testing.T) {
	cache := t.TempDir()
	builds := 0
	_, _, err := runBuild(t, cache, keys("old", "new"), fakeBuild(&builds))
	if !errors.Is(err, errTreeChanged) {
		t.Fatalf("buildIn() error = %v, want errTreeChanged", err)
	}
	for _, k := range []string{"old", "new"} {
		if exists(filepath.Join(cache, k)) {
			t.Errorf("folder %q of the build is kept", k)
		}
	}
	dir, _, err := runBuild(t, cache, keys("new"), fakeBuild(&builds))
	if err != nil || dir != filepath.Join(cache, "new") || builds != 2 {
		t.Fatalf("next build = %q, %v after %d builds, want the folder of the new key built again", dir, err, builds)
	}
}

// A stable tree is built once and marked complete; the next run reuses it.
func TestBuildIn_aCompleteBuildIsReused(t *testing.T) {
	cache := t.TempDir()
	builds := 0
	for range 2 {
		if dir, _, err := runBuild(t, cache, keys("k1"), fakeBuild(&builds)); err != nil || dir != filepath.Join(cache, "k1") {
			t.Fatalf("buildIn() = %q, %v", dir, err)
		}
	}
	if done := exists(filepath.Join(cache, "k1", "done")); builds != 1 || !done {
		t.Fatalf("%d builds, done mark %t: want 1 build, marked complete", builds, done)
	}
}

// A build that a process still holds survives the build of another key; once
// released, the next build of another key removes it.
func TestBuildIn_aBuildInUseIsNeverPurged(t *testing.T) {
	cache := t.TempDir()
	builds := 0
	_, held, err := runBuild(t, cache, keys("k1"), fakeBuild(&builds))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = runBuild(t, cache, keys("k2"), fakeBuild(&builds)); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(cache, "k1", "GMHost")) {
		t.Fatal("the build k1, still held, was purged")
	}
	releaseBuild(t, held)
	if _, _, err = runBuild(t, cache, keys("k3"), fakeBuild(&builds)); err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(cache, "k1")) {
		t.Error("the released build k1 was kept")
	}
	if !exists(filepath.Join(cache, "k2", "GMHost")) {
		t.Error("the build k2, still held, was purged")
	}
}

// A failed build is not marked complete and leaves no folder.
func TestBuildIn_aFailedBuildIsNotKept(t *testing.T) {
	cache := t.TempDir()
	boom := errors.New("compile error")
	if _, _, err := runBuild(t, cache, keys("k"), func(string) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("buildIn() error = %v, want the build error", err)
	}
	if exists(filepath.Join(cache, "k")) {
		t.Error("the folder of the failed build is kept")
	}
}
