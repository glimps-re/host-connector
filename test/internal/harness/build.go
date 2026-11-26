//go:build linux

// Package harness runs the real binary for the e2e scenarios and holds what
// they leave to the invariants.
package harness

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// builds holds the folder of the binary and the plugins, built with the same
// toolchain (a plugin only loads in the binary it was built with) and shared by
// the test packages and the runs until the product code changes.
var builds struct {
	once sync.Once
	err  error
	dir  string
	// inUse holds a shared lock on the build for the life of the process: no
	// other process purges a build that this one still runs.
	inUse *os.File
}

func RepoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// RunCommand runs a tool the tests use to build their inputs (the toolchain, the
// embedded 7-Zip), in dir, and returns what it printed.
func RunCommand(dir, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(context.Background(), name, args...) //nolint:gosec // G204: the tests run the tools they build their inputs with; every argument is their own
	cmd.Dir = dir
	return cmd.CombinedOutput()
}

func GoBuild(root, out string, args ...string) error {
	if b, err := RunCommand(root, "go", append([]string{"build", "-o", out}, args...)...); err != nil {
		return fmt.Errorf("go build %v: %w\n%s", args, err, b)
	}
	return nil
}

// buildKey hashes what the builds depend on: the toolchain and every file of the
// repository but the tests, the documentation, the hidden folders and the
// ignored scratch folders (tmp, bin), which the runs themselves write to.
func buildKey(root string) (string, error) {
	h := sha256.New()
	for _, args := range [][]string{{"version"}, {"env", "GOOS", "GOARCH", "CGO_ENABLED", "GOFLAGS"}} {
		out, err := RunCommand(root, "go", args...)
		if err != nil {
			return "", fmt.Errorf("go %v: %w\n%s", args, err, out)
		}
		h.Write(out)
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && rel != "." || rel == "test" || rel == "docs" || rel == "tmp" || rel == "bin" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || strings.HasSuffix(rel, "_test.go") || strings.HasSuffix(rel, ".md") {
			return nil
		}
		f, err := os.Open(path) //nolint:gosec // G304: a file of the repository
		if err != nil {
			return err
		}
		h.Write([]byte(rel + "\x00"))
		_, err = io.Copy(h, f)
		return errors.Join(err, f.Close())
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

// lockBuilds holds the lock of the build cache, shared by every test process,
// until the returned function is called.
func lockBuilds(cache string) (func(), error) {
	f, err := flockFile(filepath.Join(cache, "lock"), syscall.LOCK_EX)
	if err != nil {
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}

// flockFile opens the lock file at path, creating it, and takes the flock how
// on it; the lock lasts until the file is closed or the process ends.
func flockFile(path string, how int) (*os.File, error) {
	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

func buildAll(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the binary and two plugins")
	}
	builds.once.Do(func() { builds.dir, builds.inUse, builds.err = sharedBuild(RepoRoot(t)) })
	if builds.err != nil {
		t.Fatal(builds.err)
	}
	return builds.dir
}

func sharedBuild(root string) (string, *os.File, error) {
	userCache, err := os.UserCacheDir()
	if err != nil {
		return "", nil, err
	}
	cache := filepath.Join(userCache, "gmhost-e2e")
	if err := os.MkdirAll(cache, 0o750); err != nil {
		return "", nil, err
	}
	return buildIn(cache, func() (string, error) { return buildKey(root) }, func(dir string) error { return buildTargets(root, dir) })
}

// errTreeChanged is a build whose sources changed while it compiled: its
// binaries may hold the old code or the new one, so it is not kept under any key.
var errTreeChanged = errors.New("the repository changed during the e2e build: run the tests again on a tree that does not change")

// buildIn builds into the folder of cache named by key, unless a complete build
// is already there, and returns it with a shared lock on it that the caller
// keeps while it runs the build (closing the file releases it). The key is
// computed again once the build is over, under the lock of the cache: a tree
// changed in between (a checkout, a stash) would otherwise leave binaries of one
// code under the key of another, for good. A tree changed and changed back
// during the build (A, B, then A again) is not seen: the build may then hold B.
// The builds of other keys are removed, except those another process still
// holds.
func buildIn(cache string, key func() (string, error), build func(dir string) error) (dir string, inUse *os.File, err error) {
	before, err := key()
	if err != nil {
		return "", nil, err
	}
	unlock, err := lockBuilds(cache)
	if err != nil {
		return "", nil, err
	}
	defer unlock()
	dir = filepath.Join(cache, before)
	done := filepath.Join(dir, "done")
	if _, err := os.Stat(done); err == nil {
		inUse, err = holdBuild(dir)
		return dir, inUse, err
	}
	if err := purgeUnused(cache); err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", nil, err
	}
	if err := build(dir); err != nil {
		return "", nil, errors.Join(err, os.RemoveAll(dir))
	}
	after, err := key()
	if err != nil {
		return "", nil, errors.Join(err, os.RemoveAll(dir))
	}
	if after != before {
		return "", nil, errors.Join(fmt.Errorf("%w (key %s, then %s)", errTreeChanged, before, after), os.RemoveAll(dir))
	}
	if err := syncBuild(dir); err != nil {
		return "", nil, errors.Join(err, os.RemoveAll(dir))
	}
	inUse, err = holdBuild(dir)
	return dir, inUse, err
}

// holdBuild takes a shared lock on the build in dir, kept until the file is
// closed or the process ends.
func holdBuild(dir string) (*os.File, error) {
	return flockFile(filepath.Join(dir, "lock"), syscall.LOCK_SH)
}

// purgeUnused removes the builds of cache that no process holds. The caller
// holds the lock of the cache, so no build is taken while it runs.
func purgeUnused(cache string) error {
	entries, err := os.ReadDir(cache)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(cache, e.Name())
		f, err := flockFile(filepath.Join(dir, "lock"), syscall.LOCK_EX|syscall.LOCK_NB)
		if errors.Is(err, syscall.EWOULDBLOCK) {
			continue
		}
		if err != nil {
			return err
		}
		err = os.RemoveAll(dir)
		if err = errors.Join(err, f.Close()); err != nil {
			return err
		}
	}
	return nil
}

// syncBuild writes the binaries of dir to the disk, then the mark that the build
// is complete: after a crash, a build marked complete is whole.
func syncBuild(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Type().IsRegular() {
			if err := syncFile(filepath.Join(dir, e.Name())); err != nil {
				return err
			}
		}
	}
	f, err := os.OpenFile(filepath.Clean(filepath.Join(dir, "done")), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func syncFile(path string) error {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

// buildTargets builds into dir the binary and every plugin of cmd/plugins: all
// of them at once, under the key, so that none is built later from another tree.
func buildTargets(root, dir string) error {
	targets := map[string][]string{"GMHost": {"."}}
	plugins, err := os.ReadDir(filepath.Join(root, "cmd", "plugins"))
	if err != nil {
		return err
	}
	for _, p := range plugins {
		if p.IsDir() {
			targets[p.Name()+".so"] = []string{"-buildmode=plugin", "./cmd/plugins/" + p.Name()}
		}
	}
	errs := make(chan error, len(targets))
	for out, args := range targets {
		go func() { errs <- GoBuild(root, filepath.Join(dir, out), args...) }()
	}
	all := make([]error, 0, len(targets))
	for range targets {
		all = append(all, <-errs)
	}
	return errors.Join(all...)
}

// buildPlugin returns the shared object of the plugin of cmd/plugins/<name>,
// built with the binary.
func buildPlugin(t *testing.T, name string) string {
	t.Helper()
	out := filepath.Join(buildAll(t), name+".so")
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("plugin %s: %v", name, err)
	}
	return out
}
