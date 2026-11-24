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
// repository but the tests, the documentation and the hidden folders.
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
			if strings.HasPrefix(d.Name(), ".") && rel != "." || rel == "test" || rel == "docs" {
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
	f, err := os.OpenFile(filepath.Join(cache, "lock"), os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // G304: the lock of the build cache
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return func() { _ = f.Close() }, nil
}

func buildAll(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the binary and two plugins")
	}
	builds.once.Do(func() { builds.dir, builds.err = sharedBuild(RepoRoot(t)) })
	if builds.err != nil {
		t.Fatal(builds.err)
	}
	return builds.dir
}

func sharedBuild(root string) (string, error) {
	userCache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	cache := filepath.Join(userCache, "gmhost-e2e")
	if err := os.MkdirAll(cache, 0o750); err != nil {
		return "", err
	}
	key, err := buildKey(root)
	if err != nil {
		return "", err
	}
	unlock, err := lockBuilds(cache)
	if err != nil {
		return "", err
	}
	defer unlock()
	dir := filepath.Join(cache, key)
	done := filepath.Join(dir, "done")
	if _, err := os.Stat(done); err == nil {
		return dir, nil
	}
	entries, err := os.ReadDir(cache)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() {
			if err := os.RemoveAll(filepath.Join(cache, e.Name())); err != nil {
				return "", err
			}
		}
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	targets := map[string][]string{
		"GMHost":     {"."},
		"session.so": {"-buildmode=plugin", "./cmd/plugins/session"},
		"extract.so": {"-buildmode=plugin", "./cmd/plugins/extract"},
	}
	errs := make(chan error, len(targets))
	for out, args := range targets {
		go func() { errs <- GoBuild(root, filepath.Join(dir, out), args...) }()
	}
	var all []error
	for range targets {
		all = append(all, <-errs)
	}
	if err := errors.Join(all...); err != nil {
		return "", err
	}
	return dir, os.WriteFile(done, nil, 0o600)
}

// buildPlugin builds the plugin of cmd/plugins/<name> once per build folder,
// with the toolchain of the binary, and returns the path of its shared object.
func buildPlugin(t *testing.T, name string) string {
	t.Helper()
	dir := buildAll(t)
	unlock, err := lockBuilds(filepath.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	out := filepath.Join(dir, name+".so")
	done := out + ".done"
	if _, err := os.Stat(done); err == nil {
		return out
	}
	if err := GoBuild(RepoRoot(t), out, "-buildmode=plugin", "./cmd/plugins/"+name); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(done, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}
