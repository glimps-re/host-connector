//go:build linux

package scanner

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

// Modes under test, named constants: the permission checks are the subject.
const (
	modeOwnerOnlyDir         fs.FileMode = 0o700
	modeWritableByOthersFile fs.FileMode = 0o606
)

func TestOpenPlugin_refusesAnUnsafeFileBeforeOpeningIt(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the ownership rules differ for root")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, modeOwnerOnlyDir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "evil.so")
	if err := os.WriteFile(path, []byte("not a shared object"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, modeWritableByOthersFile); err != nil {
		t.Fatal(err)
	}
	_, err := openPlugin(path)
	if !errors.Is(err, plugins.ErrUnsafeExecutable) {
		t.Fatalf("openPlugin() error = %v, want ErrUnsafeExecutable: the file must be refused before plugin.Open", err)
	}
}

func TestValidationContext_orphanPurge(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, modeOwnerOnlyDir); err != nil {
		t.Fatal(err)
	}
	live, err := NewValidationContext(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = live.Close() })
	crashed, err := NewValidationContext(base)
	if err != nil {
		t.Fatal(err)
	}
	// A crash releases the lock and leaves the directory.
	if err = crashed.lock.Close(); err != nil {
		t.Fatal(err)
	}
	crashed.lock = nil
	purgeOrphans(base, "")
	if _, err = os.Stat(live.GetWorkDir()); err != nil {
		t.Errorf("a live validation directory must be kept: %v", err)
	}
	if _, err = os.Stat(crashed.GetWorkDir()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an orphan validation directory must be purged (stat error = %v)", err)
	}
}
