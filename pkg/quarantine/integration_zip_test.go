package quarantine

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestIntegration_MixedFormatDirectory exercises mixed tar and zip containers end to end with
// a real QuarantineHandler (real tarLocker + zipLocker via the router, real
// sqlite-backed registry, real filesystem): a tar `.lock` produced by the
// normal Quarantine() call coexists with a hand-dropped ZIP `.lock` in the
// same directory, and both are listed (without a password) and restored
// correctly.
func TestIntegration_MixedFormatDirectory(t *testing.T) {
	ctx := t.Context()
	quarantineDir := t.TempDir()

	q, err := NewQuarantineHandler(ctx, Config{Location: quarantineDir, LockPassword: "infected"})
	if err != nil {
		t.Fatalf("NewQuarantineHandler() error = %s", err)
	}
	defer func() {
		if err := q.Close(); err != nil {
			t.Errorf("Close() error = %s", err)
		}
	}()

	// 1. Quarantine a real file the normal way: this writes a tar
	// container (the write format is hard-wired to tar in this milestone).
	tarSamplePath := filepath.Join(t.TempDir(), "tar_sample.exe")
	if err := os.WriteFile(tarSamplePath, []byte("tar sample content"), 0o600); err != nil {
		t.Fatalf("write tar sample: %s", err)
	}
	_, tarID, err := q.Quarantine(ctx, tarSamplePath, sha256Hex([]byte("tar sample content")), []string{"trojan.tar"})
	if err != nil {
		t.Fatalf("Quarantine() error = %s", err)
	}

	// 2. Hand-produce a ZIP container for a second sample, as if it had
	// been written by a future version of this software with
	// format:zip configured, and drop it directly into the quarantine
	// directory with the id/registry entry a real Quarantine() call would
	// have produced.
	zipSamplePath := filepath.Join(t.TempDir(), "zip sample two.bin")
	zipContent := "zip sample content, protected with ZipCrypto"
	zipID := ComputeCacheID(zipSamplePath, sha256Hex([]byte(zipContent)))

	zl := zipLocker{Password: "infected"}
	var zipBuf bytes.Buffer
	info := &zipFakeFileInfo{size: int64(len(zipContent)), mode: 0o644, modTime: time.Now().Truncate(time.Second)}
	if err := zl.LockFile(zipSamplePath, bytes.NewReader([]byte(zipContent)), info, "malware: worm.zip", &zipBuf); err != nil {
		t.Fatalf("zipLocker.LockFile() error = %s", err)
	}
	zipLockPath := filepath.Join(quarantineDir, zipID+".lock")
	if err := os.WriteFile(zipLockPath, zipBuf.Bytes(), 0o600); err != nil {
		t.Fatalf("write zip lock file: %s", err)
	}
	if err := q.registry.Set(ctx, &Entry{
		ID:                 zipID,
		SHA256:             sha256Hex([]byte(zipContent)),
		InitialLocation:    zipSamplePath,
		QuarantineLocation: zipLockPath,
	}); err != nil {
		t.Fatalf("registry.Set() for the zip entry error = %s", err)
	}

	// 3. Listing must surface both, without needing the password anywhere
	// in the call path (ListQuarantinedFiles takes no password argument).
	seen := map[string]string{} // id -> original path
	for f, err := range q.ListQuarantinedFiles(ctx) {
		if err != nil {
			t.Fatalf("ListQuarantinedFiles() error = %s", err)
		}
		seen[f.ID] = f.Filepath
	}
	if seen[tarID] != tarSamplePath {
		t.Errorf("listing: tar entry path = %q, want %q", seen[tarID], tarSamplePath)
	}
	if seen[zipID] != zipSamplePath {
		t.Errorf("listing: zip entry path = %q, want %q", seen[zipID], zipSamplePath)
	}

	// 4. Both restore correctly.
	if err := q.Restore(ctx, tarID); err != nil {
		t.Fatalf("Restore(tar) error = %s", err)
	}
	gotTar, err := os.ReadFile(filepath.Clean(tarSamplePath))
	if err != nil {
		t.Fatalf("reading restored tar sample: %s", err)
	}
	if string(gotTar) != "tar sample content" {
		t.Errorf("restored tar content = %q, want %q", gotTar, "tar sample content")
	}

	if err := q.Restore(ctx, zipID); err != nil {
		t.Fatalf("Restore(zip) error = %s", err)
	}
	gotZip, err := os.ReadFile(filepath.Clean(zipSamplePath))
	if err != nil {
		t.Fatalf("reading restored zip sample: %s", err)
	}
	if string(gotZip) != zipContent {
		t.Errorf("restored zip content = %q, want %q", gotZip, zipContent)
	}

	// Both .lock files must be gone after a successful restore.
	if _, err := os.Stat(filepath.Join(quarantineDir, tarID+".lock")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("tar .lock file should have been removed after restore")
	}
	if _, err := os.Stat(zipLockPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("zip .lock file should have been removed after restore")
	}
}

// TestIntegration_UnknownContainer_SkippedByListing_RejectedByRestore
// exercises a .lock file that matches neither known container
// format is skipped (with a warning, not a hard failure) by
// ListQuarantinedFiles, and rejected with a typed error by Restore.
func TestIntegration_UnknownContainer_SkippedByListing_RejectedByRestore(t *testing.T) {
	ctx := t.Context()
	quarantineDir := t.TempDir()

	q, err := NewQuarantineHandler(ctx, Config{Location: quarantineDir, LockPassword: "infected"})
	if err != nil {
		t.Fatalf("NewQuarantineHandler() error = %s", err)
	}
	defer func() {
		if err := q.Close(); err != nil {
			t.Errorf("Close() error = %s", err)
		}
	}()

	const id = testRestoreID
	garbagePath := filepath.Join(quarantineDir, id+".lock")
	if err := os.WriteFile(garbagePath, bytes.Repeat([]byte{0x00}, 512), 0o600); err != nil {
		t.Fatalf("write garbage lock file: %s", err)
	}
	if err := q.registry.Set(ctx, &Entry{ID: id, SHA256: "sha-garbage", InitialLocation: "/tmp/whatever", QuarantineLocation: garbagePath}); err != nil {
		t.Fatalf("registry.Set() error = %s", err)
	}

	count := 0
	for f, err := range q.ListQuarantinedFiles(ctx) {
		if err != nil {
			t.Fatalf("ListQuarantinedFiles() unexpectedly surfaced an error for one bad file: %s", err)
		}
		if f != nil {
			count++
		}
	}
	if count != 0 {
		t.Errorf("ListQuarantinedFiles() yielded %d entries, want 0 (the only file is an unknown container and must be skipped)", count)
	}

	err = q.Restore(ctx, id)
	if !errors.Is(err, errUnknownLockFormat) {
		t.Errorf("Restore() error = %v, want errUnknownLockFormat", err)
	}
	if _, statErr := os.Stat(garbagePath); statErr != nil {
		t.Errorf("Restore() must keep the .lock file on failure: %s", statErr)
	}
}

// TestIntegration_ZipRestore_SizeMismatch exercises the zip path through the
// same restore contract as tar: a payload whose size differs from the one
// recorded in the index is rejected, the destination is never created, and
// the temp file is removed.
func TestIntegration_ZipRestore_SizeMismatch(t *testing.T) {
	ctx := t.Context()
	quarantineDir := t.TempDir()

	q, err := NewQuarantineHandler(ctx, Config{
		Location:     quarantineDir,
		LockPassword: "infected",
	})
	if err != nil {
		t.Fatalf("NewQuarantineHandler() error = %s", err)
	}
	defer func() {
		if err := q.Close(); err != nil {
			t.Errorf("Close() error = %s", err)
		}
	}()

	destPath := filepath.Join(t.TempDir(), "too_big.bin")
	content := "payload longer than the size recorded in the index"
	id := ComputeCacheID(destPath, "sha-big")

	zl := zipLocker{Password: "infected"}
	var buf bytes.Buffer
	info := &zipFakeFileInfo{size: 4, mode: 0o600, modTime: time.Now()}
	if err := zl.LockFile(destPath, bytes.NewReader([]byte(content)), info, "malware: big", &buf); err != nil {
		t.Fatalf("LockFile() error = %s", err)
	}
	lockPath := filepath.Join(quarantineDir, id+".lock")
	if err := os.WriteFile(lockPath, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write lock file: %s", err)
	}
	if err := q.registry.Set(ctx, &Entry{ID: id, SHA256: "sha-big", InitialLocation: destPath, QuarantineLocation: lockPath}); err != nil {
		t.Fatalf("registry.Set() error = %s", err)
	}

	err = q.Restore(ctx, id)
	if !errors.Is(err, ErrRestoreSizeMismatch) {
		t.Errorf("Restore() error = %v, want ErrRestoreSizeMismatch", err)
	}
	if _, statErr := os.Stat(destPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("Restore() must not create the destination file on a size mismatch")
	}
	if _, statErr := os.Stat(lockPath); statErr != nil {
		t.Errorf("Restore() must keep the .lock file on failure: %s", statErr)
	}
	entries, readErr := os.ReadDir(filepath.Dir(destPath))
	if readErr != nil {
		t.Fatalf("reading destination dir: %s", readErr)
	}
	for _, e := range entries {
		t.Errorf("destination directory must be empty, found leftover entry %q", e.Name())
	}
}
