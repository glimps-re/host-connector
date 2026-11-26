package quarantine

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

const testRestoreID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newE2EHandler(t *testing.T, format Format) (*QuarantineHandler, string) {
	t.Helper()
	dir := t.TempDir()
	q, err := NewQuarantineHandler(t.Context(), Config{Location: dir, LockPassword: "infected", Format: format})
	if err != nil {
		t.Fatalf("NewQuarantineHandler() error = %v", err)
	}
	t.Cleanup(func() {
		if err := q.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return q, dir
}

func writeSample(t *testing.T, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
