package quarantine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
)

const largeTestsEnv = "GMHOST_LARGE_TESTS"

func TestRestore_SparseFileOver5GiB(t *testing.T) {
	if os.Getenv(largeTestsEnv) != "1" {
		t.Skipf("set %s=1 to run", largeTestsEnv)
	}
	const size = int64(5<<30) + 4096
	for _, format := range []Format{FormatTar, FormatZip} {
		t.Run(string(format), func(t *testing.T) {
			q, _ := newE2EHandler(t, format)
			src := filepath.Join(t.TempDir(), "big.bin")
			f, err := os.Create(filepath.Clean(src))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteAt([]byte("tail"), size-4); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			h := sha256.New()
			in, err := os.Open(filepath.Clean(src))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(h, in); err != nil {
				t.Fatal(err)
			}
			if err := in.Close(); err != nil {
				t.Fatal(err)
			}
			_, id, err := q.Quarantine(t.Context(), src, hex.EncodeToString(h.Sum(nil)), []string{"m"})
			if err != nil {
				t.Fatalf("Quarantine() error = %v", err)
			}
			if _, err := os.Stat(src); err == nil {
				if err := os.Remove(src); err != nil {
					t.Fatal(err)
				}
			}
			if err := q.Restore(t.Context(), id); err != nil {
				t.Fatalf("Restore() of a %d byte file error = %v", size, err)
			}
			info, err := os.Stat(src)
			if err != nil || info.Size() != size {
				t.Fatalf("restored size = %v (err %v), want %d", info, err, size)
			}
			r, err := os.Open(filepath.Clean(src))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			}()
			tail := make([]byte, 4)
			if _, err := r.ReadAt(tail, size-4); err != nil && err != io.EOF {
				t.Fatal(err)
			}
			if !bytes.Equal(tail, []byte("tail")) {
				t.Errorf("tail = %q, want tail", tail)
			}
		})
	}
}
