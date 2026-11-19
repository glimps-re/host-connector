package quarantine

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestZipStrictReader_ListAndRestore(t *testing.T) {
	enc := bytes.Repeat([]byte("x"), 20)
	tests := []struct {
		name    string
		entries func(index []byte) []zipEntrySpec
		wantErr error
	}{
		{"one entry", func(i []byte) []zipEntrySpec {
			return []zipEntrySpec{{name: "index.json", data: i, method: zip.Store}}
		}, errZipLayout},
		{"three entries", func(i []byte) []zipEntrySpec {
			return []zipEntrySpec{
				{name: "index.json", data: i, method: zip.Store},
				{name: "payload.bin", data: enc, method: zip.Store, encrypted: true},
				{name: "extra", data: []byte("x"), method: zip.Store},
			}
		}, errZipLayout},
		{"reversed entries", func(i []byte) []zipEntrySpec {
			return []zipEntrySpec{
				{name: "payload.bin", data: enc, method: zip.Store, encrypted: true},
				{name: "index.json", data: i, method: zip.Store},
			}
		}, errZipIndexNotFound},
		{"deflate payload", func(i []byte) []zipEntrySpec {
			return []zipEntrySpec{
				{name: "index.json", data: i, method: zip.Store},
				{name: "payload.bin", data: enc, method: zip.Deflate, encrypted: true},
			}
		}, errZipMethod},
		{"payload not encrypted", func(i []byte) []zipEntrySpec {
			return []zipEntrySpec{
				{name: "index.json", data: i, method: zip.Store},
				{name: "payload.bin", data: enc, method: zip.Store},
			}
		}, errZipPayloadNotLocked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, dir := newE2EHandler(t, FormatZip)
			dest := filepath.Join(t.TempDir(), "victim.bin")
			idx, err := json.Marshal(LockIndex{Version: 1, Filepath: dest, Reason: "malware: x", Entry: "payload.bin"})
			if err != nil {
				t.Fatal(err)
			}
			id := ComputeCacheID(dest, "sha-z2")
			lock := filepath.Join(dir, id+".lock")
			if err := os.WriteFile(lock, buildZip(t, tt.entries(idx)), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := q.registry.Set(t.Context(), &Entry{ID: id, SHA256: "sha-z2", InitialLocation: dest, QuarantineLocation: lock}); err != nil {
				t.Fatal(err)
			}

			for f, err := range q.ListQuarantinedFiles(t.Context()) {
				if err == nil && f != nil && f.ID == id {
					t.Errorf("listing must not surface the refused container %s", id)
				}
			}
			err = q.Restore(t.Context(), id)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Restore() error = %v, want %v", err, tt.wantErr)
			}
			if _, err := os.Stat(dest); err == nil {
				t.Error("nothing must be written at the destination")
			}
			if _, err := os.Stat(lock); err != nil {
				t.Errorf(".lock must be kept: %v", err)
			}
			if entries, err := os.ReadDir(filepath.Dir(dest)); err != nil || len(entries) != 0 {
				t.Errorf("destination dir = %v (err %v), want empty (no temporary left)", entries, err)
			}
		})
	}
}

func TestLimitWriter_NoFixedCap(t *testing.T) {
	const lockSize = int64(6 << 30)
	lw := &limitWriter{w: io.Discard, remaining: lockSize}
	chunk := make([]byte, 1<<20)
	for range 6 << 10 {
		if _, err := lw.Write(chunk); err != nil {
			t.Fatalf("Write() error = %v before reaching the lock size", err)
		}
	}
	if lw.written != lockSize {
		t.Fatalf("written = %d, want %d", lw.written, lockSize)
	}
	if _, err := lw.Write([]byte{0}); !errors.Is(err, ErrRestoreTooLarge) {
		t.Errorf("Write() past the limit error = %v, want ErrRestoreTooLarge", err)
	}
}

func TestCreateRestoreTempFile(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	for _, base := range []string{"a.bin", strings.Repeat("é", 200), strings.Repeat("a", 255)} {
		name, f, err := createRestoreTempFile(root, base)
		if err != nil {
			t.Fatalf("createRestoreTempFile(%d bytes) error = %v", len(base), err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(name, TempPrefix) || len(name) > 255 {
			t.Errorf("name %q: want prefix %q and <= 255 bytes (got %d)", name, TempPrefix, len(name))
		}
	}
	n1, f1, err := createRestoreTempFile(root, "same")
	if err != nil {
		t.Fatal(err)
	}
	if err := f1.Close(); err != nil {
		t.Fatal(err)
	}
	n2, f2, err := createRestoreTempFile(root, "same")
	if err != nil {
		t.Fatal(err)
	}
	if err := f2.Close(); err != nil {
		t.Fatal(err)
	}
	if n1 == n2 {
		t.Error("two temporary files must get distinct names")
	}
}

func TestTruncateUTF8(t *testing.T) {
	tests := []struct {
		in   string
		max  int
		want string
	}{
		{"abc", 5, "abc"},
		{"abc", 2, "ab"},
		{"aé", 2, "a"},
		{"éé", 3, "é"},
		{"é", 0, ""},
	}
	for _, tt := range tests {
		got := truncateUTF8(tt.in, tt.max)
		if got != tt.want || !utf8.ValidString(got) {
			t.Errorf("truncateUTF8(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
		}
	}
}
