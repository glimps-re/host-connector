package quarantine

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func benchSize() int {
	if testing.Short() {
		return 1 << 20
	}
	return 64 << 20
}

func BenchmarkLockFile(b *testing.B) {
	data := bytes.Repeat([]byte("0123456789abcdef"), benchSize()/16)
	info := &zipFakeFileInfo{size: int64(len(data)), mode: 0o600, modTime: time.Now()}
	for name, l := range map[string]fileLocker{"tar": &tarLocker{Password: "infected"}, "zip": &zipLocker{Password: "infected"}} {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			for b.Loop() {
				if err := l.LockFile("/tmp/x", bytes.NewReader(data), info, "malware: x", io.Discard); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkRestore(b *testing.B) {
	data := bytes.Repeat([]byte("0123456789abcdef"), benchSize()/16)
	info := &zipFakeFileInfo{size: int64(len(data)), mode: 0o600, modTime: time.Now()}
	for name, l := range map[string]fileLocker{"tar": &tarLocker{Password: "infected"}, "zip": &zipLocker{Password: "infected"}} {
		var container bytes.Buffer
		if err := l.LockFile("/tmp/x", bytes.NewReader(data), info, "malware: x", &container); err != nil {
			b.Fatal(err)
		}
		path := filepath.Join(b.TempDir(), "x.lock")
		if err := os.WriteFile(path, container.Bytes(), 0o600); err != nil {
			b.Fatal(err)
		}
		b.Run(name, func(b *testing.B) {
			f, err := os.Open(filepath.Clean(path))
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() {
				if e := f.Close(); e != nil {
					b.Error(e)
				}
			})
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := l.UnlockFile(f, int64(container.Len()), io.Discard); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkIsRestored(b *testing.B) {
	r, err := newSQLiteRegistry(b.Context(), "")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if e := r.Close(); e != nil {
			b.Error(e)
		}
	})
	const n = 100_000
	location := func(i int) string { return fmt.Sprintf("/in/user/f-%d.bin", i) }
	sha := func(i int) string { return fmt.Sprintf("%064x", i) }
	tx, err := r.db.BeginTx(b.Context(), nil)
	if err != nil {
		b.Fatal(err)
	}
	for i := range n {
		restored := int64(0)
		if i%1000 == 0 {
			restored = time.Now().UnixMilli()
		}
		if _, err = tx.ExecContext(b.Context(), "INSERT INTO entries(id, sha256, created_at, updated_at, quarantine, location, restored_at) VALUES(?,?,?,?,?,?,?)",
			ComputeCacheID(location(i), sha(i)), sha(i), 1, 1, "", location(i), restored); err != nil {
			b.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		b.Fatal(err)
	}
	q := &QuarantineHandler{registry: r}
	for name, tt := range map[string]struct {
		location, sha256 string
		want             bool
	}{
		"restored": {location: location(n / 2), sha256: sha(n / 2), want: true},
		"unknown":  {location: location(n + 1), sha256: sha(n + 1)},
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if got, e := q.IsRestored(b.Context(), tt.location, tt.sha256); e != nil || got != tt.want {
					b.Fatalf("IsRestored() = %t, %v, want %t", got, e, tt.want)
				}
			}
		})
	}
}
