package quarantine

import (
	"bytes"
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
