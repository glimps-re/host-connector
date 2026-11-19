package quarantine

import (
	"archive/zip"
	"bytes"
	"io"
	"testing"
	"time"
)

// zipFuzzSeed returns a genuine, valid zipLocker-produced container, so the
// fuzzer has something structurally correct to mutate from.
func zipFuzzSeed(t testing.TB) []byte {
	t.Helper()
	l := zipLocker{Password: "infected"}
	info := &zipFakeFileInfo{size: 11, mode: 0o644, modTime: time.Unix(1700000000, 0)}
	var buf bytes.Buffer
	if err := l.LockFile("/tmp/seed.exe", bytes.NewReader([]byte("hello world")), info, "malware: seed", &buf); err != nil {
		t.Fatalf("zipFuzzSeed: LockFile: %s", err)
	}
	return buf.Bytes()
}

// FuzzZipGetHeader feeds arbitrary bytes to zipLocker.GetHeader, exactly as
// a crafted or corrupted .lock file would. The only requirement is "never
// panic, never hang, never allocate without bound" - any error is fine.
func FuzzZipGetHeader(f *testing.F) {
	seed := zipFuzzSeed(f)
	f.Add(seed)
	f.Add(seed[:len(seed)/2]) // truncated
	f.Add([]byte{})
	f.Add([]byte("PK\x03\x04"))
	f.Add(bytes.Repeat([]byte{0x00}, 4096))

	// Structural mutation seeds: same container, but with the index
	// entry's declared size/flags tampered directly in the raw bytes,
	// which a byte-level fuzzer might take much longer to discover on its
	// own from an encrypted/compressed seed.
	if withoutIndex, ok := stripEntry(f, seed, "index.json"); ok {
		f.Add(withoutIndex)
	}

	idx := validIndexBytes(f, "payload.bin")
	payload := bytes.Repeat([]byte("x"), 20)
	f.Add(buildZip(f, []zipEntrySpec{
		{name: "index.json", data: idx, method: zip.Store},
		{name: "payload.bin", data: payload, method: zip.Deflate, encrypted: true},
	}))
	f.Add(buildZip(f, []zipEntrySpec{
		{name: "index.json", data: idx, method: zip.Store},
		{name: "payload.bin", data: payload, method: zip.Store, encrypted: true},
		{name: "extra", data: payload, method: zip.Store},
	}))

	f.Fuzz(func(t *testing.T, data []byte) {
		l := zipLocker{Password: "infected"}
		_, _ = l.GetHeader(bytes.NewReader(data), int64(len(data)))
	})
}

// FuzzZipUnlock feeds arbitrary bytes to zipLocker.UnlockFile, the highest-
// risk entry point (it drives decompression and decryption). Output is
// bounded defensively in the test itself in case a bug were to make the
// package's own caps ineffective - which is part of what's being fuzzed.
func FuzzZipUnlock(f *testing.F) {
	seed := zipFuzzSeed(f)
	f.Add(seed)
	f.Add(seed[:len(seed)/2])
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 2048))

	f.Fuzz(func(t *testing.T, data []byte) {
		l := zipLocker{Password: "infected"}
		var sink boundedDiscard
		_, _ = l.UnlockFile(bytes.NewReader(data), int64(len(data)), &sink)
	})
}

// boundedDiscard is an io.Writer that discards everything but errors out
// past a generous cap, so a hypothetical bug in the package's own size caps
// cannot make a fuzz run itself allocate unboundedly.
type boundedDiscard struct {
	n int64
}

func (b *boundedDiscard) Write(p []byte) (int, error) {
	b.n += int64(len(p))
	if b.n > 64<<20 {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

// stripEntry rebuilds a zip file identical to data but without the named
// entry, using stdlib parsing/writing only (a plain structural mutation,
// not a crypto operation). Returns ok=false if data cannot be parsed as a
// well-formed zip (e.g. because a prior corpus mutation already broke it),
// in which case the caller should skip adding it as a seed.
func stripEntry(t testing.TB, data []byte, skip string) ([]byte, bool) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, false
	}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, zf := range zr.File {
		if zf.Name == skip {
			continue
		}
		rc, err := zf.OpenRaw()
		if err != nil {
			return nil, false
		}
		compressedSize, err := safeInt64(zf.CompressedSize64)
		if err != nil {
			return nil, false
		}
		raw, err := io.ReadAll(io.LimitReader(rc, compressedSize))
		if err != nil {
			return nil, false
		}
		fh := zf.FileHeader
		w, err := zw.CreateRaw(&fh)
		if err != nil {
			return nil, false
		}
		if _, err := w.Write(raw); err != nil {
			return nil, false
		}
	}
	if err := zw.Close(); err != nil {
		return nil, false
	}
	return out.Bytes(), true
}
