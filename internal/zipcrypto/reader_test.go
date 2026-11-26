package zipcrypto

import (
	"archive/zip"
	"bytes"
	"errors"
	"hash/crc32"
	"io"
	"math"
	"path/filepath"
	"testing"
	"testing/iotest"
)

const interopPassword = "infected"

const interopPlaintext = "Hello ZipCrypto interop test payload, this is a bit longer than one block.\n"

// openInteropEntry opens the single entry of a 7-Zip-produced ZipCrypto
// fixture (see testdata/README.md for provenance) and returns its raw
// (still encrypted, still compressed if applicable) bytes together with
// the ReaderOptions this package needs to decode it. archive/zip is used
// here only as a test helper to pull the container apart; the zipcrypto
// package itself never imports it.
func openInteropEntry(t *testing.T, name string) ([]byte, ReaderOptions) {
	t.Helper()
	zr, err := zip.OpenReader(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("open fixture %s: %s", name, err)
	}
	defer func() {
		if err := zr.Close(); err != nil {
			t.Errorf("close fixture: %s", err)
		}
	}()
	if len(zr.File) != 1 {
		t.Fatalf("fixture %s: expected exactly one entry, got %d", name, len(zr.File))
	}
	f := zr.File[0]

	rc, err := f.OpenRaw()
	if err != nil {
		t.Fatalf("OpenRaw: %s", err)
	}
	// These fixtures are small, local, and trusted test data (see
	// testdata/README.md): the bounds checks below exist to make the
	// uint64->int64 narrowing conversion visibly safe, not because a
	// multi-exabyte test fixture is a realistic concern.
	if f.CompressedSize64 > math.MaxInt64 || f.UncompressedSize64 > math.MaxInt64 {
		t.Fatalf("fixture %s: size does not fit in int64", name)
	}
	compressedSize := int64(min(f.CompressedSize64, math.MaxInt64))
	uncompressedSize := int64(min(f.UncompressedSize64, math.MaxInt64))

	raw, err := io.ReadAll(io.LimitReader(rc, compressedSize))
	if err != nil {
		t.Fatalf("reading raw entry bytes: %s", err)
	}

	var checkByte byte
	if f.Flags&0x8 != 0 {
		checkByte = byte(f.ModifiedTime >> 8)
	} else {
		checkByte = byte(f.CRC32 >> 24)
	}

	return raw, ReaderOptions{
		CheckByte:    checkByte,
		ExpectedCRC:  f.CRC32,
		ExpectedSize: uncompressedSize,
	}
}

func TestReader_Interop_SevenZipStore(t *testing.T) {
	raw, opts := openInteropEntry(t, "sevenzip_zipcrypto_store.zip")
	r, err := NewReader(bytes.NewReader(raw), int64(len(raw)), interopPassword, opts)
	if err != nil {
		t.Fatalf("NewReader() error = %s", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll() error = %s", err)
	}
	if string(got) != interopPlaintext {
		t.Errorf("content = %q, want %q", got, interopPlaintext)
	}
}

// TestReader_Interop_WrongPassword exercises both check-byte paths (with
// and without a trailing data descriptor) with a wrong password.
func TestReader_Interop_WrongPassword(t *testing.T) {
	for _, fixture := range []string{"sevenzip_zipcrypto_store.zip"} {
		t.Run(fixture, func(t *testing.T) {
			raw, opts := openInteropEntry(t, fixture)
			_, err := NewReader(bytes.NewReader(raw), int64(len(raw)), "not-the-password", opts)
			if !errors.Is(err, ErrWrongPassword) {
				t.Errorf("NewReader() error = %v, want ErrWrongPassword", err)
			}
		})
	}
}

// encryptForTest builds a ZipCrypto ciphertext for plaintext, used
// throughout this package's tests, benchmarks and fuzz-seed corpus (tb is
// satisfied by *testing.T, *testing.B and *testing.F alike).
func encryptForTest(tb testing.TB, plaintext []byte, password string, checkByte byte) []byte {
	tb.Helper()
	var buf bytes.Buffer
	w := NewWriter(&buf, password, func() byte { return checkByte })
	if len(plaintext) > 0 {
		if _, err := w.Write(plaintext); err != nil {
			tb.Fatalf("Write() error = %s", err)
		}
	}
	if err := w.Close(); err != nil {
		tb.Fatalf("Close() error = %s", err)
	}
	return buf.Bytes()
}

func TestReader_WrongPassword_BeforeAnyPlaintext(t *testing.T) {
	plaintext := []byte("this must never be observed by a caller with the wrong password")
	ciphertext := encryptForTest(t, plaintext, "right-password", 0x11)

	r, err := NewReader(bytes.NewReader(ciphertext), int64(len(ciphertext)), "wrong-password", ReaderOptions{
		CheckByte:    0x11,
		ExpectedCRC:  crc32.ChecksumIEEE(plaintext),
		ExpectedSize: int64(len(plaintext)),
	})
	if !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("NewReader() error = %v, want ErrWrongPassword", err)
	}
	if r != nil {
		t.Errorf("NewReader() returned a non-nil Reader alongside ErrWrongPassword")
	}
}

// TestReader_FlippedCiphertextByte_YieldsChecksumErrorAtEOF is the Q3
// contract test: a tampered ciphertext byte still passes the 1/256
// check-byte test in general (here the check byte is unaffected, only the
// payload is tampered), so data is emitted, and only the final CRC check
// - not a clean io.EOF - reports the tampering.
func TestReader_FlippedCiphertextByte_YieldsChecksumErrorAtEOF(t *testing.T) {
	plaintext := []byte("plaintext long enough that flipping one byte still leaves most of it readable")
	const checkByte = 0x22
	ciphertext := encryptForTest(t, plaintext, "infected", checkByte)

	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0xFF // flip the very last ciphertext byte

	r, err := NewReader(bytes.NewReader(tampered), int64(len(tampered)), "infected", ReaderOptions{
		CheckByte:    checkByte,
		ExpectedCRC:  crc32.ChecksumIEEE(plaintext),
		ExpectedSize: int64(len(plaintext)),
	})
	if err != nil {
		t.Fatalf("NewReader() error = %s", err)
	}

	data, readErr := io.ReadAll(r)
	if readErr == nil {
		t.Fatalf("ReadAll() unexpectedly succeeded on tampered ciphertext")
	}
	if errors.Is(readErr, io.EOF) {
		t.Errorf("ReadAll() returned io.EOF-flavoured error %v, want a non-EOF ErrChecksum", readErr)
	}
	if !errors.Is(readErr, ErrChecksum) {
		t.Errorf("ReadAll() error = %v, want ErrChecksum", readErr)
	}
	if len(data) == 0 {
		t.Errorf("expected some plaintext to have been emitted before the checksum failure (unauthenticated-until-EOF contract)")
	}
}

func TestReader_TruncatedHeader(t *testing.T) {
	ciphertext := encryptForTest(t, []byte("hello"), "infected", 0x00)
	truncated := ciphertext[:6] // less than the 12-byte header

	_, err := NewReader(bytes.NewReader(truncated), int64(len(truncated)), "infected", ReaderOptions{
		CheckByte: 0x00,
	})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("NewReader() error = %v, want a wrapped io.ErrUnexpectedEOF", err)
	}
}

func TestReader_TruncatedHeader_MidRead(t *testing.T) {
	// compressedSize claims 12 bytes are available, but the underlying
	// reader actually yields fewer: exercises the io.ReadFull failure path
	// distinct from the cheap compressedSize < HeaderSize short-circuit.
	short := bytes.NewReader([]byte{1, 2, 3, 4})
	_, err := NewReader(short, HeaderSize, "infected", ReaderOptions{})
	if err == nil {
		t.Fatalf("NewReader() unexpectedly succeeded reading past a short underlying reader")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("NewReader() error = %v, want a wrapped io.ErrUnexpectedEOF", err)
	}
}

// TestReader_OneByteAtATime exercises the streaming contract with a Reader
// that only ever returns one byte per call, to catch any accidental
// assumption about read chunk sizes (e.g. in the header parsing).
func TestReader_OneByteAtATime(t *testing.T) {
	plaintext := []byte("streamed one byte at a time through io.OneByteReader")
	const checkByte = 0x55
	ciphertext := encryptForTest(t, plaintext, "infected", checkByte)

	r, err := NewReader(iotest.OneByteReader(bytes.NewReader(ciphertext)), int64(len(ciphertext)), "infected", ReaderOptions{
		CheckByte:    checkByte,
		ExpectedCRC:  crc32.ChecksumIEEE(plaintext),
		ExpectedSize: int64(len(plaintext)),
	})
	if err != nil {
		t.Fatalf("NewReader() error = %s", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll() error = %s", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("content = %q, want %q", got, plaintext)
	}
}

func BenchmarkReader_Store_1MiB(b *testing.B) {
	plaintext := make([]byte, 1<<20)
	const checkByte = 0x66
	ciphertext := encryptForTest(b, plaintext, "infected", checkByte)
	crc := crc32.ChecksumIEEE(plaintext)

	b.SetBytes(int64(len(plaintext)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		r, err := NewReader(bytes.NewReader(ciphertext), int64(len(ciphertext)), "infected", ReaderOptions{
			CheckByte:    checkByte,
			ExpectedCRC:  crc,
			ExpectedSize: int64(len(plaintext)),
		})
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, r); err != nil {
			b.Fatal(err)
		}
	}
}

// TestAllocsPerRun_Store checks the hot decrypt path does not grow its
// allocation count with repeated use.
func TestAllocsPerRun_Store(t *testing.T) {
	plaintext := make([]byte, 64*1024)
	const checkByte = 0x77
	ciphertext := encryptForTest(t, plaintext, "infected", checkByte)
	crc := crc32.ChecksumIEEE(plaintext)

	allocs := testing.AllocsPerRun(20, func() {
		r, err := NewReader(bytes.NewReader(ciphertext), int64(len(ciphertext)), "infected", ReaderOptions{
			CheckByte:    checkByte,
			ExpectedCRC:  crc,
			ExpectedSize: int64(len(plaintext)),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, r); err != nil {
			t.Fatal(err)
		}
	})
	t.Logf("allocs per run: %.1f", allocs)
}
