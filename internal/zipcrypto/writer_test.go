package zipcrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	mrand "math/rand"
	"testing"
)

// TestWriter_PinnedRand_ByteExact pins the writer's output through the
// unexported rand-source test seam, guarding against any accidental change
// to the header framing or the encryption byte order.
func TestWriter_PinnedRand_ByteExact(t *testing.T) {
	rnd := bytes.NewReader(bytes.Repeat([]byte{0xAA}, 64))
	var buf bytes.Buffer
	w := newWriterWithRand(&buf, "infected", func() byte { return 0xAB }, rnd)
	if _, err := w.Write([]byte("azerty")); err != nil {
		t.Fatalf("Write() error = %s", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %s", err)
	}

	const want = "a9329126d701a1ac346a83fcc796fa96ae36"
	if got := hex.EncodeToString(buf.Bytes()); got != want {
		t.Errorf("ciphertext = %s, want %s", got, want)
	}
}

// TestWriter_ZeroBytes_StillEmitsHeaderOnClose covers the 0-byte payload
// case explicitly: Write is never called, only Close, and the 12-byte
// encryption header must still be produced.
func TestWriter_ZeroBytes_StillEmitsHeaderOnClose(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, "infected", func() byte { return 0x00 })
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %s", err)
	}
	if buf.Len() != HeaderSize {
		t.Errorf("output length = %d, want %d (header only)", buf.Len(), HeaderSize)
	}
}

// TestWriter_CheckByteCalledOnce verifies the lazy, exactly-once contract
// checkByte must satisfy to be usable as a zip.Writer compressor factory.
func TestWriter_CheckByteCalledOnce(t *testing.T) {
	calls := 0
	var buf bytes.Buffer
	w := NewWriter(&buf, "infected", func() byte {
		calls++
		return 0x00
	})
	if _, err := w.Write([]byte("a")); err != nil {
		t.Fatalf("Write() error = %s", err)
	}
	if _, err := w.Write([]byte("b")); err != nil {
		t.Fatalf("Write() error = %s", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %s", err)
	}
	if calls != 1 {
		t.Errorf("checkByte called %d times, want exactly 1", calls)
	}
}

// TestWriter_ErrorIsSticky documents that once the underlying writer fails,
// a Writer never attempts to write again and reports the same failure on
// every subsequent call.
func TestWriter_ErrorIsSticky(t *testing.T) {
	fw := &failingWriter{}
	w := NewWriter(fw, "infected", func() byte { return 0x00 })
	if _, err := w.Write([]byte("trigger the header write")); err == nil {
		t.Fatalf("Write() unexpectedly succeeded against a failing underlying writer")
	}
	if _, err := w.Write([]byte("more")); err == nil {
		t.Errorf("Write() after a prior error unexpectedly succeeded")
	}
	if err := w.Close(); err == nil {
		t.Errorf("Close() after a prior error unexpectedly succeeded")
	}
}

type failingWriter struct{}

func (f *failingWriter) Write(p []byte) (int, error) {
	return 0, errors.New("simulated write failure")
}

// TestWriter_Close_FailureIsSticky is a regression test: a Writer that
// fails to write its header must report that same failure on every
// subsequent Close call, never silently succeed on retry once the header
// was never actually written.
func TestWriter_Close_FailureIsSticky(t *testing.T) {
	fw := &failingWriter{}
	w := NewWriter(fw, "infected", func() byte { return 0x00 })

	if err := w.Close(); err == nil {
		t.Fatalf("Close() unexpectedly succeeded against a failing underlying writer")
	}
	if err := w.Close(); err == nil {
		t.Errorf("second Close() call unexpectedly succeeded after the header was never written")
	}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Errorf("Write() after a failed Close() unexpectedly succeeded")
	}
}

// roundTripSizes are the payload sizes exercised end to end (Writer -> Reader);
// the largest is skipped in short mode.
var roundTripSizes = []int{0, 1, 2, 15, 16, 4095, 4096, 1 << 20, 16 << 20}

func TestRoundTrip_Sizes_Store(t *testing.T) {
	for _, size := range roundTripSizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			if testing.Short() && size > 1<<20 {
				t.Skip("large payload skipped in short mode")
			}
			data := randomBytes(t, size)
			const checkByte = 0x42

			ciphertext := encryptForTest(t, data, "infected", checkByte)
			if len(ciphertext) != size+HeaderSize {
				t.Fatalf("ciphertext length = %d, want %d", len(ciphertext), size+HeaderSize)
			}

			r, err := NewReader(bytes.NewReader(ciphertext), int64(len(ciphertext)), "infected", ReaderOptions{
				CheckByte:    checkByte,
				ExpectedCRC:  crc32.ChecksumIEEE(data),
				ExpectedSize: int64(size),
			})
			if err != nil {
				t.Fatalf("NewReader() error = %s", err)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("ReadAll() error = %s", err)
			}
			if !bytes.Equal(got, data) {
				t.Errorf("round trip mismatch for size %d", size)
			}
		})
	}
}

// randomBytes returns n pseudo-random bytes. Content does not need to be
// cryptographically random (it is test payload data, not key material);
// math/rand is used for the larger sizes purely for speed.
func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if n <= 4096 {
		if _, err := rand.Read(b); err != nil {
			t.Fatalf("rand.Read: %s", err)
		}
		return b
	}
	src := mrand.New(mrand.NewSource(int64(n))) //nolint:gosec // test payload content, not security-sensitive
	if _, err := src.Read(b); err != nil {
		t.Fatalf("math/rand Read: %s", err)
	}
	return b
}

func BenchmarkWriter_Store_1MiB(b *testing.B) {
	data := make([]byte, 1<<20)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		w := NewWriter(io.Discard, "infected", func() byte { return 0 })
		if _, err := w.Write(data); err != nil {
			b.Fatal(err)
		}
		if err := w.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriter_Store_64MiB(b *testing.B) {
	data := make([]byte, 64<<20)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		w := NewWriter(io.Discard, "infected", func() byte { return 0 })
		if _, err := w.Write(data); err != nil {
			b.Fatal(err)
		}
		if err := w.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
