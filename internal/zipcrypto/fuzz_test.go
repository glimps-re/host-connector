package zipcrypto

import (
	"bytes"
	"crypto/rand"
	"hash/crc32"
	"io"
	"testing"
)

// FuzzZipcryptoReader feeds NewReader and the Reader it returns arbitrary
// bytes and metadata, exactly as a crafted or corrupted quarantine
// container would. The only requirement is "never panic, never hang,
// never allocate without bound" - a returned error (of any kind) is always
// an acceptable outcome.
func FuzzZipcryptoReader(f *testing.F) {
	// A genuine, valid ciphertext as a seed, so the fuzzer has something
	// structurally correct to mutate from.
	plaintext := []byte("seed corpus plaintext for the zipcrypto fuzzer")
	const password = "infected"
	const checkByte byte = 0x10
	valid := encryptForTest(f, plaintext, password, checkByte)

	f.Add(valid, crc32.ChecksumIEEE(plaintext), int64(len(plaintext)), password, checkByte)
	f.Add([]byte{}, uint32(0), int64(0), password, byte(0))
	f.Add(valid[:6], uint32(0), int64(0), password, checkByte) // truncated header
	f.Add(valid, crc32.ChecksumIEEE(plaintext), int64(len(plaintext)), "wrong", checkByte)

	f.Fuzz(func(t *testing.T, data []byte, expectedCRC uint32, expectedSize int64, password string, checkByte byte) {
		opts := ReaderOptions{CheckByte: checkByte, ExpectedCRC: expectedCRC, ExpectedSize: expectedSize}
		r, err := NewReader(bytes.NewReader(data), int64(len(data)), password, opts)
		if err != nil {
			return
		}
		// The output is bounded by the input size; the limit only protects
		// the test process from a Reader bug.
		_, _ = io.Copy(io.Discard, io.LimitReader(r, 4<<20))
	})
}

// FuzzZipcryptoKeys exercises the key schedule and byte cipher directly
// with arbitrary passwords and plaintext, checking only the one invariant
// that must always hold: encrypting then decrypting with the same password
// returns the original bytes, and it never panics.
func FuzzZipcryptoKeys(f *testing.F) {
	f.Add([]byte("infected"), []byte("hello"))
	f.Add([]byte(""), []byte(""))
	seedPW := make([]byte, 32)
	_, _ = rand.Read(seedPW)
	f.Add(seedPW, []byte("a longer plaintext to exercise more key updates"))

	f.Fuzz(func(t *testing.T, password, plaintext []byte) {
		enc := newKeys(password)
		ciphertext := make([]byte, len(plaintext))
		for i, p := range plaintext {
			ciphertext[i] = enc.encryptByte(p)
		}
		dec := newKeys(password)
		got := make([]byte, len(ciphertext))
		for i, c := range ciphertext {
			got[i] = dec.decryptByte(c)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round trip mismatch for password %x", password)
		}
	})
}
