package zipcrypto

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
)

var (
	// ErrWrongPassword is returned by NewReader when the decrypted
	// password-check byte does not match ReaderOptions.CheckByte, before any
	// plaintext byte is produced.
	ErrWrongPassword = errors.New("zipcrypto: wrong password")

	// ErrChecksum is returned by a Reader's Read method, in place of a clean
	// io.EOF, when the decrypted plaintext does not match
	// ReaderOptions.ExpectedCRC or ReaderOptions.ExpectedSize. ZipCrypto has
	// no authentication: every byte returned before this check completes is
	// unverified, and a caller MUST discard everything read so far if Read
	// returns a non-nil, non-io.EOF error.
	ErrChecksum = errors.New("zipcrypto: checksum or size mismatch")
)

// ReaderOptions configures the checks a Reader performs. Only entries stored
// without compression (ZIP method 0) are supported.
type ReaderOptions struct {
	// CheckByte is the expected value of the encryption header's 12th byte,
	// computed by the caller from container metadata: the entry's DOS-time
	// high byte if a trailing data descriptor is used, or its CRC-32 high
	// byte otherwise (APPNOTE.TXT 6.1.6).
	CheckByte byte
	// ExpectedCRC is the plaintext CRC-32 the container claims.
	ExpectedCRC uint32
	// ExpectedSize is the plaintext size the container claims.
	ExpectedSize int64
}

// NewReader returns a Reader that decrypts compressedSize bytes read from r
// with password and verifies the CRC-32 and size of the result. At most
// compressedSize bytes are read from r. The header length and the password
// check byte are verified before returning.
func NewReader(r io.Reader, compressedSize int64, password string, opts ReaderOptions) (io.Reader, error) {
	if compressedSize < HeaderSize {
		return nil, fmt.Errorf("zipcrypto: truncated encryption header (compressed size %d < %d): %w", compressedSize, HeaderSize, io.ErrUnexpectedEOF)
	}

	limited := &io.LimitedReader{R: r, N: compressedSize}
	k := newKeys([]byte(password))

	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(limited, header); err != nil {
		return nil, fmt.Errorf("zipcrypto: reading encryption header: %w", err)
	}
	for i, b := range header {
		header[i] = k.decryptByte(b)
	}
	// The check byte is derived from container metadata visible to anyone
	// holding the file, so a timing side channel leaks nothing.
	if subtle.ConstantTimeByteEq(header[HeaderSize-1], opts.CheckByte) == 0 {
		return nil, ErrWrongPassword
	}

	return &verifyingReader{
		r:            &decryptingReader{r: limited, keys: k},
		crc:          crc32.NewIEEE(),
		expectedCRC:  opts.ExpectedCRC,
		expectedSize: opts.ExpectedSize,
	}, nil
}

// decryptingReader decrypts bytes read from r buffer by buffer.
type decryptingReader struct {
	r    io.Reader
	keys *keys
}

func (d *decryptingReader) Read(p []byte) (n int, err error) {
	n, err = d.r.Read(p)
	for i := range p[:n] {
		p[i] = d.keys.decryptByte(p[i])
	}
	return n, err
}

// verifyingReader tracks a running CRC-32 and byte count over everything read
// from r, and turns a clean io.EOF into ErrChecksum if either mismatches.
type verifyingReader struct {
	r            io.Reader
	crc          hash.Hash32
	n            int64
	expectedCRC  uint32
	expectedSize int64
}

func (v *verifyingReader) Read(p []byte) (n int, err error) {
	n, err = v.r.Read(p)
	if n > 0 {
		_, _ = v.crc.Write(p[:n]) // hash.Hash.Write never returns an error
		v.n += int64(n)
	}
	if errors.Is(err, io.EOF) {
		if v.crc.Sum32() != v.expectedCRC || v.n != v.expectedSize {
			return n, ErrChecksum
		}
	}
	return n, err
}
