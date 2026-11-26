package zipcrypto

import (
	"crypto/rand"
	"io"
)

// HeaderSize is the length of the ZipCrypto encryption header prepended to
// the (compressed) payload: 11 random bytes plus a 1-byte password check
// value (APPNOTE.TXT §6.1.6).
const HeaderSize = 12

// Writer encrypts everything written to it with traditional PKWARE
// encryption and writes the result to an underlying io.Writer.
//
// The 12-byte encryption header is not written until the first Write call
// (or, if nothing is ever written, until Close): this lets a caller use a
// Writer as a zip.Writer per-entry compressor, where the compressor is
// instantiated before the entry's local file header - and therefore before
// values the check byte may depend on, such as the entry's DOS modification
// time - has been finalised. checkByte is only ever invoked at that lazy
// point, exactly once.
type Writer struct {
	w             io.Writer
	keys          *keys
	checkByte     func() byte
	rnd           io.Reader
	headerWritten bool
	buf           []byte
	err           error
}

// NewWriter returns a Writer that encrypts data written to it with
// password before writing it to w. checkByte is called exactly once, the
// first time the encryption header must be emitted, and must return the
// value the corresponding Reader will be told to expect (see
// ReaderOptions.CheckByte): the high byte of the entry's DOS modification
// time if the entry will be flagged with a trailing data descriptor, or the
// high byte of the entry's CRC-32 otherwise.
func NewWriter(w io.Writer, password string, checkByte func() byte) io.WriteCloser {
	return newWriterWithRand(w, password, checkByte, rand.Reader)
}

// newWriterWithRand is NewWriter with an explicit entropy source for the
// 11 random header bytes. It exists so tests can produce byte-exact,
// reproducible ciphertext; production code must always go through
// NewWriter, which uses crypto/rand.
func newWriterWithRand(w io.Writer, password string, checkByte func() byte, rnd io.Reader) *Writer {
	return &Writer{
		w:         w,
		keys:      newKeys([]byte(password)),
		checkByte: checkByte,
		rnd:       rnd,
	}
}

// writeHeader emits the 12-byte encryption header exactly once. It only
// marks the header as written once it has actually, fully reached zw.w:
// any failure (entropy source, write error, or short write) is stored in
// zw.err and returned, so a caller that calls Close (or Write) again after
// a failed header write is told about the same failure again, rather than
// being told the header was written when it never was.
func (zw *Writer) writeHeader() error {
	if zw.headerWritten {
		return zw.err
	}

	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(zw.rnd, header[:HeaderSize-1]); err != nil {
		zw.err = err
		return err
	}
	header[HeaderSize-1] = zw.checkByte()
	for i, b := range header {
		header[i] = zw.keys.encryptByte(b)
	}
	n, err := zw.w.Write(header)
	if n != HeaderSize && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		zw.err = err
		return err
	}
	zw.headerWritten = true
	return nil
}

// Write encrypts p and writes it to the underlying writer. Like
// crypto/cipher.StreamWriter, a short write from the underlying writer
// without an accompanying error is treated as a fatal, unrecoverable
// condition: the cipher's internal state has already advanced past every
// byte of p, so a partial write cannot be safely retried.
func (zw *Writer) Write(p []byte) (n int, err error) {
	if zw.err != nil {
		return 0, zw.err
	}
	if err = zw.writeHeader(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}

	if cap(zw.buf) < len(p) {
		zw.buf = make([]byte, len(p))
	}
	buf := zw.buf[:len(p)]
	for i, b := range p {
		buf[i] = zw.keys.encryptByte(b)
	}

	n, err = zw.w.Write(buf)
	if n != len(p) && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		zw.err = err
	}
	return n, err
}

// Close emits the encryption header if nothing was ever written (the
// 0-byte payload case) and reports any previously stored write error.
func (zw *Writer) Close() error {
	return zw.writeHeader()
}
