package quarantine

import (
	"io"
	"os"
	"time"
)

// LockEntry is the public header information extracted from a quarantine
// container without unlocking (decrypting) the payload. It is returned by
// GetHeader and embedded in LockedFile and QuarantinedFile.
type LockEntry struct {
	Filepath string
	Reason   string
}

// LockedFile carries the full metadata restored together with the plaintext
// payload of a quarantine container. It replaces the historical 4-value
// UnlockFile return and the os.FileInfo.Sys() type assertion that silently
// disabled chown/chtimes for any locker implementation other than the tar
// one.
//
// AccessTime is intentionally absent: the tar container never stored an
// access time for the payload entry, so restore has always effectively set
// atime = mtime. LockedFile makes that contract explicit instead of leaving
// it as an accident of the tar format.
type LockedFile struct {
	LockEntry
	Mode     os.FileMode
	UID, GID int
	ModTime  time.Time
	// Size is the plaintext payload size in bytes, as recorded by the
	// container. Untrusted: Restore only uses it as a final consistency
	// check against the bytes actually produced.
	Size int64
}

// fileLocker writes and reads quarantine containers. Every byte read back
// from disk is hostile: implementations must validate lengths, offsets and
// counts before trusting them, and must never buffer a whole file in memory.
//
// UnlockFile and GetHeader take an io.ReaderAt plus the container size
// instead of an io.Reader so that:
//   - a ZIP-backed implementation can seek to its central directory without
//     buffering the archive;
//   - a tar-backed implementation is unaffected (io.NewSectionReader adapts
//     an io.ReaderAt into the io.Reader the tar package needs);
//   - concurrent GetHeader/UnlockFile calls on a single open file handle
//     (*os.File implements io.ReaderAt) are safe, removing the need for a
//     shared Seek(0) before every read.
type fileLocker interface {
	// LockFile writes a quarantine container for in (the plaintext content
	// of file, described by info) to out, recording reason in the
	// container's cleartext index.
	LockFile(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error

	// UnlockFile decrypts and verifies the payload of the container read
	// from src (size bytes long), streaming the plaintext to out.
	//
	// Contract: any plaintext byte written to out before UnlockFile returns
	// is unverified. A non-nil, non-io.EOF-wrapping error (including an
	// integrity error detected only once the stream is fully read) means
	// the caller MUST discard everything written to out so far; only a
	// clean return with a nil error certifies out's content.
	UnlockFile(src io.ReaderAt, size int64, out io.Writer) (LockedFile, error)

	// GetHeader reads only the cleartext index of the container read from
	// src (size bytes long), without touching the encrypted payload.
	GetHeader(src io.ReaderAt, size int64) (LockEntry, error)
}
