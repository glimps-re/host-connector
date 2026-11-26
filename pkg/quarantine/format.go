package quarantine

import (
	"errors"
	"fmt"
	"io"
)

// Format selects the on-disk container LockFile writes for new quarantine
// files. The read path is independent of Format: it always auto-detects the
// container from file content (see detectFormat), so every existing .lock
// stays restorable regardless of the configured write Format, and both
// formats can coexist in one quarantine directory forever.
type Format string

const (
	// FormatTar is the original quarantine container: a tar archive with a
	// cleartext index and an AES-128-CTR encrypted payload. It is the
	// default.
	FormatTar Format = "tar"

	// FormatZip is a ZIP archive whose payload is protected with
	// traditional PKWARE encryption ("ZipCrypto"), so it opens in Windows
	// Explorer, 7-Zip, WinZip and other common tools using the quarantine
	// password. ZipCrypto is cryptographically weak: the quarantine password
	// must be considered public with this format (see the README).
	FormatZip Format = "zip"
)

// ErrUnknownFormat is returned by ParseFormat for any value other than the
// empty string, "tar" or "zip".
var ErrUnknownFormat = errors.New("unknown quarantine format")

// ParseFormat validates and normalises a configured format string. An
// empty string selects FormatTar (the package default); any other value
// that is not "tar" or "zip" is a configuration error.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case "", FormatTar:
		return FormatTar, nil
	case FormatZip:
		return FormatZip, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnknownFormat, s)
	}
}

// containerFormat identifies the on-disk container format detected from a
// .lock file's content (see detectFormat). It is independent of Format,
// which only selects what LockFile writes.
type containerFormat uint8

const (
	formatUnknown containerFormat = iota
	formatTarContainer
	formatZipContainer
)

// errUnknownLockFormat is returned by detectFormat when a .lock file's
// content matches neither container's signature.
var errUnknownLockFormat = errors.New("unknown quarantine container format")

// detectProbeLen is the number of bytes detectFormat reads from the start
// of a container to identify it: enough to cover the ZIP local-file-header
// signature (4 bytes at offset 0) and the tar USTAR magic (5 bytes at
// offset 257), with margin.
const detectProbeLen = 512

// tarMagicOffset and tarMagicLen locate the USTAR magic Go's tar writer
// emits at a fixed offset for every historical .lock file (plain USTAR,
// PAX and GNU output all carry it - PAX's extended-header block, written
// first by the existing code, is itself a USTAR-format block).
const (
	tarMagicOffset = 257
	tarMagicLen    = 5
)

var (
	zipLocalFileHeaderSignature = [4]byte{'P', 'K', 0x03, 0x04}
	tarMagic                    = [tarMagicLen]byte{'u', 's', 't', 'a', 'r'}
)

// detectFormat identifies the on-disk container format of src (size bytes
// long) from its content: it reads at most detectProbeLen bytes at offset
// 0 (one ReadAt, O(1), no seeking) and never returns io.ErrUnexpectedEOF -
// a file shorter than the signature it would need to match is simply
// classified as formatUnknown along with errUnknownLockFormat.
//
// Only the ZIP local-file-header signature (PK\x03\x04) counts as ZIP:
// PK\x05\x06 (empty archive) and PK\x07\x08 (spanning marker) are treated
// as unknown, since this package's own zip writer never produces them.
// Detection is strict: no fallback chain, no guessing.
func detectFormat(src io.ReaderAt, size int64) (containerFormat, error) {
	n := min(size, int64(detectProbeLen))
	if n <= 0 {
		return formatUnknown, errUnknownLockFormat
	}

	buf := make([]byte, n)
	read, err := src.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return formatUnknown, err
	}
	// A conforming io.ReaderAt may return fewer bytes than requested
	// together with io.EOF; classify strictly from what was actually
	// read; matching the doc comment above, never bytes that were merely
	// zero-allocated.
	buf = buf[:read]

	if len(buf) >= len(zipLocalFileHeaderSignature) &&
		[4]byte(buf[:4]) == zipLocalFileHeaderSignature {
		return formatZipContainer, nil
	}
	if len(buf) >= tarMagicOffset+tarMagicLen &&
		[tarMagicLen]byte(buf[tarMagicOffset:tarMagicOffset+tarMagicLen]) == tarMagic {
		return formatTarContainer, nil
	}
	return formatUnknown, errUnknownLockFormat
}
