package quarantine

import (
	"archive/zip"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"log/slog"
	"math"
	"os"
	"sync"
	"time"

	"github.com/glimps-re/host-connector/internal/zipcrypto"
)

// zipLockIndexVersion is the only LockIndex.Version this package writes and
// accepts on read.
const zipLockIndexVersion = 1

// The reader accepts exactly what zipLocker writes, nothing else: the quarantine
// only reads back its own files, so every other variant (more entries,
// Deflate, unencrypted payload) is attack surface without use.
const (
	zipIndexName       = "index.json"
	zipEntryCount      = 2
	maxZipIndexSize    = 64 * 1024
	maxZipReasonLen    = 1024
	maxZipEntryNameLen = 255
)

var (
	errZipLayout           = errors.New("zip container must hold exactly the index and the payload entries")
	errZipIndexNotFound    = errors.New("zip index entry not found")
	errZipIndexEncrypted   = errors.New("zip index entry must not be encrypted")
	errZipMethod           = errors.New("zip entry must use the store method")
	errZipIndexTooLarge    = errors.New("zip index entry too large")
	errZipInvalidIndex     = errors.New("zip index has an invalid size, path or entry name")
	errZipUnknownVersion   = errors.New("unsupported zip lock index version")
	errZipPayloadNotFound  = errors.New("zip payload entry not found")
	errZipPayloadNotLocked = errors.New("zip payload entry is not marked encrypted")
	errZipEntryNameTooLong = errors.New("zip entry name too long")
	errZipPayloadTooSmall  = errors.New("zip payload entry too small to contain an encryption header")
	errZipSizeOutOfRange   = errors.New("zip entry declares a size out of the accepted range")
)

// LockIndex is the JSON document zipLocker stores in clear as the ZIP
// container's "index.json" entry. Field names are frozen: v1 readers must
// keep accepting them.
type LockIndex struct {
	Version  int    `json:"version"`  // 1
	Filepath string `json:"filepath"` // absolute original path
	Reason   string `json:"reason"`   // "malware: <family>"
	Mode     uint32 `json:"mode"`     // os.FileMode bits
	UID      int    `json:"uid"`      // always emitted: 0 is a valid owner
	GID      int    `json:"gid"`
	ModTime  int64  `json:"mtime"` // unix milliseconds; no atime (see LockedFile)
	Size     int64  `json:"size"`  // plaintext size, advisory
	Entry    string `json:"entry"` // payload entry name
}

// zipBufPool holds reusable 64 KiB buffers for streaming entry content
// to/from disk without allocating a fresh buffer per file. It stores
// *[]byte (not []byte): sync.Pool.Put boxes whatever is passed to it into
// an interface value, and boxing a slice header on every Put would itself
// allocate, defeating the point of pooling; boxing a pointer does not.
var zipBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64*1024)
		return &b
	},
}

// getZipBuf borrows a buffer from zipBufPool; putZipBuf must be called
// (typically via defer) to return it.
func getZipBuf() []byte {
	return *zipBufPool.Get().(*[]byte)
}

func putZipBuf(b []byte) {
	zipBufPool.Put(&b)
}

// zipLocker is the ZIP-based quarantine container: a cleartext "index.json"
// entry (this LockIndex, JSON-encoded) and a payload entry, named after the
// sanitised original basename, encrypted with traditional PKWARE
// encryption ("ZipCrypto", package internal/zipcrypto) so it opens in
// Windows Explorer, 7-Zip and other common archive tools using the
// quarantine password. ZipCrypto is cryptographically weak: with this format
// the quarantine password must be considered public.
type zipLocker struct {
	Password string
}

var _ fileLocker = &zipLocker{}

// LockFile writes a ZIP container for in (the plaintext content of file,
// described by info) to out, recording reason and file metadata in the
// cleartext index and encrypting the payload with the quarantine password.
func (l *zipLocker) LockFile(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) (err error) {
	entryName := sanitizeEntryName(file)

	index := LockIndex{
		Version:  zipLockIndexVersion,
		Filepath: file,
		Reason:   truncateBytes(reason, maxZipReasonLen),
		Mode:     uint32(info.Mode()),
		UID:      getUID(info),
		GID:      getGid(info),
		ModTime:  info.ModTime().UnixMilli(),
		Size:     info.Size(),
		Entry:    entryName,
	}
	idxBytes, err := json.Marshal(index)
	if err != nil {
		return err
	}
	if len(idxBytes) > maxZipIndexSize {
		return errZipIndexTooLarge
	}

	zw := zip.NewWriter(out)
	defer func() {
		if e := zw.Close(); e != nil {
			err = errors.Join(err, e)
		}
	}()

	// index.json: cleartext, tiny, sizes known up front - CreateRaw
	// bypasses compressors entirely and leaves CreatorVersion and
	// ReaderVersion at 0 unless set explicitly.
	ih := &zip.FileHeader{
		Name:               zipIndexName,
		Method:             zip.Store,
		Modified:           now(),
		CRC32:              crc32.ChecksumIEEE(idxBytes),
		CompressedSize64:   uint64(len(idxBytes)),
		UncompressedSize64: uint64(len(idxBytes)),
		CreatorVersion:     20,
		ReaderVersion:      20,
	}
	iw, err := zw.CreateRaw(ih)
	if err != nil {
		return err
	}
	if _, err = iw.Write(idxBytes); err != nil {
		return err
	}

	// payload: Store + ZipCrypto through a per-instance compressor.
	// Because index.json used CreateRaw above, this Store compressor is
	// only ever invoked for the payload.
	ph := &zip.FileHeader{
		Name:     entryName,
		Method:   zip.Store,
		Modified: info.ModTime(),
	}
	ph.SetMode(info.Mode().Perm())
	ph.Flags |= 0x1 // encrypted
	zw.RegisterCompressor(zip.Store, func(w io.Writer) (io.WriteCloser, error) {
		return zipcrypto.NewWriter(w, l.Password, func() byte { return dosTimeHighByte(ph.Modified) }), nil
	})
	pw, err := zw.CreateHeader(ph)
	if err != nil {
		return err
	}

	buf := getZipBuf()
	defer putZipBuf(buf)
	_, err = io.CopyBuffer(pw, in, buf)
	return err
}

// UnlockFile decrypts and verifies the payload of the ZIP container read
// from src, streaming the plaintext to out. See the fileLocker interface
// documentation for the "unauthenticated until a clean nil return" contract
// this method upholds via internal/zipcrypto's Reader.
func (l *zipLocker) UnlockFile(src io.ReaderAt, size int64, out io.Writer) (locked LockedFile, err error) {
	idx, zr, err := readZipIndex(src, size)
	if err != nil {
		return LockedFile{}, err
	}

	f := zr.File[1]

	rawPayloadSize, err := safeInt64(f.CompressedSize64)
	if err != nil {
		return LockedFile{}, err
	}
	plainSize, err := safeInt64(f.UncompressedSize64)
	if err != nil {
		return LockedFile{}, err
	}
	rc, err := f.OpenRaw()
	if err != nil {
		return LockedFile{}, err
	}

	plain, err := zipcrypto.NewReader(rc, rawPayloadSize, l.Password, zipcrypto.ReaderOptions{
		CheckByte:    zipPayloadCheckByte(f),
		ExpectedCRC:  f.CRC32,
		ExpectedSize: plainSize,
	})
	if err != nil {
		return LockedFile{}, err
	}

	buf := getZipBuf()
	defer putZipBuf(buf)
	if _, err = io.CopyBuffer(out, plain, buf); err != nil {
		return LockedFile{}, err
	}

	return lockIndexToLockedFile(idx), nil
}

// GetHeader reads only the cleartext index of the ZIP container read from
// src, without touching the encrypted payload.
func (l *zipLocker) GetHeader(src io.ReaderAt, size int64) (LockEntry, error) {
	idx, _, err := readZipIndex(src, size)
	if err != nil {
		return LockEntry{}, err
	}
	return LockEntry{Filepath: idx.Filepath, Reason: idx.Reason}, nil
}

// lockIndexToLockedFile converts a decoded LockIndex into the LockedFile
// the fileLocker interface returns. idx.Mode is narrowed via .Perm(), which
// - regardless of the preceding mask - keeps only the low 9 permission
// bits: setuid/setgid/sticky bits from an attacker-forgeable cleartext
// index are never restored, matching restore_linux.go/restore_windows.go's
// treatment of ownership as best-effort, never security-relevant. idx.UID,
// idx.GID and idx.ModTime (unauthenticated cleartext metadata) are trusted
// no more than the tar format already trusts its own header fields (the
// index is cleartext by design).
func lockIndexToLockedFile(idx LockIndex) LockedFile {
	return LockedFile{
		Filepath: idx.Filepath,
		Reason:   idx.Reason,
		Mode:     os.FileMode(idx.Mode).Perm(),
		UID:      idx.UID,
		GID:      idx.GID,
		ModTime:  time.UnixMilli(idx.ModTime),
		Size:     idx.Size,
	}
}

// readZipIndex opens src as a ZIP container, checks its layout (the cleartext
// index entry first, then the payload entry, nothing else), decodes the index
// and checks the payload entry against it.
func readZipIndex(src io.ReaderAt, size int64) (LockIndex, *zip.Reader, error) {
	if err := checkZipEOCD(src, size); err != nil {
		return LockIndex{}, nil, err
	}
	zr, err := zip.NewReader(src, size)
	if err != nil {
		return LockIndex{}, nil, err
	}
	if len(zr.File) != zipEntryCount {
		return LockIndex{}, nil, errZipLayout
	}

	f := zr.File[0]
	if f.Name != zipIndexName {
		return LockIndex{}, nil, errZipIndexNotFound
	}
	if f.Flags&0x1 != 0 {
		return LockIndex{}, nil, errZipIndexEncrypted
	}
	if f.Method != zip.Store {
		return LockIndex{}, nil, errZipMethod
	}
	if f.UncompressedSize64 > maxZipIndexSize {
		return LockIndex{}, nil, errZipIndexTooLarge
	}
	if f.CompressedSize64 != f.UncompressedSize64 {
		return LockIndex{}, nil, errZipSizeOutOfRange
	}

	rc, err := f.Open()
	if err != nil {
		return LockIndex{}, nil, err
	}
	defer func() {
		if e := rc.Close(); e != nil {
			logger.Error("readZipIndex cannot close index entry", slog.String("error", e.Error()))
		}
	}()

	var idx LockIndex
	if err := json.NewDecoder(io.LimitReader(rc, maxZipIndexSize+1)).Decode(&idx); err != nil {
		return LockIndex{}, nil, err
	}
	if idx.Version != zipLockIndexVersion {
		return LockIndex{}, nil, errZipUnknownVersion
	}
	if idx.Size < 0 || idx.Filepath == "" || idx.Entry == "" {
		return LockIndex{}, nil, errZipInvalidIndex
	}
	if err := checkPayloadEntry(zr.File[1], idx.Entry); err != nil {
		return LockIndex{}, nil, err
	}
	return idx, zr, nil
}

// checkPayloadEntry refuses a payload entry that is not what zipLocker
// writes, so listing and restoring reject the same containers.
func checkPayloadEntry(f *zip.File, wantName string) error {
	if wantName == "" || f.Name != wantName {
		return errZipPayloadNotFound
	}
	if len(f.Name) > maxZipEntryNameLen {
		return errZipEntryNameTooLong
	}
	if f.Method != zip.Store {
		return errZipMethod
	}
	if f.Flags&0x1 == 0 {
		return errZipPayloadNotLocked
	}
	if f.CompressedSize64 < zipcrypto.HeaderSize {
		return errZipPayloadTooSmall
	}
	if f.Flags&0x8 == 0 {
		return errZipLayout
	}
	if f.CompressedSize64-zipcrypto.HeaderSize != f.UncompressedSize64 {
		return errZipSizeOutOfRange
	}
	return nil
}

// checkZipEOCD reads the end of central directory record, which must be the
// last 22 bytes of the file (no comment) and announce exactly zipEntryCount
// entries; when the ZIP64 markers are set, the ZIP64 record must announce the
// same count, since that is the one zip.NewReader then trusts. It runs before
// zip.NewReader, which sizes its allocations from that count.
func checkZipEOCD(src io.ReaderAt, size int64) error {
	const (
		eocdLen     = 22
		locatorLen  = 20
		zip64RecLen = 56
		zip64Marker = 0xffffffff
		eocdSig     = 0x06054b50
		locatorSig  = 0x07064b50
		zip64RecSig = 0x06064b50
	)
	if size < eocdLen {
		return errZipLayout
	}
	var eocd [eocdLen]byte
	if n, err := src.ReadAt(eocd[:], size-eocdLen); n != eocdLen && err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(eocd[0:4]) != eocdSig ||
		binary.LittleEndian.Uint16(eocd[8:10]) != zipEntryCount ||
		binary.LittleEndian.Uint16(eocd[10:12]) != zipEntryCount ||
		binary.LittleEndian.Uint16(eocd[20:22]) != 0 {
		return errZipLayout
	}
	if binary.LittleEndian.Uint32(eocd[12:16]) != zip64Marker && binary.LittleEndian.Uint32(eocd[16:20]) != zip64Marker {
		return nil
	}

	if size < eocdLen+locatorLen {
		return errZipLayout
	}
	var locator [locatorLen]byte
	if n, err := src.ReadAt(locator[:], size-eocdLen-locatorLen); n != locatorLen && err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(locator[0:4]) != locatorSig {
		return errZipLayout
	}
	rawOff := binary.LittleEndian.Uint64(locator[8:16])
	off := int64(rawOff & math.MaxInt64)
	if rawOff > math.MaxInt64 || off > size-eocdLen-locatorLen-zip64RecLen {
		return errZipLayout
	}
	var rec [zip64RecLen]byte
	if n, err := src.ReadAt(rec[:], off); n != zip64RecLen && err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(rec[0:4]) != zip64RecSig ||
		binary.LittleEndian.Uint64(rec[24:32]) != zipEntryCount ||
		binary.LittleEndian.Uint64(rec[32:40]) != zipEntryCount {
		return errZipLayout
	}
	return nil
}

// zipPayloadCheckByte returns the byte the payload's encryption header's
// check byte must match, per APPNOTE.TXT §6.1.6: the DOS-time high byte if
// the entry carries a trailing data descriptor (bit 3 set - always true for
// entries this package's own writer produces, since the stdlib zip.Writer
// always sets it), otherwise the CRC-32 high byte.
func zipPayloadCheckByte(f *zip.File) byte {
	if f.Flags&0x8 != 0 {
		return byte(f.ModifiedTime >> 8)
	}
	return byte(f.CRC32 >> 24)
}

// safeInt64 converts an untrusted uint64 (a ZIP entry's declared size) to
// int64, rejecting values that would overflow rather than silently
// wrapping to a negative number. The bound is deliberately far below
// math.MaxInt64 (which would itself be safe to convert): no legitimate
// quarantined file is ever this large, and rejecting early avoids handing
// an implausible size to any downstream arithmetic.
func safeInt64(u uint64) (int64, error) {
	const maxAccepted = 1 << 48 // 256 TiB
	if u > maxAccepted {
		return 0, errZipSizeOutOfRange
	}
	return int64(u), nil
}

// dosTimeHighByte returns the high byte of the DOS time zip.Writer derives
// from modified as is (no UTC conversion), which the encryption header check
// byte must carry (APPNOTE.TXT 6.1.6). FileHeader.ModifiedTime holds the same
// value but is deprecated.
func dosTimeHighByte(modified time.Time) byte {
	return byte((modified.Hour()<<3 | modified.Minute()>>3) & 0xff)
}
