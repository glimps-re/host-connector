package quarantine

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

// tarLocker is the original quarantine container format: a tar archive with
// a cleartext "index" entry (JSON LockEntry) and a "file" entry encrypted
// with AES-128-CTR (PBKDF2-SHA256, lockPasswordIter iterations). It is kept
// byte-for-byte compatible with every file produced by GMHost <= v1.5.3 (see
// testdata/legacy_v1.5.3.lock).
type tarLocker struct {
	Password string
}

const lockPasswordIter = 4096

var _ fileLocker = &tarLocker{}

// tarPayloadOverhead is the number of extra bytes (32-byte salt + 16-byte
// IV) prepended to the plaintext payload by cipherFile.
const tarPayloadOverhead = 48

// maxTarIndexSize bounds how much of the "index" tar entry is fed to the
// JSON decoder. The index is a couple of short strings and ints in
// practice; without this cap, a crafted/tampered .lock file declaring a
// huge "index" entry size would cause an allocation proportional to that
// declared size on every GetHeader/UnlockFile call - including the routine
// per-file GetHeader done by ListQuarantinedFiles.
const maxTarIndexSize = 64 * 1024

var (
	errIndexNotFound      = errors.New("index part not found")
	errFileNotFound       = errors.New("file part not found")
	errTarUnexpectedEntry = errors.New("tar container must hold exactly a regular index entry then a regular file entry")
)

func (l *tarLocker) LockFile(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) (err error) {
	tw := tar.NewWriter(out)
	defer func() {
		if e := tw.Close(); e != nil {
			logger.Error("LockFile cannot close tar writer", slog.String("error", e.Error()))
			err = errors.Join(err, e)
			return
		}
	}()

	// add index entry
	entry := LockEntry{
		Filepath: file,
		Reason:   reason,
	}
	var buffer bytes.Buffer
	err = json.NewEncoder(&buffer).Encode(entry)
	if err != nil {
		return
	}

	indexHeader := tar.Header{
		Name:       "index",
		Size:       int64(len(buffer.Bytes())),
		ChangeTime: now(),
		AccessTime: now(),
	}
	if err = tw.WriteHeader(&indexHeader); err != nil {
		return
	}

	if _, err = tw.Write(buffer.Bytes()); err != nil {
		return
	}

	// add encrypted file
	entryHeader := tar.Header{
		Name:    "file",
		Size:    info.Size() + tarPayloadOverhead,
		Mode:    int64(info.Mode()),
		ModTime: info.ModTime(),
	}
	entryHeader.Uid = getUID(info)
	entryHeader.Gid = getGid(info)

	if err = tw.WriteHeader(&entryHeader); err != nil {
		return
	}
	if err = cipherFile(l.Password, in, tw); err != nil {
		return
	}
	return
}

// UnlockFile accepts only what LockFile writes: the "index" entry, then the
// "file" entry, both regular, and nothing else.
func (l *tarLocker) UnlockFile(src io.ReaderAt, size int64, out io.Writer) (locked LockedFile, err error) {
	tr := tar.NewReader(io.NewSectionReader(src, 0, size))
	entry, err := readTarIndex(tr)
	if err != nil {
		return
	}
	hdr, err := nextTarEntry(tr, "file", errFileNotFound)
	if err != nil {
		return
	}
	if err = decipherFile(l.Password, tr, out); err != nil {
		return
	}
	if _, err = tr.Next(); !errors.Is(err, io.EOF) {
		err = errTarUnexpectedEntry
		return
	}
	err = nil
	// hdr.Mode is read from an untrusted tar header: mask to the low 12 bits
	// before the narrowing conversion so a crafted huge/negative value can
	// never be misread as an overflowed mode.
	locked.Mode = os.FileMode(uint32(hdr.Mode & 0o7777)).Perm()
	locked.UID = hdr.Uid
	locked.GID = hdr.Gid
	locked.ModTime = hdr.ModTime
	// hdr.Size is untrusted: a header declaring less than the fixed overhead
	// would otherwise give a negative size.
	if hdr.Size >= tarPayloadOverhead {
		locked.Size = hdr.Size - tarPayloadOverhead
	}
	locked.LockEntry = entry
	return
}

func (l *tarLocker) GetHeader(src io.ReaderAt, size int64) (LockEntry, error) {
	return readTarIndex(tar.NewReader(io.NewSectionReader(src, 0, size)))
}

func readTarIndex(tr *tar.Reader) (entry LockEntry, err error) {
	if _, err = nextTarEntry(tr, "index", errIndexNotFound); err != nil {
		return
	}
	err = json.NewDecoder(io.LimitReader(tr, maxTarIndexSize+1)).Decode(&entry)
	return
}

// nextTarEntry advances to the next entry, which must be the regular file name.
func nextTarEntry(tr *tar.Reader, name string, errMissing error) (*tar.Header, error) {
	hdr, err := tr.Next()
	if errors.Is(err, io.EOF) {
		return nil, errMissing
	}
	if err != nil {
		return nil, err
	}
	if hdr.Name != name || hdr.Typeflag != tar.TypeReg {
		return nil, errTarUnexpectedEntry
	}
	return hdr, nil
}

func cipherFile(password string, in io.Reader, out io.Writer) (err error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := pbkdf2.Key([]byte(password), salt, lockPasswordIter, aes.BlockSize, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return err
	}

	if _, err = out.Write(salt); err != nil {
		return err
	}
	if _, err = out.Write(iv); err != nil {
		return err
	}
	wstream := &cipher.StreamWriter{S: cipher.NewCTR(block, iv), W: out}
	defer func() {
		if e := wstream.Close(); e != nil {
			logger.Error("error closing cipher locker", slog.String("error", e.Error()))
			err = errors.Join(e, err)
		}
	}()
	_, err = io.Copy(wstream, in)
	return
}

func decipherFile(password string, in io.Reader, out io.Writer) (err error) {
	salt := make([]byte, 32)
	// use io.ReadFull to ensure all salt is read (for example, io.Reader.Read may return fewer bytes than requested
	// without error, which would silently corrupt cryptographic material)
	if _, err = io.ReadFull(in, salt); err != nil {
		return
	}
	iv := make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(in, iv); err != nil {
		return
	}
	key := pbkdf2.Key([]byte(password), salt, lockPasswordIter, aes.BlockSize, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	rstream := &cipher.StreamReader{S: cipher.NewCTR(block, iv), R: in}
	_, err = io.Copy(out, rstream)
	return
}
