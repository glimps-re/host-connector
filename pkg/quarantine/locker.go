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
	"io/fs"
	"log/slog"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

type fileLocker interface {
	LockFile(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error
	UnlockFile(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error)
	GetHeader(in io.Reader) (entry LockEntry, err error)
}

type fileLock struct {
	Password string
}

const LockPasswordIter = 4096

type LockEntry struct {
	Filepath string
	Reason   string
}

var _ fileLocker = &fileLock{}

func (l *fileLock) LockFile(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) (err error) {
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
		ChangeTime: Now(),
		AccessTime: Now(),
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
		Size:    info.Size() + 48, // 48 == len(salt) + len(iv)
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

func (l *fileLock) UnlockFile(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error) {
	tr := tar.NewReader(in)
	var entry LockEntry
	indexFound := false
	fileFound := false
	for {
		var hdr *tar.Header
		hdr, err = tr.Next()
		if errors.Is(err, io.EOF) {
			err = nil
			break // End of archive
		}
		if err != nil {
			return
		}
		if hdr.Name == "index" {
			if err = json.NewDecoder(tr).Decode(&entry); err != nil {
				return
			}
			indexFound = true
		}
		if hdr.Name == "file" {
			if err = decipherFile(l.Password, tr, out); err != nil {
				return
			}
			info = &lockedFileInfo{hdr.FileInfo()}
			fileFound = true
		}
	}
	if !indexFound {
		err = errIndexNotFound
		return
	}

	if !fileFound {
		err = errFileNotFound
		return
	}
	reason = entry.Reason
	file = entry.Filepath
	return
}

func (l *fileLock) GetHeader(in io.Reader) (entry LockEntry, err error) {
	tr := tar.NewReader(in)
	for {
		var hdr *tar.Header
		hdr, err = tr.Next()
		if errors.Is(err, io.EOF) {
			break // End of archive
		}
		if err != nil {
			return
		}
		if hdr.Name == "index" {
			if err = json.NewDecoder(tr).Decode(&entry); err != nil {
				return
			}
			return
		}
	}
	err = errIndexNotFound
	return
}

type lockedFileInfo struct {
	fs.FileInfo
}

func (lfi *lockedFileInfo) Size() int64 {
	return lfi.FileInfo.Size() - 48
}

var (
	errIndexNotFound = errors.New("index part not found")
	errFileNotFound  = errors.New("file part not found")
)

func cipherFile(password string, in io.Reader, out io.Writer) (err error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := pbkdf2.Key([]byte(password), salt, LockPasswordIter, aes.BlockSize, sha256.New)
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
	if _, err = in.Read(salt); err != nil {
		return
	}
	iv := make([]byte, aes.BlockSize)
	if _, err = in.Read(iv); err != nil {
		return
	}
	key := pbkdf2.Key([]byte(password), salt, LockPasswordIter, aes.BlockSize, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	rstream := &cipher.StreamReader{S: cipher.NewCTR(block, iv), R: in}
	_, err = io.Copy(out, rstream)
	return
}
