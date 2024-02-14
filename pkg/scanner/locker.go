package scanner

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

type Locker interface {
	LockFile(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error
	UnlockFile(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error)
	GetHeader(in io.Reader) (entry LockEntry, err error)
}

type Lock struct {
	Password string
}

var LockPasswordIter = 4096

type LockEntry struct {
	Filepath string
	Reason   string
}

var _ Locker = &Lock{}

func (l *Lock) LockFile(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error {
	gzw := gzip.NewWriter(out)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	// add index entry
	entry := LockEntry{
		Filepath: file,
		Reason:   reason,
	}
	var buffer bytes.Buffer
	err := json.NewEncoder(&buffer).Encode(entry)
	if err != nil {
		return err
	}

	indexHeader := tar.Header{
		Name:       "index",
		Size:       int64(len(buffer.Bytes())),
		ChangeTime: Now(),
		AccessTime: Now(),
	}
	if err = tw.WriteHeader(&indexHeader); err != nil {
		return err
	}

	if _, err = tw.Write(buffer.Bytes()); err != nil {
		return err
	}

	// add encrypted file
	entryHeader := tar.Header{
		Name:    "file",
		Size:    info.Size() + 48, // 48 == len(salt) + len(iv)
		Mode:    int64(info.Mode()),
		ModTime: info.ModTime(),
	}
	entryHeader.Uid = getUid(info)
	entryHeader.Gid = getGid(info)

	if err = tw.WriteHeader(&entryHeader); err != nil {
		return err
	}
	if err = cipherFile(l.Password, in, tw); err != nil {
		return err
	}
	return nil
}

func (l *Lock) UnlockFile(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error) {
	gr, err := gzip.NewReader(in)
	if err != nil {
		return
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	var entry LockEntry
	indexFound := false
	fileFound := false
	for {
		var hdr *tar.Header
		hdr, err = tr.Next()
		if err == io.EOF {
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
			info = &LockFileInfo{hdr.FileInfo()}
			fileFound = true
		}
	}
	if !indexFound {
		err = ErrIndexNotFound
		return
	}

	if !fileFound {
		err = ErrFileNotFound
		return
	}
	reason = entry.Reason
	file = entry.Filepath
	return
}

func (l *Lock) GetHeader(in io.Reader) (entry LockEntry, err error) {
	gr, err := gzip.NewReader(in)
	if err != nil {
		return
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		var hdr *tar.Header
		hdr, err = tr.Next()
		if err == io.EOF {
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
			return
		}
	}
	err = ErrIndexNotFound
	return
}

type LockFileInfo struct {
	fs.FileInfo
}

func (lfi *LockFileInfo) Size() int64 {
	return lfi.FileInfo.Size() - 48
}

var (
	ErrIndexNotFound = errors.New("index part not found")
	ErrFileNotFound  = errors.New("file part not found")
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
	wstream := &cipher.StreamWriter{S: cipher.NewOFB(block, iv), W: out}
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
	rstream := &cipher.StreamReader{S: cipher.NewOFB(block, iv), R: in}
	_, err = io.Copy(out, rstream)
	return
}
