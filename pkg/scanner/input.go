package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
)

// errNotRegular is returned for a deposited path that is not a regular file
// (a FIFO or a device put there after the stability check would block a worker
// forever).
var errNotRegular = errors.New("not a regular file")

// errSizeChanged is returned when a file holds more or less bytes than the
// size its identity recorded.
var errSizeChanged = errors.New("file size changed while it was read")

// descriptorPath returns the path that reads the file held by a descriptor, and
// whether it can be used. Replaced in tests.
var descriptorPath = descriptorPathOS

// openInputs counts the descriptors held on deposited files, to check that none
// is leaked.
var openInputs atomic.Int64

// inputFD is the descriptor opened on a deposited file when it was identified.
// It stays open until the last read of the content, so that everything the
// connector reads is the file whose identity was verified, whatever happens to
// its name meanwhile. Close is idempotent.
type inputFD struct {
	f    *os.File
	once sync.Once
	err  error
}

func newInputFD(f *os.File) *inputFD {
	openInputs.Add(1)
	return &inputFD{f: f}
}

// Close releases the descriptor; only the first call has an effect.
func (i *inputFD) Close() error {
	if i == nil {
		return nil
	}
	i.once.Do(func() {
		openInputs.Add(-1)
		i.err = i.f.Close()
	})
	return i.err
}

// reader reads the first size bytes of the file from its start, independently
// of any other reader of the same descriptor.
func (i *inputFD) reader(size int64) io.Reader {
	return io.NewSectionReader(i.f, 0, size)
}

// hashSection returns the SHA256 of the first size bytes of f. It fails with
// errSizeChanged if f holds more or less: an append in progress must not keep a
// worker reading.
func hashSection(f io.ReaderAt, size int64) (string, error) {
	hash := sha256.New()
	buf, ok := sha256BufferPool.Get().(*[]byte)
	if !ok {
		return "", errors.New("error with sha256 computing, could not get correct buffer type from pool")
	}
	defer sha256BufferPool.Put(buf)
	n, err := io.CopyBuffer(hash, io.NewSectionReader(f, 0, size+1), *buf)
	if err != nil {
		return "", err
	}
	if n != size {
		return "", fmt.Errorf("%w: %d bytes read, %d expected", errSizeChanged, n, size)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
