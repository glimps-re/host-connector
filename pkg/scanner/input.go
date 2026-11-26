package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/glimps-re/host-connector/internal/safepath"
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
	f *os.File
	// sf is the file opened below its root without following any link, of which
	// f is the descriptor: the one handle the pipeline and the actions share.
	sf *safepath.File
	// root is the monitored root the file was opened below.
	root string
	// viaLink is set when the file was reached through a symbolic link, which
	// the configuration told to follow: no handle then, and the actions that
	// remove or move it refuse.
	viaLink bool
	once    sync.Once
	err     error
}

func newInputFD(f *os.File) *inputFD {
	openInputs.Add(1)
	return &inputFD{f: f}
}

// Close releases the descriptor (and the handle of its folder); only the first
// call has an effect.
func (i *inputFD) Close() error {
	if i == nil {
		return nil
	}
	i.once.Do(func() {
		openInputs.Add(-1)
		if i.sf != nil {
			i.err = i.sf.Close()
			return
		}
		i.err = i.f.Close()
	})
	return i.err
}

// openInput opens the deposited file at location, once: below its monitored
// root, without following any link and without ever blocking on it. With
// follow_symlinks a path that crosses a link is opened as the operator asked,
// and the descriptor then carries that fact (viaLink).
func (c *Connector) openInput(location string) (*inputFD, error) {
	abs, err := filepath.Abs(location)
	if err != nil {
		return nil, err
	}
	root := c.rootFor(abs)
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return nil, err
	}
	if rel == "." {
		// The scan was started on the file itself: its folder is the root.
		root, rel = filepath.Dir(abs), filepath.Base(abs)
	}
	sf, err := safepath.Open(root, rel)
	switch {
	case err == nil:
		openInputs.Add(1)
		return &inputFD{f: sf.OS(), sf: sf, root: root}, nil
	case c.config.FollowSymlinks && errors.Is(err, safepath.ErrSymlink):
		f, openErr := openRegular(location, true)
		if openErr != nil {
			return nil, openErr
		}
		in := newInputFD(f)
		in.root, in.viaLink = root, true
		return in, nil
	case errors.Is(err, safepath.ErrNotRegular):
		return nil, fmt.Errorf("%w: %s", errNotRegular, location)
	}
	return nil, err
}

// source is the Source of the file this descriptor holds, for the actions. The
// handle is given where the pipeline keeps it open during the actions.
func (i *inputFD) source(path string, id FileIdentity, sha256 string) Source {
	if i == nil {
		return Source{Path: path, Identity: id, SHA256: sha256}
	}
	src := Source{Path: path, Root: i.root, Identity: id, SHA256: sha256, viaLink: i.viaLink}
	if holdsHandle {
		src.handle = i.sf
		if i.viaLink {
			src.fd = i.f
		}
	}
	return src
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
