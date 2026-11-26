package quarantine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	// ErrContentChanged is returned when the bytes copied do not hash to the
	// SHA256 that was analyzed: the source changed between the analysis and the
	// copy. Nothing is published.
	ErrContentChanged = errors.New("copied content does not match the analyzed content")
	// ErrNoExpectedHash is returned when the SHA256 to check the copy against is
	// missing or malformed: a copy that cannot be verified is never published.
	ErrNoExpectedHash = errors.New("no valid SHA256 to verify the copy against")
)

// copyBlockSize is the size of the blocks of a verified copy: a fixed buffer,
// whatever the size of the file.
const copyBlockSize = 128 << 10

var copyBlocks = sync.Pool{New: func() any {
	b := make([]byte, copyBlockSize)
	return &b
}}

// Replaced in tests: a hook run after every block (a writer that rewrites the
// source, a cancellation) and a wrapper of the writer of the copy (a full disk).
var (
	afterCopyBlock = func(copied int64) {}
	wrapCopyWriter = func(w io.Writer) io.Writer { return w }
)

// CopyVerified copies src into a new file dst, never replaced, and fails with
// ErrContentChanged when the copied bytes do not hash to wantSHA256: what
// reaches dst is exactly what was analyzed, whatever the writer of src does
// afterwards. src is read from its start, neither closed nor removed. The copy
// is made under stagingDir, which must be on the file system of dst. It returns
// ErrDestinationExists when dst exists, and ErrNoExpectedHash when wantSHA256
// is empty or not a SHA256.
func CopyVerified(ctx context.Context, src *os.File, dst, stagingDir, wantSHA256 string) error {
	_, err := copyVerified(ctx, src, dst, stagingDir, wantSHA256, func(int) (string, bool) { return "", false }, nil)
	return err
}

// MoveVerifiedCopy is CopyVerified followed by remove, which removes the name
// the source was found under; when dst exists the copy, made once, takes a
// ConflictName next to it (up to maxConflicts names) and its path is returned.
// A name that no longer holds the source (changed, replaced, gone) is left alone
// and the copy stays: it is the analyzed content. Any other failure of remove
// takes the copy back, so the file is never in two places, and is marked with
// ErrSourceNotRemovable. A nil remove removes nothing.
func MoveVerifiedCopy(ctx context.Context, src *os.File, remove func() error, dst, stagingDir, wantSHA256 string, now func() time.Time, maxConflicts int) (string, error) {
	return copyVerified(ctx, src, dst, stagingDir, wantSHA256, conflictNames(dst, now, maxConflicts), remove)
}

// MoveEmpty creates dst as a new empty file with the permission bits of perm
// (without write for others), under a ConflictName when dst exists, then removes
// the source with remove as MoveVerifiedCopy does; label names the source in
// messages. An empty file has no content to verify, and nothing is linked or
// renamed from the source.
func MoveEmpty(remove func() error, label string, perm os.FileMode, dst string, now func() time.Time, maxConflicts int) (string, error) {
	return runPublication(&emptyFile{perm: perm, remove: remove, label: label}, dst, conflictNames(dst, now, maxConflicts))
}

// emptyFile publishes a new empty file: no inode of the source is involved.
type emptyFile struct {
	perm   os.FileMode
	remove func() error
	label  string
}

func (e *emptyFile) publish(target string) error {
	f, err := os.OpenFile(filepath.Clean(target), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%w: %s", ErrDestinationExists, target)
	}
	if err != nil {
		return err
	}
	// On the descriptor, so that the umask does not decide.
	err = f.Chmod(e.perm & copiedMode)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return rollback(target, err)
	}
	return nil
}

// finish makes the new empty file durable, then removes the source. A source that
// is no longer the empty file it was (it was written to meanwhile) is left alone,
// and so the empty copy is taken back: it would stand for a file that has content.
func (e *emptyFile) finish(target string) error {
	if err := syncDir(filepath.Dir(target)); err != nil {
		return rollback(target, fmt.Errorf("could not make %s durable: %w", target, err))
	}
	if e.remove == nil {
		return nil
	}
	removed, err := removeNamed(target, e.label, e.remove)
	if err == nil && !removed {
		return rollback(target, fmt.Errorf("%w: %s is no longer the empty file that was moved", ErrSourceChanged, e.label))
	}
	return err
}

func (*emptyFile) cleanup() {}

func copyVerified(ctx context.Context, src *os.File, dst, stagingDir, wantSHA256 string, next func(attempt int) (string, bool), remove func() error) (string, error) {
	want, err := parseSHA256(wantSHA256)
	if err != nil {
		return "", err
	}
	staged, _, err := stageVerified(ctx, src, stagingDir, want)
	if err != nil {
		return "", err
	}
	return runPublication(&stagedCopy{staged: staged, remove: remove, label: src.Name()}, dst, next)
}

// stagedCopy publishes a private, verified copy: the inode of the source is
// never involved.
type stagedCopy struct {
	staged string
	remove func() error
	label  string
}

func (c *stagedCopy) publish(target string) error {
	_, err := publishNoReplace(c.staged, target)
	return err
}

func (c *stagedCopy) finish(target string) error { return finishCopy(target, c.label, c.remove) }

func (c *stagedCopy) cleanup() { removeStaged(c.staged) }

// finishCopy makes the new name of a copy durable, then removes the source: a
// crash between the two must not keep the removal and lose the new name. A
// directory that cannot be synced takes the copy back and keeps the source.
func finishCopy(target, label string, remove func() error) error {
	if err := syncDir(filepath.Dir(target)); err != nil {
		return rollback(target, fmt.Errorf("could not make %s durable: %w", target, err))
	}
	if remove == nil {
		return nil
	}
	_, err := removeNamed(target, label, remove)
	return err
}

func parseSHA256(s string) ([]byte, error) {
	if len(s) != sha256.Size*2 {
		return nil, fmt.Errorf("%w: %q", ErrNoExpectedHash, s)
	}
	b, err := hex.DecodeString(strings.ToLower(s))
	if err != nil {
		return nil, fmt.Errorf("%w: %q", ErrNoExpectedHash, s)
	}
	return b, nil
}

// stageVerified copies src into a new private file of stagingDir, hashing what
// it writes, and returns its path once the copy has the wanted hash. On any
// failure nothing is left behind.
func stageVerified(ctx context.Context, src *os.File, stagingDir string, want []byte) (string, fs.FileInfo, error) {
	return stagePrivate(src, src.Name(), stagingDir, func(out *os.File, info fs.FileInfo) error {
		sum, n, err := copyHashing(ctx, out, src, info.Size())
		if err != nil {
			return err
		}
		if n != info.Size() {
			return fmt.Errorf("%w: %d bytes read, %d expected", ErrContentChanged, n, info.Size())
		}
		if !bytes.Equal(sum, want) {
			return fmt.Errorf("%w: the copy hashes to %s, want %s", ErrContentChanged, hex.EncodeToString(sum), hex.EncodeToString(want))
		}
		return nil
	}, nil)
}

// copyHashing copies the first size bytes of src, read from the start by
// position (the offset of src is not used and not changed), plus one byte to
// notice a file that grew, and returns their hash and the number of bytes read
// up to size.
func copyHashing(ctx context.Context, dst io.Writer, src io.ReaderAt, size int64) (sum []byte, n int64, err error) {
	buf, ok := copyBlocks.Get().(*[]byte)
	if !ok {
		return nil, 0, errors.New("could not get a copy buffer from the pool")
	}
	defer copyBlocks.Put(buf)
	h := sha256.New()
	w := wrapCopyWriter(dst)
	var off int64
	for {
		if err = ctx.Err(); err != nil {
			return nil, off, err
		}
		toRead := int64(len(*buf))
		if off+toRead > size+1 {
			toRead = size + 1 - off
		}
		if toRead <= 0 {
			break
		}
		read, rerr := src.ReadAt((*buf)[:toRead], off)
		if read > 0 {
			chunk := (*buf)[:read]
			if off+int64(read) > size {
				// More than the size observed: the file grew. Only the observed
				// size is copied; the extra byte tells the caller.
				chunk = chunk[:max(size-off, 0)]
				off += int64(read)
				if _, werr := w.Write(chunk); werr != nil {
					return nil, off, werr
				}
				h.Write(chunk)
				return h.Sum(nil), off, nil
			}
			if _, werr := w.Write(chunk); werr != nil {
				return nil, off, werr
			}
			h.Write(chunk)
			off += int64(read)
			afterCopyBlock(off)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			return nil, off, rerr
		}
	}
	return h.Sum(nil), off, nil
}
