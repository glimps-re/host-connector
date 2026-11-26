package quarantine

import (
	"fmt"
	"io"
	"os"
)

// lockerRouter dispatches LockFile to a single configured write locker, and
// GetHeader/UnlockFile to whichever reader matches the container's detected
// format - independent of the configured write format, so every existing
// .lock stays restorable and both formats can coexist in one quarantine
// directory forever (see detectFormat).
type lockerRouter struct {
	write   fileLocker
	readers map[containerFormat]fileLocker
}

var _ fileLocker = &lockerRouter{}

// newLockerRouter builds a router whose readers always cover both known
// container formats, regardless of which one write is.
func newLockerRouter(write fileLocker, tarReader, zipReader fileLocker) *lockerRouter {
	return &lockerRouter{
		write: write,
		readers: map[containerFormat]fileLocker{
			formatTarContainer: tarReader,
			formatZipContainer: zipReader,
		},
	}
}

// LockFile always uses the router's single configured write locker.
func (r *lockerRouter) LockFile(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error {
	return r.write.LockFile(file, in, info, reason, out)
}

// reader detects src's container format and returns the matching reader,
// or errUnknownLockFormat if it matches neither known format.
func (r *lockerRouter) reader(src io.ReaderAt, size int64) (fileLocker, error) {
	format, err := detectFormat(src, size)
	if err != nil {
		return nil, err
	}
	l, ok := r.readers[format]
	if !ok || l == nil {
		return nil, fmt.Errorf("%w: no reader registered for detected format", errUnknownLockFormat)
	}
	return l, nil
}

// UnlockFile detects src's container format and dispatches to the matching
// reader.
func (r *lockerRouter) UnlockFile(src io.ReaderAt, size int64, out io.Writer) (LockedFile, error) {
	l, err := r.reader(src, size)
	if err != nil {
		return LockedFile{}, err
	}
	return l.UnlockFile(src, size, out)
}

// GetHeader detects src's container format and dispatches to the matching
// reader.
func (r *lockerRouter) GetHeader(src io.ReaderAt, size int64) (LockEntry, error) {
	l, err := r.reader(src, size)
	if err != nil {
		return LockEntry{}, err
	}
	return l.GetHeader(src, size)
}
