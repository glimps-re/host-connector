package quarantine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/glimps-re/host-connector/pkg/config"
)

type Quarantiner interface {
	// Quarantine stores the content read from in. file is the original
	// location, recorded in the registry and in the container; it is never
	// opened. in is positioned at its start, stays owned by the caller and is
	// not closed. The source file is not deleted.
	Quarantine(ctx context.Context, file string, in *os.File, fileSHA256 string, malwares []string) (quarantineLocation string, entryID string, err error)
	Restore(ctx context.Context, entryID string) (err error)
	Reconfigure(ctx context.Context, newConfig Config) (err error)
	// IsRestored reports whether the file at location holding this content was
	// restored from quarantine. A release is per file: the same content at another
	// location, or another content at this location, is not restored.
	IsRestored(ctx context.Context, location string, sha256 string) (restored bool, err error)
	ListQuarantinedFiles(ctx context.Context) iter.Seq2[*QuarantinedFile, error]
	Close() (err error)
}

const sha256Len = 64

// ErrRestored is returned by Quarantine for a file that was restored (same
// location, same content): nothing is written, and asking again gives the same
// answer.
var ErrRestored = errors.New("this file was restored from quarantine")

// TempPrefix starts the name of every temporary file this package creates
// next to user files; the scanner and the monitor ignore names with this
// prefix (see IsTempFile), so a file being restored is never picked up.
const TempPrefix = ".gmhost-tmp-"

// IsTempFile reports whether path names a temporary file of this package.
func IsTempFile(path string) bool {
	return strings.HasPrefix(filepath.Base(path), TempPrefix)
}

type Config struct {
	Location         string
	RegistryLocation string
	LockPassword     string
	// Format is the container written for new quarantined files; the empty
	// value means FormatTar. Existing files are restored whatever its value.
	Format Format
	// WatchedPaths are the monitored paths: Restore refuses a destination
	// whose path crosses a symbolic link below the one that contains it.
	WatchedPaths []string
}

// QuarantineHandler implements Quarantiner over a single quarantine
// directory and registry.
//
// locker and location are guarded by mu: Quarantine,
// Restore and ListQuarantinedFiles take a read snapshot; Reconfigure swaps
// them under the write lock. restoreLocks additionally serialises concurrent
// Restore calls for the same id so two callers cannot race on the same
// temp file / rename / registry update.
type QuarantineHandler struct {
	mu       sync.RWMutex
	locker   fileLocker
	registry quarantineRegistry
	location string
	watched  []string
	// workDir and onUnregistered are bindings of the running instance, not
	// configuration: Reconfigure never touches them, and they are read without mu.
	workDir        atomic.Pointer[string]
	onUnregistered atomic.Pointer[func(ctx context.Context, id, dest, sha256 string)]

	restoreLocks keyedMutex

	// previousRegistry is the location of the registry replaced by the last
	// Reconfigure: a rollback may reuse it, it is not an unrelated one.
	previousRegistry string
}

func NewQuarantineHandler(ctx context.Context, conf Config) (quarantineHandler *QuarantineHandler, err error) {
	if conf.Location == "" {
		conf.Location = config.DefaultQuarantineLocation
	}

	if _, err = ensureLocation(conf.Location); err != nil {
		return
	}

	locker, err := newQuarantineLocker(conf.LockPassword, conf.Format)
	if err != nil {
		return
	}
	registry, err := newSQLiteRegistry(ctx, conf.RegistryLocation)
	if err != nil {
		return
	}
	quarantineHandler = &QuarantineHandler{
		registry: registry,
		locker:   locker,
		location: conf.Location,
		watched:  slices.Clone(conf.WatchedPaths),
	}
	return
}

// SetWorkDir sets the private work directory of the connector: Restore never
// writes below it. "" disables the check (CLI, tests). Safe for concurrent use;
// Reconfigure never changes it.
func (q *QuarantineHandler) SetWorkDir(dir string) {
	q.workDir.Store(&dir)
}

// SetUnregisteredRestoreHook sets the function called once after a successful
// restore that had no registry entry (decision Q30), so that the caller raises a
// console event. It runs in a goroutine of its own, with a context that the end
// of the restoration does not cancel, so that it never delays the reply; it must
// still end. nil removes it. Safe for concurrent use; Reconfigure never changes it.
func (q *QuarantineHandler) SetUnregisteredRestoreHook(f func(ctx context.Context, id, dest, sha256 string)) {
	if f == nil {
		q.onUnregistered.Store(nil)
		return
	}
	q.onUnregistered.Store(&f)
}

// newQuarantineLocker builds the fileLocker used for both writing and
// reading: it writes the given format (tar when empty) and reads both,
// detected from the file content.
func newQuarantineLocker(password string, format Format) (fileLocker, error) {
	format, err := ParseFormat(string(format))
	if err != nil {
		return nil, err
	}
	var write fileLocker = &tarLocker{Password: password}
	if format == FormatZip {
		write = &zipLocker{Password: password}
	}
	return newLockerRouter(write, &tarLocker{Password: password}, &zipLocker{Password: password}), nil
}

// ErrFileChanged is returned by Quarantine when the file size changed while it
// was being read; no quarantine file is kept.
var ErrFileChanged = errors.New("file changed while being quarantined")

// ErrQuarantineSHA256Mismatch is returned by Quarantine when the SHA256 of the
// file content differs from the one given; no quarantine file is kept.
var ErrQuarantineSHA256Mismatch = errors.New("file content does not match the SHA256 given for quarantine")

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// ctxWriter wraps an io.Writer to abort on context cancellation.
type ctxWriter struct {
	ctx context.Context
	w   io.Writer
}

func (cw *ctxWriter) Write(p []byte) (int, error) {
	if err := cw.ctx.Err(); err != nil {
		return 0, err
	}
	return cw.w.Write(p)
}

// ctxReader wraps an io.Reader to abort on context cancellation.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (cr *ctxReader) Read(p []byte) (n int, err error) {
	if err = cr.ctx.Err(); err != nil {
		return
	}
	n, err = cr.r.Read(p)
	return
}

func (q *QuarantineHandler) Quarantine(ctx context.Context, file string, fIn *os.File, fileSHA256 string, malwares []string) (location string, id string, err error) {
	// The container records the same path as the registry: Restore checks one
	// against the other.
	file = filepath.Clean(file)
	entry := Entry{
		ID:              entryID(file, fileSHA256),
		SHA256:          strings.ToLower(fileSHA256),
		InitialLocation: file,
	}
	// Same order as Restore: the lock of the entry, then the lock of the handler.
	// A restoration of this very entry cannot run between the check below and
	// the registration, nor read the container while it is being written.
	unlockID := q.restoreLocks.Lock(entry.ID)
	defer unlockID()
	// Held for the whole operation: Reconfigure swaps the registry and moves the
	// files under the write lock, and must not run in the middle of this.
	q.mu.RLock()
	defer q.mu.RUnlock()
	locker := q.locker
	quarantineDir := q.location

	refusedAnyway := isRefusedAnyway(ctx)
	if restored, restoredErr := q.isRestored(ctx, file, fileSHA256); restoredErr != nil {
		return "", "", restoredErr
	} else if restored && !refusedAnyway {
		return "", "", ErrRestored
	}
	if refusedAnyway {
		// A refusal for the path or the type of the file is no verdict on its content:
		// the mark of a restored entry is never lowered by it.
		prev, getErr := q.registry.Get(ctx, entry.ID)
		switch {
		case getErr == nil && prev.Restored():
			entry.RestoredAt, entry.CreatedAt = prev.RestoredAt, prev.CreatedAt
		case getErr != nil && !errors.Is(getErr, errEntryNotFound):
			return "", "", getErr
		}
	}
	// Stat the open descriptor: the size recorded in the container must be the
	// one of the bytes read, not of a path that may be swapped meanwhile.
	stat, err := fIn.Stat()
	if err != nil {
		return
	}
	entry.QuarantineLocation = filepath.Join(quarantineDir, entry.ID+".lock")

	fOut, err := os.OpenFile(entry.QuarantineLocation, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return
	}

	success := false
	defer func() {
		if e := fOut.Close(); e != nil {
			logger.Warn("could not close output quarantined file", slog.String("file", entry.QuarantineLocation), slog.String("error", e.Error()))
		}
		if !success {
			if e := os.Remove(entry.QuarantineLocation); e != nil && !errors.Is(e, os.ErrNotExist) {
				logger.Error("could not remove orphaned quarantine lock file", slog.String("file", entry.QuarantineLocation), slog.String("error", e.Error()))
			}
		}
	}()

	malware := "unknown"
	if len(malwares) > 0 {
		malware = malwares[0]
	}
	// Wrap reader so LockFile I/O respects the context timeout
	// One byte more than the size is allowed through, to detect growth.
	hasher := sha256.New()
	in := &countingReader{r: io.TeeReader(io.LimitReader(&ctxReader{ctx: ctx, r: fIn}, stat.Size()+1), hasher)}
	if err = locker.LockFile(file, in, stat, "malware: "+malware, fOut); err != nil {
		return
	}
	if in.n != stat.Size() {
		err = fmt.Errorf("%w: read %d bytes, expected %d", ErrFileChanged, in.n, stat.Size())
		return
	}
	// Restore checks the content against this SHA256: a quarantine that could
	// never be restored is refused now.
	if !strings.EqualFold(hex.EncodeToString(hasher.Sum(nil)), fileSHA256) {
		err = ErrQuarantineSHA256Mismatch
		return
	}
	if err = q.registry.Set(ctx, &entry); err != nil {
		return
	}
	success = true
	location = entry.QuarantineLocation
	id = entry.ID
	return
}

type refusedAnywayKey struct{}

// WithRefusedAnyway marks ctx for Quarantine: the file is quarantined although its
// content was restored, because it is refused for where it is or what type it is,
// not for what it holds. Only the scanner sets it, for a restored file that the path
// rules or the OnScanFile chain refused. The restored mark of the content is kept.
func WithRefusedAnyway(ctx context.Context) context.Context {
	return context.WithValue(ctx, refusedAnywayKey{}, true)
}

// isRefusedAnyway tells whether ctx carries the mark of WithRefusedAnyway.
func isRefusedAnyway(ctx context.Context) bool {
	v, _ := ctx.Value(refusedAnywayKey{}).(bool)
	return v
}

func (q *QuarantineHandler) IsRestored(ctx context.Context, location string, sha256 string) (restored bool, err error) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.isRestored(ctx, location, sha256)
}

// entryID is the registry id of the file at location holding this content: the
// one key of a quarantine, a restoration and the restored check.
func entryID(location, contentSHA256 string) string {
	return ComputeCacheID(filepath.Clean(location), strings.ToLower(contentSHA256))
}

// isRestored reports whether the entry of this very file was restored. The
// caller holds q.mu (a second read lock could deadlock against a Reconfigure
// waiting for the write lock).
func (q *QuarantineHandler) isRestored(ctx context.Context, location, contentSHA256 string) (bool, error) {
	if len(contentSHA256) != sha256Len {
		// Empty or not a SHA256: nothing can have been restored under it.
		return false, nil
	}
	entry, err := q.registry.Get(ctx, entryID(location, contentSHA256))
	switch {
	case err == nil:
		return entry.Restored(), nil
	case errors.Is(err, errEntryNotFound):
		return false, nil
	default:
		return false, err
	}
}

var (
	// ErrRestorePathMismatch is returned by Restore when the path recorded
	// inside the quarantine container is not a clean absolute path, is a
	// Windows UNC/device path, or does not match the registry's
	// InitialLocation for this id. It defends against a tampered or crafted
	// container redirecting a restore to an arbitrary filesystem location.
	ErrRestorePathMismatch = errors.New("quarantine container path does not match the registry entry")

	// ErrRestoreTooLarge is returned by Restore when the plaintext is larger
	// than the .lock file: no container format compresses, so this can only
	// come from a corrupted or crafted container.
	ErrRestoreTooLarge = errors.New("restored content is larger than its quarantine container")

	// ErrRestoreContentMismatch is returned by Restore when the SHA256 of the
	// restored content differs from the one in the registry (wrong password or
	// corrupted container). The .lock file is kept.
	ErrRestoreContentMismatch = errors.New("restored content does not match the SHA256 recorded in the registry")

	// ErrRestoreSizeMismatch is returned by Restore when the number of bytes
	// produced differs from the size recorded in the container index.
	ErrRestoreSizeMismatch = errors.New("restored content size differs from the size recorded in the container")

	// ErrRestoreDestinationUnsafe is returned by Restore when the
	// destination directory is not a plain directory (e.g. a symlink) at
	// the moment it is inspected, or when its identity changes between
	// that inspection and the os.Root open used for every subsequent
	// filesystem operation. os.OpenRoot follows a symlink given as its
	// argument, so this check is what actually prevents a symlink swapped
	// in for the destination directory from redirecting the restore.
	ErrRestoreDestinationUnsafe = errors.New("quarantine restore destination directory is not safe to use")

	// ErrRestoreRollbackFailed is joined to the error of a restoration that failed
	// when the change it made to the registry could not be undone: the content is
	// allowed by its SHA256 although nothing was restored. The container is kept.
	ErrRestoreRollbackFailed = errors.New("the registry change of a failed restore could not be undone")

	// ErrRestoredLockKept is joined to the error of a restoration that published
	// the file but could not remove its container: the file is restored, and
	// restoring it again would fail with a destination that exists.
	ErrRestoredLockKept = errors.New("the file was restored but its container could not be removed")

	// ErrRestoredNotRegistered is joined to the error of a restoration of a
	// container without registry entry that published the file but could not
	// register it: the file is there, and the registry does not know it, so its
	// content is detected and quarantined again at the next pass.
	ErrRestoredNotRegistered = errors.New("the file was restored but the registry could not be told")

	errInvalidQuarantineID = errors.New("invalid quarantine id")

	validQuarantineID = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// validRestorePath reports whether path is an acceptable Restore destination: a
// clean, absolute path, not a Windows UNC/device path.
func validRestorePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && isRestorePathAllowed(path)
}

// limitWriter caps the number of bytes it accepts and counts those written.
type limitWriter struct {
	w         io.Writer
	remaining int64
	written   int64
}

func (l *limitWriter) Write(p []byte) (n int, err error) {
	if int64(len(p)) > l.remaining {
		return 0, ErrRestoreTooLarge
	}
	n, err = l.w.Write(p)
	l.remaining -= int64(n)
	l.written += int64(n)
	return
}

const restoreTempCreateAttempts = 5

// maxTempBaseLen keeps the temp name under the usual 255-byte file name limit.
const maxTempBaseLen = 255 - len(TempPrefix) - 1 - 16

func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// createRestoreTempFile creates a uniquely-named, exclusively-owned regular
// file inside root, suitable to receive the restored plaintext before the
// final atomic rename. O_EXCL guarantees the name did not already exist
// (as a real file, a dangling symlink, or otherwise), so a pre-planted
// symlink at a guessable name cannot redirect the write.
func createRestoreTempFile(root *os.Root, base string) (string, *os.File, error) {
	var lastErr error
	for range restoreTempCreateAttempts {
		suffix, err := randomHex(8)
		if err != nil {
			return "", nil, err
		}
		name := TempPrefix + truncateBytes(base, maxTempBaseLen) + "-" + suffix
		f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			return name, f, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", nil, err
		}
		lastErr = err
	}
	return "", nil, lastErr
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (q *QuarantineHandler) Close() (err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	err = q.registry.Close()
	return
}

// MoveFile moves a file from src to dst, falling back to copy+delete
// when src and dst are on different mount points (EXDEV).
func MoveFile(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) && errors.Is(linkErr.Err, syscall.EXDEV) {
		return copyAndDelete(src, dst)
	}
	return fmt.Errorf("could not move file %s to %s: %w", src, dst, err)
}

func copyAndDelete(src, dst string) (err error) {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return
	}

	srcFile, err := os.Open(filepath.Clean(src))
	if err != nil {
		return
	}
	defer func() {
		if e := srcFile.Close(); e != nil {
			logger.Error("copyAndDelete cannot close source file", slog.String("file", src), slog.String("error", e.Error()))
		}
	}()

	dstFile, err := os.OpenFile(filepath.Clean(dst), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return
	}

	success := false
	defer func() {
		if e := dstFile.Close(); e != nil {
			logger.Error("copyAndDelete cannot close destination file", slog.String("file", dst), slog.String("error", e.Error()))
		}
		if !success {
			if e := os.Remove(dst); e != nil {
				logger.Error("copyAndDelete cannot remove destination file after failed copy", slog.String("file", dst), slog.String("error", e.Error()))
			}
		}
	}()
	if _, err = io.Copy(dstFile, srcFile); err != nil {
		return
	}
	// Permission bits only: setuid and setgid must not follow the copy.
	if err = os.Chmod(dst, srcInfo.Mode()&0o777); err != nil {
		return
	}
	success = true
	err = os.Remove(src)
	return
}

// keyedMutex hands out one mutex per key, used to serialise concurrent
// Restore calls for the same quarantine id. Entries are removed as
// soon as their last holder releases them, so the map never grows
// unbounded with the total number of ids ever restored.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*refCountedMutex
}

type refCountedMutex struct {
	mu  sync.Mutex
	ref int
}

// Lock blocks until the mutex for key is acquired and returns a function
// that releases it. The returned function must be called exactly once.
func (k *keyedMutex) Lock(key string) (unlock func()) {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = make(map[string]*refCountedMutex)
	}
	l, ok := k.locks[key]
	if !ok {
		l = &refCountedMutex{}
		k.locks[key] = l
	}
	l.ref++
	k.mu.Unlock()

	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		k.mu.Lock()
		l.ref--
		if l.ref == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}
