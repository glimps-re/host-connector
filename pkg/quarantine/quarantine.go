package quarantine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/glimps-re/host-connector/pkg/config"
)

type Quarantiner interface {
	Quarantine(ctx context.Context, file string, fileSHA256 string, malwares []string) (quarantineLocation string, entryID string, err error)
	Restore(ctx context.Context, entryID string) (err error)
	Reconfigure(ctx context.Context, newConfig Config) (err error)
	IsRestored(ctx context.Context, sha256 string) (restored bool, err error)
	ListQuarantinedFiles(ctx context.Context) iter.Seq2[*QuarantinedFile, error]
	Close() (err error)
}

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

	restoreLocks keyedMutex
}

func NewQuarantineHandler(ctx context.Context, conf Config) (quarantineHandler *QuarantineHandler, err error) {
	if conf.Location == "" {
		conf.Location = config.DefaultQuarantineLocation
	}

	_, err = os.Stat(conf.Location)
	if errors.Is(err, os.ErrNotExist) {
		if err = os.MkdirAll(conf.Location, 0o750); err != nil {
			err = fmt.Errorf("failed to create quarantine location: %w", err)
			return
		}
	} else if err != nil {
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
	}
	return
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

// Reconfigure applies newConfig under the write lock. The new locker is built
// first, so an invalid format changes nothing. Past that point the steps are
// not transactional: a failure while moving the quarantine files can leave the
// registry migrated.
func (q *QuarantineHandler) Reconfigure(ctx context.Context, newConfig Config) (err error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	newLocker, err := newQuarantineLocker(newConfig.LockPassword, newConfig.Format)
	if err != nil {
		return err
	}

	if err = q.registry.Migrate(ctx, newConfig.RegistryLocation); err != nil {
		return err
	}

	if newConfig.Location == "" {
		newConfig.Location = config.DefaultQuarantineLocation
	}

	if newConfig.Location == q.location {
		q.locker = newLocker
		return
	}

	_, err = os.Stat(newConfig.Location)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err = os.MkdirAll(newConfig.Location, 0o750); err != nil {
			return
		}
	case err != nil:
		return
	}
	if err = q.moveQuarantinedFiles(ctx, q.location, newConfig.Location); err != nil {
		return
	}
	q.locker = newLocker
	q.location = newConfig.Location
	return
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

func (q *QuarantineHandler) Quarantine(ctx context.Context, file string, fileSHA256 string, malwares []string) (location string, id string, err error) {
	q.mu.RLock()
	locker := q.locker
	quarantineDir := q.location
	q.mu.RUnlock()

	entry := Entry{
		ID:              ComputeCacheID(file, fileSHA256),
		SHA256:          fileSHA256,
		InitialLocation: file,
	}
	fIn, err := os.Open(filepath.Clean(file))
	if err != nil {
		return
	}
	defer func() {
		if e := fIn.Close(); e != nil {
			logger.Warn("could not close input quarantined file", slog.String("file", file), slog.String("error", e.Error()))
		}
	}()
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

func (q *QuarantineHandler) IsRestored(ctx context.Context, sha256 string) (restored bool, err error) {
	entry, getEntryErr := q.registry.GetBySHA256(ctx, sha256)
	switch {
	case getEntryErr == nil:
		if entry.RestoredAt.UnixMilli() > 0 {
			restored = true
			return
		}
		return
	case errors.Is(getEntryErr, errEntryNotFound):
		// ok
		return
	default:
		err = getEntryErr
		return
	}
}

var (
	// ErrNoRegistryEntry is returned by Restore when no registry entry
	// exists for the requested id. The check happens before any filesystem
	// write.
	ErrNoRegistryEntry = errors.New("no registry entry for this quarantine id")

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

	errInvalidQuarantineID = errors.New("invalid quarantine id")

	validQuarantineID = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// isValidRestorePath reports whether path is an acceptable Restore
// destination: a clean, absolute path, not a Windows UNC/device path, and
// exactly equal to expected (the registry's InitialLocation for this id).
func isValidRestorePath(path, expected string) bool {
	if path == "" || expected == "" {
		return false
	}
	if !filepath.IsAbs(path) {
		return false
	}
	if filepath.Clean(path) != path {
		return false
	}
	if path != expected {
		return false
	}
	return isRestorePathAllowed(path)
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

// Restore restores the file of quarantine id to its original location: the
// registry is consulted, and the destination path validated, before any
// filesystem write; the plaintext goes to an exclusive temp file in the
// destination directory and is renamed into place only once its size and
// SHA256 match the container index and the registry. Any failure before the
// rename leaves the filesystem as it was, except for a possibly created
// destination directory tree.
func (q *QuarantineHandler) Restore(ctx context.Context, id string) (err error) {
	if !validQuarantineID.MatchString(id) {
		return fmt.Errorf("%w: %q", errInvalidQuarantineID, id)
	}

	unlockID := q.restoreLocks.Lock(id)
	defer unlockID()

	q.mu.RLock()
	locker := q.locker
	location := q.location
	q.mu.RUnlock()

	lockPath := filepath.Join(location, id+".lock")
	f, err := os.OpenInRoot(location, id+".lock")
	if err != nil {
		return
	}
	closed := false
	defer func() {
		if !closed {
			if e := f.Close(); e != nil {
				logger.Error("Restore cannot close container file", slog.String("error", e.Error()))
			}
		}
	}()

	stat, err := f.Stat()
	if err != nil {
		return
	}
	if !stat.Mode().IsRegular() {
		err = fmt.Errorf("%w: not a regular file", errInvalidQuarantineID)
		return
	}
	header, err := locker.GetHeader(f, stat.Size())
	if err != nil {
		return
	}

	// Restoring an id without registry entry is refused, before any write.
	entry, err := q.registry.Get(ctx, id)
	if err != nil {
		if errors.Is(err, errEntryNotFound) {
			err = ErrNoRegistryEntry
		}
		return
	}

	// Path policy: Nothing derived from container content alone is
	// ever trusted as a write destination.
	// The container index is JSON: invalid UTF-8 bytes of the original path were
	// replaced, so the comparison uses the same replacement. The exact path of
	// the registry is the destination.
	dest := entry.InitialLocation
	if !isValidRestorePath(header.Filepath, strings.Map(func(r rune) rune { return r }, dest)) {
		err = ErrRestorePathMismatch
		return
	}

	// os.OpenRoot follows a symlink given as its argument, so the final
	// directory is checked before (plain directory, identity captured) and
	// after (same file) opening it: swapping the final component for a link is
	// caught. Parent components are not protected here.
	restoreDir := filepath.Dir(dest)
	preOpenInfo, statErr := os.Lstat(restoreDir)
	switch {
	case errors.Is(statErr, os.ErrNotExist):
		logger.Debug("recreating dir tree for restore", slog.String("dir", restoreDir))
		if err = os.MkdirAll(restoreDir, 0o750); err != nil {
			return
		}
		if preOpenInfo, err = os.Lstat(restoreDir); err != nil {
			return
		}
	case statErr != nil:
		err = statErr
		return
	case preOpenInfo.Mode()&os.ModeSymlink != 0, !preOpenInfo.IsDir():
		err = ErrRestoreDestinationUnsafe
		return
	}

	root, err := os.OpenRoot(restoreDir)
	if err != nil {
		return
	}
	defer func() {
		if e := root.Close(); e != nil {
			logger.Error("Restore cannot close destination directory", slog.String("error", e.Error()))
		}
	}()

	openedInfo, err := root.Lstat(".")
	if err != nil {
		return
	}
	if !os.SameFile(preOpenInfo, openedInfo) {
		err = ErrRestoreDestinationUnsafe
		return
	}

	base := filepath.Base(dest)

	tmpName, tmpFile, err := createRestoreTempFile(root, base)
	if err != nil {
		return
	}
	tmpRemoved := false
	tmpClosed := false
	defer func() {
		if !tmpClosed {
			if e := tmpFile.Close(); e != nil {
				logger.Error("Restore cannot close temp file", slog.String("error", e.Error()))
			}
		}
		if !tmpRemoved {
			if e := root.Remove(tmpName); e != nil && !errors.Is(e, os.ErrNotExist) {
				logger.Error("Restore cannot remove leftover temp file", slog.String("name", tmpName), slog.String("error", e.Error()))
			}
		}
	}()

	// No format compresses: the plaintext cannot be larger than the container,
	// whatever size the container claims.
	hasher := sha256.New()
	limited := &limitWriter{w: &ctxWriter{ctx: ctx, w: io.MultiWriter(tmpFile, hasher)}, remaining: stat.Size()}
	locked, err := locker.UnlockFile(f, stat.Size(), limited)
	if err != nil {
		return
	}
	if limited.written != locked.Size {
		err = fmt.Errorf("%w: wrote %d, recorded %d", ErrRestoreSizeMismatch, limited.written, locked.Size)
		return
	}
	// A wrong password decrypts the tar format to random bytes without error.
	if got := hex.EncodeToString(hasher.Sum(nil)); !strings.EqualFold(got, entry.SHA256) {
		err = ErrRestoreContentMismatch
		return
	}
	if e := f.Close(); e != nil {
		logger.Error("Restore cannot close container file", slog.String("error", e.Error()))
	}
	closed = true

	if err = restoreFileInfo(root, tmpFile, tmpName, locked); err != nil {
		return
	}
	if err = tmpFile.Sync(); err != nil {
		return
	}
	// Closed before the rename: Windows cannot rename an open file.
	tmpClosed = true
	if err = tmpFile.Close(); err != nil {
		return
	}

	// Atomic rename: the destination never holds partial or unverified bytes.
	if err = root.Rename(tmpName, base); err != nil {
		return
	}
	tmpRemoved = true // renamed away; nothing left to clean up

	// A failure here leaves the restored file in place with the .lock also
	// still present.
	entry.QuarantineLocation = ""
	entry.RestoredAt = now()
	if err = q.registry.Set(ctx, entry); err != nil {
		err = fmt.Errorf("error set cache for sha256 %v, %w", entry.SHA256, err)
		return
	}
	logger.Info("file restored", slog.String("file", dest), slog.String("reason", locked.Reason))
	if e := os.Remove(lockPath); e != nil {
		logger.Error("Restore cannot remove lock file", slog.String("error", e.Error()))
	}
	return
}

type QuarantinedFile struct {
	LockEntry
	ID string
}

// ListQuarantinedFiles lists every container in the quarantine directory
// without needing the password (both formats store their index in
// cleartext). A single unreadable or malformed container is logged and
// skipped; only a failure of the walk itself (e.g. the quarantine
// directory disappearing) surfaces as an error to the caller.
func (q *QuarantineHandler) ListQuarantinedFiles(ctx context.Context) iter.Seq2[*QuarantinedFile, error] {
	return func(yield func(f *QuarantinedFile, err error) bool) {
		q.mu.RLock()
		locker := q.locker
		location := q.location
		q.mu.RUnlock()

		walkErr := filepath.WalkDir(location, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				logger.Warn("list quarantined error", slog.String("path", path), slog.String("error", err.Error()))
				return nil
			}
			if ctx.Err() != nil {
				return filepath.SkipAll
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".lock") {
				return nil
			}

			relPath, relErr := filepath.Rel(location, path)
			if relErr != nil {
				logger.Warn("list quarantined: cannot compute relative path", slog.String("path", path), slog.String("error", relErr.Error()))
				return nil
			}
			file, openErr := os.OpenInRoot(location, relPath)
			if openErr != nil {
				logger.Warn("list quarantined: cannot open file", slog.String("path", path), slog.String("error", openErr.Error()))
				return nil
			}
			defer func() {
				if e := file.Close(); e != nil {
					logger.Error("ListQuarantinedFiles cannot close file", slog.String("error", e.Error()))
				}
			}()

			stat, statErr := file.Stat()
			if statErr != nil {
				logger.Warn("list quarantined: cannot stat file", slog.String("path", path), slog.String("error", statErr.Error()))
				return nil
			}

			entry, headerErr := locker.GetHeader(file, stat.Size())
			if headerErr != nil {
				logger.Warn("list quarantined: cannot read header", slog.String("path", path), slog.String("error", headerErr.Error()))
				return nil
			}
			id := strings.TrimSuffix(filepath.Base(path), ".lock")

			if !yield(&QuarantinedFile{LockEntry: entry, ID: id}, nil) {
				return filepath.SkipAll
			}
			return nil
		})
		if walkErr != nil {
			yield(nil, walkErr)
		}
	}
}

func (q *QuarantineHandler) Close() (err error) {
	err = q.registry.Close()
	return
}

func (q *QuarantineHandler) moveQuarantinedFiles(ctx context.Context, oldLocation, newLocation string) (err error) {
	err = filepath.WalkDir(oldLocation, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			logger.Warn("move quarantined files error", slog.String("error", walkErr.Error()))
			return nil
		}
		if ctx.Err() != nil {
			return filepath.SkipAll
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".lock") {
			return nil
		}

		filename := filepath.Base(path)
		newPath := filepath.Join(newLocation, filename)

		if moveErr := MoveFile(path, newPath); moveErr != nil {
			return moveErr
		}

		id := strings.TrimSuffix(filename, ".lock")
		entry, getErr := q.registry.Get(ctx, id)
		if getErr != nil {
			if errors.Is(getErr, errEntryNotFound) {
				return nil
			}
			return getErr
		}

		entry.QuarantineLocation = newPath
		if setErr := q.registry.Set(ctx, entry); setErr != nil {
			return setErr
		}

		return nil
	})
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

	dstFile, err := os.OpenFile(filepath.Clean(dst), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
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
	if err = os.Chmod(dst, srcInfo.Mode()); err != nil {
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
