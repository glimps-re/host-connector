package quarantine

import (
	"context"
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

	"github.com/glimps-re/host-connector/internal/pathutil"
)

var lockFileName = regexp.MustCompile(`^[0-9a-f]{64}\.lock$`)

// betweenLstatAndOpen is where tests swap the name for something else.
var betweenLstatAndOpen = func() {}

// openContainer opens the container called name in the quarantine directory and
// checks that what was opened is the regular file the name designates: a link, a
// directory or a special file is refused. os.Root follows a link on the last
// component whatever the flags, so the name is also examined without following it
// and must be the very file that was opened (a name swapped for a link in between
// is refused). The opening never blocks on a special file swapped in at any time.
func openContainer(location, name string) (*os.File, fs.FileInfo, error) {
	root, err := os.OpenRoot(location)
	if err != nil {
		return nil, nil, err
	}
	defer closeQuietly(root, "quarantine directory")
	named, err := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if !named.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: not a regular file", errInvalidQuarantineID)
	}
	betweenLstatAndOpen()
	f, err := root.OpenFile(name, containerOpenFlags, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err == nil && (!info.Mode().IsRegular() || !os.SameFile(named, info)) {
		err = fmt.Errorf("%w: not the regular file the name designates", errInvalidQuarantineID)
	}
	if err != nil {
		closeQuietly(f, "container file")
		return nil, nil, err
	}
	return f, info, nil
}

func closeQuietly(c io.Closer, what string) {
	if err := c.Close(); err != nil {
		logger.Error("Restore cannot close "+what, slog.String("error", err.Error()))
	}
}

// forbiddenDestination refuses a destination a restoration must never write: one
// that is not a plain absolute path, or that lies in the work directory of the
// connector, in the quarantine directory, or in a folder that belongs to the
// moves and the restorations themselves.
func forbiddenDestination(dest, location, workDir string) error {
	if strings.ContainsRune(dest, 0) {
		return fmt.Errorf("%w: the path has a NUL", ErrRestorePathMismatch)
	}
	for elem := range strings.SplitSeq(filepath.ToSlash(dest), "/") {
		switch {
		case elem == "..":
			// Defense in depth: the callers already require a clean path.
			return fmt.Errorf("%w: the path has a parent element", ErrRestorePathMismatch)
		case strings.EqualFold(elem, StagingDir), strings.HasPrefix(elem, TempPrefix):
			return fmt.Errorf("%w: the path goes through %q", ErrRestorePathMismatch, elem)
		}
	}
	if location != "" && pathutil.UnderResolved(location, dest) {
		return fmt.Errorf("%w: the destination is in the quarantine directory", ErrRestorePathMismatch)
	}
	if workDir != "" && pathutil.UnderResolved(workDir, dest) {
		return fmt.Errorf("%w: the destination is in the work directory", ErrRestorePathMismatch)
	}
	return nil
}

// Replaced in tests: a file system that refuses links, one without
// RENAME_NOREPLACE.
var (
	rootLink            = func(root *os.Root, oldname, newname string) error { return root.Link(oldname, newname) }
	rootRenameNoReplace = rootRenameNoReplaceOS
)

// publishRestored puts the verified temp file in place under its final name
// without ever replacing a file already there, whoever wrote it: by a hard link,
// which fails when the name is taken; when the file system refuses links, by
// RENAME_NOREPLACE; and only when neither is available, by a rename after a check
// under an exclusive lock, which stops this process and not another writer of the
// directory (the window of the move, documented). removed tells that the temp
// name is gone.
func publishRestored(root *os.Root, tmpName, base string) (removed bool, err error) {
	linkMu.RLock()
	err = rootLink(root, tmpName, base)
	linkMu.RUnlock()
	switch {
	case err == nil:
		// A temp name that cannot be removed is reported once, by the caller.
		return root.Remove(tmpName) == nil, nil
	case errors.Is(err, fs.ErrExist):
		return false, fmt.Errorf("%w: %s", ErrDestinationExists, base)
	case isLinkRefused(err):
		return publishWithoutLink(root, tmpName, base)
	default:
		return false, err
	}
}

func publishWithoutLink(root *os.Root, tmpName, base string) (removed bool, err error) {
	handled, err := rootRenameNoReplace(root, tmpName, base)
	switch {
	case handled && errors.Is(err, fs.ErrExist):
		return false, fmt.Errorf("%w: %s", ErrDestinationExists, base)
	case handled:
		return err == nil, err
	}
	linkMu.Lock()
	defer linkMu.Unlock()
	if _, e := root.Lstat(base); e == nil {
		return false, fmt.Errorf("%w: %s", ErrDestinationExists, base)
	} else if !errors.Is(e, fs.ErrNotExist) {
		return false, e
	}
	if e := root.Rename(tmpName, base); e != nil {
		return false, e
	}
	return true, nil
}

// Restore restores the file of quarantine id to its original location. The
// container is opened without following a link, the destination is validated and
// opened (nothing derived from the container alone is trusted) before any write,
// and the plaintext goes to an exclusive temp file in the destination directory:
// it is published only once its size and SHA256 match the container index and the
// registry, and never over a file that is there (ErrDestinationExists). The
// registry entry is marked restored before the publication and put back as it was
// if the publication fails; the container is removed only after a successful
// publication.
//
// A container without registry entry (decision Q30) is restored to the path its
// index records, only below a watched path, after the same checks, once the id
// proves to be the one that path and content give (ComputeCacheID): a wrong
// password or an index edited since is refused. It is logged and reported to the
// hook of SetUnregisteredRestoreHook. It is published first and registered after,
// so that a crash between the two leaves no entry that allows content with no file:
// when the registry then fails, the file is there and ErrRestoredNotRegistered is
// returned.
func (q *QuarantineHandler) Restore(ctx context.Context, id string) (err error) {
	notify, err := q.restore(ctx, id)
	if notify != nil {
		go notify()
	}
	return err
}

// restore does the work of Restore under the locks, and returns what is to be
// done once they are released.
func (q *QuarantineHandler) restore(ctx context.Context, id string) (notify func(), err error) {
	if !validQuarantineID.MatchString(id) {
		return nil, fmt.Errorf("%w: %q", errInvalidQuarantineID, id)
	}

	unlockID := q.restoreLocks.Lock(id)
	defer unlockID()

	// restoreLocks is taken before this lock, and Reconfigure never takes it:
	// no deadlock.
	q.mu.RLock()
	defer q.mu.RUnlock()
	locker, location, watched := q.locker, q.location, q.watched
	workDir := ""
	if w := q.workDir.Load(); w != nil {
		workDir = *w
	}
	var onUnregistered func(ctx context.Context, id, dest, sha256 string)
	if h := q.onUnregistered.Load(); h != nil {
		onUnregistered = *h
	}

	lockPath := filepath.Join(location, id+".lock")
	f, stat, err := openContainer(location, id+".lock")
	if err != nil {
		return nil, err
	}
	closed := false
	defer func() {
		if !closed {
			closeQuietly(f, "container file")
		}
	}()
	header, err := locker.GetHeader(f, stat.Size())
	if err != nil {
		return nil, err
	}

	entry, err := q.registry.Get(ctx, id)
	registered := err == nil
	if err != nil && !errors.Is(err, errEntryNotFound) {
		return nil, err
	}
	dest := header.Filepath
	if registered {
		// The container index is JSON: invalid UTF-8 bytes of the original path were
		// replaced, so the comparison uses the same replacement. The exact path of
		// the registry is the destination.
		dest = entry.InitialLocation
		if header.Filepath != strings.Map(func(r rune) rune { return r }, dest) || !validRestorePath(header.Filepath) {
			return nil, ErrRestorePathMismatch
		}
	} else if !validRestorePath(header.Filepath) {
		return nil, fmt.Errorf("%w: the path of the container is not a clean absolute path", ErrRestorePathMismatch)
	}
	if err = forbiddenDestination(dest, location, workDir); err != nil {
		return nil, err
	}
	if !registered {
		// The id of a container without entry is an unkeyed hash: it proves the
		// integrity of the index, not who wrote it. Such a container only goes
		// where files are deposited, so that it cannot allow-list content at an
		// arbitrary place of the host.
		if watchedRoot(watched, filepath.Dir(dest)) == "" {
			return nil, fmt.Errorf("%w: a container without registry entry is restored only below a watched path; restore it with a registry entry", ErrRestoreDestinationUnsafe)
		}
		logger.Warn("restoring a quarantined file that has no registry entry", slog.String("id", id), slog.String("destination", dest))
	}

	root, closeRoot, err := openRestoreDir(watched, filepath.Dir(dest))
	if err != nil {
		return nil, err
	}
	defer closeRoot()
	base := filepath.Base(dest)

	tmpName, tmpFile, err := createRestoreTempFile(root, base)
	if err != nil {
		return nil, err
	}
	tmpRemoved, tmpClosed := false, false
	defer func() {
		if !tmpClosed {
			closeQuietly(tmpFile, "temp file")
		}
		if !tmpRemoved {
			if e := root.Remove(tmpName); e != nil && !errors.Is(e, os.ErrNotExist) {
				logger.Error("Restore cannot remove the temp file, it is left in the destination directory", slog.String("path", filepath.Join(root.Name(), tmpName)), slog.String("error", e.Error()))
			}
		}
	}()

	// No format compresses: the plaintext cannot be larger than the container,
	// whatever size the container claims.
	hasher := sha256.New()
	limited := &limitWriter{w: &ctxWriter{ctx: ctx, w: io.MultiWriter(tmpFile, hasher)}, remaining: stat.Size()}
	locked, err := locker.UnlockFile(f, stat.Size(), limited)
	if err != nil {
		return nil, err
	}
	if limited.written != locked.Size {
		return nil, fmt.Errorf("%w: wrote %d, recorded %d", ErrRestoreSizeMismatch, limited.written, locked.Size)
	}
	// A wrong password decrypts the tar format to random bytes without error.
	got := hex.EncodeToString(hasher.Sum(nil))
	if registered && !strings.EqualFold(got, entry.SHA256) {
		return nil, ErrRestoreContentMismatch
	}
	if !registered && id != ComputeCacheID(header.Filepath, got) {
		return nil, fmt.Errorf("%w: the id is not the one of this path and content", ErrRestorePathMismatch)
	}
	closeQuietly(f, "container file")
	closed = true

	if err = restoreFileInfo(root, tmpFile, tmpName, locked); err != nil {
		return nil, err
	}
	if err = tmpFile.Sync(); err != nil {
		return nil, err
	}
	// Closed before the publication: Windows cannot rename an open file.
	tmpClosed = true
	if err = tmpFile.Close(); err != nil {
		return nil, err
	}

	if !registered {
		return q.publishThenRegister(ctx, root, tmpName, base, id, dest, got, lockPath, locked.Reason, onUnregistered, &tmpRemoved)
	}

	// Marked before the file is published, so that a registry that cannot be
	// written leaves the file where it was, not restored and re-quarantined at the
	// next scan; put back as it was if the publication fails.
	marked := *entry
	marked.QuarantineLocation = ""
	marked.RestoredAt = now()
	if err = q.registry.Set(ctx, &marked); err != nil {
		return nil, fmt.Errorf("error set cache for sha256 %v, %w", got, err)
	}
	removed, err := publishRestored(root, tmpName, base)
	tmpRemoved = removed
	if err != nil {
		if undoErr := q.registry.Set(context.WithoutCancel(ctx), entry); undoErr != nil {
			logger.Error("Restore cannot put the registry entry back after a failed restoration", slog.String("id", id), slog.String("error", undoErr.Error()))
			err = errors.Join(err, ErrRestoreRollbackFailed, fmt.Errorf("the registry entry of %s could not be put back: %w", id, undoErr))
		}
		return nil, err
	}
	logger.Info("file restored", slog.String("file", dest), slog.String("reason", locked.Reason))
	if e := os.Remove(lockPath); e != nil {
		logger.Error("Restore cannot remove lock file", slog.String("error", e.Error()))
	}
	return nil, nil
}

// publishThenRegister restores a container that has no registry entry: the file is
// published first and the entry created after, so that no entry ever allows a
// content that was not restored.
func (q *QuarantineHandler) publishThenRegister(ctx context.Context, root *os.Root, tmpName, base, id, dest, sha, lockPath, reason string, hook func(ctx context.Context, id, dest, sha256 string), tmpRemoved *bool) (notify func(), err error) {
	removed, err := publishRestored(root, tmpName, base)
	*tmpRemoved = removed
	if err != nil {
		return nil, err
	}
	logger.Info("file restored", slog.String("file", dest), slog.String("reason", reason))
	if e := os.Remove(lockPath); e != nil {
		logger.Error("Restore cannot remove lock file", slog.String("error", e.Error()))
	}
	entry := Entry{ID: id, SHA256: sha, CreatedAt: now(), RestoredAt: now(), InitialLocation: dest}
	if e := q.registry.Set(context.WithoutCancel(ctx), &entry); e != nil {
		logger.Error("Restore published a file but cannot register it: its content will be quarantined again", slog.String("id", id), slog.String("file", dest), slog.String("error", e.Error()))
		return nil, errors.Join(ErrRestoredNotRegistered, fmt.Errorf("the entry of %s could not be written: %w", id, e))
	}
	if hook != nil {
		bound := context.WithoutCancel(ctx)
		notify = func() { hook(bound, id, dest, sha) }
	}
	return notify, nil
}

// QuarantinedFile is a container of the quarantine directory: the index it holds
// and its id.
type QuarantinedFile struct {
	LockEntry
	ID string
}

// ListQuarantinedFiles lists every container of the quarantine directory without
// needing the password (both formats store their index in cleartext). Only the
// top level is read, and only regular files named like a container: a link, a
// sub-directory or a special file called "….lock", or a name that is not an id,
// is skipped with a warning. A single unreadable or malformed container is
// logged and skipped; only a failure to read the directory itself surfaces as an
// error to the caller.
func (q *QuarantineHandler) ListQuarantinedFiles(ctx context.Context) iter.Seq2[*QuarantinedFile, error] {
	return func(yield func(f *QuarantinedFile, err error) bool) {
		q.mu.RLock()
		locker := q.locker
		location := q.location
		q.mu.RUnlock()

		dir, err := openFolder(location)
		if err != nil {
			yield(nil, err)
			return
		}
		defer closeQuietly(dir, "quarantine directory")
		for {
			entries, readErr := dir.ReadDir(listBatch)
			for _, de := range entries {
				if ctx.Err() != nil {
					return
				}
				if !listOne(location, locker, de, yield) {
					return
				}
			}
			if errors.Is(readErr, io.EOF) {
				return
			}
			if readErr != nil {
				yield(nil, readErr)
				return
			}
		}
	}
}

// listBatch is how many names of the quarantine directory are read at a time.
const listBatch = 256

func openFolder(location string) (*os.File, error) {
	return os.Open(filepath.Clean(location))
}

// listOne lists one name of the directory; it returns false when the caller
// stopped the iteration.
func listOne(location string, locker fileLocker, de fs.DirEntry, yield func(*QuarantinedFile, error) bool) bool {
	name := de.Name()
	if !strings.HasSuffix(name, ".lock") {
		return true
	}
	if !lockFileName.MatchString(name) {
		logger.Warn("list quarantined: not the name of a container, skipped", slog.String("name", name))
		return true
	}
	file, stat, err := openContainer(location, name)
	if err != nil {
		logger.Warn("list quarantined: not a container, skipped", slog.String("name", name), slog.String("error", err.Error()))
		return true
	}
	entry, err := locker.GetHeader(file, stat.Size())
	closeQuietly(file, "container file")
	if err != nil {
		logger.Warn("list quarantined: cannot read header", slog.String("name", name), slog.String("error", err.Error()))
		return true
	}
	return yield(&QuarantinedFile{LockEntry: entry, ID: strings.TrimSuffix(name, ".lock")}, nil)
}
