package quarantine

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

// StagingDir is the private directory, at the root of a destination, where a
// file crossing file systems is copied before being linked to its final name.
// Whoever consumes the destination must ignore it.
const StagingDir = ".gmhost-staging"

// maxFileNameLen is the usual file name limit, in bytes.
const maxFileNameLen = 255

// stagingTTL is how old a leftover of a crashed move must be to be purged.
const stagingTTL = 24 * time.Hour

var (
	// ErrDestinationExists is returned when the destination of a move is
	// taken: moves never overwrite.
	ErrDestinationExists = errors.New("destination already exists")
	// ErrStagingUnsafe is returned when the transit directory is not a private
	// directory of this process owner.
	ErrStagingUnsafe = errors.New("transit directory is not a private directory")
	// ErrSourceNotRemovable is returned when the source of a move cannot be
	// removed for a lasting reason (permission, read-only file system): the
	// moved file is taken back, retrying cannot help.
	ErrSourceNotRemovable = errors.New("source cannot be removed")
	// ErrSourceChanged is returned when the source changed while it was copied.
	ErrSourceChanged = errors.New("source changed while it was moved")
)

// Replaced in tests: a refused link, another device, an error during a copy,
// a system without atomic rename, a collision of transit names.
var (
	osLink           = os.Link
	copyData         = io.Copy
	atomicRename     = renameNoReplaceAtomicOS
	stagedNameSuffix = randomHex
)

// linkMu lets links run in parallel while the rename fallback, which has to
// check then rename, excludes them and itself: only this process writes the
// destination.
var linkMu sync.RWMutex

// stagingPurged remembers the transit directories already purged.
var stagingPurged sync.Map

// IsRemovalRefused reports whether err is the refusal of the file system or of
// its permissions (EACCES, EPERM, EROFS): a lasting one, retrying cannot help.
func IsRemovalRefused(err error) bool {
	return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EROFS)
}

// MarkRemovalRefused wraps a refusal of a removal in ErrSourceNotRemovable.
func MarkRemovalRefused(err error) error {
	if IsRemovalRefused(err) {
		return fmt.Errorf("%w: %w", ErrSourceNotRemovable, err)
	}
	return err
}

// MoveFileNoReplace moves src to dst and never overwrites dst. stagingDir must
// be on the same file system as dst: it receives the copy when src and dst are
// on different file systems. It returns ErrDestinationExists when dst exists.
func MoveFileNoReplace(src, dst, stagingDir string) error {
	_, err := moveFile(src, dst, stagingDir, func(int) (string, bool) { return "", false })
	return err
}

// MoveFileResolvingConflicts moves src to dst, or when dst exists to a
// ConflictName next to it, up to maxConflicts names; the last
// ErrDestinationExists is returned past that. The copy made for a move across
// file systems is made once and published under each candidate name. It
// returns the path the file now has.
func MoveFileResolvingConflicts(src, dst, stagingDir string, now func() time.Time, maxConflicts int) (string, error) {
	return moveFile(src, dst, stagingDir, func(attempt int) (string, bool) {
		if attempt >= maxConflicts {
			return "", false
		}
		return ConflictName(dst, now(), attempt), true
	})
}

// moveFile publishes src under dst, then under next(attempt) while the name is
// taken. When src is on another device it is first copied into stagingDir.
func moveFile(src, dst, stagingDir string, next func(attempt int) (string, bool)) (final string, err error) {
	cur, staged, target := src, "", dst
	var srcInfo fs.FileInfo
	defer func() {
		if staged != "" {
			if e := os.Remove(staged); e != nil && !errors.Is(e, fs.ErrNotExist) {
				logger.Error("move cannot remove the staged copy", slog.String("file", staged), slog.String("error", e.Error()))
			}
		}
	}()
	for attempt := 0; ; {
		renamed, pubErr := publishNoReplace(cur, target)
		switch {
		case pubErr == nil:
			return target, finishMove(src, target, cur == src, renamed, srcInfo)
		case errors.Is(pubErr, syscall.EXDEV) && staged == "":
			if staged, srcInfo, err = stageCopy(src, stagingDir); err != nil {
				return "", err
			}
			cur = staged
		case errors.Is(pubErr, ErrDestinationExists):
			name, ok := next(attempt)
			if !ok {
				return "", pubErr
			}
			target = name
			attempt++
		default:
			return "", pubErr
		}
	}
}

// finishMove removes what is left of the source once the destination exists.
func finishMove(src, dst string, linkedSource, renamed bool, copied fs.FileInfo) error {
	switch {
	case renamed && linkedSource:
		return nil // the rename moved the source itself
	case linkedSource:
		return removeSource(src, dst, true)
	default:
		return removeCopiedSource(src, dst, copied)
	}
}

// publishNoReplace makes dst name the file src without replacing anything. On
// Linux and Windows the rename itself refuses an existing destination; the
// hard link (EEXIST is atomic) is tried first elsewhere, and when the file
// system refuses links, a check followed by a rename under an exclusive lock
// (a small window remains against writers outside this process). renamed
// reports that src is gone rather than still there under its old name.
func publishNoReplace(src, dst string) (renamed bool, err error) {
	linkMu.RLock()
	err = osLink(src, dst)
	linkMu.RUnlock()
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, fs.ErrExist):
		return false, fmt.Errorf("%w: %s", ErrDestinationExists, dst)
	case errors.Is(err, syscall.EPERM), errors.Is(err, syscall.ENOTSUP), errors.Is(err, syscall.EMLINK):
		return true, renameNoReplace(src, dst)
	default:
		return false, err
	}
}

// renameNoReplace renames src to dst without ever replacing dst: atomically
// when the system offers it, else under an exclusive lock.
func renameNoReplace(src, dst string) error {
	handled, err := atomicRename(src, dst)
	if handled {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", ErrDestinationExists, dst)
		}
		return err
	}
	linkMu.Lock()
	defer linkMu.Unlock()
	if _, err := os.Lstat(dst); err == nil {
		return fmt.Errorf("%w: %s", ErrDestinationExists, dst)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return os.Rename(src, dst)
}

// removeSource ends a link-based move: only the old name is left to remove,
// provided it still is the file that was linked. When the removal fails dst is
// removed too, so the file is never in two places.
func removeSource(src, dst string, linked bool) error {
	srcInfo, err := os.Lstat(src)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return rollback(dst, fmt.Errorf("could not examine %s after moving it: %w", src, err))
	}
	if linked {
		dstInfo, err := os.Lstat(dst)
		if err != nil || !os.SameFile(srcInfo, dstInfo) {
			// The name now holds another file than the one that was linked: the
			// destination is not what was verified either, it is taken back.
			return rollback(dst, fmt.Errorf("%w: %s is no longer the file that was moved", ErrSourceChanged, src))
		}
	}
	if err := os.Remove(src); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return rollback(dst, fmt.Errorf("could not remove %s after moving it: %w", src, MarkRemovalRefused(err)))
	}
	return nil
}

// removeCopiedSource removes src after a copy, unless it changed since it was
// read: then the copy is removed and the source is kept.
func removeCopiedSource(src, dst string, copied fs.FileInfo) error {
	now, err := os.Lstat(src)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || !unchanged(copied, now) {
		return rollback(dst, fmt.Errorf("%w: %s", ErrSourceChanged, src))
	}
	return removeSource(src, dst, false)
}

func rollback(dst string, cause error) error {
	if e := os.Remove(dst); e != nil && !errors.Is(e, fs.ErrNotExist) {
		logger.Error("move cannot roll back the destination", slog.String("file", dst), slog.String("error", e.Error()))
	}
	return cause
}

// stageCopy copies src, read through a single descriptor, into a new file of
// the transit directory, and returns its path with the source info taken from
// that descriptor. The copy is verified: size, and a source unchanged since.
func stageCopy(src, stagingDir string) (staged string, srcInfo fs.FileInfo, err error) {
	in, err := os.Open(filepath.Clean(src))
	if err != nil {
		return "", nil, err
	}
	defer func() {
		if e := in.Close(); e != nil {
			logger.Error("move cannot close the source file", slog.String("file", src), slog.String("error", e.Error()))
		}
	}()
	return stageFrom(in, src, stagingDir, func(before fs.FileInfo) error { return checkUnchanged(in, before, src) })
}

// stageFrom copies in into a new file of the transit directory. verify is
// called once the copy is made, with the file as it was when it began.
func stageFrom(in *os.File, label, stagingDir string, verify func(before fs.FileInfo) error) (staged string, srcInfo fs.FileInfo, err error) {
	if err = prepareStaging(stagingDir); err != nil {
		return "", nil, err
	}
	srcInfo, err = in.Stat()
	if err != nil {
		return "", nil, err
	}
	if !srcInfo.Mode().IsRegular() {
		return "", nil, fmt.Errorf("%s is not a regular file", label)
	}
	staged, out, err := createStaged(stagingDir)
	if err != nil {
		return "", nil, err
	}
	defer func() {
		if err != nil {
			if e := os.Remove(staged); e != nil && !errors.Is(e, fs.ErrNotExist) {
				logger.Error("move cannot remove the staged copy", slog.String("file", staged), slog.String("error", e.Error()))
			}
			staged = ""
		}
	}()
	n, err := copyData(out, in)
	if err == nil && n != srcInfo.Size() {
		err = fmt.Errorf("%w: copied %d bytes of %d", ErrSourceChanged, n, srcInfo.Size())
	}
	if err == nil {
		err = verify(srcInfo)
	}
	if err == nil {
		// Permission bits only, on the descriptor: setuid and setgid must not
		// follow the copy.
		err = out.Chmod(srcInfo.Mode() & 0o777)
	}
	if err == nil {
		err = out.Sync()
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	return staged, srcInfo, err
}

// checkUnchanged compares what the descriptor now says, and what the path now
// designates, with the file as it was when the copy began.
func checkUnchanged(in *os.File, before fs.FileInfo, path string) error {
	after, err := in.Stat()
	if err != nil {
		return err
	}
	byPath, err := os.Lstat(path)
	if err != nil || !unchanged(before, after) || !unchanged(before, byPath) {
		return fmt.Errorf("%w: %s", ErrSourceChanged, path)
	}
	return nil
}

// unchanged reports whether now is the very file that before described: same
// identity, size, modification time and, where the system tells it, change
// time. A rewrite with the modification time reset moves the change time, a
// swap for another file changes the identity.
func unchanged(before, now fs.FileInfo) bool {
	if !os.SameFile(before, now) || before.Size() != now.Size() || !before.ModTime().Equal(now.ModTime()) {
		return false
	}
	b, bok := changeTime(before)
	n, nok := changeTime(now)
	return !bok || !nok || b.Equal(n)
}

// prepareStaging creates the transit directory, checks it is a private
// directory of this process owner, and on first use purges the leftovers of
// crashed moves.
func prepareStaging(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 || !ownedByCurrentUser(fi) || fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s", ErrStagingUnsafe, dir)
	}
	if _, done := stagingPurged.LoadOrStore(dir, struct{}{}); !done {
		purgeStaging(dir)
	}
	return nil
}

func purgeStaging(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() || time.Since(info.ModTime()) < stagingTTL {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			logger.Warn("cannot purge an old transit file", slog.String("file", e.Name()), slog.String("error", err.Error()))
		}
	}
}

func createStaged(stagingDir string) (string, *os.File, error) {
	var lastErr error
	for range 5 {
		suffix, err := stagedNameSuffix(8)
		if err != nil {
			return "", nil, err
		}
		name := filepath.Join(stagingDir, suffix)
		f, err := os.OpenFile(filepath.Clean(name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return name, f, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", nil, err
		}
		lastErr = err
	}
	return "", nil, lastErr
}

// ConflictName returns the name given to a file whose destination dst is
// taken: <base>.conflict-<UTC time>[-n]<ext>, in the same directory. The name
// never exceeds 255 bytes: the base is cut first, on a character boundary,
// then the extension when even that is not enough; the suffix is never cut.
func ConflictName(dst string, t time.Time, n int) string {
	dir, name := filepath.Split(dst)
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	suffix := ".conflict-" + t.UTC().Format("20060102T150405Z")
	if n > 0 {
		suffix += "-" + strconv.Itoa(n)
	}
	if room := maxFileNameLen - len(suffix); len(ext) > room {
		ext = truncateOnRune(ext, room)
	}
	return FitName(dir, base, suffix+ext)
}

// FitName joins dir, base and suffix into a path whose last element stays
// within 255 bytes: the base is cut, on a character boundary, never the suffix.
func FitName(dir, base, suffix string) string {
	if room := maxFileNameLen - len(suffix); len(base) > room {
		base = truncateOnRune(base, room)
	}
	return dir + base + suffix
}

func truncateOnRune(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
