//go:build linux

package scanner

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	tmpfsMagic uint32 = 0x01021994
	ramfsMagic uint32 = 0x858458f6
)

// statfsType returns the filesystem type of path; replaced in tests.
var statfsType = func(path string) (uint32, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return lowBits(st.Type), nil
}

// lowBits keeps the 32 bits of Statfs_t.Type: its width and sign differ
// between architectures (ramfsMagic is negative on 32-bit systems).
func lowBits[T ~int32 | ~int64 | ~uint32](v T) uint32 { return uint32(v) }

func inMemoryFS(path string) bool {
	t, err := statfsType(path)
	return err == nil && (t == tmpfsMagic || t == ramfsMagic)
}

func createWorkDirLock(path string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

// purgeOrphans removes the work directories of crashed processes next to own.
// A sibling is removed only when all the following hold: name gmhost-*, a real
// directory (not a link), owned by this user, mode 0o700, holding a regular
// .lock file whose lock is free. Anything else is a user folder and is kept.
func purgeOrphans(base, own string) {
	entries, err := os.ReadDir(base)
	if err != nil {
		logger.Warn("cannot list work dir base, orphans not purged", slog.String("base", base), slog.String("error", err.Error()))
		return
	}
	for _, e := range entries {
		full := filepath.Join(base, e.Name())
		if !strings.HasPrefix(e.Name(), workDirPrefix) || full == own {
			continue
		}
		if reason, kept := purgeIfOrphan(full); kept {
			logger.Warn("folder next to the work directory kept", slog.String("path", full), slog.String("reason", reason))
		}
	}
}

// purgeIfOrphan removes dir when it is an orphan work directory. It returns
// why dir was kept, and kept=false when it was removed or is held by a live
// process (nothing to report).
func purgeIfOrphan(dir string) (reason string, kept bool) {
	fi, err := os.Lstat(dir)
	if err != nil {
		return "cannot stat: " + err.Error(), true
	}
	if !fi.IsDir() {
		return "not a directory", true
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return "owned by another user", true
	}
	if fi.Mode().Perm() != dirPrivate {
		return "mode is not 0700", true
	}
	lock, err := os.OpenFile(filepath.Clean(filepath.Join(dir, workDirLock)), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "no lock file", true
	}
	defer func() {
		if e := lock.Close(); e != nil {
			logger.Warn("cannot close lock file", slog.String("path", dir), slog.String("error", e.Error()))
		}
	}()
	lfi, err := lock.Stat()
	if err != nil || !lfi.Mode().IsRegular() {
		return "lock is not a regular file", true
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return "", false // held by a live process
	}
	if err = os.RemoveAll(dir); err != nil {
		return "cannot remove: " + err.Error(), true
	}
	logger.Info("orphan work directory removed", slog.String("path", dir))
	return "", false
}
