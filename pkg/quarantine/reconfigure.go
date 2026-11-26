package quarantine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/glimps-re/host-connector/internal/pathutil"
	"github.com/glimps-re/host-connector/pkg/config"
)

// ErrRollbackIncomplete is returned, wrapped, when a failed Reconfigure could
// not put everything back: some lock files or registry entries may be in the
// new place. The handler cannot be trusted any more; stop it.
var ErrRollbackIncomplete = errors.New("quarantine rollback incomplete")

// rollbackTimeout bounds the rollback, which runs detached from the
// cancellation of the request that failed.
const rollbackTimeout = time.Minute

// locationMode is the mode of a quarantine directory the connector creates.
const locationMode = 0o700

// movedLock is a .lock file moved to the new location, with the registry entry
// as it was, so that a later failure puts everything back.
type movedLock struct {
	oldPath, newPath string
	previous         *Entry
}

// Reconfigure applies newConfig under the write lock, all or nothing. The new
// registry is built beside the current one and the lock files are moved first;
// the registry and the locker (the password) are switched last. Any error puts
// the moved files back, abandons the new registry and leaves the handler as it
// was.
func (q *QuarantineHandler) Reconfigure(ctx context.Context, newConfig Config) (err error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	newLocker, err := newQuarantineLocker(newConfig.LockPassword, newConfig.Format)
	if err != nil {
		return err
	}
	if newConfig.Location == "" {
		newConfig.Location = config.DefaultQuarantineLocation
	}

	registry := q.registry
	var newRegistry quarantineRegistry
	if registryLocation(newConfig.RegistryLocation) != q.registry.GetLocation() {
		mergeExisting := registryLocation(newConfig.RegistryLocation) == q.previousRegistry
		if newRegistry, err = q.registry.Clone(ctx, newConfig.RegistryLocation, mergeExisting); err != nil {
			return fmt.Errorf("cannot prepare the new quarantine registry: %w", err)
		}
		registry = newRegistry
	}

	var moved []movedLock
	var created []string
	if newConfig.Location != q.location {
		if overlap(q.location, newConfig.Location) {
			if newRegistry != nil {
				err = newRegistry.Discard()
			}
			return errors.Join(fmt.Errorf("the new quarantine directory %q and the current one %q are, or contain, one another", newConfig.Location, q.location), err)
		}
		if created, err = ensureLocation(newConfig.Location); err == nil {
			moved, err = moveLocks(ctx, q.location, newConfig.Location, registry)
		}
		if err != nil {
			if rbErr := q.rollback(context.WithoutCancel(ctx), moved, registry, newRegistry, created); rbErr != nil {
				return errors.Join(err, fmt.Errorf("%w: %w", ErrRollbackIncomplete, rbErr))
			}
			return err
		}
	}

	if newRegistry != nil {
		oldRegistry := q.registry
		q.previousRegistry = oldRegistry.GetLocation()
		q.registry = newRegistry
		if e := oldRegistry.Close(); e != nil {
			logger.Error("failed to close old registry database", slog.String("error", e.Error()))
		}
	}
	q.locker = newLocker
	q.location = newConfig.Location
	q.watched = slices.Clone(newConfig.WatchedPaths)
	return nil
}

// registryLocation is the form GetLocation reports for a configured location.
func registryLocation(configured string) string {
	if configured == "" {
		return "file::memory:"
	}
	return configured
}

// rollback undoes a failed Reconfigure, detached from the cancellation of ctx:
// moved files go back, then the registry entries changed in place are restored
// (only for files that are really back), an abandoned new registry and the
// directories created for it are removed. It returns what it could not undo.
func (q *QuarantineHandler) rollback(ctx context.Context, moved []movedLock, registry, newRegistry quarantineRegistry, created []string) error {
	ctx, cancel := context.WithTimeout(ctx, rollbackTimeout)
	defer cancel()
	var errs []error
	for _, m := range slices.Backward(moved) {
		if e := MoveFile(m.newPath, m.oldPath); e != nil {
			errs = append(errs, fmt.Errorf("%s: %w", m.newPath, e))
			continue
		}
		if newRegistry == nil && m.previous != nil {
			if e := registry.Set(ctx, m.previous); e != nil {
				errs = append(errs, fmt.Errorf("registry entry %s: %w", m.previous.ID, e))
			}
		}
	}
	if newRegistry != nil {
		if e := newRegistry.Discard(); e != nil {
			errs = append(errs, fmt.Errorf("new registry: %w", e))
		}
	}
	for _, dir := range slices.Backward(created) {
		if e := os.Remove(dir); e != nil && !errors.Is(e, os.ErrNotExist) {
			logger.Warn("cannot remove the new quarantine directory", slog.String("dir", dir), slog.String("error", e.Error()))
		}
	}
	return errors.Join(errs...)
}

// overlap reports whether one directory is, or contains, the other.
func overlap(a, b string) bool {
	return pathutil.Same(a, b) || pathutil.UnderResolved(a, b) || pathutil.UnderResolved(b, a)
}

// ensureLocation creates dir (mode 0700) when absent and returns the
// directories it created, outermost first.
func ensureLocation(dir string) (created []string, err error) {
	_, err = os.Stat(dir)
	switch {
	case err == nil:
		return nil, nil
	case errors.Is(err, os.ErrNotExist):
		for cur := dir; ; cur = filepath.Dir(cur) {
			if _, statErr := os.Stat(cur); statErr == nil || cur == filepath.Dir(cur) {
				break
			}
			created = append([]string{cur}, created...)
		}
		if err = os.MkdirAll(dir, locationMode); err != nil {
			return nil, fmt.Errorf("failed to create quarantine location: %w", err)
		}
		return created, nil
	default:
		return nil, err
	}
}

// moveLocks moves every .lock file directly in oldLocation to newLocation and
// points the registry entries at them. A destination that already exists is
// refused, never overwritten. A missing old directory has nothing to move. On
// error it returns what was moved so far.
func moveLocks(ctx context.Context, oldLocation, newLocation string, registry quarantineRegistry) (moved []movedLock, err error) {
	dirEntries, err := os.ReadDir(oldLocation)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot list the quarantine directory: %w", err)
	}
	for _, d := range dirEntries {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return moved, ctxErr
		}
		if !d.Type().IsRegular() || !strings.HasSuffix(d.Name(), ".lock") {
			continue
		}
		path := filepath.Join(oldLocation, d.Name())
		newPath := filepath.Join(newLocation, d.Name())
		if _, statErr := os.Lstat(newPath); statErr == nil {
			return moved, fmt.Errorf("%s already exists in the new quarantine directory: not overwritten", newPath)
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return moved, statErr
		}
		id := strings.TrimSuffix(d.Name(), ".lock")
		entry, getErr := registry.Get(ctx, id)
		hasEntry := getErr == nil
		if getErr != nil && !errors.Is(getErr, errEntryNotFound) {
			return moved, getErr
		}
		if err = MoveFile(path, newPath); err != nil {
			return moved, err
		}
		m := movedLock{oldPath: path, newPath: newPath}
		if hasEntry {
			previous := *entry
			m.previous = &previous
		}
		moved = append(moved, m)
		if hasEntry {
			entry.QuarantineLocation = newPath
			if err = registry.Set(ctx, entry); err != nil {
				return moved, err
			}
		}
	}
	return moved, nil
}
