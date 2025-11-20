package quarantine

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

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

type Config struct {
	Location         string
	RegistryLocation string
	LockPassword     string
}

type QuarantineHandler struct {
	locker   fileLocker
	registry quarantineRegistry
	location string
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

	registry, err := newSQLiteRegistry(ctx, conf.RegistryLocation)
	if err != nil {
		return
	}
	locker := fileLock{Password: conf.LockPassword}
	quarantineHandler = &QuarantineHandler{
		registry: registry,
		locker:   &locker,
		location: conf.Location,
	}
	return
}

func (q *QuarantineHandler) Reconfigure(ctx context.Context, newConfig Config) (err error) {
	q.locker = &fileLock{Password: newConfig.LockPassword}

	err = q.registry.Migrate(ctx, newConfig.RegistryLocation)
	if err != nil {
		return err
	}

	if newConfig.Location == "" {
		newConfig.Location = config.DefaultQuarantineLocation
	}

	if newConfig.Location == q.location {
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
	err = q.moveQuarantinedFiles(ctx, q.location, newConfig.Location)
	if err != nil {
		return
	}
	q.location = newConfig.Location
	return
}

func (q *QuarantineHandler) Quarantine(ctx context.Context, file string, fileSHA256 string, malwares []string) (location string, id string, err error) {
	entry := Entry{
		ID:              ComputeCacheID(file, fileSHA256),
		SHA256:          fileSHA256,
		InitialLocation: file,
	}
	stat, err := os.Stat(file)
	if err != nil {
		return
	}
	entry.QuarantineLocation = filepath.Join(q.location, entry.ID+".lock")

	fOut, err := os.Create(entry.QuarantineLocation)
	if err != nil {
		return
	}
	defer func() {
		if e := fOut.Close(); e != nil {
			logger.Warn("could not close output quarantined file", slog.String("file", entry.QuarantineLocation), slog.String("error", e.Error()))
		}
	}()

	fIn, err := os.Open(filepath.Clean(file))
	if err != nil {
		return
	}
	defer func() {
		if e := fIn.Close(); e != nil {
			logger.Warn("could not close input quarantined file", slog.String("file", file), slog.String("error", e.Error()))
		}
	}()

	malware := "unknown"
	if len(malwares) > 0 {
		malware = malwares[0]
	}
	if err = q.locker.LockFile(file, fIn, stat, "malware: "+malware, fOut); err != nil {
		return
	}
	if err = q.registry.Set(ctx, &entry); err != nil {
		return
	}
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
	case errors.Is(getEntryErr, ErrEntryNotFound):
		// ok
		return
	default:
		err = getEntryErr
		return
	}
}

func (q *QuarantineHandler) Restore(ctx context.Context, id string) (err error) {
	fPath := filepath.Join(q.location, id+".lock")
	f, err := os.Open(filepath.Clean(fPath))
	if err != nil {
		return
	}
	// prepare file handle to be closed
	// if we correctly restore the file we must delete the lock file
	deleteLocked := false
	defer func() {
		if e := f.Close(); e != nil {
			logger.Error("QuarantineAction cannot close file", slog.String("error", e.Error()))
		}
		if deleteLocked {
			if e := os.Remove(f.Name()); e != nil {
				logger.Error("QuarantineAction cannot remove file", slog.String("error", e.Error()))
			}
		}
	}()
	header, err := q.locker.GetHeader(f)
	if err != nil {
		return
	}
	out, err := os.Create(filepath.Clean(header.Filepath))
	if err != nil {
		return
	}
	defer func() {
		if e := out.Close(); e != nil {
			logger.Error("cannot close restored file", slog.String("file", header.Filepath), slog.String("error", e.Error()))
		}
		if err != nil {
			if e := os.Remove(out.Name()); e != nil {
				logger.Error("cannot remove restored file after error", slog.String("file", header.Filepath), slog.String("error", e.Error()))
			}
		}
	}()
	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return
	}
	file, info, reason, err := q.locker.UnlockFile(f, out)
	if err != nil {
		return
	}
	err = restoreFileInfo(out.Name(), info)
	if err != nil {
		return
	}
	entry, err := q.registry.Get(ctx, id)
	if err == nil {
		entry.QuarantineLocation = ""
		entry.RestoredAt = Now()
		err = q.registry.Set(ctx, entry)
		if err != nil {
			logger.Error("error set cache", slog.String("sha256", entry.SHA256), slog.String("error", err.Error()))
		}
	}
	logger.Info("file restored", slog.String("file", file), slog.String("reason", reason))
	// from here we want the lock file to be deleted
	deleteLocked = true
	return
}

type QuarantinedFile struct {
	LockEntry
	ID string
}

func (q *QuarantineHandler) ListQuarantinedFiles(ctx context.Context) iter.Seq2[*QuarantinedFile, error] {
	return func(yield func(f *QuarantinedFile, err error) bool) {
		err := filepath.WalkDir(q.location, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				logger.Warn("list quarantined error", slog.String("error", err.Error()))
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
			file, err := os.Open(filepath.Clean(path))
			if err != nil {
				return err
			}
			defer func() {
				if e := file.Close(); e != nil {
					logger.Error("QuarantineAction cannot close file", slog.String("error", e.Error()))
				}
			}()

			entry, err := q.locker.GetHeader(file)
			if err != nil {
				return err
			}
			ID := strings.TrimSuffix(filepath.Base(path), ".lock")

			if !yield(&QuarantinedFile{LockEntry: entry, ID: ID}, nil) {
				return nil
			}
			return err
		})
		if err != nil {
			yield(nil, err)
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

		moveErr := os.Rename(path, newPath)
		if moveErr != nil {
			return moveErr
		}

		id := strings.TrimSuffix(filename, ".lock")
		entry, getErr := q.registry.Get(ctx, id)
		if getErr != nil {
			if errors.Is(getErr, ErrEntryNotFound) {
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

func restoreFileInfo(path string, info os.FileInfo) (err error) {
	err = os.Chmod(path, info.Mode())
	if err != nil {
		return
	}
	if stat, ok := info.Sys().(*tar.Header); ok {
		err = os.Chown(path, stat.Uid, stat.Gid)
		if err != nil {
			logger.Error("error chown file", slog.String("path", path), slog.String("error", err.Error()))
		}
		err = os.Chtimes(path, stat.AccessTime, stat.ModTime)
		if err != nil {
			logger.Error("error chtimes file", slog.String("path", path), slog.String("error", err.Error()))
		}
	}
	return
}
