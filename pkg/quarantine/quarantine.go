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
	// Wrap reader so LockFile I/O respects the context timeout
	fInCtxAware := &ctxReader{ctx: ctx, r: fIn}
	if err = q.locker.LockFile(file, fInCtxAware, stat, "malware: "+malware, fOut); err != nil {
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
	restored := false
	defer func() {
		if e := out.Close(); e != nil {
			logger.Error("cannot close restored file", slog.String("file", header.Filepath), slog.String("error", e.Error()))
		}
		if err != nil && !restored {
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

	restored = true
	deleteLocked = true

	logger.Info("file restored", slog.String("file", file), slog.String("reason", reason))
	entry, err := q.registry.Get(ctx, id)
	if err != nil {
		return
	}

	entry.QuarantineLocation = ""
	entry.RestoredAt = Now()
	err = q.registry.Set(ctx, entry)
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

			relPath, err := filepath.Rel(q.location, path)
			if err != nil {
				return err
			}
			file, err := os.OpenInRoot(q.location, relPath)
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

		if moveErr := MoveFile(path, newPath); moveErr != nil {
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

	dstFile, err := os.Create(dst) //nolint:gosec // G304 - dst is constructed from controlled paths
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
