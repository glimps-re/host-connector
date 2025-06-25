package scanner

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/glimps-re/host-connector/pkg/cache"
	"github.com/glimps-re/host-connector/pkg/filesystem"
)

type Actions struct {
	Deleted    bool
	Quarantine bool
	Log        bool
	Inform     bool
	Verbose    bool
	InformDest io.Writer
	Move       bool
}

// for test purposes
var (
	now = time.Now
)

type Action interface {
	Handle(path string, result SummarizedGMalwareResult, report *Report) error
}

type NoAction struct{}

func (*NoAction) Handle(path string, result SummarizedGMalwareResult, report *Report) error {
	return nil
}

type LogAction struct {
	logger *slog.Logger
}

type ReportAction struct{}

func (a *ReportAction) Handle(path string, result SummarizedGMalwareResult, report *Report) (err error) {
	report.FileName = path
	report.Malicious = result.Malware
	report.Sha256 = result.SHA256
	report.Malware = result.Malwares
	return
}

func (a *LogAction) Handle(path string, result SummarizedGMalwareResult, report *Report) (err error) {
	if result.Malware {
		if len(result.Malwares) == 0 {
			result.Malwares = []string{}
		}
		if len(result.MaliciousSubfiles) == 0 {
			a.logger.Info("info scanned", slog.String("file", path), slog.String("sha256", result.SHA256), slog.Bool("malware", true), slog.Any("malwares", result.Malwares))
		} else {
			a.logger.Info("info scanned", slog.String("file", path), slog.String("sha256", result.SHA256), slog.Bool("malware", true), slog.Any("malwares", result.Malwares), slog.Any("malicious-subfiles", result.MaliciousSubfiles))
		}
	} else {
		a.logger.Debug("info scanned", slog.String("file", path), slog.String("sha256", result.SHA256), slog.Bool("malware", false))
	}
	return nil
}

type MultiAction struct {
	Actions []Action
}

func (a *MultiAction) Handle(path string, result SummarizedGMalwareResult, report *Report) (err error) {
	for _, h := range a.Actions {
		if err = h.Handle(path, result, report); err != nil {
			return
		}
	}
	return
}

func NewMultiAction(actions ...Action) *MultiAction {
	return &MultiAction{Actions: actions}
}

type RemoveFileAction struct {
	fs filesystem.FileSystem
}

func NewRemoveFileAction(fs filesystem.FileSystem) *RemoveFileAction {
	return &RemoveFileAction{fs}
}

func (a *RemoveFileAction) Handle(path string, result SummarizedGMalwareResult, report *Report) (err error) {
	if !result.Malware {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	err = a.fs.Remove(ctx, path)
	if err != nil {
		return
	}
	report.Deleted = true
	return
}

type QuarantineAction struct {
	fs       filesystem.FileSystem
	cache    cache.Cacher
	location string
	locker   Locker
}

func NewQuarantineAction(fs filesystem.FileSystem, cache cache.Cacher, location string, locker Locker) *QuarantineAction {
	return &QuarantineAction{fs: fs, cache: cache, location: location, locker: locker}
}

func (a *QuarantineAction) Handle(path string, result SummarizedGMalwareResult, report *Report) (err error) {
	// skip legit files
	if !result.Malware {
		return
	}

	if a.location == "" {
		return errors.New("quarantine location must be specified")
	}

	entry := &cache.Entry{
		ID:              cache.ComputeCacheID(path),
		Sha256:          result.SHA256,
		InitialLocation: path,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// ensure folder/bucket still exists
	err = a.fs.MkdirAll(ctx, a.location, 0o755)
	if err != nil {
		return
	}
	// Get file info using filesystem abstraction
	stat, err := a.fs.Stat(ctx, path)
	if err != nil {
		return
	}

	entry.QuarantineLocation = filepath.Join(a.location, entry.ID+".lock")

	fout, err := a.fs.Create(ctx, entry.QuarantineLocation)
	if err != nil {
		return
	}
	defer func() {
		if e := fout.Close(); e != nil {
			Logger.Warn("could not close quarantine file", slog.String("path", entry.QuarantineLocation), slog.String("error", e.Error()))
		}
	}()

	inputFile, err := a.fs.Open(ctx, path)
	if err != nil {
		return
	}
	defer func() {
		if e := inputFile.Close(); e != nil {
			Logger.Warn("could not close input file", slog.String("path", path), slog.String("error", e.Error()))
		}
	}()

	malware := "unknown"
	if len(result.Malwares) > 0 {
		malware = result.Malwares[0]
	}

	if err = a.locker.LockFile(path, inputFile, stat, "malware: "+malware, fout); err != nil {
		return
	}

	if err = a.cache.Set(entry); err != nil {
		return
	}

	report.QuarantineLocation = entry.QuarantineLocation
	return nil
}

func (a *QuarantineAction) Restore(id string) (err error) {
	if a.location == "" {
		return errors.New("quarantine location must be specified")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// Construct file path appropriately for the filesystem type
	var fpath string
	if a.fs.IsLocal() {
		fpath = filepath.Join(a.location, id+".lock")
	} else {
		fpath = path.Join(a.location, id+".lock")
	}

	f, err := a.fs.Open(ctx, fpath)
	if err != nil {
		return
	}
	// prepare file handle to be closed
	// if we correctly restore the file we must delete the lock file
	deleteLocked := false
	defer func() {
		if e := f.Close(); e != nil {
			Logger.Warn("could not close locked file properly", slog.String("path", fpath), slog.String("error", e.Error()))
		}
		if deleteLocked {
			if e := a.fs.Remove(context.Background(), fpath); e != nil {
				Logger.Warn("could not remove locked file properly", slog.String("path", fpath), slog.String("error", e.Error()))
			}
		}
	}()

	header, err := a.locker.GetHeader(f)
	if err != nil {
		return
	}

	out, err := a.fs.Create(ctx, header.Filepath)
	if err != nil {
		return
	}
	defer func() {
		if err := out.Close(); err != nil {
			Logger.Warn("could not close restored file properly", slog.String("path", header.Filepath), slog.String("error", err.Error()))
		}
	}()

	defer func() {
		if err != nil {
			if e := a.fs.Remove(context.Background(), header.Filepath); e != nil {
				Logger.Warn("could not remove restored file properly after error", slog.String("path", header.Filepath), slog.String("error", e.Error()))
			}
		}
	}()

	// We need to seek back to start for unlocking
	if seeker, ok := f.(io.Seeker); ok {
		_, err = seeker.Seek(0, io.SeekStart)
		if err != nil {
			return
		}
	} else {
		// If we can't seek, we need to reopen the file
		if e := f.Close(); e != nil {
			Logger.Warn("could not close file before reopening", slog.String("path", fpath), slog.String("error", e.Error()))
		}
		f, err = a.fs.Open(ctx, fpath)
		if err != nil {
			return
		}
	}

	file, info, reason, err := a.locker.UnlockFile(f, out)
	if err != nil {
		return
	}

	// Only try to restore file info for local filesystems
	if a.fs.IsLocal() {
		err = restoreFileInfo(header.Filepath, info)
		if err != nil {
			Logger.Warn("could not restore file info", slog.String("path", header.Filepath), slog.String("error", err.Error()))
			// Don't return error here, file restoration is more important than metadata
		}
	}

	entry, err := a.cache.Get(id)
	if err == nil {
		entry.QuarantineLocation = ""
		entry.RestoredAt = now()
		err = a.cache.Set(entry)
		if err != nil {
			Logger.Error("error set cache", slog.String("sha256", entry.Sha256), slog.String("err", err.Error()))
		}
	}

	Logger.Info("file restored", slog.String("file", file), slog.String("reason", reason))
	// from here we want the lock file to be deleted
	deleteLocked = true

	return err
}

func restoreFileInfo(path string, info os.FileInfo) (err error) {
	err = os.Chmod(path, info.Mode())
	if err != nil {
		return
	}
	if stat, ok := info.Sys().(*tar.Header); ok {
		err = os.Chown(path, stat.Uid, stat.Gid)
		if err != nil {
			Logger.Error("error chown file", slog.String("path", path), slog.String("err", err.Error()))
		}
		err = os.Chtimes(path, stat.AccessTime, stat.ModTime)
		if err != nil {
			Logger.Error("error chtimes file", slog.String("path", path), slog.String("err", err.Error()))
		}
	}
	return
}

type QuarantinedFile struct {
	LockEntry
	ID string
}

func (a *QuarantineAction) ListQuarantinedFiles(ctx context.Context) (qfiles chan QuarantinedFile, err error) {
	if a.location == "" {
		return nil, errors.New("quarantine location must be specified")
	}

	qfiles = make(chan QuarantinedFile)
	go func() {
		defer close(qfiles)

		err := a.fs.WalkDir(ctx, a.location, func(filePath string, d fs.DirEntry, err error) error {
			if err != nil {
				Logger.Warn("list quarantined error", slog.String("error", err.Error()))
				return nil
			}
			if ctx.Err() != nil {
				return filepath.SkipAll
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(filePath, ".lock") {
				return nil
			}

			file, err := a.fs.Open(ctx, filePath)
			if err != nil {
				Logger.Warn("could not open quarantined file", slog.String("path", filePath), slog.String("error", err.Error()))
				return nil
			}
			defer func() {
				if err := file.Close(); err != nil {
					Logger.Warn("could not close lock file properly", slog.String("path", filePath), slog.String("error", err.Error()))
				}
			}()

			entry, err := a.locker.GetHeader(file)
			if err != nil {
				Logger.Warn("could not get header from quarantined file", slog.String("path", filePath), slog.String("error", err.Error()))
				return nil
			}

			// Extract ID from filename
			var fileName string
			if a.fs.IsLocal() {
				fileName = filepath.Base(filePath)
			} else {
				fileName = path.Base(filePath)
			}
			ID := strings.TrimSuffix(fileName, ".lock")

			select {
			case <-ctx.Done():
				return filepath.SkipAll
			case qfiles <- QuarantinedFile{LockEntry: entry, ID: ID}:
				return nil
			}
		})
		if err != nil {
			Logger.Error("error walking quarantine directory", slog.String("location", a.location), slog.String("error", err.Error()))
		}
	}()
	return qfiles, nil
}

type InformAction struct {
	Verbose bool
	Out     io.Writer
}

func (a *InformAction) Handle(path string, result SummarizedGMalwareResult, report *Report) (err error) {
	if a.Out == nil {
		a.Out = os.Stdout
	}
	switch {
	case result.Malware:
		sb := strings.Builder{}
		if _, e := fmt.Fprintf(&sb, "file %s seems malicious", path); e != nil {
			Logger.Warn("could not write output infos (file seems malicious)", slog.String("error", e.Error()))
		}
		if len(result.Malwares) > 0 {
			if _, e := fmt.Fprintf(&sb, " [%v]", result.Malwares); e != nil {
				Logger.Warn("could not write output infos (malwares result)", slog.String("error", e.Error()))
			}
		}
		if report.QuarantineLocation != "" {
			if _, e := fmt.Fprintf(&sb, ", it has been quarantined to %s", report.QuarantineLocation); e != nil {
				Logger.Warn("could not write output infos (file quarantined)", slog.String("error", e.Error()))
			}
		}
		if report.Deleted {
			if _, e := fmt.Fprint(&sb, ", it has been deleted"); e != nil {
				Logger.Warn("could not write output infos (file deleted)", slog.String("error", e.Error()))
			}
		}
		if _, e := fmt.Fprintln(a.Out, sb.String()); e != nil {
			Logger.Warn("could not output infos (report)", slog.String("error", e.Error()))
		}
	case report.MoveTo != "":
		if _, e := fmt.Fprintf(a.Out, "file %s has been move to %s\n", path, report.MoveTo); e != nil {
			Logger.Warn("could not output infos (report)", slog.String("error", e.Error()))
		}
	case a.Verbose:
		if _, e := fmt.Fprintf(a.Out, "file %s no malware found\n", path); e != nil {
			Logger.Warn("could not output infos (malware found)", slog.String("error", e.Error()))
		}
	}
	return nil
}

type MoveAction struct {
	fs   filesystem.FileSystem
	dest string
	src  string
}

func NewMoveAction(fs filesystem.FileSystem, dest string, src string) (a *MoveAction, err error) {
	a = &MoveAction{}
	if fs.IsLocal() {
		dest, err = filepath.Abs(dest)
		if err != nil {
			return
		}
		src, err = filepath.Abs(src)
	}
	a.src = src
	a.dest = dest
	a.fs = fs
	return
}

func (a *MoveAction) Handle(path string, result SummarizedGMalwareResult, report *Report) (err error) {
	if a.fs.IsLocal() {
		path, err = filepath.Abs(path)
		if err != nil {
			return
		}
	}
	if strings.HasPrefix(path, a.src) {
		destSubpath, ok := strings.CutPrefix(path, a.src)
		if !ok {
			destSubpath = path
		}
		dest := filepath.Join(a.dest, destSubpath)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		err = a.fs.MkdirAll(ctx, filepath.Dir(dest), 0o755)
		if err != nil {
			return
		}
		// do not move malicious files
		// write report instead
		if result.Malware {
			if f, err := a.fs.Create(ctx, dest+".locked.json"); err == nil {
				defer func() {
					if e := f.Close(); e != nil {
						Logger.Warn("cloud not close lock file properly", slog.String("path", dest+".locked.json"), slog.String("error", e.Error()))
					}
				}()
				w := json.NewEncoder(f)
				w.SetIndent("", "  ")
				if err = w.Encode(report); err != nil {
					return err
				}
			}
			return
		}
		err = a.fs.Rename(ctx, path, dest)
		if err != nil {
			return err
		}
		report.MoveTo = dest
		return

	}
	return errors.New("file not in paths")
}
