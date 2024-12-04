package scanner

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/glimps-re/host-connector/pkg/cache"
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
	Now      = time.Now
	Rename   = os.Rename
	MkdirAll = os.MkdirAll
	Create   = os.Create
)

type Action interface {
	Handle(path string, result SummarizedGMalwareResult, report *Report) error
}

type NoAction struct{}

func (*NoAction) Handle(path string, result SummarizedGMalwareResult, report *Report) error {
	return nil
}

type QuarantineAction struct {
	cache  cache.Cacher
	root   string
	locker Locker
}

func NewQuarantineAction(cache cache.Cacher, root string, locker Locker) *QuarantineAction {
	return &QuarantineAction{cache: cache, root: root, locker: locker}
}

type LogAction struct {
	logger *slog.Logger
}

type ReportAction struct{}

func (a *ReportAction) Handle(path string, result SummarizedGMalwareResult, report *Report) (err error) {
	report.FileName = path
	report.Malicious = result.Malware
	report.Sha256 = result.Sha256
	report.Malware = result.Malwares
	return
}

func (a *LogAction) Handle(path string, result SummarizedGMalwareResult, report *Report) (err error) {
	if result.Malware {
		if len(result.Malwares) == 0 {
			result.Malwares = []string{}
		}
		if len(result.MaliciousSubfiles) == 0 {
			a.logger.Info("info scanned", slog.String("file", path), slog.String("sha256", result.Sha256), slog.Bool("malware", true), slog.Any("malwares", result.Malwares))
		} else {
			a.logger.Info("info scanned", slog.String("file", path), slog.String("sha256", result.Sha256), slog.Bool("malware", true), slog.Any("malwares", result.Malwares), slog.Any("malicious-subfiles", result.MaliciousSubfiles))
		}
	} else {
		a.logger.Debug("info scanned", slog.String("file", path), slog.String("sha256", result.Sha256), slog.Bool("malware", false))
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

type RemoveFileAction struct{}

func (a *RemoveFileAction) Handle(path string, result SummarizedGMalwareResult, report *Report) (err error) {
	if !result.Malware {
		return
	}
	err = os.Remove(path)
	if err != nil {
		return
	}
	report.Deleted = true
	return
}

func (a *QuarantineAction) Handle(path string, result SummarizedGMalwareResult, report *Report) (err error) {
	// skip legit files
	if !result.Malware {
		return
	}
	if a.root == "" {
		a.root, err = os.MkdirTemp(os.TempDir(), "quarantine")
		if err != nil {
			return err
		}
	}
	entry := &cache.Entry{
		ID:              cache.ComputeCacheID(path),
		Sha256:          result.Sha256,
		InitialLocation: path,
	}
	stat, err := os.Stat(path)
	if err != nil {
		return
	}

	entry.QuarantineLocation = filepath.Join(a.root, fmt.Sprintf("%s.lock", entry.ID))

	fout, err := os.Create(entry.QuarantineLocation)
	if err != nil {
		return
	}
	fin, err := os.Open(path)
	if err != nil {
		return
	}
	defer fin.Close()
	malware := "unknown"
	if len(result.Malwares) > 0 {
		malware = result.Malwares[0]
	}
	if err = a.locker.LockFile(path, fin, stat, fmt.Sprintf("malware: %s", malware), fout); err != nil {
		return
	}
	if err = a.cache.Set(entry); err != nil {
		return
	}

	report.QuarantineLocation = entry.QuarantineLocation

	return nil
}

func (a *QuarantineAction) Restore(id string) (err error) {
	if a.root == "" {
		a.root, err = os.MkdirTemp(os.TempDir(), "quarantine")
		if err != nil {
			return err
		}
	}
	fpath := filepath.Join(a.root, fmt.Sprintf("%s.lock", id))
	f, err := os.Open(fpath)
	if err != nil {
		return
	}
	// prepare file handle to be closed
	// if we correctly restore the file we must delete the lock file
	deleteLocked := false
	defer func() {
		f.Close()
		if deleteLocked {
			os.Remove(f.Name())
		}
	}()
	header, err := a.locker.GetHeader(f)
	if err != nil {
		return
	}
	out, err := os.Create(header.Filepath)
	if err != nil {
		return
	}
	defer out.Close()

	defer func() {
		if err != nil {
			os.Remove(out.Name())
		}
	}()
	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return
	}
	file, info, reason, err := a.locker.UnlockFile(f, out)
	if err != nil {
		return
	}
	err = restoreFileInfo(out.Name(), info)
	if err != nil {
		return
	}
	entry, err := a.cache.Get(id)
	if err == nil {
		entry.QuarantineLocation = ""
		entry.RestoredAt = Now()
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
	qfiles = make(chan QuarantinedFile)
	go func() {
		err := filepath.WalkDir(a.root, func(path string, d fs.DirEntry, err error) error {
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
			if !strings.HasSuffix(path, ".lock") {
				return nil
			}
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			entry, err := a.locker.GetHeader(file)
			if err != nil {
				return err
			}
			ID := strings.TrimSuffix(filepath.Base(path), ".lock")
			select {
			case <-ctx.Done():
				return filepath.SkipAll
			case qfiles <- QuarantinedFile{LockEntry: entry, ID: ID}:
				// push entry
				return nil
			}
		})
		if err != nil {
			return
		}
		close(qfiles)
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
		fmt.Fprintf(&sb, "file %s seems malicious", path)
		if len(result.Malwares) > 0 {
			fmt.Fprintf(&sb, " [%v]", result.Malwares)
		}
		if report.QuarantineLocation != "" {
			fmt.Fprintf(&sb, ", it has been quarantined to %s", report.QuarantineLocation)
		}
		if report.Deleted {
			fmt.Fprint(&sb, ", it has been deleted")
		}
		fmt.Fprintln(a.Out, sb.String())
	case report.MoveTo != "":
		fmt.Fprintf(a.Out, "file %s has been move to %s\n", path, report.MoveTo)
	case a.Verbose:
		fmt.Fprintf(a.Out, "file %s no malware found\n", path)
	}
	return nil
}

type MoveAction struct {
	Dest string
	Src  string
}

func NewMoveAction(dest string, src string) (*MoveAction, error) {
	a := &MoveAction{}
	var err error
	a.Dest, err = filepath.Abs(dest)
	if err != nil {
		return nil, err
	}
	pp, err := filepath.Abs(src)
	if err != nil {
		return nil, err
	}
	a.Src = pp
	return a, nil
}

func (a *MoveAction) Handle(path string, result SummarizedGMalwareResult, report *Report) (err error) {
	path, err = filepath.Abs(path)
	if err != nil {
		return
	}
	if strings.HasPrefix(path, a.Src) {
		destSubpath, ok := strings.CutPrefix(path, a.Src)
		if !ok {
			destSubpath = path
		}
		dest := filepath.Join(a.Dest, destSubpath)
		err = MkdirAll(filepath.Dir(dest), 0o755)
		if err != nil {
			return
		}
		// do not move malicious files
		// write report instead
		if result.Malware {
			if f, err := Create(fmt.Sprintf("%s.locked.json", dest)); err == nil {
				defer f.Close()
				w := json.NewEncoder(f)
				w.SetIndent("", "  ")
				if err = w.Encode(report); err != nil {
					return err
				}
			} else {
				return err
			}
			return
		}
		err = Rename(path, dest)
		if err != nil {
			return err
		}
		report.MoveTo = dest
		return

	}
	return fmt.Errorf("file not in paths")
}
