package scanner

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/cache"
)

type Actions struct {
	Deleted    bool
	Quarantine bool
	Log        bool
	Inform     bool
	Verbose    bool
	InformDest io.Writer
}

// for test purposes
var Now = time.Now

type Action interface {
	Handle(path string, sha256 string, result gdetect.Result, report *Report) error
}

type NoAction struct{}

func (*NoAction) Handle(path string, sha256 string, result gdetect.Result, report *Report) error {
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

func (a *ReportAction) Handle(path string, sha256 string, result gdetect.Result, report *Report) (err error) {
	report.FileName = path
	report.Malicious = result.Malware
	report.Sha256 = sha256
	return
}

func (a *LogAction) Handle(path string, sha256 string, result gdetect.Result, report *Report) (err error) {
	if result.Malware {
		if len(result.Malwares) == 0 {
			result.Malwares = []string{}
		}
		a.logger.Info("info scanned", "file", path, "sha256", sha256, "malware", true, "malwares", result.Malwares)
	} else {
		a.logger.Debug("info scanned", "file", path, "sha256", sha256, "malware", false)
	}
	return nil
}

type MultiAction struct {
	Actions []Action
}

func (a *MultiAction) Handle(path string, sha256 string, result gdetect.Result, report *Report) (err error) {
	for _, h := range a.Actions {
		if err = h.Handle(path, sha256, result, report); err != nil {
			return
		}
	}
	return
}

func NewMultiAction(actions ...Action) *MultiAction {
	return &MultiAction{Actions: actions}
}

type RemoveFileAction struct{}

func (a *RemoveFileAction) Handle(path string, sha256 string, result gdetect.Result, report *Report) (err error) {
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

func (a *QuarantineAction) Handle(path string, sha256 string, result gdetect.Result, report *Report) (err error) {
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
		Sha256:          sha256,
		InitialLocation: path,
	}
	stat, err := os.Stat(path)
	if err != nil {
		return
	}

	entry.QuarantineLocation = filepath.Join(a.root, fmt.Sprintf("%s.lock", sha256))

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

func (a *QuarantineAction) Restore(sha256 string) (err error) {
	if a.root == "" {
		a.root, err = os.MkdirTemp(os.TempDir(), "quarantine")
		if err != nil {
			return err
		}
	}
	path := filepath.Join(a.root, fmt.Sprintf("%s.lock", sha256))
	f, err := os.Open(path)
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
	f.Seek(0, io.SeekStart)
	file, info, reason, err := a.locker.UnlockFile(f, out)
	if err != nil {
		return
	}
	err = restoreFileInfo(out.Name(), info)
	if err != nil {
		return
	}
	entry, err := a.cache.Get(sha256)
	if err == nil {
		entry.QuarantineLocation = ""
		entry.RestoredAt = Now()
		a.cache.Set(entry)
	}
	Logger.Info("file restored", "file", file, "reason", reason)
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
		os.Chown(path, stat.Uid, stat.Gid)
		os.Chtimes(path, stat.AccessTime, stat.ModTime)
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
		filepath.WalkDir(a.root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				Logger.Warn("list quarantined error", "error", err)
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
		close(qfiles)
	}()
	return qfiles, nil
}

type InformAction struct {
	Verbose bool
	Out     io.Writer
}

func (a *InformAction) Handle(path string, sha256 string, result gdetect.Result, report *Report) (err error) {
	if a.Out == nil {
		a.Out = os.Stdout
	}
	if result.Malware {
		sb := strings.Builder{}
		fmt.Fprintf(&sb, "file %s seems malicious", path)
		if len(result.Malwares) > 0 {
			fmt.Fprintf(&sb, " [%v]", result.Malwares)
		}
		if report.QuarantineLocation != "" {
			fmt.Fprintf(&sb, ", it has been quarantine to %s", report.QuarantineLocation)
		}
		if report.Deleted {
			fmt.Fprint(&sb, ", it has been deleted")
		}
		fmt.Fprintln(a.Out, sb.String())
	} else if a.Verbose {
		fmt.Fprintf(a.Out, "file %s no malware found\n", path)
	}
	return nil
}
