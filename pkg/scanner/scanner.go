package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/units"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/cache"
	"github.com/glimps-re/host-connector/pkg/filesystem"
	"github.com/google/uuid"
	"golift.io/xtractr"
)

type Submitter interface {
	gdetect.GDetectSubmitter
	ExtractExpertViewURL(result *gdetect.Result) (urlExpertView string, err error)
}

type Config struct {
	// Path             string
	QuarantineFolder string
	Workers          int
	Password         string

	Cache         cache.Cacher
	Submitter     Submitter
	Timeout       time.Duration
	WaitOpts      gdetect.WaitForOptions
	Actions       Actions
	CustomActions []Action
	ScanPeriod    time.Duration
	Extract       bool
	MaxFileSize   int64
	MoveTo        string
	MoveFrom      string
}

type fileToAnalyze struct {
	location  string
	filename  string
	archiveID string
}

type archiveStatus struct {
	finished    bool
	archiveName string
	result      SummarizedGMalwareResult
	analyzed    int
	total       int
	tmpFolder   string
}

type Connector struct {
	done           context.Context
	cancel         context.CancelFunc
	config         Config
	wg             sync.WaitGroup
	fileChan       chan fileToAnalyze
	action         Action
	reportMutex    sync.Mutex
	reports        []*Report
	archivesStatus map[string]archiveStatus
	archiveMutex   sync.RWMutex
	fs             filesystem.FileSystem
}

const MaxWorkers = 40

const MaxFileSize int64 = 100 * 1024 * 1024

func NewConnector(config Config, fs filesystem.FileSystem) *Connector {
	ctx, cancel := context.WithCancel(context.Background())

	if config.Workers < 1 {
		config.Workers = 1
	}
	if config.Workers > MaxWorkers {
		config.Workers = MaxWorkers
	}

	if config.MaxFileSize <= 0 {
		config.MaxFileSize = MaxFileSize
	}

	return &Connector{
		done:           ctx,
		cancel:         cancel,
		fileChan:       make(chan fileToAnalyze),
		config:         config,
		archivesStatus: make(map[string]archiveStatus),
		action:         newAction(config, fs),
		fs:             fs,
	}
}

func newAction(config Config, fs filesystem.FileSystem) Action {
	action := NewMultiAction(&ReportAction{})
	if config.Actions.Log {
		action.Actions = append(action.Actions, &LogAction{logger: Logger})
	}
	if config.Actions.Quarantine {
		action.Actions = append(action.Actions, NewQuarantineAction(fs, config.Cache, config.QuarantineFolder, &Lock{Password: config.Password}))
	}
	if config.Actions.Deleted {
		action.Actions = append(action.Actions, NewRemoveFileAction(fs))
	}
	if config.Actions.Move {
		move, err := NewMoveAction(fs, config.MoveTo, config.MoveFrom)
		if err == nil {
			action.Actions = append(action.Actions, move)
		} else {
			Logger.Error("could not add move legit action", slog.String("error", err.Error()))
		}
	}
	if config.Actions.Inform {
		action.Actions = append(action.Actions, &InformAction{Verbose: config.Actions.Verbose, Out: config.Actions.InformDest})
	}
	action.Actions = append(action.Actions, config.CustomActions...)
	return action
}

func (c *Connector) Start() error {
	for range c.config.Workers {
		c.wg.Add(1)
		go c.worker()
	}
	return nil
}

func (c *Connector) ScanFile(ctx context.Context, input string) (err error) {
	info, err := c.fs.Lstat(ctx, input)
	if err != nil {
		return
	}
	if info.IsDir() {
		return c.scanDir(ctx, input)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		Logger.Debug("skip file", slog.String("file", input), slog.String("reason", "size 0"))
		return
	}
	if info.Size() == 0 {
		Logger.Warn("skip file", slog.String("file", input), slog.String("reason", "size 0"))
		return
	}
	if info.Size() > c.config.MaxFileSize {
		if !c.config.Extract {
			Logger.Warn("skip file",
				slog.String("file", input),
				slog.String("reason", "file too large"),
				slog.String("size", units.Base2Bytes(info.Size()).Round(1).String()),
			)
			return
		}
		hash := sha256.New()
		f, openErr := c.fs.Open(ctx, input)
		if openErr != nil {
			err = openErr
			return
		}
		if _, err = io.Copy(hash, f); err != nil {
			if e := f.Close(); e != nil {
				Logger.Warn("could not close scanned file properly", slog.String("path", input), slog.String("error", e.Error()))
			}
			return
		}
		if e := f.Close(); e != nil {
			Logger.Warn("could not close scanned file properly", slog.String("path", input), slog.String("error", e.Error()))
		}
		archiveSha256 := hex.EncodeToString(hash.Sum(nil))
		outputDir, outputDirErr := os.MkdirTemp(os.TempDir(), archiveSha256)
		if outputDirErr != nil {
			err = outputDirErr
			return
		}

		xfile := &xtractr.XFile{
			FilePath:  input,
			OutputDir: outputDir,
			FileMode:  0o750,
			DirMode:   0o750,
		}

		if !c.fs.IsLocal() {
			file, openErr := c.fs.Open(ctx, input)
			if openErr != nil {
				err = openErr
				return
			}
			inputArchive, createTempErr := os.CreateTemp(os.TempDir(), archiveSha256+"*"+filepath.Ext(input)) // preserve extension for xtractr
			if createTempErr != nil {
				err = createTempErr
				if e := file.Close(); e != nil {
					Logger.Warn("could not close input file properly", slog.String("name", input), slog.String("error", e.Error()))
				}
				return
			}
			_, err = io.Copy(inputArchive, file)
			if e := file.Close(); e != nil {
				Logger.Warn("could not close input file properly", slog.String("name", input), slog.String("error", e.Error()))
			}
			if e := inputArchive.Close(); e != nil {
				Logger.Warn("could not close created archive properly", slog.String("name", inputArchive.Name()), slog.String("error", e.Error()))
			}
			if err != nil {
				return
			}
			xfile.FilePath = inputArchive.Name()
		}

		_, files, _, extractErr := xfile.Extract()
		switch {
		case extractErr == nil:
			// OK
		case errors.Is(extractErr, xtractr.ErrUnknownArchiveType):
			Logger.Warn("skip file",
				slog.String("file", input),
				slog.String("reason", "file too large (not an archive)"),
				slog.String("size", units.Base2Bytes(info.Size()).Round(1).String()),
			)
			return
		default:
			Logger.Warn("failed extraction", slog.String("archive", input), slog.String("reason", extractErr.Error()))
			return
		}

		Logger.Info("extract files from archive", slog.String("archive", input), slog.Int("files", len(files)))

		id := uuid.New()

		eStatus := archiveStatus{
			archiveName: input,
			result: SummarizedGMalwareResult{
				SHA256:            archiveSha256,
				MaliciousSubfiles: make(map[string]SummarizedGMalwareResult),
				Malware:           false,
				Malwares:          []string{},
			},
			analyzed:  0,
			total:     len(files),
			tmpFolder: outputDir,
		}

		// Filter files
		filteredFiles := []string{}
		for _, f := range files {
			info, infoErr := os.Stat(f)
			if infoErr != nil {
				eStatus.total--
				c.archivesStatus[id.String()] = eStatus
				if err := os.Remove(f); err != nil {
					Logger.Warn("could not remove archive inner file", slog.String("archive", input), slog.String("file", f), slog.String("error", err.Error()))
				}
				Logger.Warn("could not stat archive inner file", slog.String("archive", input), slog.String("file", f), slog.String("error", infoErr.Error()))
				continue
			}
			if info.Size() > c.config.MaxFileSize {
				eStatus.total--
				c.archivesStatus[id.String()] = eStatus
				if err := os.Remove(f); err != nil {
					Logger.Warn("could not remove archive inner file", slog.String("archive", input), slog.String("file", f), slog.String("error", err.Error()))
				}
				Logger.Warn(
					"skip archive inner file",
					slog.String("archive", input),
					slog.String("file", f),
					slog.String("reason", "file too large"),
					slog.String("size", fmt.Sprintf("file too large [%s]", units.Base2Bytes(info.Size()).Round(1).String())),
				)
				continue
			}
			if info.Size() <= 0 {
				eStatus.total--
				c.archivesStatus[id.String()] = eStatus
				if err := os.Remove(f); err != nil {
					Logger.Warn("could not remove archive inner file", slog.String("archive", input), slog.String("file", f), slog.String("error", err.Error()))
				}
				Logger.Warn(
					"skip archive inner file",
					slog.String("archive", input),
					slog.String("file", f),
					slog.String("reason", "size 0"),
				)
				continue
			}
			filteredFiles = append(filteredFiles, f)
		}
		c.archivesStatus[id.String()] = eStatus
		for _, f := range filteredFiles {
			dir, file := filepath.Split(f)
			bef, _ := strings.CutPrefix(dir, outputDir)
			realPath := filepath.Join(bef, file)
			select {
			case <-ctx.Done():
				return context.Canceled
			case c.fileChan <- fileToAnalyze{location: f, archiveID: id.String(), filename: realPath}:
				continue
			}
		}
		return
	}

	select {
	case <-ctx.Done():
		return context.Canceled
	case c.fileChan <- fileToAnalyze{location: input}:
		return
	}
}

func (c *Connector) scanDir(ctx context.Context, input string) (err error) {
	// WalkDir seems to not handle correctly path without ending /
	input += string(filepath.Separator)

	err = c.fs.WalkDir(ctx, input, func(path string, d fs.DirEntry, walkErr error) (err error) {
		if walkErr != nil {
			err = walkErr
			return
		}
		if !d.IsDir() {
			err = c.ScanFile(ctx, path)
			if err != nil {
				Logger.Error("could not scan file", slog.String("file", path), slog.String("err", err.Error()))
				return
			}
		}
		return
	})
	return
}

func (c *Connector) worker() {
	defer c.wg.Done()
	for {
		select {
		case <-c.done.Done():
			return
		case input := <-c.fileChan:
			switch input.archiveID {
			case "":
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				file, err := c.fs.Open(ctx, input.location)
				if err != nil {
					return
				}
				result, err := c.handleFile(input.location, file)
				if err != nil {
					Logger.Error("could not handle file", slog.String("file", input.filename), slog.String("error", err.Error()))
				}
				if e := file.Close(); e != nil {
					Logger.Warn("could not close file properly", slog.String("name", input.location), slog.String("error", e.Error()))
				}
				report := &Report{}
				if err = c.action.Handle(input.location, result, report); err != nil {
					return
				}
				c.addReport(report)
			default:
				err := c.handleArchive(input)
				if err != nil {
					Logger.Error("could not handle file", slog.String("archive-id", input.archiveID), slog.String("file", input.filename), slog.String("error", err.Error()))
				}
			}
		}
	}
}

func (c *Connector) handleArchive(input fileToAnalyze) (err error) {
	c.archiveMutex.Lock()
	defer c.archiveMutex.Unlock()
	status := c.archivesStatus[input.archiveID]
	if status.finished {
		Logger.Debug("archive already analyzed", slog.String("archive-id", input.archiveID))
		return
	}

	file, err := os.Open(input.location)
	if err != nil {
		return
	}
	defer func() {
		if e := file.Close(); e != nil {
			Logger.Warn("could not close file properly", slog.String("name", input.location), slog.String("error", e.Error()))
		}
	}()
	result, err := c.handleFile(input.location, file)
	if err != nil {
		status.total--
		c.archivesStatus[input.archiveID] = status
		return
	}
	status.analyzed++
	status.result = mergeResult(status.result, result, input.filename)
	if (c.config.Extract && status.analyzed == status.total) || (!c.config.Extract && result.Malware) {
		status.finished = true
		report := &Report{}
		if err = c.action.Handle(status.archiveName, status.result, report); err != nil {
			return
		}
		c.addReport(report)
		if e := os.RemoveAll(status.tmpFolder); e != nil {
			Logger.Warn("could not remove tmp extract folder properly", slog.String("path", status.tmpFolder), slog.String("error", e.Error()))
		}
	}
	c.archivesStatus[input.archiveID] = status
	return
}

type SummarizedGMalwareResult struct {
	MaliciousSubfiles map[string]SummarizedGMalwareResult `json:"malicious-subfiles,omitempty"`
	SHA256            string                              `json:"sha256"`
	Malware           bool                                `json:"malware"`
	Malwares          []string                            `json:"malwares"`
}

func mergeResult(baseResult, resultToMerge SummarizedGMalwareResult, filename string) (result SummarizedGMalwareResult) {
	result = baseResult
	for _, m := range resultToMerge.Malwares {
		if !slices.Contains(result.Malwares, m) {
			result.Malwares = append(result.Malwares, m)
		}
	}
	result.Malware = baseResult.Malware || resultToMerge.Malware

	result.MaliciousSubfiles = make(map[string]SummarizedGMalwareResult)
	if baseResult.MaliciousSubfiles != nil {
		result.MaliciousSubfiles = baseResult.MaliciousSubfiles
	}
	if resultToMerge.Malware {
		result.MaliciousSubfiles[filename] = resultToMerge
	}
	return
}

func (c *Connector) handleFile(name string, f io.ReadSeeker) (sumResult SummarizedGMalwareResult, err error) {
	hash := sha256.New()
	if _, err = io.Copy(hash, f); err != nil {
		return
	}
	fileSHA256 := hex.EncodeToString(hash.Sum(nil))

	// check if file has already been handle
	// get result by sha instead of id because same files may have different ids (if different names)
	entry, err := c.config.Cache.GetBySha256(fileSHA256)
	switch {
	case err == nil:
		if entry.RestoredAt.UnixMilli() > 0 {
			Logger.Debug("skip file", slog.String("file", name), slog.String("reason", "restored"))
			return
		}
	case errors.Is(err, cache.ErrEntryNotFound):
		// ok
	default:
		return
	}
	// GDetect cache
	ctx, cancel := context.WithTimeout(context.Background(), c.config.Timeout)
	defer cancel()

	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return
	}
	opts := c.config.WaitOpts
	opts.Filename = name
	result, err := c.config.Submitter.WaitForReader(ctx, f, opts)
	if err != nil {
		return
	}

	sumResult = SummarizedGMalwareResult{
		SHA256:   fileSHA256,
		Malware:  result.Malware,
		Malwares: result.Malwares,
	}
	return
}

func (c *Connector) addReport(report *Report) {
	c.reportMutex.Lock()
	defer c.reportMutex.Unlock()
	c.reports = append(c.reports, report)
}

func (c *Connector) Close() {
	c.cancel()
	c.wg.Wait()
}

var Logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
