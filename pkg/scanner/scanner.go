package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/report"
	"github.com/google/uuid"
	"golift.io/xtractr"
)

var LogLevel = &slog.LevelVar{}

var logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
	Level: LogLevel,
}))

const (
	logReasonKey = "reason"
	logSizeKey   = "size"
	logErrorKey  = "error"
)

type Submitter interface {
	gdetect.ControllerGDetectSubmitter
	ExtractExpertViewURL(result *gdetect.Result) (urlExpertView string, err error)
}

type Config struct {
	// Path             string
	QuarantineFolder string
	Workers          int
	Password         string
	Cache            cache.Cacher
	Submitter        Submitter
	Timeout          time.Duration
	WaitOpts         gdetect.WaitForOptions
	Actions          Actions
	CustomActions    []Action
	ScanPeriod       time.Duration
	Extract          bool
	MaxFileSize      int64
	MoveTo           string
	MoveFrom         string
	// Plugins          map[string]string
	PluginsConfigPath string
	ConsoleEvents     chan<- any
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
	done               context.Context
	cancel             context.CancelFunc
	config             Config
	wg                 sync.WaitGroup
	fileChan           chan fileToAnalyze
	action             Action
	reportMutex        sync.Mutex
	reports            []*report.Report
	archivesStatus     map[string]archiveStatus
	archiveMutex       sync.RWMutex
	loadedPlugins      []plugins.Plugin
	onStartScanFileCbs []plugins.OnStartScanFile
	onFileScannedCbs   []plugins.OnFileScanned
	onReportCbs        []plugins.OnReport
	generateReport     plugins.GenerateReport
}

var MaxWorkers = 40

var MaxFileSize int64 = 100 * 1024 * 1024

func NewConnector(config Config) *Connector {
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
		action:         newAction(config),
		generateReport: report.GenerateReport,
	}
}

func newAction(config Config) Action {
	action := NewMultiAction(&ReportAction{})
	if config.Actions.Log {
		action.Actions = append(action.Actions, &LogAction{logger: logger})
	}
	if config.Actions.Quarantine {
		action.Actions = append(action.Actions, &QuarantineAction{
			cache:  config.Cache,
			root:   config.QuarantineFolder,
			locker: &Lock{Password: config.Password},
			events: config.ConsoleEvents,
		})
	}
	if config.Actions.Deleted {
		action.Actions = append(action.Actions, &RemoveFileAction{})
	}
	if config.Actions.Move {
		move, err := NewMoveAction(config.MoveTo, config.MoveFrom)
		if err == nil {
			action.Actions = append(action.Actions, move)
		} else {
			logger.Error("could not add move legit action", slog.String(logErrorKey, err.Error()))
		}
	}
	if config.Actions.Inform {
		action.Actions = append(action.Actions, &InformAction{Verbose: config.Actions.Verbose, Out: config.Actions.InformDest})
	}
	action.Actions = append(action.Actions, config.CustomActions...)
	return action
}

func (c *Connector) Start(ctx context.Context) error {
	for i := 0; i < c.config.Workers; i++ {
		c.wg.Add(1)
		go c.worker(ctx)
	}
	return nil
}

// XtractFile could be used to override xtract.ExtractFile method
var XtractFile = xtractr.ExtractFile

func (c *Connector) ScanFile(ctx context.Context, input string) (err error) {
	inputLogger := logger.With(slog.String("input file", input))
	info, err := os.Lstat(input)
	if err != nil {
		return
	}
	if info.IsDir() {
		return c.scanDir(ctx, input)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		inputLogger.Debug("skip file", slog.String(logReasonKey, "size 0"))
		return
	}
	if info.Size() == 0 {
		inputLogger.Warn("skip file", slog.String(logReasonKey, "size 0"))
		return
	}
	if info.Size() > c.config.MaxFileSize {
		if !c.config.Extract {
			inputLogger.Warn("skip file",
				slog.String(logReasonKey, "file too large"),
				slog.String(logSizeKey, units.Base2Bytes(info.Size()).Round(1).String()),
			)
			return
		}
		hash := sha256.New()
		f, openErr := os.Open(filepath.Clean(input))
		if openErr != nil {
			err = openErr
			return
		}
		if _, err = io.Copy(hash, f); err != nil {
			e := f.Close()
			if e != nil {
				return e
			}
			return
		}
		archiveSha256 := hex.EncodeToString(hash.Sum(nil))
		outputDir, outputDirErr := os.MkdirTemp(os.TempDir(), archiveSha256)
		if outputDirErr != nil {
			err = outputDirErr
			return
		}

		xfile := xtractr.XFile{
			FilePath:  input,
			OutputDir: outputDir,
			FileMode:  0o755,
			DirMode:   0o755,
		}

		_, files, _, extractErr := XtractFile(&xfile)
		switch {
		case extractErr == nil:
			// OK
		case errors.Is(extractErr, xtractr.ErrUnknownArchiveType):
			inputLogger.Warn("skip file",
				slog.String(logReasonKey, "file too large (not an archive)"),
				slog.String(logSizeKey, units.Base2Bytes(info.Size()).Round(1).String()),
			)
			return
		default:
			inputLogger.Warn("failed extraction", slog.String(logReasonKey, extractErr.Error()))
			return
		}

		inputLogger.Info("extract files from archive", slog.Int("files", len(files)))

		id := uuid.New()

		eStatus := archiveStatus{
			archiveName: input,
			result: SummarizedGMalwareResult{
				Sha256:            archiveSha256,
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
			fileLogger := inputLogger.With(slog.String("subfile", f))
			info, infoErr := os.Stat(f)
			if infoErr != nil {
				eStatus.total--
				c.archivesStatus[id.String()] = eStatus
				errRemove := os.Remove(f)
				if errRemove != nil {
					fileLogger.Warn("could not remove inner file", slog.String(logErrorKey, errRemove.Error()))
				}
				fileLogger.Warn("could not stat archive inner file", slog.String(logErrorKey, infoErr.Error()))
				continue
			}
			if info.Size() > c.config.MaxFileSize {
				eStatus.total--
				c.archivesStatus[id.String()] = eStatus
				errRemove := os.Remove(f)
				if errRemove != nil {
					fileLogger.Warn("could not remove inner file", slog.String(logErrorKey, errRemove.Error()))
				}
				fileLogger.Warn("skip archive inner file",
					slog.String(logReasonKey, "file too large"),
					slog.String(logSizeKey, units.Base2Bytes(info.Size()).Round(1).String()),
				)
				continue
			}
			if info.Size() <= 0 {
				eStatus.total--
				c.archivesStatus[id.String()] = eStatus
				errRemove := os.Remove(f)
				if errRemove != nil {
					logger.Warn("could not remove inner file",
						slog.String(logErrorKey, errRemove.Error()),
					)
				}
				logger.Warn(
					"skip archive inner file",
					slog.String(logReasonKey, "size 0"),
				)
				continue
			}
			filteredFiles = append(filteredFiles, f)
		}
		files = filteredFiles
		c.archivesStatus[id.String()] = eStatus
		for _, f := range files {
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

	err = filepath.WalkDir(input, func(path string, d fs.DirEntry, walkErr error) (err error) {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() {
			err = c.ScanFile(ctx, path)
			if err != nil {
				logger.Error("could not scan file", slog.String("file", path), slog.String("err", err.Error()))
				return
			}
		}
		return
	})
	return
}

func (c *Connector) worker(ctx context.Context) {
	defer c.wg.Done()
	for {
		select {
		case <-c.done.Done():
			return
		case input := <-c.fileChan:
			inputLogger := logger.With(slog.String("input", input.filename))

			if input.archiveID != "" {
				err := c.handleArchive(ctx, input)
				if err != nil {
					inputLogger.Error("could not handle file", slog.String("archive-id", input.archiveID), slog.String(logErrorKey, err.Error()))
				}
				continue
			}
			result, err := c.handleFile(ctx, input)
			if err != nil {
				inputLogger.Error("could not handle file", slog.String(logErrorKey, err.Error()))
			}
			report := &report.Report{}
			if err = c.action.Handle(ctx, input.location, result, report); err != nil {
				inputLogger.Error("could not handle file action", slog.String(logErrorKey, err.Error()))
			}
			c.addReport(report)
		}
	}
}

func (c *Connector) handleArchive(ctx context.Context, input fileToAnalyze) (err error) {
	c.archiveMutex.Lock()
	defer c.archiveMutex.Unlock()
	status := c.archivesStatus[input.archiveID]
	if status.finished {
		logger.Debug("archive already analyzed", slog.String("archive-id", input.archiveID))
		return
	}
	result, err := c.handleFile(ctx, input)
	if err != nil {
		status.total--
		c.archivesStatus[input.archiveID] = status
		return
	}
	status.analyzed++
	status.result = mergeResult(status.result, result, input.filename)
	if (c.config.Extract && status.analyzed == status.total) || (!c.config.Extract && result.Malware) {
		status.finished = true
		report := &report.Report{}
		if err = c.action.Handle(ctx, status.archiveName, status.result, report); err != nil {
			return
		}
		c.addReport(report)
		removeErr := os.RemoveAll(status.tmpFolder)
		if removeErr != nil {
			logger.Error("could not remove temp folder",
				slog.String("archive", input.archiveID),
				slog.String("folder", status.tmpFolder),
				slog.String(logErrorKey, err.Error()),
			)
		}
	}
	c.archivesStatus[input.archiveID] = status
	return
}

var Since = time.Since

type SummarizedGMalwareResult struct {
	MaliciousSubfiles map[string]SummarizedGMalwareResult `json:"malicious-subfiles,omitempty"`
	Sha256            string                              `json:"sha256,omitempty"`
	Malware           bool                                `json:"malware,omitempty"`
	Malwares          []string                            `json:"malwares,omitempty"`
	Size              int64                               `json:"size,omitempty"`
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

func (c *Connector) handleFile(ctx context.Context, input fileToAnalyze) (sumResult SummarizedGMalwareResult, err error) {
	fileLoger := logger.With(slog.String("file", input.location))

	hash := sha256.New()
	f, err := os.Open(filepath.Clean(input.location))
	if err != nil {
		return
	}
	if _, err = io.Copy(hash, f); err != nil {
		errClose := f.Close()
		if errClose != nil {
			fileLoger.Error("cannot close file", slog.String(logErrorKey, err.Error()))
		}
		return
	}
	fileSHA256 := hex.EncodeToString(hash.Sum(nil))

	// check if file has already been handle
	// get result by sha instead of id because same files may have different ids (if different names)
	entry, err := c.config.Cache.GetBySha256(ctx, fileSHA256)
	switch {
	case err == nil:
		if entry.RestoredAt.UnixMilli() > 0 {
			fileLoger.Debug("skip file", slog.String(logReasonKey, "restored"))
			errClose := f.Close()
			if errClose != nil {
				fileLoger.Error("cannot close file", slog.String(logErrorKey, err.Error()))
			}
			return
		}
		fileLoger.Warn("file cached but not restored correctly, analyzing it again", slog.String(logReasonKey, "not restored"))
	case errors.Is(err, cache.ErrEntryNotFound):
		// ok
	default:
		errClose := f.Close()
		if errClose != nil {
			fileLoger.Error("cannot close file",
				slog.String(logErrorKey, err.Error()),
			)
		}
		return
	}
	// GDetect cache
	submitCtx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return
	}
	var result gdetect.Result
	if res := c.onStartScanFile(input.filename, fileSHA256); res != nil {
		result = *res
	} else {
		opts := c.config.WaitOpts
		opts.Filename = input.location
		result, err = c.config.Submitter.WaitForReader(submitCtx, f, opts)
	}
	c.onFileScanned(input.location, fileSHA256, result, err)
	if err != nil {
		errClose := f.Close()
		if errClose != nil {
			fileLoger.Error("cannot close file",
				slog.String(logErrorKey, err.Error()),
			)
		}
		return
	}

	// f need to be closed before action, to allow deletion
	errClose := f.Close()
	if errClose != nil {
		fileLoger.Error("cannot close file",
			slog.String(logErrorKey, err.Error()),
		)
	}

	sumResult = SummarizedGMalwareResult{
		Sha256:   fileSHA256,
		Malware:  result.Malware,
		Malwares: result.Malwares,
		Size:     result.FileSize,
	}
	return
}

func (c *Connector) addReport(report *report.Report) {
	c.onReport(report)
	c.reportMutex.Lock()
	defer c.reportMutex.Unlock()
	c.reports = append(c.reports, report)
}

func (c *Connector) Close() {
	c.cancel()
	c.wg.Wait()
	for _, x := range c.loadedPlugins {
		if closeErr := x.Close(context.TODO()); closeErr != nil {
			logger.Error("failed to close plugin", slog.String(logErrorKey, closeErr.Error()))
		}
	}
}

func (c *Connector) GetLogger() *slog.Logger {
	return logger
}
