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
	Workers          uint
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
}

var MaxWorkers uint = 40

var MaxFileSize int64 = 100 * 1024 * 1024

func NewConnector(config Config) *Connector {
	ctx, cancel := context.WithCancel(context.Background())

	if config.Workers == 0 {
		config.Workers = 1
	}
	if config.Workers > MaxWorkers {
		config.Workers = MaxWorkers
	}

	if config.MaxFileSize <= 0 || config.MaxFileSize > MaxFileSize {
		config.MaxFileSize = MaxFileSize
	}

	return &Connector{
		done:           ctx,
		cancel:         cancel,
		fileChan:       make(chan fileToAnalyze),
		config:         config,
		archivesStatus: make(map[string]archiveStatus),
		action:         newAction(config),
	}
}

func newAction(config Config) Action {
	action := NewMultiAction(&ReportAction{})
	if config.Actions.Log {
		action.Actions = append(action.Actions, &LogAction{logger: Logger})
	}
	if config.Actions.Quarantine {
		action.Actions = append(action.Actions, &QuarantineAction{
			cache:  config.Cache,
			root:   config.QuarantineFolder,
			locker: &Lock{Password: config.Password},
		})
	}
	if config.Actions.Deleted {
		action.Actions = append(action.Actions, &RemoveFileAction{})
	}
	if config.Actions.Inform {
		action.Actions = append(action.Actions, &InformAction{Verbose: config.Actions.Verbose, Out: config.Actions.InformDest})
	}
	action.Actions = append(action.Actions, config.CustomActions...)
	return action
}

func (c *Connector) Start() error {
	for i := 0; i < int(c.config.Workers); i++ {
		c.wg.Add(1)
		go c.worker()
	}
	return nil
}

func (c *Connector) ScanFile(ctx context.Context, input string) (err error) {
	info, err := os.Stat(input)
	if err != nil {
		return
	}
	if info.Size() == 0 {
		Logger.Warn("skip file", slog.String("file", input), slog.String("reason", "size 0"))
		return
	}
	if info.Size() > c.config.MaxFileSize {
		if !c.config.Extract {
			Logger.Warn("skip file", slog.String("file", input), slog.String("reason", "size above max file size"))
			return
		}
		hash := sha256.New()
		f, openErr := os.Open(input)
		if openErr != nil {
			err = openErr
			return
		}
		if _, err = io.Copy(hash, f); err != nil {
			f.Close()
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

		_, files, _, extractErr := xtractr.ExtractFile(&xfile)
		if extractErr != nil {
			Logger.Warn("failed extraction", slog.String("archive", input), slog.String("reason", extractErr.Error()))
			return
		}

		Logger.Info("extract files from archive", slog.String("archive", input), slog.Int("files", len(files)))

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
		for i, f := range files {
			info, infoErr := os.Stat(f)
			if infoErr != nil {
				eStatus.total--
				c.archivesStatus[id.String()] = eStatus
				files = append(files[:i], files[i+1:]...)
				os.Remove(f)
				Logger.Warn("could not stat archive inner file", slog.String("archive", input), slog.String("file", f), slog.String("error", infoErr.Error()))
				continue
			}
			if info.Size() <= 0 || info.Size() > c.config.MaxFileSize {
				eStatus.total--
				c.archivesStatus[id.String()] = eStatus
				files = append(files[:i], files[i+1:]...)
				os.Remove(f)
				Logger.Warn(
					"skip archive inner file",
					slog.String("archive", input),
					slog.String("file", f),
					slog.String("raison", fmt.Sprintf("file too large [%s]", units.Base2Bytes(info.Size()).Round(1).String())),
				)
				continue
			}
		}
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

	if !info.IsDir() {
		select {
		case <-ctx.Done():
			return context.Canceled
		case c.fileChan <- fileToAnalyze{location: input}:
			return
		}
	}

	// WalkDir seems to not handle correctly path without ending /
	input += string(filepath.Separator)

	err = filepath.WalkDir(input, func(path string, d fs.DirEntry, walkErr error) (err error) {
		if walkErr != nil {
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
				result, err := c.handleFile(input.location)
				if err != nil {
					Logger.Error("could not handle file", slog.String("file", input.filename), slog.String("error", err.Error()))
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
	result, err := c.handleFile(input.location)
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
		os.RemoveAll(status.tmpFolder)
	}
	c.archivesStatus[input.archiveID] = status
	return
}

var Since = time.Since

type SummarizedGMalwareResult struct {
	MaliciousSubfiles map[string]SummarizedGMalwareResult `json:"malicious-subfiles,omitempty"`
	Sha256            string                              `json:"sha256"`
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

func (c *Connector) handleFile(file string) (sumResult SummarizedGMalwareResult, err error) {
	hash := sha256.New()
	f, err := os.Open(file)
	if err != nil {
		return
	}
	if _, err = io.Copy(hash, f); err != nil {
		f.Close()
		return
	}
	fileSHA256 := hex.EncodeToString(hash.Sum(nil))

	// check if file has already been handle
	entry, err := c.config.Cache.Get(fileSHA256)
	switch {
	case err == nil:
		if entry.RestoredAt.UnixMilli() > 0 {
			Logger.Debug("skip file", slog.String("file", file), slog.String("reason", "restored"))
			f.Close()
			return
		}
		if entry.InitialLocation == file && c.config.ScanPeriod.Milliseconds() > 0 && Since(entry.UpdatedAt) <= c.config.ScanPeriod {
			// skip file
			Logger.Debug("skip file", slog.String("file", file), slog.String("reason", "cache valid"))
			f.Close()
			return
		}
	case errors.Is(err, cache.ErrEntryNotFound):
		// ok
	default:
		f.Close()
		return
	}
	// GDetect cache
	ctx, cancel := context.WithTimeout(context.Background(), c.config.Timeout)
	defer cancel()
	result, err := c.config.Submitter.GetResultBySHA256(ctx, fileSHA256)
	if err != nil {
		// result not found, ask a new scan
		if _, err = f.Seek(0, io.SeekStart); err != nil {
			return
		}

		opts := c.config.WaitOpts
		opts.Filename = file
		result, err = c.config.Submitter.WaitForReader(ctx, f, opts)
		if err != nil {
			f.Close()
			return
		}
	}
	// f need to be closed before action, to allow deletion
	f.Close()
	sumResult = SummarizedGMalwareResult{
		Sha256:   fileSHA256,
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
