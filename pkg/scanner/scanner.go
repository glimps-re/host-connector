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
	"sync"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/cache"
)

type Submitter interface {
	gdetect.GDetectSubmitter
	ExtractExpertViewURL(result *gdetect.Result) (urlExpertView string, err error)
}

type Config struct {
	// Path             string
	QuarantineFolder string
	ExportLocation   string
	Workers          uint
	Password         string
	Cache            cache.Cacher
	Submitter        Submitter
	Timeout          time.Duration
	WaitOpts         gdetect.WaitForOptions
	Actions          Actions
	ScanPeriod       time.Duration
}

type Connector struct {
	done        context.Context
	cancel      context.CancelFunc
	config      Config
	wg          sync.WaitGroup
	fileChan    chan string
	Action      ResultHandler
	reportMutex sync.Mutex
	reports     []*Report
}

var MaxWorkers uint = 40

func NewConnector(config Config) *Connector {
	ctx, cancel := context.WithCancel(context.Background())
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
	if config.Workers == 0 {
		config.Workers = 1
	}
	if config.Workers > MaxWorkers {
		config.Workers = MaxWorkers
	}
	return &Connector{
		done:     ctx,
		cancel:   cancel,
		fileChan: make(chan string),
		config:   config,
		Action:   action,
	}
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
		Logger.Warn("skip file", "file", input, "reason", "size 0")
		return nil
	}
	if info.Size() > 100*1024*1024 {
		Logger.Warn("skip file", "file", input, "reason", "size above 100MiB")
		return nil
	}
	if !info.IsDir() {
		select {
		case <-ctx.Done():
			return context.Canceled
		case c.fileChan <- input:
			return nil
		}
	}

	// WalkDir seems to not handle correctly path without ending /
	input = input + string(filepath.Separator)

	err = filepath.WalkDir(input, func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() {
			c.fileChan <- path
		}
		return err
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
			err := c.handleFile(input)
			if err != nil {
				Logger.Error("could not handle file", "file", input, "error", err)
			}
		}
	}
}

var Since = time.Since

func (c *Connector) handleFile(file string) error {
	hash := sha256.New()
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = io.Copy(hash, f); err != nil {
		return err
	}
	sha256 := hex.EncodeToString(hash.Sum(nil))

	// check if file has already been handle
	entry, err := c.config.Cache.Get(sha256)
	switch {
	case err == nil:
		if c.config.ScanPeriod.Milliseconds() > 0 && Since(entry.UpdatedAt) <= c.config.ScanPeriod {
			// skip file
			Logger.Debug("skip cached file", "file", file)
			return nil
		}
	case errors.Is(err, cache.ErrEntryNotFound):
		// ok
	default:
		return err
	}

	// GDetect cache
	ctx, cancel := context.WithTimeout(context.Background(), c.config.Timeout)
	defer cancel()
	result, err := c.config.Submitter.GetResultBySHA256(ctx, sha256)
	if err != nil {
		// result not found, ask a new scan
		f.Seek(0, io.SeekStart)

		opts := c.config.WaitOpts
		opts.Filename = file
		result, err = c.config.Submitter.WaitForReader(ctx, f, opts)
		if err != nil {
			return err
		}
	}
	report := &Report{}
	if err = c.Action.Handle(file, sha256, result, report); err != nil {
		return err
	}
	c.addReport(report)
	return nil
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
