package handler

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/rfsnotify"
)

type Monitorer interface {
	Start()
	Close() error
	Add(path string) error
}

type OnNewFileFunc func(file string) error

type Config struct {
	PreScan  bool
	ReScan   bool
	Period   sdk.Duration
	ModDelay sdk.Duration
}

type Monitor struct {
	watcher      *rfsnotify.RWatcher
	wg           sync.WaitGroup
	cb           OnNewFileFunc
	preScan      bool
	reScan       bool
	period       sdk.Duration
	modDelay     sdk.Duration
	paths        *sync.Map
	done         chan struct{}
	filesToScan  chan string
	pendingFiles *sync.Map
}

func NewMonitor(onNewFile OnNewFileFunc, config Config) (*Monitor, error) {
	watcher, err := rfsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &Monitor{
		watcher:      watcher,
		cb:           onNewFile,
		preScan:      config.PreScan,
		reScan:       config.ReScan,
		period:       config.Period,
		modDelay:     config.ModDelay,
		paths:        new(sync.Map),
		filesToScan:  make(chan string),
		pendingFiles: new(sync.Map),
		done:         make(chan struct{}),
	}, nil
}

func (m *Monitor) Close() (err error) {
	if err := m.watcher.Close(); err != nil {
		logger.Error("cannot close watcher", slog.String("error", err.Error()))
		return fmt.Errorf("cannot close watcher, error: %w", err)
	}
	close(m.done)
	m.wg.Wait()
	return
}

func (m *Monitor) Start() {
	m.wg.Go(func() {
		m.work()
	})
	if m.period != 0 {
		m.wg.Go(func() {
			m.scan()
		})
	}
	m.wg.Go(func() {
		m.scanFiles()
	})
}

func (m *Monitor) scan() {
	ticker := time.NewTicker(time.Duration(m.period))
	defer ticker.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			m.paths.Range(func(key, value any) bool {
				path, ok := key.(string)
				if !ok {
					m.paths.Delete(key)
				}
				err := m.cb(path)
				if err != nil {
					logger.Error("error action on new file", slog.String("path", path), slog.String("error", err.Error()))
				}
				return true
			})
		}
	}
}

func (m *Monitor) work() {
	for {
		select {
		case <-m.done:
			return
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Create) || event.Has(fsnotify.Write) {
				if _, loaded := m.pendingFiles.LoadOrStore(event.Name, struct{}{}); !loaded {
					m.filesToScan <- event.Name
				}
			}
		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			logger.Error("watcher error", slog.String("error", err.Error()))
		}
	}
}

var (
	ScanFileLoopPause = time.Millisecond * 100
	Since             = time.Since
)

func (m *Monitor) scanFiles() {
	for {
		select {
		case <-m.done:
			return
		case path, ok := <-m.filesToScan:
			if !ok {
				return
			}

			info, statErr := os.Stat(path)
			if statErr != nil {
				m.pendingFiles.Delete(path)
				continue
			}

			if Since(info.ModTime()) < time.Duration(m.modDelay) {
				delay := time.Duration(m.modDelay) - Since(info.ModTime())
				time.AfterFunc(delay, func() {
					select {
					case <-m.done:
						m.pendingFiles.Delete(path)
						return
					case m.filesToScan <- path:
					}
				})
				continue
			}

			if err := m.cb(path); err != nil {
				logger.Error("error action on new file", slog.String("path", path), slog.String("err", err.Error()))
			}
			m.pendingFiles.Delete(path)
		}
	}
}

func (m *Monitor) Add(path string) error {
	if _, ok := m.paths.Load(path); ok {
		return nil
	}
	if err := m.watcher.AddRecursive(filepath.Clean(path)); err != nil {
		return fmt.Errorf("error watching %s: %w", path, err)
	}
	m.paths.Store(path, struct{}{})
	if m.preScan {
		m.wg.Go(func() {
			err := m.cb(path)
			if err != nil {
				logger.Error("error action on new file", slog.String("path", path), slog.String("err", err.Error()))
			}
		})
	}
	return nil
}
