package handler

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/host-connector/pkg/datamodel"
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
	Period   sdk.Duration
	ModDelay sdk.Duration
}

type Monitor struct {
	watcher      *rfsnotify.RWatcher
	wg           sync.WaitGroup
	cb           OnNewFileFunc // callbacks
	preScan      bool
	period       sdk.Duration
	modDelay     sdk.Duration // modification delay
	paths        *sync.Map
	done         chan struct{}
	closeOnce    sync.Once
	filesToScan  chan string
	pendingFiles *sync.Map
	states       *sync.Map // path -> fileState, last observed metadata
	started      atomic.Bool
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
		period:       config.Period,
		modDelay:     config.ModDelay,
		paths:        new(sync.Map),
		filesToScan:  make(chan string),
		pendingFiles: new(sync.Map),
		states:       new(sync.Map),
		done:         make(chan struct{}),
	}, nil
}

func (m *Monitor) Close() (err error) {
	if !m.started.Load() {
		return
	}
	if err := m.watcher.Close(); err != nil {
		logger.Error("cannot close watcher", slog.String("error", err.Error()))
		return fmt.Errorf("cannot close watcher, error: %w", err)
	}
	m.closeOnce.Do(func() { close(m.done) })
	m.wg.Wait()
	m.started.Store(false)
	return
}

func (m *Monitor) Start() {
	m.wg.Go(func() {
		m.dispatchEvents()
	})
	if m.period != 0 {
		m.wg.Go(func() {
			m.periodicalScan()
		})
	}
	m.wg.Go(func() {
		m.scanFiles()
	})
	m.started.Store(true)
}

func (m *Monitor) periodicalScan() {
	ticker := time.NewTicker(time.Duration(m.period))
	defer ticker.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			seen := make(map[string]struct{})
			m.paths.Range(func(key, value any) bool {
				path, ok := key.(string)
				if !ok {
					m.paths.Delete(key)
				}
				path += string(filepath.Separator)
				err := filepath.WalkDir(path, func(path string, d fs.DirEntry, walkErr error) (err error) {
					if walkErr != nil {
						return walkErr
					}
					if d.IsDir() {
						return
					}
					seen[path] = struct{}{}
					if _, loaded := m.pendingFiles.LoadOrStore(path, struct{}{}); !loaded {
						select {
						case <-m.done:
							return fs.SkipAll
						case m.filesToScan <- path:
						}
					}
					return
				})
				if err != nil {
					logger.Error("cannot walk dir at rescan", slog.String("path", path), slog.String("error", err.Error()))
				}
				return true
			})
			// forget files not seen anymore (deleted, moved), their state would never be cleaned otherwise
			m.states.Range(func(key, _ any) bool {
				if path, ok := key.(string); ok {
					if _, found := seen[path]; found {
						return true
					}
				}
				m.states.Delete(key)
				return true
			})
		}
	}
}

// dispatchEvents reads filesystem events from the watcher and queue these files for scanning.
// Returns when m.done or a watcher channel is closed.
func (m *Monitor) dispatchEvents() {
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
					select {
					case <-m.done:
						return
					case m.filesToScan <- event.Name:
					}
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

var since = time.Since

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
				m.states.Delete(path)
				continue
			}
			if wait := m.stabilityWait(path, info); wait > 0 {
				time.AfterFunc(wait, func() {
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
				logger.Error("could not scan file", slog.String("path", path), slog.String("err", err.Error()), slog.String(datamodel.LogSourceKey, "monitor"))
			}
			m.pendingFiles.Delete(path)
		}
	}
}

type fileState struct {
	size       int64
	modTime    time.Time
	changeTime time.Time
	seen       time.Time // when this metadata was first observed
}

func (s fileState) sameAs(o fileState) bool {
	return s.size == o.size && s.modTime.Equal(o.modTime) && s.changeTime.Equal(o.changeTime)
}

// stabilityWait returns how long to wait before scanning path: its metadata (size, mtime, ctime)
// must stay unchanged for modDelay. mtime alone is not enough, as some copy tools preserve the
// source one while writing. Only metadata is compared, file content is never read.
func (m *Monitor) stabilityWait(path string, info fs.FileInfo) time.Duration {
	delay := time.Duration(m.modDelay)
	if delay == 0 {
		return 0
	}
	cur := fileState{size: info.Size(), modTime: info.ModTime(), changeTime: changeTime(info)}
	if prev, ok := m.states.Load(path); ok {
		if s, ok := prev.(fileState); ok && s.sameAs(cur) {
			return max(delay-since(s.seen), 0)
		}
	}
	cur.seen = time.Now()
	m.states.Store(path, cur)
	return delay
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
				logger.Error("could not scan file", slog.String("path", path), slog.String("err", err.Error()), slog.String(datamodel.LogSourceKey, "monitor"))
			}
		})
	}
	return nil
}
