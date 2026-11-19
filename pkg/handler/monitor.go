package handler

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/host-connector/pkg/config"
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
	// DisableWatcher turns off filesystem events: files are only found by
	// the pre-scan and the periodic rescan (network filesystems where watches
	// are not available or reliable). It requires a non-zero Period.
	DisableWatcher bool
	PreScan        bool
	Period         sdk.Duration
	ModDelay       sdk.Duration
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

func NewMonitor(onNewFile OnNewFileFunc, cfg Config) (*Monitor, error) {
	var watcher *rfsnotify.RWatcher
	if cfg.DisableWatcher {
		if cfg.Period == 0 {
			return nil, config.ErrWatcherNeedsPeriod
		}
	} else {
		var err error
		watcher, err = rfsnotify.NewWatcher()
		if err != nil {
			return nil, err
		}
	}
	return &Monitor{
		watcher:      watcher,
		cb:           onNewFile,
		preScan:      cfg.PreScan,
		period:       cfg.Period,
		modDelay:     cfg.ModDelay,
		paths:        new(sync.Map),
		filesToScan:  make(chan string),
		pendingFiles: new(sync.Map),
		states:       new(sync.Map),
		done:         make(chan struct{}),
	}, nil
}

func (m *Monitor) Close() (err error) {
	m.closeOnce.Do(func() {
		if m.watcher != nil {
			if e := m.watcher.Close(); e != nil {
				logger.Error("cannot close watcher", slog.String("error", e.Error()))
				err = fmt.Errorf("cannot close watcher, error: %w", e)
			}
		}
		close(m.done)
	})
	m.wg.Wait()
	m.started.Store(false)
	return err
}

func (m *Monitor) Start() {
	if m.watcher != nil {
		m.wg.Go(func() {
			m.dispatchEvents()
		})
	}
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
			var partialRoots []string
			m.paths.Range(func(key, _ any) bool {
				root, ok := key.(string)
				if !ok {
					m.paths.Delete(key)
					return true
				}
				if partial := m.walkRoot(root, seen); partial {
					partialRoots = append(partialRoots, filepath.Clean(root))
				}
				return true
			})
			m.purgeStates(seen, partialRoots)
		}
	}
}

// maxRescanWarns caps the per-root Warn logs of one rescan: a network
// filesystem can deny access to thousands of directories at every rescan.
const maxRescanWarns = 10

// walkRoot queues every file under root and records it in seen. An unreadable
// entry is logged and skipped so the other entries are still visited. partial
// is true when entries may be missing from seen: an unreadable entry, a missing
// root (e.g. unmounted share) or an interrupted walk. A subdirectory removed
// during the walk is not partial: its files are really gone.
func (m *Monitor) walkRoot(root string, seen map[string]struct{}) (partial bool) {
	root = filepath.Clean(root)
	// The trailing separator makes WalkDir follow a root that is a symlink.
	walkPath := withSeparator(root)
	warns, skipped := 0, 0
	err := filepath.WalkDir(walkPath, func(path string, d fs.DirEntry, walkErr error) error {
		select {
		case <-m.done:
			partial = true
			return fs.SkipAll
		default:
		}
		if walkErr != nil {
			isRoot := path == root || path == walkPath
			if !isRoot && errors.Is(walkErr, fs.ErrNotExist) {
				logger.Debug("path removed during rescan", slog.String("path", path))
			} else {
				partial = true
				if warns < maxRescanWarns {
					warns++
					logger.Warn("cannot access path at rescan", slog.String("path", path), slog.String("error", walkErr.Error()))
				} else {
					skipped++
					logger.Debug("cannot access path at rescan", slog.String("path", path), slog.String("error", walkErr.Error()))
				}
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		seen[path] = struct{}{}
		if _, loaded := m.pendingFiles.LoadOrStore(path, struct{}{}); !loaded {
			select {
			case <-m.done:
				partial = true
				return fs.SkipAll
			case m.filesToScan <- path:
			}
		}
		return nil
	})
	if err != nil {
		partial = true
		logger.Error("cannot walk dir at rescan", slog.String("path", root), slog.String("error", err.Error()))
	}
	if skipped > 0 {
		logger.Warn("more paths could not be accessed at rescan", slog.String("root", root), slog.Int("more", skipped))
	}
	return partial
}

// purgeStates forgets the state of files not seen anymore (deleted, moved): it
// would never be cleaned otherwise. States under a partially walked root are
// kept, absence from seen proves nothing there.
func (m *Monitor) purgeStates(seen map[string]struct{}, partialRoots []string) {
	m.states.Range(func(key, _ any) bool {
		path, ok := key.(string)
		if ok {
			if _, found := seen[path]; found {
				return true
			}
			if underAny(path, partialRoots) {
				return true
			}
		}
		m.states.Delete(key)
		return true
	})
}

func withSeparator(path string) string {
	if strings.HasSuffix(path, string(filepath.Separator)) {
		return path
	}
	return path + string(filepath.Separator)
}

// underAny reports whether path is one of roots or lies under one of them.
// Roots must be cleaned, like the paths returned by WalkDir.
func underAny(path string, roots []string) bool {
	for _, root := range roots {
		if path == root || strings.HasPrefix(path, withSeparator(root)) {
			return true
		}
	}
	return false
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
	path = filepath.Clean(path)
	if _, ok := m.paths.Load(path); ok {
		return nil
	}
	if m.watcher != nil {
		if err := m.watcher.AddRecursive(path); err != nil {
			return fmt.Errorf("error watching %s: %w", path, err)
		}
	} else if _, err := os.Stat(path); err != nil {
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
