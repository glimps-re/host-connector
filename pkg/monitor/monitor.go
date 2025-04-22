package monitor

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/glimps-re/host-connector/pkg/filesystem"
)

var Logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

type Monitorer interface {
	Start()
	Stop()
	Add(path string) error
	Remove(path string) error
}

type OnNewFileFunc func(file string) error

type Monitor struct {
	fs            filesystem.FileSystem
	cb            OnNewFileFunc
	preScan       bool
	period        time.Duration
	modDelay      time.Duration
	watchers      map[string]filesystem.Watcher
	watchersMutex sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup

	// File deduplication
	fileToScan     map[string]struct{}
	fileToScanLock sync.Mutex
	scanTicker     *time.Ticker
}

var (
	DefaultScanPeriod = time.Millisecond * 100
	Since             = time.Since
)

func NewMonitor(fs filesystem.FileSystem, onNewFile OnNewFileFunc, prescan bool, period time.Duration, modDelay time.Duration) (*Monitor, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Force default period if 0
	if period == 0 {
		period = DefaultScanPeriod
	}

	return &Monitor{
		fs:         fs,
		cb:         onNewFile,
		preScan:    prescan,
		period:     period,
		modDelay:   modDelay,
		watchers:   make(map[string]filesystem.Watcher),
		ctx:        ctx,
		cancel:     cancel,
		fileToScan: make(map[string]struct{}),
	}, nil
}

func (m *Monitor) Close() {
	m.cancel()

	// Stop the scan ticker if it exists
	if m.scanTicker != nil {
		m.scanTicker.Stop()
	}

	m.wg.Wait()

	m.watchersMutex.Lock()
	defer m.watchersMutex.Unlock()

	for path, watcher := range m.watchers {
		if err := watcher.Close(); err != nil {
			Logger.Warn("Monitor could not close watcher", slog.String("path", path), slog.String("error", err.Error()))
		}
	}
	m.watchers = make(map[string]filesystem.Watcher)
}

func (m *Monitor) Start() {
	// Always start the scan ticker with the configured period
	m.scanTicker = time.NewTicker(m.period)
	m.wg.Add(1)
	go m.scanFiles()
}

func (m *Monitor) Add(path string) error {
	m.watchersMutex.Lock()
	defer m.watchersMutex.Unlock()

	// Check if already watching this path
	if _, exists := m.watchers[path]; exists {
		return nil
	}

	watcher, err := m.fs.Watch(m.ctx, path)
	if err != nil {
		return err
	}

	m.watchers[path] = watcher

	// Start handling events for this watcher
	m.wg.Add(1)
	go m.handleWatcherEvents(path, watcher)

	// Handle prescan if enabled
	if m.preScan {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			if err := m.cb(path); err != nil {
				Logger.Error("error action on prescan", slog.String("path", path), slog.String("err", err.Error()))
			}
		}()
	}

	return nil
}

func (m *Monitor) Remove(path string) error {
	m.watchersMutex.Lock()
	defer m.watchersMutex.Unlock()

	watcher, exists := m.watchers[path]
	if !exists {
		return nil
	}

	delete(m.watchers, path)
	return watcher.Close()
}

func (m *Monitor) handleWatcherEvents(path string, watcher filesystem.Watcher) {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return

		case event, ok := <-watcher.Events():
			if !ok {
				Logger.Info("Watcher events channel closed", slog.String("path", path))
				return
			}

			// Only process CREATE and WRITE events for new files
			if event.Type == filesystem.WatchEventCreate || event.Type == filesystem.WatchEventWrite {
				// Skip directories
				if event.FileInfo != nil && event.FileInfo.IsDir() {
					continue
				}

				Logger.Debug("File system event",
					slog.String("path", event.Path),
					slog.String("type", event.Type.String()),
					slog.Time("time", event.Time))

				// Always add to scan queue for deduplication
				m.fileToScanLock.Lock()
				m.fileToScan[event.Path] = struct{}{}
				m.fileToScanLock.Unlock()
			}

		case err, ok := <-watcher.Errors():
			if !ok {
				Logger.Info("Watcher errors channel closed", slog.String("path", path))
				return
			}

			Logger.Error("watcher error",
				slog.String("path", path),
				slog.String("error", err.Error()))
		}
	}
}

func (m *Monitor) scanFiles() {
	defer m.wg.Done()
	defer m.scanTicker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-m.scanTicker.C:
			m.fileToScanLock.Lock()
			for filePath := range m.fileToScan {
				if m.ctx.Err() != nil {
					m.fileToScanLock.Unlock()
					return
				}

				// Check file stability only if modDelay > 0
				if m.modDelay > 0 {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					err := m.checkFileStability(ctx, filePath)
					cancel()

					if err != nil {
						// File is still being modified or doesn't exist, keep it for next iteration
						continue
					}
				}

				// Process the file
				if err := m.cb(filePath); err != nil {
					Logger.Error("error action on new file",
						slog.String("path", filePath),
						slog.String("err", err.Error()))
				}

				// Remove from map after processing
				delete(m.fileToScan, filePath)
			}
			m.fileToScanLock.Unlock()
		}
	}
}

func (m *Monitor) checkFileStability(ctx context.Context, filePath string) (err error) {
	info, err := m.fs.Stat(ctx, filePath)
	if err != nil {
		return
	}
	if Since(info.ModTime()) < m.modDelay {
		err = errors.New("file still being modified")
		return
	}
	return
}
