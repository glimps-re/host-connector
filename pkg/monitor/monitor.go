package monitor

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

var Logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

type Monitorer interface {
	Start()
	Stop()
	Add(path string) error
	Remove(path string) error
}

type MonitorFunc func(file string) error

type Monitor struct {
	watcher        *fsnotify.Watcher
	wg             sync.WaitGroup
	cb             MonitorFunc
	preScan        bool
	period         time.Duration
	modDelay       time.Duration
	paths          map[string]struct{}
	stop           context.Context
	cancel         context.CancelFunc
	fileToScan     map[string]struct{}
	fileToScanLock sync.Mutex
}

func NewMonitor(onNewFile MonitorFunc, prescan bool, period time.Duration, modDelay time.Duration) (*Monitor, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	stop, cancel := context.WithCancel(context.Background())
	return &Monitor{
		watcher:    watcher,
		cb:         onNewFile,
		preScan:    prescan,
		period:     period,
		paths:      map[string]struct{}{},
		fileToScan: map[string]struct{}{},
		stop:       stop,
		cancel:     cancel,
		modDelay:   modDelay,
	}, nil
}

func (m *Monitor) Close() {
	m.watcher.Close()
	m.cancel()
	m.wg.Wait()
}

func (m *Monitor) Start() {
	m.wg.Add(1)
	go m.work()
	if m.period != 0 {
		m.wg.Add(1)
		go m.scan()
	}
	m.wg.Add(1)
	go m.scanFiles()
}

func (m *Monitor) scan() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.period)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop.Done():
			return
		case <-ticker.C:
			for path := range m.paths {
				m.cb(path)
			}
		}
	}
}

func (m *Monitor) work() {
	defer m.wg.Done()
	for {
		select {
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			Logger.Debug("new event", "event", event)
			if event.Has(fsnotify.Create) || event.Has(fsnotify.Write) {
				m.fileToScanLock.Lock()
				m.fileToScan[event.Name] = struct{}{}
				m.fileToScanLock.Unlock()
			}
		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			Logger.Error("watcher error", "error", err)
		}
	}
}

var (
	ScanFileLoopPause = time.Millisecond * 100
	Since             = time.Since
)

func (m *Monitor) scanFiles() {
	defer m.wg.Done()
	ticker := time.NewTicker(ScanFileLoopPause)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop.Done():
			return
		case <-ticker.C:
			for path := range m.fileToScan {
				if info, err := os.Stat(path); err == nil && Since(info.ModTime()) > m.modDelay {
					m.cb(path)
					m.fileToScanLock.Lock()
					delete(m.fileToScan, path)
					m.fileToScanLock.Unlock()
				}
			}
		}
	}
}

func (m *Monitor) Add(path string) error {
	if err := m.watcher.Add(path); err != nil {
		return err
	}
	m.paths[path] = struct{}{}
	if m.preScan {
		go func() {
			m.cb(path)
		}()
	}
	return nil
}

func (m *Monitor) Remove(path string) error {
	delete(m.paths, path)
	return m.watcher.Remove(path)
}
