package filesystem

import (
	"context"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// LocalFileSystem implements FileSystem interface for local filesystem
type LocalFileSystem struct{}

// NewLocalFileSystem creates a new LocalFileSystem instance
func NewLocalFileSystem() *LocalFileSystem {
	return &LocalFileSystem{}
}

// localReadSeekCloser wraps os.File to implement io.ReadSeekCloser
type localReadSeekCloser struct {
	*os.File
}

// Open opens a file for reading
func (l *LocalFileSystem) Open(ctx context.Context, name string) (reader io.ReadSeekCloser, err error) {
	file, err := os.Open(name) //nolint:gosec // file indicated by user, for submitting only
	if err != nil {
		return
	}
	reader = &localReadSeekCloser{file}
	return
}

// Stat returns file info
func (l *LocalFileSystem) Stat(ctx context.Context, name string) (info fs.FileInfo, err error) {
	info, err = os.Stat(name)
	return
}

// Lstat returns file info without following symlinks
func (l *LocalFileSystem) Lstat(ctx context.Context, name string) (info fs.FileInfo, err error) {
	info, err = os.Lstat(name)
	return
}

// WalkDir walks the file tree rooted at root
func (l *LocalFileSystem) WalkDir(ctx context.Context, root string, fn fs.WalkDirFunc) (err error) {
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		// Check context cancellation
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fn(path, d, err)
	})
	return
}

// Remove deletes a file
func (l *LocalFileSystem) Remove(ctx context.Context, path string) (err error) {
	err = os.Remove(path)
	return
}

// localWriteCloser wraps os.File to implement io.WriteCloser
type localWriteCloser struct {
	*os.File
}

// Create creates a new file
func (l *LocalFileSystem) Create(ctx context.Context, name string) (writer io.WriteCloser, err error) {
	file, err := os.Create(name) //nolint:gosec // create quarantine file
	if err != nil {
		return
	}
	writer = &localWriteCloser{file}
	return
}

// MkdirAll creates a directory path
func (l *LocalFileSystem) MkdirAll(ctx context.Context, path string, perm fs.FileMode) (err error) {
	err = os.MkdirAll(path, perm)
	return
}

// Rename moves a file from oldpath to newpath
func (l *LocalFileSystem) Rename(ctx context.Context, oldpath, newpath string) (err error) {
	err = os.Rename(oldpath, newpath)
	return
}

// IsLocal returns true for LocalFileSystem
func (l *LocalFileSystem) IsLocal() bool {
	return true
}

// Watch starts watching the specified path for changes
func (l *LocalFileSystem) Watch(ctx context.Context, path string) (Watcher, error) {
	return newLocalWatcher(ctx, path)
}

// localWatcher implements Watcher interface for local filesystem
type localWatcher struct {
	watcher  *fsnotify.Watcher
	events   chan WatchEvent
	errors   chan error
	done     chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.RWMutex
	watching map[string]bool
}

func newLocalWatcher(ctx context.Context, path string) (*localWatcher, error) {
	fsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	watchCtx, cancel := context.WithCancel(ctx)

	w := &localWatcher{
		watcher:  fsWatcher,
		events:   make(chan WatchEvent, 100),
		errors:   make(chan error, 10),
		done:     make(chan struct{}),
		ctx:      watchCtx,
		cancel:   cancel,
		watching: make(map[string]bool),
	}

	// Add initial path
	if err := w.addPath(path); err != nil {
		if e := fsWatcher.Close(); e != nil {
			Logger.Error("could not close fsnotify watcher", slog.String("error", e.Error()))
		}
		cancel()
		return nil, err
	}

	// Start watching goroutine
	go w.watch()

	return w, nil
}

func (w *localWatcher) addPath(path string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.watching[path] {
		return nil
	}

	err := w.watcher.Add(path)
	if err != nil {
		return err
	}
	w.watching[path] = true

	return filepath.WalkDir(path, func(walkPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() && walkPath != path && !w.watching[walkPath] {
			if addErr := w.watcher.Add(walkPath); addErr == nil {
				w.watching[walkPath] = true
			}
		}
		return nil
	})
}

func (w *localWatcher) watch() {
	defer close(w.done)
	defer close(w.events)
	defer close(w.errors)

	for {
		select {
		case <-w.ctx.Done():
			return
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			w.handleFsnotifyEvent(event)
		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			select {
			case w.errors <- err:
			case <-w.ctx.Done():
				return
			}
		}
	}
}

func (w *localWatcher) handleFsnotifyEvent(event fsnotify.Event) {
	var watchEventType WatchEventType
	switch {
	case event.Has(fsnotify.Create):
		watchEventType = WatchEventCreate
	case event.Has(fsnotify.Write):
		watchEventType = WatchEventWrite
	default:
		return
	}

	var fileInfo fs.FileInfo
	if info, err := os.Lstat(event.Name); err == nil {
		fileInfo = info
		// Add new directory
		if watchEventType == WatchEventCreate && info.IsDir() {
			if e := w.addPath(event.Name); e != nil {
				Logger.Error("could not monitor path", slog.String("path", event.Name), slog.String("error", e.Error()))
			}
		}
	}

	watchEvent := WatchEvent{
		Path:     event.Name,
		Type:     watchEventType,
		Time:     time.Now(),
		FileInfo: fileInfo,
	}

	select {
	case w.events <- watchEvent:
	case <-w.ctx.Done():
		return
	}
}

func (w *localWatcher) Events() <-chan WatchEvent {
	return w.events
}

func (w *localWatcher) Errors() <-chan error {
	return w.errors
}

func (w *localWatcher) Close() error {
	w.cancel()
	err := w.watcher.Close()
	<-w.done
	return err
}
