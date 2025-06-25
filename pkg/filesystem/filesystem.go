package filesystem

import (
	"context"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"time"
)

var Logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

// WatchEventType represents the type of filesystem event
type WatchEventType int

const (
	WatchEventCreate WatchEventType = iota
	WatchEventWrite
)

func (t WatchEventType) String() string {
	switch t {
	case WatchEventCreate:
		return "CREATE"
	case WatchEventWrite:
		return "WRITE"
	default:
		return "UNKNOWN"
	}
}

// WatchEvent represents a filesystem event
type WatchEvent struct {
	Path     string
	Type     WatchEventType
	Time     time.Time
	OldPath  string // Used for rename events
	FileInfo fs.FileInfo
}

// Watcher represents an active watch session
type Watcher interface {
	// Events returns a channel of watch events
	Events() <-chan WatchEvent
	// Errors returns a channel of watch errors
	Errors() <-chan error
	// Close stops watching and cleans up resources
	Close() error
}

type FileSystem interface {
	Open(ctx context.Context, name string) (io.ReadSeekCloser, error)
	Stat(ctx context.Context, name string) (fs.FileInfo, error)
	Lstat(ctx context.Context, name string) (fs.FileInfo, error)
	WalkDir(ctx context.Context, root string, fn fs.WalkDirFunc) error
	Remove(ctx context.Context, path string) error
	Create(ctx context.Context, name string) (io.WriteCloser, error)
	MkdirAll(ctx context.Context, path string, perm fs.FileMode) error
	Rename(ctx context.Context, oldpath, newpath string) error
	IsLocal() bool

	// Watch starts watching the specified path for changes
	Watch(ctx context.Context, path string) (Watcher, error)
}
