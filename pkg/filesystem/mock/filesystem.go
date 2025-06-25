package mock

import (
	"context"
	"io"
	"io/fs"

	"github.com/glimps-re/host-connector/pkg/filesystem"
)

type FileSystemMock struct {
	OpenMock     func(ctx context.Context, name string) (io.ReadSeekCloser, error)
	StatMock     func(ctx context.Context, name string) (fs.FileInfo, error)
	LstatMock    func(ctx context.Context, name string) (fs.FileInfo, error)
	WalkDirMock  func(ctx context.Context, root string, fn fs.WalkDirFunc) error
	RemoveMock   func(ctx context.Context, path string) error
	CreateMock   func(ctx context.Context, name string) (io.WriteCloser, error)
	MkdirAllMock func(ctx context.Context, path string, perm fs.FileMode) error
	RenameMock   func(ctx context.Context, oldpath, newpath string) error
	IsLocalMock  func() bool
	WatchMock    func(ctx context.Context, path string) (filesystem.Watcher, error)
}

func (fsm *FileSystemMock) Open(ctx context.Context, name string) (io.ReadSeekCloser, error) {
	if fsm.OpenMock != nil {
		return fsm.OpenMock(ctx, name)
	}
	panic("FileSystemMock.Open() not implemented in current test")
}

func (fsm *FileSystemMock) Stat(ctx context.Context, name string) (fs.FileInfo, error) {
	if fsm.StatMock != nil {
		return fsm.StatMock(ctx, name)
	}
	panic("FileSystemMock.Stat() not implemented in current test")
}

func (fsm *FileSystemMock) Lstat(ctx context.Context, name string) (fs.FileInfo, error) {
	if fsm.LstatMock != nil {
		return fsm.LstatMock(ctx, name)
	}
	panic("FileSystemMock.Lstat() not implemented in current test")
}

func (fsm *FileSystemMock) WalkDir(ctx context.Context, root string, fn fs.WalkDirFunc) error {
	if fsm.WalkDirMock != nil {
		return fsm.WalkDirMock(ctx, root, fn)
	}
	panic("FileSystemMock.WalkDir() not implemented in current test")
}

func (fsm *FileSystemMock) Remove(ctx context.Context, path string) error {
	if fsm.RemoveMock != nil {
		return fsm.RemoveMock(ctx, path)
	}
	panic("FileSystemMock.Remove() not implemented in current test")
}

func (fsm *FileSystemMock) Create(ctx context.Context, name string) (io.WriteCloser, error) {
	if fsm.CreateMock != nil {
		return fsm.CreateMock(ctx, name)
	}
	panic("FileSystemMock.Create() not implemented in current test")
}

func (fsm *FileSystemMock) MkdirAll(ctx context.Context, path string, perm fs.FileMode) error {
	if fsm.MkdirAllMock != nil {
		return fsm.MkdirAllMock(ctx, path, perm)
	}
	panic("FileSystemMock.MkdirAll() not implemented in current test")
}

func (fsm *FileSystemMock) Rename(ctx context.Context, oldpath, newpath string) error {
	if fsm.RenameMock != nil {
		return fsm.RenameMock(ctx, oldpath, newpath)
	}
	panic("FileSystemMock.Rename() not implemented in current test")
}

func (fsm *FileSystemMock) IsLocal() bool {
	if fsm.IsLocalMock != nil {
		return fsm.IsLocalMock()
	}
	panic("FileSystemMock.IsLocal() not implemented in current test")
}

func (fsm *FileSystemMock) Watch(ctx context.Context, path string) (filesystem.Watcher, error) {
	if fsm.WatchMock != nil {
		return fsm.WatchMock(ctx, path)
	}
	panic("FileSystemMock.Watch() not implemented in current test")
}

// MockWatcher implements filesystem.Watcher for testing
type MockWatcher struct {
	EventsMock func() <-chan filesystem.WatchEvent
	ErrorsMock func() <-chan error
	CloseMock  func() error
}

func (mw *MockWatcher) Events() <-chan filesystem.WatchEvent {
	if mw.EventsMock != nil {
		return mw.EventsMock()
	}
	panic("MockWatcher.Events() not implemented in current test")
}

func (mw *MockWatcher) Errors() <-chan error {
	if mw.ErrorsMock != nil {
		return mw.ErrorsMock()
	}
	panic("MockWatcher.Errors() not implemented in current test")
}

func (mw *MockWatcher) Close() error {
	if mw.CloseMock != nil {
		return mw.CloseMock()
	}
	panic("MockWatcher.Close() not implemented in current test")
}
