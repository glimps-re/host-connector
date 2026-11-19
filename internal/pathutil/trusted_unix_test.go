//go:build unix

package pathutil

import (
	"io/fs"
	"syscall"
	"testing"
	"time"
)

type fakeInfo struct {
	mode fs.FileMode
	uid  uint32
}

func (f fakeInfo) Name() string       { return "x" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

func TestTrustedLink(t *testing.T) {
	tests := []struct {
		name         string
		link, parent fakeInfo
		want         bool
	}{
		{"root link in a root directory", fakeInfo{fs.ModeSymlink, 0}, fakeInfo{fs.ModeDir | 0o755, 0}, true},
		{"root link in a read-only root directory", fakeInfo{fs.ModeSymlink, 0}, fakeInfo{fs.ModeDir | 0o555, 0}, true},
		{"root link in /tmp (sticky, writable by others)", fakeInfo{fs.ModeSymlink, 0}, fakeInfo{fs.ModeDir | fs.ModeSticky | 0o777, 0}, false},
		{"root link in a group-writable root directory", fakeInfo{fs.ModeSymlink, 0}, fakeInfo{fs.ModeDir | 0o775, 0}, false},
		{"user link in a root directory", fakeInfo{fs.ModeSymlink, 1000}, fakeInfo{fs.ModeDir | 0o755, 0}, false},
		{"root link in a user directory", fakeInfo{fs.ModeSymlink, 0}, fakeInfo{fs.ModeDir | 0o755, 1000}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TrustedLink(tt.link, tt.parent); got != tt.want {
				t.Errorf("TrustedLink() = %t, want %t", got, tt.want)
			}
		})
	}
}
