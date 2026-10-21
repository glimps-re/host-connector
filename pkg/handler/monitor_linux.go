//go:build linux

package handler

import (
	"io/fs"
	"syscall"
	"time"
)

// changeTime returns the file ctime, updated by the kernel on every write and not settable by user space.
func changeTime(info fs.FileInfo) time.Time {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}
	}
	return time.Unix(st.Ctim.Unix())
}
