//go:build linux
// +build linux

package scanner

import (
	"io/fs"
	"syscall"
)

func getUid(info fs.FileInfo) int {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(stat.Uid)
	}
	return 0
}

func getGid(info fs.FileInfo) int {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(stat.Gid)
	}
	return 0
}
