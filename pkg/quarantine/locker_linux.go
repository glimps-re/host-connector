//go:build linux

package quarantine

import (
	"io/fs"
	"syscall"
)

func getUID(info fs.FileInfo) int {
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
