//go:build windows
// +build windows

package scanner

import (
	"io/fs"
)

func getUID(info fs.FileInfo) int {
	return 0
}

func getGid(info fs.FileInfo) int {
	return 0
}
