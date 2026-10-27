//go:build windows

package handler

import (
	"io/fs"
	"time"
)

// changeTime is not available on Windows, stability relies on size and mtime only.
func changeTime(_ fs.FileInfo) time.Time {
	return time.Time{}
}
