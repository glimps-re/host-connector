//go:build !linux

package scanner

import (
	"io/fs"
	"time"
)

// systemIdentity has no device, inode or change time here (Windows, macOS, BSD):
// the identity reduces to size and modification time.
func systemIdentity(fs.FileInfo) (dev, ino uint64, ctime time.Time) {
	return 0, 0, time.Time{}
}
