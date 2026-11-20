//go:build !linux

package quarantine

import (
	"io/fs"
	"time"
)

// changeTime is not available: the identity of the file (os.SameFile) is the
// only extra guard.
func changeTime(fs.FileInfo) (time.Time, bool) { return time.Time{}, false }
