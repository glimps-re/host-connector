//go:build linux

package quarantine

import (
	"io/fs"
	"syscall"
	"time"
)

// changeTime returns the inode change time: a rewrite followed by a reset of
// the modification time still moves it.
func changeTime(fi fs.FileInfo) (time.Time, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(toInt64(st.Ctim.Sec), toInt64(st.Ctim.Nsec)), true
}

// toInt64 hides the width of the timespec fields, which differs between
// architectures.
func toInt64[T ~int32 | ~int64](v T) int64 { return int64(v) }
