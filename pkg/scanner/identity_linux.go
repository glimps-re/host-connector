//go:build linux

package scanner

import (
	"io/fs"
	"syscall"
	"time"
)

func systemIdentity(info fs.FileInfo) (dev, ino uint64, ctime time.Time) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, time.Time{}
	}
	return toUint64(st.Dev), toUint64(st.Ino), time.Unix(st.Ctim.Unix())
}

// toUint64 widens the device and inode numbers, whose type depends on the
// architecture.
func toUint64[T ~uint32 | ~uint64](v T) uint64 { return uint64(v) }
