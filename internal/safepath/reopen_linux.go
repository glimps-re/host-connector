//go:build linux

package safepath

import (
	"os"
	"strconv"
)

// FDPath is the path that reads the file held by f through its descriptor: the
// one of this process, or, with a pid, the one a process that inherited it can
// use. No name of the file is involved.
func FDPath(f *os.File, pid int) string {
	who := "self"
	if pid > 0 {
		who = strconv.Itoa(pid)
	}
	return "/proc/" + who + "/fd/" + strconv.FormatUint(uint64(f.Fd()), 10)
}

// Reopen opens the file behind f again, with its own offset: it goes through the
// descriptor, so it is the same inode whatever the name of the file is now.
func Reopen(f *os.File) (*os.File, error) {
	return os.Open(FDPath(f, 0))
}
