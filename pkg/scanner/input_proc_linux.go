//go:build linux

package scanner

import (
	"os"
	"strconv"
)

// descriptorPathOS returns the path /proc/<pid>/fd/<N> that reads the file held
// by f, and whether it can be used: it must resolve to the very same file.
func descriptorPathOS(f *os.File) (string, bool) {
	link := "/proc/" + strconv.Itoa(os.Getpid()) + "/fd/" + strconv.FormatUint(uint64(f.Fd()), 10)
	want, err := f.Stat()
	if err != nil {
		return "", false
	}
	got, err := os.Stat(link)
	if err != nil || !os.SameFile(want, got) {
		return "", false
	}
	return link, true
}
