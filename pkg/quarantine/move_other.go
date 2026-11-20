//go:build !linux && !windows

package quarantine

import (
	"os"
	"syscall"
)

func renameNoReplaceAtomicOS(string, string) (bool, error) { return false, nil }

func ownedByCurrentUser(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}
