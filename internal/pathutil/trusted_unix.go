//go:build unix

package pathutil

import (
	"io/fs"
	"syscall"
)

// TrustedLink reports whether a link is the system's own: owned by root, in a
// directory owned by root that neither the group nor others can write. There is
// no exception for the sticky bit: a root link in /tmp is not trusted.
func TrustedLink(link, parent fs.FileInfo) bool {
	ls, ok := link.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	ps, ok := parent.Sys().(*syscall.Stat_t)
	return ok && ls.Uid == 0 && ps.Uid == 0 && parent.Mode().Perm()&0o022 == 0
}
