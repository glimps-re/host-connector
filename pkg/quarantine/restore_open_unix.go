//go:build unix

package quarantine

import (
	"os"
	"syscall"
)

// containerOpenFlags keeps the intent of not following a link and of not blocking
// on a special file swapped in for the container. os.Root ignores O_NOFOLLOW on
// the last component: the guard against a link is the examination of the name
// without following it, the check of the file opened and os.SameFile
// (openContainer); O_NONBLOCK is what keeps a named pipe from blocking.
const containerOpenFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
