//go:build unix

package quarantine

import (
	"errors"
	"syscall"
)

// isLinkRefused tells whether the file system refuses hard links.
func isLinkRefused(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EMLINK) || errors.Is(err, syscall.ENOSYS)
}
