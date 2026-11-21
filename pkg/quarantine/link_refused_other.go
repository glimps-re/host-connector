//go:build !unix

package quarantine

import (
	"errors"
	"syscall"
)

// Windows error codes of a file system that cannot make hard links
// (ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED).
const (
	errorInvalidFunction syscall.Errno = 1
	errorNotSupported    syscall.Errno = 50
)

// isLinkRefused tells whether the file system refuses hard links.
func isLinkRefused(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EMLINK) ||
		errors.Is(err, errorInvalidFunction) || errors.Is(err, errorNotSupported)
}
