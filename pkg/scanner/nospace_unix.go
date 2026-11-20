//go:build !windows

package scanner

import (
	"errors"
	"syscall"
)

// isNoSpace tells a full disk, or a quota that is used up.
func isNoSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}
