package scanner

import (
	"errors"
	"syscall"
)

// isNoSpace tells a full disk.
func isNoSpace(err error) bool { return errors.Is(err, syscall.ENOSPC) }
