//go:build windows

package quarantine

import "errors"

// ErrUnsafeLocation is returned when the quarantine directory could be
// modified by another account.
var ErrUnsafeLocation = errors.New("unsafe quarantine directory")

// CheckLocation accepts any directory: ownership and permission checks are not
// implemented on Windows, where the ACLs of the directory apply.
func CheckLocation(string) error { return nil }
