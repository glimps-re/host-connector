//go:build !linux

package safepath

import "os"

// Reopen opens the file named by f again, by name: these systems have no way to
// reopen a descriptor, and the caller compares the identity of what it gets (a
// documented limit).
func Reopen(f *os.File) (*os.File, error) {
	return os.Open(f.Name())
}
