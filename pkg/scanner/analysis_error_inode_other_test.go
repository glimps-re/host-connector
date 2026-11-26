//go:build !linux

package scanner

import "testing"

// isACopy cannot tell without inodes: the copy is checked by classOf only.
func isACopy(*testing.T, string, uint64) bool { return true }
