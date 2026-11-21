//go:build linux

package scanner

import "testing"

// isACopy tells whether the file at path is not the file the source was: a verified
// copy makes a new file, a rename would keep the inode.
func isACopy(t *testing.T, path string, sourceIno uint64) bool {
	t.Helper()
	return inoOf(t, path) != sourceIno
}
