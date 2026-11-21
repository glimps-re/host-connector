//go:build !linux

package quarantine

import "os"

// rootRenameNoReplaceOS is not available: the caller falls back on a check under
// an exclusive lock.
func rootRenameNoReplaceOS(*os.Root, string, string) (handled bool, err error) {
	return false, nil
}
