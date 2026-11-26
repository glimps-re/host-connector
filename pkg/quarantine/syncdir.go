//go:build !windows

package quarantine

import (
	"os"
	"path/filepath"
)

// syncDir makes the entries of dir durable. Replaced in tests.
var syncDir = syncDirectory

func syncDirectory(dir string) error {
	d, err := os.Open(filepath.Clean(dir))
	if err != nil {
		return err
	}
	err = d.Sync()
	if closeErr := d.Close(); err == nil {
		err = closeErr
	}
	return err
}
