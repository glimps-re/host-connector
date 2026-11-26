package quarantine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// quarantinePath quarantines the file at path, opened for the occasion like the
// scanner does with the file it verified.
func quarantinePath(ctx context.Context, t testing.TB, q Quarantiner, path, sha256 string, malwares []string) (location, id string, err error) {
	t.Helper()
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", "", err
	}
	defer func() {
		if e := f.Close(); e != nil {
			t.Error(e)
		}
	}()
	return q.Quarantine(ctx, path, f, sha256, malwares)
}
