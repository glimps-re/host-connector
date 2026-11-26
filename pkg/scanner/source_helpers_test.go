package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/glimps-re/host-connector/internal/safepath"
)

// testSource is the Source of the file at path as the pipeline would verify it:
// its identity is the one of the file now (zero if there is no such file).
func testSource(t testing.TB, path string) Source {
	t.Helper()
	src := Source{Path: path}
	if info, err := os.Lstat(path); err == nil {
		src.Identity = IdentityOf(info)
		if info.Mode().IsRegular() {
			if sha, shaErr := getFileSHA256(path); shaErr == nil {
				src.SHA256 = sha
			}
		}
		// The handle the pipeline would hold, where it holds one.
		if holdsHandle && info.Mode().IsRegular() {
			h, err := safepath.Open(filepath.Dir(path), filepath.Base(path))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if e := h.Close(); e != nil {
					t.Error(e)
				}
			})
			src.Root, src.handle = filepath.Dir(path), h
		}
	}
	return src
}

func (s Source) withHandle(h *safepath.File) Source {
	s.handle = h
	return s
}
