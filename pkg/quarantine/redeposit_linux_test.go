//go:build linux

package quarantine

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/glimps-re/host-connector/internal/safepath"
)

// A file is redeposited under the same name between the copy and the removal of
// the source: the removal, which goes through the verified handle, leaves the new
// file alone, and the verified copy stays published.
func TestMoveVerifiedCopy_aFileRedepositedBeforeTheSourceRemovalIsKeptAndTheVerifiedCopyIsPublished(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                  string
		verified, redeposited string
	}{
		{name: "redeposited under the same name", verified: "verified content", redeposited: "REDEPOSITED AFTER THE COPY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			in, out := filepath.Join(root, "in"), filepath.Join(root, "out")
			for _, d := range []string{in, out} {
				if err := os.Mkdir(d, 0o750); err != nil {
					t.Fatal(err)
				}
			}
			name := filepath.Join(in, "f.bin")
			writeFile(t, name, tt.verified, 0o640)
			h, err := safepath.Open(in, "f.bin")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if e := h.Close(); e != nil {
					t.Error(e)
				}
			})
			redeposit := func() error {
				fresh := filepath.Join(in, ".fresh")
				writeFile(t, fresh, tt.redeposited, 0o640)
				if err := os.Rename(fresh, name); err != nil {
					return err
				}
				return h.Remove()
			}
			dst := filepath.Join(out, "f.bin")
			got, err := MoveVerifiedCopy(t.Context(), h.OS(), redeposit, dst, filepath.Join(out, StagingDir), shaHex(tt.verified), fixedNow(), 3)
			if err != nil {
				t.Fatalf("MoveVerifiedCopy() error = %v: the redeposit is not a failure of the move", err)
			}
			if got != dst || readFile(t, dst) != tt.verified {
				t.Errorf("published %q holding %q, want the verified copy under %q", got, readFile(t, dst), dst)
			}
			if b, err := os.ReadFile(filepath.Clean(name)); err != nil || string(b) != tt.redeposited {
				t.Errorf("the redeposited file = %q (%v), want it kept: it is not ours to remove", b, err)
			}
			fi, err := os.Lstat(dst)
			if err != nil {
				t.Fatal(err)
			}
			if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Nlink != 1 {
				t.Errorf("the published file has a name elsewhere (stat %+v): it must be a private copy", fi.Sys())
			}
			if entries, readErr := os.ReadDir(filepath.Join(out, StagingDir)); readErr == nil && len(entries) != 0 {
				t.Errorf("the transit folder holds %d file(s)", len(entries))
			}
		})
	}
}
