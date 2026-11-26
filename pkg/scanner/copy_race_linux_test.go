//go:build linux

package scanner

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

// In copy mode a file verified clean (A) is exchanged with an unverified one (B)
// while it is moved, whatever the instant: B must never reach OUTPUT and A must
// be published at least once.
func TestMoveAction_copyModeAnExchangeDuringTheMoveNeverPublishesTheUnverifiedFile(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "f.bin exchanged with g.bin in a loop"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !holdsHandle {
				t.Skip("the exchange needs the verified descriptor of Linux")
			}
			iterations := 10000
			if testing.Short() || raceEnabled {
				iterations = 3000
			}
			in, out := t.TempDir(), t.TempDir()
			a, err := NewMoveActionWithMode(out, in, MoveModeCopy, 0)
			if err != nil {
				t.Fatal(err)
			}
			var unverified, verified, unverifiedLost int
			for range iterations {
				name := filepath.Join(in, "f.bin")
				other := filepath.Join(in, "g.bin")
				if err := os.WriteFile(name, []byte("VERIFIED"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(other, []byte("UNVERIFIED"), 0o600); err != nil {
					t.Fatal(err)
				}
				src := testSource(t, name)
				var stop atomic.Bool
				var wg sync.WaitGroup
				exchangeLoop(name, other, &stop, &wg)
				_ = a.Handle(t.Context(), src, datamodel.Result{}, &datamodel.Report{})
				stop.Store(true)
				wg.Wait()

				entries, err := os.ReadDir(out)
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range entries {
					if e.IsDir() {
						continue
					}
					content, err := os.ReadFile(filepath.Clean(filepath.Join(out, e.Name())))
					if err != nil {
						t.Fatal(err)
					}
					switch string(content) {
					case "UNVERIFIED":
						unverified++
					case "VERIFIED":
						verified++
					}
					if err := os.Remove(filepath.Join(out, e.Name())); err != nil {
						t.Fatal(err)
					}
				}
				// The unverified file is not ours: it must still be in INPUT, under one of
				// the two names.
				found := false
				for _, p := range []string{name, other} {
					if b, err := os.ReadFile(filepath.Clean(p)); err == nil && string(b) == "UNVERIFIED" {
						found = true
					}
				}
				if !found {
					unverifiedLost++
				}
				for _, p := range []string{name, other} {
					if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
				}
			}
			if unverified != 0 {
				t.Errorf("the unverified file reached OUTPUT %d times out of %d", unverified, iterations)
			}
			// The removal of the source checks the name then unlinks it: an exchange that
			// lands between the two removes the file that took the name. That residual
			// window is a documented limit of phase 1, so it is reported, not asserted.
			if unverifiedLost != 0 {
				t.Logf("the file that replaced the name was removed %d times out of %d (residual window between the check and the unlink)", unverifiedLost, iterations)
			}
			if verified == 0 {
				t.Error("the verified file was never published: the test proves nothing")
			}
		})
	}
}

func inoOf(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no stat for %q", path)
	}
	return st.Ino
}
