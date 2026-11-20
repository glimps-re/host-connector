//go:build linux

package scanner

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

// exchangeLoop swaps the two paths over and over until stop is set: whatever
// name is looked up, it holds one file or the other at any instant.
func exchangeLoop(a, b string, stop *atomic.Bool, wg *sync.WaitGroup) {
	wg.Go(func() {
		for !stop.Load() {
			_ = unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE)
		}
	})
}

// A file verified clean (A) is exchanged with an unverified one (B) while it is
// moved: B must never reach the destination, whatever the instant of the
// exchange. 3000 moves with the race detector, 10000 without (the cost of an
// iteration is mostly file creation).
func TestMoveAction_anExchangeDuringTheMoveNeverPublishesTheUnverifiedFile(t *testing.T) {
	if !holdsHandle {
		t.Skip("moves go by name on this system")
	}
	iterations := 10000
	if testing.Short() || raceEnabled {
		iterations = 3000
	}
	in, out := t.TempDir(), t.TempDir()
	a, err := NewMoveAction(out, in)
	if err != nil {
		t.Fatal(err)
	}
	var unverifiedPublished, verifiedPublished int
	for i := range iterations {
		name := filepath.Join(in, "f.bin")
		other := filepath.Join(in, "g.bin")
		if err := os.WriteFile(name, []byte("VERIFIED"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(other, []byte("UNVERIFIED"), 0o600); err != nil {
			t.Fatal(err)
		}
		src := testSource(t, name) // the handle and the identity are those of A
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
			content, err := os.ReadFile(filepath.Clean(filepath.Join(out, e.Name())))
			if err != nil {
				t.Fatal(err)
			}
			switch string(content) {
			case "UNVERIFIED":
				unverifiedPublished++
			case "VERIFIED":
				verifiedPublished++
			}
			if err := os.Remove(filepath.Join(out, e.Name())); err != nil {
				t.Fatal(err)
			}
		}
		for _, p := range []string{name, other} {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
		}
		_ = i
	}
	if unverifiedPublished != 0 {
		t.Errorf("the unverified file reached the destination %d times out of %d", unverifiedPublished, iterations)
	}
	if verifiedPublished == 0 {
		t.Error("the verified file was never moved: the test proves nothing")
	}
}

// The folder of the deposit is exchanged with a link to a folder holding a file
// of the same name while the file is removed: the file behind the link must
// never be deleted.
func TestRemoveFileAction_anExchangeOfTheFolderNeverDeletesAFileElsewhere(t *testing.T) {
	if !holdsHandle {
		t.Skip("removals go by name on this system")
	}
	iterations := 5000
	if testing.Short() || raceEnabled {
		iterations = 2000
	}
	base := t.TempDir()
	victim := filepath.Join(base, "victim")
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	victimFile := filepath.Join(victim, "f.bin")
	for range iterations {
		deposit := filepath.Join(base, "in", "d")
		link := filepath.Join(base, "in", "lnk")
		if err := os.MkdirAll(deposit, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, link); err != nil {
			t.Skipf("symbolic links unavailable: %v", err)
		}
		if err := os.WriteFile(filepath.Join(deposit, "f.bin"), []byte("malware"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(victimFile, []byte("someone else's file"), 0o600); err != nil {
			t.Fatal(err)
		}
		src := testSource(t, filepath.Join(deposit, "f.bin"))
		var stop atomic.Bool
		var wg sync.WaitGroup
		exchangeLoop(deposit, link, &stop, &wg)
		_ = (&RemoveFileAction{}).Handle(t.Context(), src, datamodel.Result{Malware: true}, &datamodel.Report{})
		stop.Store(true)
		wg.Wait()
		if _, err := os.Stat(victimFile); err != nil {
			t.Fatalf("the file behind the redirected folder was deleted: %v", err)
		}
		_ = os.RemoveAll(filepath.Join(base, "in"))
	}
}
