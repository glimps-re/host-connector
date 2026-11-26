package quarantine

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// The restoration of the file at A and the quarantine of the same content at B
// run together: B is quarantined, A is released, neither waits for ever on the
// other, and the release of A never reaches B.
func TestQuarantine_aRestorationAndTheQuarantineOfTheSameContentElsewhereRunTogether(t *testing.T) {
	for _, format := range []Format{FormatTar, FormatZip} {
		t.Run(string(format), func(t *testing.T) {
			for range 20 {
				q, _ := newIntegrityHandler(t, "infected", format)
				content := "one content at two places"
				sha := sha256Hex([]byte(content))
				dir := t.TempDir()
				a := depositSample(t, dir, "a.bin", content)
				_, idA, err := quarantinePath(t.Context(), t, q, a, sha, []string{"m"})
				if err != nil {
					t.Fatal(err)
				}
				removeQuarantined(t, a)
				b := depositSample(t, dir, "b.bin", content)

				var wg sync.WaitGroup
				var restoreErr, quarantineErr error
				var idB string
				wg.Go(func() { restoreErr = q.Restore(t.Context(), idA) })
				wg.Go(func() { _, idB, quarantineErr = quarantinePath(t.Context(), t, q, b, sha, []string{"m"}) })
				waitOrFail(t, &wg, 20*time.Second)

				if restoreErr != nil || quarantineErr != nil {
					t.Fatalf("Restore() = %v, Quarantine() = %v, want both to succeed", restoreErr, quarantineErr)
				}
				assertRestored(t, q, a, sha, true)
				assertRestored(t, q, b, sha, false)
				if idB == idA || idB == "" {
					t.Fatalf("B quarantined under id %q, A under %q: want an id of its own", idB, idA)
				}
				if entry, e := q.registry.Get(t.Context(), idB); e != nil || entry.Restored() {
					t.Errorf("the entry of B = %+v, %v, want it quarantined and not restored", entry, e)
				}
				if got, e := os.ReadFile(filepath.Clean(a)); e != nil || string(got) != content {
					t.Errorf("A restored as %q (%v), want %q", got, e, content)
				}
			}
		})
	}
}

// The same file is restored and quarantined again over and over by a rescan
// that races the restoration: once the restoration is done, a quarantine of the
// file is refused with ErrRestored and writes nothing.
func TestQuarantine_aRescanRacingTheRestorationNeverQuarantinesAgain(t *testing.T) {
	q, dir := newIntegrityHandler(t, "infected", FormatTar)
	content := "a file restored while a rescan looks at it"
	sha := sha256Hex([]byte(content))
	src := depositSample(t, t.TempDir(), "f.bin", content)
	_, id, err := quarantinePath(t.Context(), t, q, src, sha, []string{"m"})
	if err != nil {
		t.Fatal(err)
	}
	removeQuarantined(t, src)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				runtime.Gosched()
			}
			if _, _, e := quarantinePath(t.Context(), t, q, src, sha, []string{"m"}); e != nil && !errors.Is(e, ErrRestored) && !errors.Is(e, os.ErrNotExist) {
				t.Errorf("Quarantine() error = %v", e)
				return
			}
		}
	})
	restoreErr := q.Restore(t.Context(), id)
	if restoreErr != nil {
		close(stop)
		wg.Wait()
		t.Fatalf("Restore() error = %v", restoreErr)
	}
	for range 50 {
		if _, _, e := quarantinePath(t.Context(), t, q, src, sha, []string{"m"}); !errors.Is(e, ErrRestored) {
			t.Errorf("Quarantine() after the restoration = %v, want ErrRestored", e)
		}
	}
	close(stop)
	waitOrFail(t, &wg, 20*time.Second)
	assertRestored(t, q, src, sha, true)
	if got, e := os.ReadFile(filepath.Clean(src)); e != nil || string(got) != content {
		t.Errorf("the restored file holds %q (%v), want %q", got, e, content)
	}
	if entries, e := os.ReadDir(dir); e != nil || len(entries) != 0 {
		t.Errorf("quarantine folder holds %v (%v) after the restoration, want nothing", entries, e)
	}
}

// removeQuarantined does what the action does once a file is quarantined: the
// file leaves its place, which a restoration needs free.
func removeQuarantined(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func assertRestored(t *testing.T, q *QuarantineHandler, location, sha string, want bool) {
	t.Helper()
	got, err := q.IsRestored(t.Context(), location, sha)
	if err != nil || got != want {
		t.Errorf("IsRestored(%s) = %t, %v, want %t", filepath.Base(location), got, err, want)
	}
}

func waitOrFail(t *testing.T, wg *sync.WaitGroup, limit time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatal("deadlock: the goroutines did not end")
	}
}
