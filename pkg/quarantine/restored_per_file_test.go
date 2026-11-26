package quarantine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func depositSample(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Two copies of one content are quarantined and one is restored: only that file
// is restored, the other copy and any other location of the content are not.
func TestIsRestored_aReleaseIsPerFile(t *testing.T) {
	for _, format := range []Format{FormatTar, FormatZip} {
		t.Run(string(format), func(t *testing.T) {
			q, _ := newIntegrityHandler(t, "infected", format)
			content := "content that was restored"
			sha := sha256Hex([]byte(content))
			tom := depositSample(t, t.TempDir(), "a.bin", content)
			jerry := depositSample(t, t.TempDir(), "a.bin", content)
			_, idTom, err := quarantinePath(t.Context(), t, q, tom, sha, []string{"m"})
			if err != nil {
				t.Fatal(err)
			}
			_, idJerry, err := quarantinePath(t.Context(), t, q, jerry, sha, []string{"m"})
			if err != nil {
				t.Fatal(err)
			}
			if err = os.Remove(tom); err != nil {
				t.Fatal(err)
			}
			if err = q.Restore(t.Context(), idTom); err != nil {
				t.Fatal(err)
			}
			if got, e := q.IsRestored(t.Context(), tom, sha); e != nil || !got {
				t.Errorf("IsRestored(restored file) = %t (%v), want true", got, e)
			}
			for name, loc := range map[string]string{
				"another quarantined copy": jerry,
				"a new location":           filepath.Join(t.TempDir(), "another-user.bin"),
			} {
				if got, e := q.IsRestored(t.Context(), loc, sha); e != nil || got {
					t.Errorf("IsRestored(%s) = %t (%v), want false: a release is per file", name, got, e)
				}
			}
			if got, e := q.IsRestored(t.Context(), tom, sha256Hex([]byte("another content"))); e != nil || got {
				t.Errorf("IsRestored(another content at the restored location) = %t (%v), want false", got, e)
			}
			if entry, e := q.registry.Get(t.Context(), idJerry); e != nil || entry.Restored() {
				t.Errorf("the other copy must stay in quarantine: %+v (%v)", entry, e)
			}
		})
	}
}

func TestIsRestored_normalisesLocationAndHash(t *testing.T) {
	q, _ := newIntegrityHandler(t, "infected", FormatTar)
	path, sha := restoreContent(t, q, "f.bin", "a restored content")
	dir, base := filepath.Dir(path), filepath.Base(path)
	for name, tt := range map[string]struct {
		location, sha256 string
		want             bool
	}{
		"dot dot":            {location: dir + "/sub/../" + base, sha256: sha, want: true},
		"double slash":       {location: dir + "//" + base, sha256: sha, want: true},
		"dot":                {location: dir + "/./" + base, sha256: sha, want: true},
		"upper case hash":    {location: path, sha256: strings.ToUpper(sha), want: true},
		"mixed case hash":    {location: path, sha256: sha[:30] + strings.ToUpper(sha[30:]), want: true},
		"empty hash":         {location: path, sha256: ""},
		"63 characters hash": {location: path, sha256: sha[:63]},
		"65 characters hash": {location: path, sha256: sha + "0"},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := q.IsRestored(t.Context(), tt.location, tt.sha256); err != nil || got != tt.want {
				t.Errorf("IsRestored(%q, %q) = %t (%v), want %t", tt.location, tt.sha256, got, err, tt.want)
			}
		})
	}
}

// Quarantine and IsRestored share one id: a file quarantined under another
// spelling of its path or hash is the same file once restored.
func TestQuarantine_storesTheEntryUnderTheNormalisedID(t *testing.T) {
	q, _ := newIntegrityHandler(t, "infected", FormatTar)
	content := "content quarantined under another spelling"
	sha := sha256Hex([]byte(content))
	path := depositSample(t, t.TempDir(), "f.bin", content)
	spelled := filepath.Dir(path) + "/sub/..//" + filepath.Base(path)
	_, id, err := quarantinePath(t.Context(), t, q, spelled, strings.ToUpper(sha), []string{"m"})
	if err != nil {
		t.Fatal(err)
	}
	if want := ComputeCacheID(path, sha); id != want {
		t.Fatalf("Quarantine() id = %s, want %s", id, want)
	}
	entry, err := q.registry.Get(t.Context(), id)
	if err != nil || entry.InitialLocation != path || entry.SHA256 != sha {
		t.Fatalf("entry = %+v (%v), want the location %s and the SHA256 %s", entry, err, path, sha)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = q.Restore(t.Context(), id); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	if got, e := q.IsRestored(t.Context(), path, sha); e != nil || !got {
		t.Errorf("IsRestored() = %t (%v), want true", got, e)
	}
}

func TestIsRestored_theEmptyContentFollowsTheSameRule(t *testing.T) {
	q, _ := newIntegrityHandler(t, "infected", FormatTar)
	restored, empty := restoreContent(t, q, "empty-a.bin", "")
	if got, err := q.IsRestored(t.Context(), restored, empty); err != nil || !got {
		t.Errorf("IsRestored(restored empty file) = %t (%v), want true", got, err)
	}
	if _, _, err := quarantinePath(t.Context(), t, q, restored, empty, []string{"m"}); !errors.Is(err, ErrRestored) {
		t.Errorf("Quarantine(restored empty file) error = %v, want ErrRestored", err)
	}
	other := depositSample(t, t.TempDir(), "empty-b.bin", "")
	if got, err := q.IsRestored(t.Context(), other, empty); err != nil || got {
		t.Errorf("IsRestored(another empty file) = %t (%v), want false", got, err)
	}
	if _, _, err := quarantinePath(t.Context(), t, q, other, empty, []string{"m"}); err != nil {
		t.Errorf("Quarantine(another empty file) error = %v, want it quarantined", err)
	}
}

func TestQuarantine_anotherLocationOfARestoredContentIsQuarantined(t *testing.T) {
	q, dir := newIntegrityHandler(t, "infected", FormatTar)
	restored, sha := restoreContent(t, q, "a.bin", "content restored at one place")
	restoredID := ComputeCacheID(restored, sha)
	other := depositSample(t, t.TempDir(), "b.bin", "content restored at one place")
	location, id, err := quarantinePath(t.Context(), t, q, other, sha, []string{"m"})
	if err != nil {
		t.Fatalf("Quarantine() error = %v, want the other location quarantined", err)
	}
	if location != filepath.Join(dir, id+".lock") {
		t.Errorf("Quarantine() location = %s", location)
	}
	if _, err = os.Stat(location); err != nil {
		t.Errorf("container: %v", err)
	}
	if entry, e := q.registry.Get(t.Context(), restoredID); e != nil || !entry.Restored() {
		t.Errorf("the restored file must stay restored: %+v (%v)", entry, e)
	}
}

func TestQuarantine_aRestoredFileIsRefusedWithoutWritingAnything(t *testing.T) {
	q, dir := newIntegrityHandler(t, "infected", FormatTar)
	src, sha := restoreContent(t, q, "sample.bin", "content restored once")
	id := ComputeCacheID(src, sha)
	before, err := q.registry.Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, _, err = quarantinePath(t.Context(), t, q, src, sha, []string{"m"}); !errors.Is(err, ErrRestored) {
			t.Fatalf("Quarantine() error = %v, want ErrRestored", err)
		}
	}
	if _, err = os.Stat(filepath.Join(dir, id+".lock")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("nothing may be written: stat error = %v", err)
	}
	after, err := q.registry.Get(t.Context(), id)
	if err != nil || !after.RestoredAt.Equal(before.RestoredAt) || after.QuarantineLocation != before.QuarantineLocation {
		t.Errorf("registry entry changed: %+v -> %+v (%v)", before, after, err)
	}
}

// Quarantine decides on the registry before writing anything: a registry that
// cannot answer leaves no container and no entry.
func TestQuarantine_aRegistryErrorWritesNothing(t *testing.T) {
	boom := errors.New("registry unavailable")
	registry := &registryMock{
		GetMock: func(context.Context, string) (*Entry, error) { return nil, boom },
		SetMock: func(context.Context, *Entry) error {
			t.Error("no entry may be registered")
			return nil
		},
	}
	dir := t.TempDir()
	q := &QuarantineHandler{location: dir, registry: registry}
	src := depositSample(t, t.TempDir(), "f.bin", "content")
	if _, _, err := quarantinePath(t.Context(), t, q, src, sha256Hex([]byte("content")), []string{"m"}); !errors.Is(err, boom) {
		t.Errorf("Quarantine() error = %v, want the registry error", err)
	}
	if entries, e := os.ReadDir(dir); e != nil || len(entries) != 0 {
		t.Errorf("quarantine folder holds %v (%v), want nothing", entries, e)
	}
}

// Quarantine and Restore of the same entry run one after the other: a late
// Quarantine cannot cancel a restoration, nor rewrite the container while it is
// read.
func TestQuarantine_concurrentWithRestoreOfTheSameEntry(t *testing.T) {
	for range 30 {
		q, _ := newIntegrityHandler(t, "infected", FormatTar)
		content := "content raced"
		sha := sha256Hex([]byte(content))
		src := depositSample(t, t.TempDir(), "f.bin", content)
		_, id, err := quarantinePath(t.Context(), t, q, src, sha, []string{"m"})
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var restoreErr error
		wg.Go(func() { restoreErr = q.Restore(t.Context(), id) })
		wg.Go(func() {
			if _, _, e := quarantinePath(t.Context(), t, q, src, sha, []string{"m"}); e != nil && !errors.Is(e, ErrRestored) && !errors.Is(e, os.ErrNotExist) {
				t.Errorf("Quarantine() error = %v", e)
			}
		})
		wg.Wait()
		entry, err := q.registry.Get(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		if restoreErr == nil && !entry.Restored() {
			t.Fatal("a restoration that succeeded was cancelled by a concurrent Quarantine")
		}
	}
}

// Quarantine waits for a restoration of the same entry that is in progress: it
// takes the lock of the entry first, like Restore, so it cannot check, then
// register over a restoration that completes in between.
func TestQuarantine_waitsForARestorationInProgress(t *testing.T) {
	q, _ := newIntegrityHandler(t, "infected", FormatTar)
	content := "content being restored"
	sha := sha256Hex([]byte(content))
	src := depositSample(t, t.TempDir(), "f.bin", content)
	unlock := q.restoreLocks.Lock(entryID(src, sha))
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, _, err := quarantinePath(t.Context(), t, q, src, sha, []string{"m"}); err != nil {
			t.Errorf("Quarantine() error = %v", err)
		}
	}()
	select {
	case <-done:
		t.Fatal("Quarantine ran while the entry was being restored")
	case <-time.After(150 * time.Millisecond):
	}
	unlock()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Quarantine never resumed")
	}
}

// An entry written under an id that is not the canonical one (an upper-case
// SHA256 from an older caller) is still restored, with a warning: the restored
// check will not find it.
func TestRestore_warnsAboutAnEntryWithANonCanonicalID(t *testing.T) {
	q, dir := newIntegrityHandler(t, "infected", FormatTar)
	content := "content registered with an upper-case SHA256"
	sha := sha256Hex([]byte(content))
	src := depositSample(t, t.TempDir(), "f.bin", content)
	_, canonical, err := quarantinePath(t.Context(), t, q, src, sha, []string{"m"})
	if err != nil {
		t.Fatal(err)
	}
	upper := strings.ToUpper(sha)
	id := ComputeCacheID(src, upper)
	lock := filepath.Join(dir, id+".lock")
	if err = os.Rename(filepath.Join(dir, canonical+".lock"), lock); err != nil {
		t.Fatal(err)
	}
	if err = q.registry.Set(t.Context(), &Entry{ID: id, SHA256: upper, InitialLocation: src, QuarantineLocation: lock}); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(src); err != nil {
		t.Fatal(err)
	}
	logs := captureQuarantineLogs(t)
	if err = q.Restore(t.Context(), id); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	if !strings.Contains(logs.String(), "not the one the restored check looks up") {
		t.Errorf("no warning about the id: %s", logs)
	}

	logs.Reset()
	restoreContent(t, q, "g.bin", "content registered canonically")
	if strings.Contains(logs.String(), "not the one the restored check looks up") {
		t.Errorf("a canonical id raised the warning: %s", logs)
	}
}
