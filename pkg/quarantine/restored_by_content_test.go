package quarantine

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// Two copies of one content are quarantined, one is restored: the content is
// safe wherever it is deposited, the other copy stays to restore by itself.
func TestIsRestored_aRestoredContentIsSafeEverywhere(t *testing.T) {
	for _, format := range []Format{FormatTar, FormatZip} {
		t.Run(string(format), func(t *testing.T) {
			q, _ := newIntegrityHandler(t, "infected", format)
			content := "content that was restored"
			sha := sha256Hex([]byte(content))
			a := depositSample(t, t.TempDir(), "a.bin", content)
			b := depositSample(t, t.TempDir(), "b.bin", content)
			_, idA, err := quarantinePath(t.Context(), t, q, a, sha, []string{"m"})
			if err != nil {
				t.Fatal(err)
			}
			_, idB, err := quarantinePath(t.Context(), t, q, b, sha, []string{"m"})
			if err != nil {
				t.Fatal(err)
			}
			if got, e := q.IsRestored(t.Context(), a, sha); e != nil || got {
				t.Fatalf("IsRestored() = %t (%v) before any restore, want false", got, e)
			}
			if err = os.Remove(b); err != nil {
				t.Fatal(err)
			}
			if err = q.Restore(t.Context(), idB); err != nil {
				t.Fatal(err)
			}
			elsewhere := filepath.Join(t.TempDir(), "another-user.bin")
			for _, loc := range []string{a, b, elsewhere} {
				if got, e := q.IsRestored(t.Context(), loc, sha); e != nil || !got {
					t.Errorf("IsRestored(%s) = %t (%v), want true: the content was restored", loc, got, e)
				}
			}
			if entry, e := q.registry.Get(t.Context(), idA); e != nil || entry.RestoredAt.UnixMilli() > 0 {
				t.Errorf("the other copy must stay to restore by itself: %+v (%v)", entry, e)
			}
			if got, e := q.IsRestored(t.Context(), a, sha256Hex([]byte("another content"))); e != nil || got {
				t.Errorf("IsRestored() = %t (%v) for another content, want false", got, e)
			}
		})
	}
}

// Restoring one empty file must not make every empty file safe.
func TestIsRestored_theEmptyContentIsMatchedPerLocationOnly(t *testing.T) {
	q, _ := newIntegrityHandler(t, "infected", FormatTar)
	restoredPath := "/in/alice/empty.txt"
	if err := q.registry.Set(t.Context(), &Entry{
		ID: ComputeCacheID(restoredPath, emptySHA256), SHA256: emptySHA256,
		InitialLocation: restoredPath, RestoredAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := q.IsRestored(t.Context(), restoredPath, emptySHA256); err != nil || !got {
		t.Errorf("IsRestored(restored location) = %t (%v), want true", got, err)
	}
	if got, err := q.IsRestored(t.Context(), "/in/bob/other-empty.txt", emptySHA256); err != nil || got {
		t.Errorf("IsRestored(another empty file) = %t (%v), want false: no global allow list for the empty content", got, err)
	}
}

func TestQuarantine_anAlreadyRestoredEntryIsRefusedWithoutWritingAnything(t *testing.T) {
	q, dir := newIntegrityHandler(t, "infected", FormatTar)
	content := "content restored once"
	sha := sha256Hex([]byte(content))
	src := depositSample(t, t.TempDir(), "sample.bin", content)
	_, id, err := quarantinePath(t.Context(), t, q, src, sha, []string{"m"})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(src); err != nil {
		t.Fatal(err)
	}
	if err = q.Restore(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	before, err := q.registry.Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = quarantinePath(t.Context(), t, q, src, sha, []string{"m"})
	if !errors.Is(err, ErrRestored) {
		t.Fatalf("Quarantine() error = %v, want ErrRestored", err)
	}
	if _, err = os.Stat(filepath.Join(dir, id+".lock")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("nothing may be written: stat error = %v", err)
	}
	after, err := q.registry.Get(t.Context(), id)
	if err != nil || !after.RestoredAt.Equal(before.RestoredAt) || after.QuarantineLocation != before.QuarantineLocation {
		t.Errorf("registry entry changed: %+v -> %+v (%v)", before, after, err)
	}
}

// A registry made before the index existed gets it at the next opening.
func TestRegistry_openingAddsTheContentIndex(t *testing.T) {
	location := filepath.Join(t.TempDir(), "registry.db")
	r, err := newSQLiteRegistry(t.Context(), location)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.db.ExecContext(t.Context(), "DROP INDEX idx_entries_sha256"); err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = newSQLiteRegistry(t.Context(), location)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := r.Close(); e != nil {
			t.Error(e)
		}
	}()
	var n int
	if err = r.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_entries_sha256'").Scan(&n); err != nil || n != 1 {
		t.Errorf("index count = %d (%v), want 1", n, err)
	}
}

func BenchmarkIsRestored(b *testing.B) {
	r, err := newSQLiteRegistry(b.Context(), "")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if e := r.Close(); e != nil {
			b.Error(e)
		}
	})
	const n = 100_000
	tx, err := r.db.BeginTx(b.Context(), nil)
	if err != nil {
		b.Fatal(err)
	}
	for i := range n {
		restored := int64(0)
		if i%1000 == 0 {
			restored = time.Now().UnixMilli()
		}
		if _, err = tx.ExecContext(b.Context(), "INSERT INTO entries(id, sha256, created_at, updated_at, quarantine, location, restored_at) VALUES(?,?,?,?,?,?,?)",
			fmt.Sprintf("id-%d", i), fmt.Sprintf("%064x", i), 1, 1, "", "", restored); err != nil {
			b.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		b.Fatal(err)
	}
	q := &QuarantineHandler{registry: r}
	missing := fmt.Sprintf("%064x", n+1)
	b.ResetTimer()
	for b.Loop() {
		if got, e := q.IsRestored(b.Context(), "/in/f", missing); e != nil || got {
			b.Fatalf("IsRestored() = %t, %v", got, e)
		}
	}
}

func TestEmptySHA256IsTheHashOfTheEmptyContent(t *testing.T) {
	sum := sha256.Sum256(nil)
	if got := hex.EncodeToString(sum[:]); got != emptySHA256 {
		t.Errorf("emptySHA256 = %s, want %s", emptySHA256, got)
	}
}

func TestRegistry_hasRestored(t *testing.T) {
	r, err := newSQLiteRegistry(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := r.Close(); e != nil {
			t.Error(e)
		}
	})
	restored, quarantined := sha256Hex([]byte("restored")), sha256Hex([]byte("quarantined"))
	for _, e := range []*Entry{
		{ID: "a", SHA256: restored, RestoredAt: time.Now()},
		{ID: "b", SHA256: quarantined},
		{ID: "c", SHA256: restored},
	} {
		if err = r.Set(t.Context(), e); err != nil {
			t.Fatal(err)
		}
	}
	for sha, want := range map[string]bool{restored: true, quarantined: false, sha256Hex([]byte("unknown")): false} {
		if got, e := r.HasRestored(t.Context(), sha); e != nil || got != want {
			t.Errorf("HasRestored(%s) = %t (%v), want %t", sha[:8], got, e, want)
		}
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = r.HasRestored(t.Context(), restored); err == nil {
		t.Error("HasRestored() on a closed registry must report the error")
	}
	r2, err := newSQLiteRegistry(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r2.Close() })
}

// A registry whose table does not have the expected columns cannot be indexed:
// opening it fails, instead of working without the index.
func TestRegistry_openingARegistryThatCannotBeIndexedFails(t *testing.T) {
	location := filepath.Join(t.TempDir(), "registry.db")
	db, err := sql.Open("sqlite", location)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(t.Context(), "CREATE TABLE entries (id TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = newSQLiteRegistry(t.Context(), location); err == nil {
		t.Error("newSQLiteRegistry() must fail when the index cannot be created")
	}
}

// Quarantine decides on the registry before writing anything: a registry that
// cannot answer leaves no container and no entry.
func TestQuarantine_aRegistryErrorWritesNothing(t *testing.T) {
	boom := errors.New("registry unavailable")
	for name, registry := range map[string]*registryMock{
		"content lookup": {HasRestoredMock: func(context.Context, string) (bool, error) { return false, boom }},
		"empty content":  {GetMock: func(context.Context, string) (*Entry, error) { return nil, boom }},
	} {
		t.Run(name, func(t *testing.T) {
			registry.SetMock = func(context.Context, *Entry) error {
				t.Error("no entry may be registered")
				return nil
			}
			dir := t.TempDir()
			q := &QuarantineHandler{location: dir, registry: registry}
			content := "content"
			if name == "empty content" {
				content = ""
			}
			src := depositSample(t, t.TempDir(), "f.bin", content)
			if _, _, err := quarantinePath(t.Context(), t, q, src, sha256Hex([]byte(content)), []string{"m"}); !errors.Is(err, boom) {
				t.Errorf("Quarantine() error = %v, want the registry error", err)
			}
			if entries, e := os.ReadDir(dir); e != nil || len(entries) != 0 {
				t.Errorf("quarantine folder holds %v (%v), want nothing", entries, e)
			}
		})
	}
}

// A content restored in one place is never quarantined from another: the same
// rule as IsRestored.
func TestQuarantine_aContentRestoredElsewhereIsRefused(t *testing.T) {
	q, dir := newIntegrityHandler(t, "infected", FormatTar)
	content := "content restored from another place"
	sha := sha256Hex([]byte(content))
	first := depositSample(t, t.TempDir(), "a.bin", content)
	_, id, err := quarantinePath(t.Context(), t, q, first, sha, []string{"m"})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(first); err != nil {
		t.Fatal(err)
	}
	if err = q.Restore(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	other := depositSample(t, t.TempDir(), "b.bin", content)
	if _, _, err = quarantinePath(t.Context(), t, q, other, sha, []string{"m"}); !errors.Is(err, ErrRestored) {
		t.Fatalf("Quarantine() error = %v, want ErrRestored", err)
	}
	if matches, e := filepath.Glob(filepath.Join(dir, "*.lock")); e != nil || len(matches) != 0 {
		t.Errorf("containers = %v (%v), want none", matches, e)
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
	unlock := q.restoreLocks.Lock(ComputeCacheID(src, sha))
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

// The empty content follows the same rule in Quarantine: refused where one empty
// file was restored, quarantined for any other empty file.
func TestQuarantine_anEmptyFileRestoredAtThisLocationIsRefusedOthersAreNot(t *testing.T) {
	q, _ := newIntegrityHandler(t, "infected", FormatTar)
	restored := depositSample(t, t.TempDir(), "restored-empty.txt", "")
	if err := q.registry.Set(t.Context(), &Entry{
		ID: ComputeCacheID(restored, emptySHA256), SHA256: emptySHA256, InitialLocation: restored, RestoredAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := quarantinePath(t.Context(), t, q, restored, emptySHA256, []string{"m"}); !errors.Is(err, ErrRestored) {
		t.Errorf("Quarantine(restored empty file) error = %v, want ErrRestored", err)
	}
	other := depositSample(t, t.TempDir(), "other-empty.txt", "")
	if _, _, err := quarantinePath(t.Context(), t, q, other, emptySHA256, []string{"m"}); err != nil {
		t.Errorf("Quarantine(another empty file) error = %v, want it quarantined", err)
	}
}
