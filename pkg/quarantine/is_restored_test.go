package quarantine

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func restoreContent(t *testing.T, q *QuarantineHandler, name, content string) (path, sha string) {
	t.Helper()
	path = depositSample(t, t.TempDir(), name, content)
	sha = sha256Hex([]byte(content))
	_, id, err := quarantinePath(t.Context(), t, q, path, sha, []string{"m"})
	if err != nil {
		t.Fatalf("Quarantine() error = %v", err)
	}
	if err = os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err = q.Restore(t.Context(), id); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	return path, sha
}

func TestIsRestored_hostileSHA256NeverMatchAnEntry(t *testing.T) {
	q, _ := newIntegrityHandler(t, "infected", FormatTar)
	restored, sha := restoreContent(t, q, "x.bin", "a restored content")
	for name, query := range map[string]string{
		"empty":             "",
		"only spaces":       "   ",
		"leading space":     " " + sha,
		"trailing space":    sha + " ",
		"trailing newline":  sha + "\n",
		"sql wildcard":      "%",
		"sql wildcard like": sha[:10] + "%",
		"sql injection":     "x' OR '1'='1",
		"quote and comment": "'; DROP TABLE entries; --",
		"null byte":         sha[:20] + "\x00" + sha[20:],
		"truncated":         sha[:63],
	} {
		t.Run(name, func(t *testing.T) {
			got, err := q.IsRestored(t.Context(), restored, query)
			if err != nil {
				t.Fatalf("IsRestored(%q) error = %v, want a plain \"no\"", query, err)
			}
			if got {
				t.Errorf("IsRestored(%q) = true: a malformed hash must never declare a content safe", query)
			}
		})
	}
	if got, err := q.IsRestored(t.Context(), restored, sha); err != nil || !got {
		t.Errorf("the registry did not survive the hostile queries: IsRestored(valid) = %t (%v)", got, err)
	}
}

func TestIsRestored_aClosedRegistryIsAnErrorNeverASafeAnswer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		content string
	}{
		{name: "a content restored before the registry closes", content: "restored before the registry closes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			q, err := NewQuarantineHandler(t.Context(), Config{Location: dir, LockPassword: "infected", Format: FormatTar})
			if err != nil {
				t.Fatal(err)
			}
			_, sha := restoreContent(t, q, "x.bin", tt.content)
			if err = q.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := q.IsRestored(t.Context(), filepath.Join(dir, "y.bin"), sha)
			if err == nil {
				t.Error("IsRestored() on a closed registry: error = nil, want an error")
			}
			if got {
				t.Error("IsRestored() on a closed registry answered true: the answer must be \"no\" or an error")
			}
			if _, _, qerr := quarantinePath(t.Context(), t, q, depositSample(t, t.TempDir(), "z.bin", "z"), sha256Hex([]byte("z")), nil); qerr == nil {
				t.Error("Quarantine() on a closed registry: error = nil")
			}
		})
	}
}

// A registry of the previous version keeps its rows and its content index (no
// migration, decision D-005): a restored row still releases its own file only.
func TestRegistry_aRegistryOfThePreviousVersionReleasesItsFileOnly(t *testing.T) {
	content := "restored with a registry of the previous version"
	sha := sha256Hex([]byte(content))
	const restoredPath = "/in/tom/old.bin"
	location := filepath.Join(t.TempDir(), "old-registry.db")
	db, err := sql.Open("sqlite", location)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{createTable, "CREATE INDEX IF NOT EXISTS idx_entries_sha256 ON entries(sha256);"} {
		if _, err = db.ExecContext(t.Context(), stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.ExecContext(t.Context(), "INSERT INTO entries(id, sha256, created_at, updated_at, quarantine, location, restored_at) VALUES(?,?,?,?,?,?,?)",
		ComputeCacheID(restoredPath, sha), sha, 1, 1, "/q/old.lock", restoredPath, time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}

	q, err := NewQuarantineHandler(t.Context(), Config{Location: t.TempDir(), RegistryLocation: location, LockPassword: "infected", Format: FormatTar})
	if err != nil {
		t.Fatalf("NewQuarantineHandler() on a registry of the previous version error = %v", err)
	}
	t.Cleanup(func() {
		if e := q.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	if got, e := q.IsRestored(t.Context(), restoredPath, sha); e != nil || !got {
		t.Errorf("IsRestored(restored file) = %t (%v), want true", got, e)
	}
	if got, e := q.IsRestored(t.Context(), "/in/jerry/old.bin", sha); e != nil || got {
		t.Errorf("IsRestored(same content elsewhere) = %t (%v), want false", got, e)
	}
	reg, ok := q.registry.(*sqliteRegistry)
	if !ok {
		t.Fatalf("registry is %T", q.registry)
	}
	if n := countIndexes(t, reg); n != 1 {
		t.Errorf("index count after opening = %d, want 1: an existing index is left in place", n)
	}
}

func TestRegistry_aNewRegistryHasNoContentIndex(t *testing.T) {
	r, err := newSQLiteRegistry(t.Context(), filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := r.Close(); e != nil {
			t.Error(e)
		}
	})
	if n := countIndexes(t, r); n != 0 {
		t.Errorf("index count = %d, want 0", n)
	}
}

func countIndexes(t *testing.T, r *sqliteRegistry) (n int) {
	t.Helper()
	if err := r.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_entries_sha256'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
