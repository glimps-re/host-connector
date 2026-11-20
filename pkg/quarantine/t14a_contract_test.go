package quarantine

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func restoreContent(t *testing.T, q *QuarantineHandler, name, content string) (path, sha string) {
	t.Helper()
	path = depositSample(t, t.TempDir(), name, content)
	sha = sha256Hex([]byte(content))
	_, id, err := q.Quarantine(t.Context(), path, sha, []string{"m"})
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

func TestT14a_hostileSHA256NeverMatchAnEntry(t *testing.T) {
	q, _ := newIntegrityHandler(t, "infected", FormatTar)
	_, sha := restoreContent(t, q, "x.bin", "a restored content")
	elsewhere := filepath.Join(t.TempDir(), "other.bin")
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
			got, err := q.IsRestored(t.Context(), elsewhere, query)
			if err != nil {
				t.Fatalf("IsRestored(%q) error = %v, want a plain \"no\"", query, err)
			}
			if got {
				t.Errorf("IsRestored(%q) = true: a malformed hash must never declare a content safe", query)
			}
		})
	}
	if got, err := q.IsRestored(t.Context(), elsewhere, sha); err != nil || !got {
		t.Errorf("the registry did not survive the hostile queries: IsRestored(valid) = %t (%v)", got, err)
	}
}

func TestT14a_theEmptyContentStaysPerLocationWhateverTheSpelling(t *testing.T) {
	q, _ := newIntegrityHandler(t, "infected", FormatTar)
	first, _ := restoreContent(t, q, "empty-a.bin", "")
	other := filepath.Join(t.TempDir(), "empty-b.bin")
	for name, sha := range map[string]string{
		"lower case":   emptySHA256,
		"upper case":   strings.ToUpper(emptySHA256),
		"mixed case":   emptySHA256[:30] + strings.ToUpper(emptySHA256[30:]),
		"with a space": " " + emptySHA256,
	} {
		if got, err := q.IsRestored(t.Context(), other, sha); err != nil || got {
			t.Errorf("%s: IsRestored(other location) = %t (%v): restoring one empty file must not make every empty file safe", name, got, err)
		}
	}
	if got, err := q.IsRestored(t.Context(), first, emptySHA256); err != nil || !got {
		t.Errorf("IsRestored(the restored location) = %t (%v), want true", got, err)
	}
}

func TestT14a_aClosedRegistryIsAnErrorNeverASafeAnswer(t *testing.T) {
	dir := t.TempDir()
	q, err := NewQuarantineHandler(t.Context(), Config{Location: dir, LockPassword: "infected", Format: FormatTar})
	if err != nil {
		t.Fatal(err)
	}
	_, sha := restoreContent(t, q, "x.bin", "restored before the registry closes")
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
	if _, _, qerr := q.Quarantine(t.Context(), depositSample(t, t.TempDir(), "z.bin", "z"), sha256Hex([]byte("z")), nil); qerr == nil {
		t.Error("Quarantine() on a closed registry: error = nil")
	}
}

func TestT14a_aRegistryWithoutTheIndexIsMigratedAndItsRowsStillCount(t *testing.T) {
	location := filepath.Join(t.TempDir(), "old-registry.db")
	db, err := sql.Open("sqlite", location)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(t.Context(), createTable); err != nil {
		t.Fatal(err)
	}
	content := "restored with a registry of the previous version"
	sha := sha256Hex([]byte(content))
	if _, err = db.ExecContext(t.Context(), "INSERT INTO entries(id, sha256, created_at, updated_at, quarantine, location, restored_at) VALUES(?,?,?,?,?,?,?)",
		"old-id", sha, 1, 1, "/q/old.lock", "/in/old.bin", time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	var n int
	if err = db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_entries_sha256'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("the old registry must have no index (count %d, err %v)", n, err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}

	q, err := NewQuarantineHandler(t.Context(), Config{Location: t.TempDir(), RegistryLocation: location, LockPassword: "infected", Format: FormatTar})
	if err != nil {
		t.Fatalf("NewQuarantineHandler() on an old registry error = %v", err)
	}
	t.Cleanup(func() {
		if e := q.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	if got, e := q.IsRestored(t.Context(), "/in/anywhere.bin", sha); e != nil || !got {
		t.Errorf("IsRestored() = %t (%v): a content restored before the migration must stay safe", got, e)
	}
	reg, ok := q.registry.(*sqliteRegistry)
	if !ok {
		t.Fatalf("registry is %T", q.registry)
	}
	if e := reg.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_entries_sha256'").Scan(&n); e != nil || n != 1 {
		t.Errorf("index count after opening = %d (%v), want 1", n, e)
	}
}
