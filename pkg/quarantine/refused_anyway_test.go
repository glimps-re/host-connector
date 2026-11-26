package quarantine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A file that was restored is quarantined all the same when it is refused for
// where it is or what type it is, and its restored mark is kept.
func TestQuarantine_aRestoredContentRefusedAnywayIsQuarantinedAndStaysRestored(t *testing.T) {
	for _, format := range []Format{FormatTar, FormatZip} {
		t.Run(string(format), func(t *testing.T) {
			q, _ := newIntegrityHandler(t, "infected", format)
			content := "content that was restored"
			sha := sha256Hex([]byte(content))
			a := depositSample(t, t.TempDir(), "a.bin", content)
			_, id, err := quarantinePath(t.Context(), t, q, a, sha, []string{"m"})
			if err != nil {
				t.Fatal(err)
			}
			if err = os.Remove(a); err != nil {
				t.Fatal(err)
			}
			if err = q.Restore(t.Context(), id); err != nil {
				t.Fatal(err)
			}
			before, err := q.registry.Get(t.Context(), id)
			if err != nil || !before.Restored() {
				t.Fatalf("entry %+v (%v), want a restored one", before, err)
			}

			again := depositSample(t, t.TempDir(), "a.bin", content)
			if err = os.Rename(again, a); err != nil {
				t.Fatal(err)
			}
			location, _, err := quarantinePath(WithRefusedAnyway(t.Context()), t, q, a, sha, []string{"filtered-filepath"})
			if err != nil || location == "" {
				t.Fatalf("with the mark, at the path that was restored: location %q, error %v, want it quarantined", location, err)
			}
			after, err := q.registry.Get(t.Context(), id)
			if err != nil {
				t.Fatal(err)
			}
			if !after.Restored() || !after.RestoredAt.Equal(before.RestoredAt) || !after.CreatedAt.Equal(before.CreatedAt) || after.QuarantineLocation != location {
				t.Errorf("entry %+v, want RestoredAt and CreatedAt %v kept and the new quarantine location %q", after, before.RestoredAt, location)
			}
		})
	}
}

func TestRefusedAnyway_isAMarkOfTheContext(t *testing.T) {
	if isRefusedAnyway(t.Context()) {
		t.Error("a plain context carries the mark")
	}
	if !isRefusedAnyway(WithRefusedAnyway(t.Context())) {
		t.Error("the marked context does not carry it")
	}
}

type getFailingRegistry struct {
	quarantineRegistry
	err error
}

func (r *getFailingRegistry) Get(context.Context, string) (*Entry, error) { return nil, r.err }

// The restored mark of an entry that cannot be read is not guessed: the refused
// quarantine fails, and writes nothing.
func TestQuarantine_aRegistryThatCannotBeReadFailsARefusedAnywayQuarantine(t *testing.T) {
	q, _ := newIntegrityHandler(t, "infected", FormatTar)
	content := "content that was restored"
	sha := sha256Hex([]byte(content))
	a := depositSample(t, t.TempDir(), "a.bin", content)
	_, id, err := quarantinePath(t.Context(), t, q, a, sha, []string{"m"})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(a); err != nil {
		t.Fatal(err)
	}
	if err = q.Restore(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	broken := errors.New("the registry cannot be read")
	q.registry = &getFailingRegistry{quarantineRegistry: q.registry, err: broken}
	again := depositSample(t, t.TempDir(), "b.bin", content)
	location, _, err := quarantinePath(WithRefusedAnyway(t.Context()), t, q, again, sha, []string{"filtered-filepath"})
	if !errors.Is(err, broken) || location != "" {
		t.Errorf("location %q, error %v, want the error of the registry and nothing quarantined", location, err)
	}
	locks, globErr := filepath.Glob(filepath.Join(q.location, "*.lock"))
	if globErr != nil || len(locks) != 0 {
		t.Errorf("containers %v (%v), want none", locks, globErr)
	}
}
