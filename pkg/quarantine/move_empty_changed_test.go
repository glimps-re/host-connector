package quarantine

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A source that changed while its empty copy was made is left alone, and the
// empty copy is taken back.
func TestMoveEmpty_aSourceThatChangedTakesTheEmptyCopyBack(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "e.bin")
	remove := func() error { return ErrSourceChanged }
	_, err := MoveEmpty(remove, "/in/e.bin", 0o600, dst, time.Now, 3)
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("MoveEmpty() = %v, want ErrSourceChanged", err)
	}
	if _, statErr := os.Lstat(dst); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the empty copy is still there: %v", statErr)
	}
}

func TestMoveEmpty_aSourceRemovedLeavesTheEmptyCopy(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "e.bin")
	if _, err := MoveEmpty(func() error { return nil }, "/in/e.bin", 0o600, dst, time.Now, 3); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(dst); err != nil || info.Size() != 0 {
		t.Errorf("destination = %v, %v, want an empty file", info, err)
	}
}
