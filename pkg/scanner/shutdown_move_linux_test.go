//go:build linux

package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/quarantine"
)

// A move cut in the middle of its copy by the end of the drain leaves nothing in
// the destination, not even in the transit folder, and the source stays.
func TestShutdown_aMoveCutInTheMiddleOfItsCopyLeavesNothing(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	src := filepath.Join(in, "big.bin")
	f, err := os.Create(filepath.Clean(src))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(256 << 20); err != nil { // sparse: the copy has to read and hash it all
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	c, err := NewConnector(Config{
		Roots: []string{in}, WorkDir: t.TempDir(), Workers: 1, MaxFileSize: 1 << 30,
		Actions: Actions{Move: true}, MoveTo: out, MoveFrom: in, MoveMode: MoveModeCopy,
	}, nil, cleanSubmitter())
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	if err = c.ScanFile(t.Context(), src); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(out, quarantine.StagingDir)
	deadline := time.Now().Add(60 * time.Second)
	for {
		entries, readErr := os.ReadDir(staging)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			t.Fatal(readErr)
		}
		if len(entries) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the copy never started")
		}
		time.Sleep(time.Millisecond)
	}
	summary := c.Shutdown(expired(), context.Background())
	if summary.Abandoned != 1 {
		t.Errorf("summary = %+v, want the file in its copy abandoned", summary)
	}
	if _, err = os.Stat(src); err != nil {
		t.Errorf("the source is not in place: %v", err)
	}
	var left []string
	if err = filepath.WalkDir(out, func(p string, d os.DirEntry, werr error) error {
		if werr == nil && !d.IsDir() {
			left = append(left, p)
		}
		return werr
	}); err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("files left in the destination: %v", left)
	}
}
