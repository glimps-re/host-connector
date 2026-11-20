package quarantine

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestMoveFileResolvingConflicts_concurrentSameDestinationLosesNothing(t *testing.T) {
	root := t.TempDir()
	dstDir := filepath.Join(root, "out")
	if err := os.MkdirAll(dstDir, 0o750); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dstDir, "same.bin")
	staging := filepath.Join(dstDir, StagingDir)
	const n = 24
	sources := make([]string, n)
	for i := range n {
		sources[i] = filepath.Join(root, "in", fmt.Sprintf("src-%d.bin", i))
		if err := os.MkdirAll(filepath.Dir(sources[i]), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sources[i], []byte(fmt.Sprintf("content-%d", i)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fixed := func() time.Time { return time.Date(2026, 11, 19, 20, 0, 0, 0, time.UTC) }
	var wg sync.WaitGroup
	results := make(chan string, n)
	for i := range n {
		wg.Go(func() {
			got, err := MoveFileResolvingConflicts(sources[i], dst, staging, fixed, 4*n)
			if err != nil {
				t.Errorf("move %d error = %v", i, err)
				return
			}
			results <- got
		})
	}
	wg.Wait()
	close(results)
	names := map[string]bool{}
	contents := map[string]bool{}
	for got := range results {
		if names[got] {
			t.Errorf("two moves ended at %q", got)
		}
		names[got] = true
		b, err := os.ReadFile(filepath.Clean(got))
		if err != nil {
			t.Fatal(err)
		}
		contents[string(b)] = true
	}
	if len(contents) != n {
		t.Errorf("%d distinct contents survived, want %d: a concurrent move overwrote another", len(contents), n)
	}
	if !names[dst] {
		t.Error("one move must keep the original name")
	}
}
