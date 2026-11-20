package main

import (
	"context"
	"fmt"
	"time"
)

// maxCleanupDepth is how deep the cleanup goes: one descriptor is open per
// level, so a tree of any depth cannot exhaust them.
const maxCleanupDepth = 128

// errTooDeep is returned by removeEmptyDirs, with the counts, when a part of the
// tree was left because it is deeper than maxCleanupDepth.
var errTooDeep = fmt.Errorf("the tree is deeper than %d levels: the deeper part was left", maxCleanupDepth)

// cleanupStats is what a cleanup did: folders removed, folders left on purpose
// (not empty, too recent, protected, swapped), and operations that failed, with
// the first of their errors.
type cleanupStats struct {
	removed, kept, failed int
	firstErr              error
}

func (s *cleanupStats) fail(err error) {
	s.failed++
	if s.firstErr == nil {
		s.firstErr = err
	}
}

// emptyDirsRemover removes the empty folders below the session folder root/rel.
type emptyDirsRemover func(ctx context.Context, root, rel string, olderThan time.Duration, protect string) (cleanupStats, error)
