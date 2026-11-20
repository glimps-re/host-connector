package quarantine

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"time"

	"github.com/glimps-re/host-connector/internal/safepath"
)

// publication is one way of making a destination name the content to move. The
// loop that resolves name conflicts, and the order publish, finish, cleanup, are
// the same for every way: a move by name, by descriptor, or of a verified copy.
type publication interface {
	// publish makes target a name of the content, never replacing anything. It
	// returns ErrDestinationExists when target is taken.
	publish(target string) error
	// finish ends the move once target is published: it removes the source, or
	// takes target back when the source cannot be removed.
	finish(target string) error
	// cleanup removes whatever publish left in the transit directory.
	cleanup()
}

// runPublication publishes p under dst, then under next(attempt) while the name
// is taken, and finishes the move under the name that was free.
func runPublication(p publication, dst string, next func(attempt int) (string, bool)) (final string, err error) {
	defer p.cleanup()
	target := dst
	for attempt := 0; ; {
		pubErr := p.publish(target)
		if pubErr == nil {
			if err = p.finish(target); err != nil {
				return "", err
			}
			return target, nil
		}
		if !errors.Is(pubErr, ErrDestinationExists) {
			return "", pubErr
		}
		name, ok := next(attempt)
		if !ok {
			return "", pubErr
		}
		target = name
		attempt++
	}
}

// conflictNames gives the names next to dst a move tries when dst is taken: at
// most maxConflicts, each made of the time and the attempt.
func conflictNames(dst string, now func() time.Time, maxConflicts int) func(attempt int) (string, bool) {
	return func(attempt int) (string, bool) {
		if attempt >= maxConflicts {
			return "", false
		}
		return ConflictName(dst, now(), attempt), true
	}
}

// removeStaged removes a file of the transit directory; a file already gone
// (published by rename) is not an error.
func removeStaged(staged string) {
	if staged == "" {
		return
	}
	if e := os.Remove(staged); e != nil && !errors.Is(e, fs.ErrNotExist) {
		logger.Error("move cannot remove the staged copy", slog.String("file", staged), slog.String("error", e.Error()))
	}
}

// removeNamed removes the name the source was found under, once dst holds its
// content. A name that no longer holds the source (changed, replaced, gone) is
// left alone: removed reports false and dst stays. Any other failure takes dst
// back and is marked with ErrSourceNotRemovable.
func removeNamed(dst, label string, remove func() error) (removed bool, err error) {
	err = remove()
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, safepath.ErrChanged), errors.Is(err, ErrSourceChanged), errors.Is(err, fs.ErrNotExist):
		logger.Warn("the source name no longer holds the file that was copied, it is left alone", slog.String("file", label))
		return false, nil
	default:
		return false, rollback(dst, fmt.Errorf("could not remove %s after moving it: %w", label, MarkRemovalRefused(err)))
	}
}
