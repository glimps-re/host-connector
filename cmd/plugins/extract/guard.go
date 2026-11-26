//go:build linux

package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// guardInterval is how often the output folder is measured while 7z writes.
// Between two measures 7z can write as much as the disk takes in that time:
// the kernel limit on each file (see runBatch) is what bounds the damage.
var guardInterval = 250 * time.Millisecond

// guardEnabled is false only in tests that exercise the check made after 7z.
var guardEnabled = true

// maxDirSlack is how many folders an extraction may create beyond twice the
// file budget: folders cost inodes, and RAM on a memory file system.
const maxDirSlack = 1000

// limitHit is the error of a 7z run that wrote more than the limits allow.
type limitHit struct {
	// offender is the file (relative, slash separated) found past the per-file
	// limit; empty when the budget was exceeded.
	offender string
	// size is the size of the offender when it was seen.
	size int64
	// budget is set when the whole output went past the byte or file budget.
	budget bool
	// broken is set when the output folder could not be measured.
	broken bool
	// completed is set when 7z had finished by itself, without error: the other
	// members are complete and nothing needs to be run again.
	completed bool
}

func (e *limitHit) Error() string {
	switch {
	case e.broken:
		return "the output folder of 7z could not be measured"
	case e.budget:
		return "7z wrote more than the extraction budget allows"
	}
	return "7z wrote a file past the size limit"
}

// guard measures an output folder while 7z writes into it and stops 7z past
// the limits. The sizes announced by an archive are not trusted: a gzip that
// announces 10 bytes can write gigabytes. A guard serves one run of 7z.
type guard struct {
	dir         string
	maxFileSize int64
	maxTotal    int64
	maxFiles    int
	logger      *slog.Logger

	mu     sync.Mutex
	hit    *limitHit
	killed bool
}

// measure walks the folder once and reports the first breach found, if any. It
// stops at the first one. An error other than a vanished file is a breach too:
// a total that silently misses a folder would let anything through.
func (g *guard) measure() *limitHit {
	var total int64
	var files, dirs int
	var hit *limitHit
	err := filepath.WalkDir(g.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return skipVanished(err)
		}
		if d.IsDir() {
			dirs++
			if files > g.maxFiles || files+dirs > 2*g.maxFiles+maxDirSlack {
				hit = &limitHit{budget: true}
				return fs.SkipAll
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return skipVanished(err)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		files++
		total += info.Size()
		switch {
		case info.Size() > g.maxFileSize:
			rel, e := filepath.Rel(g.dir, path)
			if e != nil {
				return e
			}
			hit = &limitHit{offender: filepath.ToSlash(rel), size: info.Size()}
			return fs.SkipAll
		case total > g.maxTotal || files > g.maxFiles:
			hit = &limitHit{budget: true}
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		g.logger.Warn("cannot measure the output folder", slog.String("error", err.Error()))
		return &limitHit{broken: true}
	}
	return hit
}

// check measures and records a breach; it reports whether 7z must be stopped.
func (g *guard) check() bool {
	hit := g.measure()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.hit != nil {
		return true
	}
	g.hit = hit
	return hit != nil
}

// watch measures every guardInterval until ctx ends, and calls stop at the
// first breach. It measures one last time when ctx ends, so a breach during
// the last moments of 7z is not missed.
func (g *guard) watch(ctx context.Context, stop func()) {
	t := time.NewTicker(guardInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			g.check()
			return
		case <-t.C:
			if g.check() {
				g.mu.Lock()
				g.killed = true
				g.mu.Unlock()
				stop()
				return
			}
		}
	}
}

// result returns a copy of the breach recorded, if any, and whether the guard
// had to stop 7z.
func (g *guard) result() (hit *limitHit, killed bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.hit == nil {
		return nil, g.killed
	}
	h := *g.hit
	return &h, g.killed
}

// bytesWritten is the size of the regular files under dir.
func bytesWritten(dir string) (total int64, err error) {
	err = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return skipVanished(err)
		}
		if d.IsDir() {
			return nil
		}
		info, e := d.Info()
		if e != nil {
			return skipVanished(e)
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}

// snapshot lists the files under dir (relative paths), to tell later what a
// run wrote. An incomplete snapshot would make later cleanups remove files
// that were there, so any error is returned.
func snapshot(dir string) (map[string]struct{}, error) {
	seen := map[string]struct{}{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return skipVanished(err)
		}
		if d.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(dir, path)
		if e != nil {
			return e
		}
		seen[rel] = struct{}{}
		return nil
	})
	return seen, err
}

// skipVanished ignores a file that disappeared while the folder was walked.
func skipVanished(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// removeNewFiles deletes the files under dir that were not in before. Names
// are resolved inside dir only.
func removeNewFiles(dir string, before map[string]struct{}, logger *slog.Logger) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() {
		if e := root.Close(); e != nil {
			logger.Warn("cannot close the output folder", slog.String("error", e.Error()))
		}
	}()
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return skipVanished(err)
		}
		if d.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(dir, path)
		if e != nil {
			return e
		}
		if _, old := before[rel]; old {
			return nil
		}
		return skipVanished(root.Remove(rel))
	})
}
