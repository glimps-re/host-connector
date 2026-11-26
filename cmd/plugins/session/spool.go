//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

const (
	// spoolFlushSize is the buffered size past which a spool is written to disk.
	spoolFlushSize = 8 << 10
	// spoolKeepBuffer is the largest write buffer kept between two flushes: a
	// plugin holds one spool per open session, a report line can be MaxReportSize.
	spoolKeepBuffer = 16 << 10
	// spoolMaxLine bounds a spool line when reading: twice datamodel.MaxReportSize,
	// so that a valid line is never rejected.
	spoolMaxLine = 8 << 20
	// maxPendingErrors bounds, for the whole plugin, the reports in error kept in
	// memory so that a later report of the same file can replace them. Each is
	// charged its encoded size plus pendingOverhead.
	maxPendingErrors = 16 << 20
	// pendingOverhead is what a report held in memory costs beyond its encoded
	// line: the Report, its strings and its map entry (measured, rounded up).
	pendingOverhead = 600
)

// spool is the file where the reports of one session wait for its closing: one
// JSON line per report. It is opened for each flush only, so that open sessions
// hold no descriptor. Not safe for concurrent use: the session guards it.
//
// Only the bytes of whole lines written without error count (durable): a failed
// write leaves garbage past them, which is never read. The lines not written yet
// stay in buf, and are read from there. A spool whose write failed must not be
// appended to again: the session that owns it enforces that.
type spool struct {
	path    string
	buf     []byte
	durable int64
	count   int
	logger  *slog.Logger
}

// createSpool creates the empty spool file of a session in dir, exclusively.
func createSpool(dir string, logger *slog.Logger) (*spool, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if dir == "" {
		return nil, errors.New("no spool directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// Refuses a planted symlink or non-directory as the spool folder; a swap after this check is not covered.
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("spool directory %q is a symlink", dir)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("spool directory %q is not a directory", dir)
	}
	for range 5 {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		path := filepath.Join(dir, hex.EncodeToString(b[:])+datamodel.SessionSpoolExt)
		f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if err == nil {
			if err = f.Close(); err != nil {
				return nil, errors.Join(err, os.Remove(path))
			}
			return &spool{path: path, logger: logger}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	return nil, errors.New("no free spool name")
}

// size is the bytes appended, written or not.
func (s *spool) size() int64 { return s.durable + int64(len(s.buf)) }

// append adds one complete line (ending with a newline). When the write it
// triggers fails, the line is not taken and the lines before it stay readable.
func (s *spool) append(line []byte) error {
	s.buf = append(s.buf, line...)
	if len(s.buf) >= spoolFlushSize {
		if err := s.flush(); err != nil {
			s.buf = s.buf[:len(s.buf)-len(line)]
			return err
		}
	}
	s.count++
	return nil
}

// flush writes the buffered lines. On failure they stay buffered.
func (s *spool) flush() error {
	if len(s.buf) == 0 {
		return nil
	}
	f, err := os.OpenFile(filepath.Clean(s.path), os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	_, err = f.Write(s.buf)
	if err = errors.Join(err, f.Close()); err != nil {
		return err
	}
	s.durable += int64(len(s.buf))
	if cap(s.buf) > spoolKeepBuffer {
		s.buf = nil
	} else {
		s.buf = s.buf[:0]
	}
	return nil
}

// open returns a reader on every line of the spool: what is on disk, then what
// is still buffered. The spool must not change while it is read.
func (s *spool) open() (io.ReadCloser, error) {
	f, err := os.OpenFile(filepath.Clean(s.path), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return &spoolReader{
		Reader: io.MultiReader(io.LimitReader(f, s.durable), bytes.NewReader(s.buf)),
		closer: f,
	}, nil
}

type spoolReader struct {
	io.Reader
	closer io.Closer
}

func (r *spoolReader) Close() error { return r.closer.Close() }

// remove deletes the spool file; a missing file is not an error. It touches no
// field: a generator may still be reading when a session is declared lost.
func (s *spool) remove() error {
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// reports yields the reports of the spool, in the order they were added. The
// sequence can be iterated again: each iteration reads the spool from its start.
func (s *spool) reports(ctx context.Context) iter.Seq2[datamodel.Report, error] {
	return func(yield func(datamodel.Report, error) bool) {
		r, err := s.open()
		if err != nil {
			yield(datamodel.Report{}, fmt.Errorf("spool: %w", err))
			return
		}
		counted := &countingReader{r: r}
		stopped := false
		for rep, err := range readLines(ctx, counted) {
			if !yield(rep, err) || err != nil {
				stopped = true
				break
			}
		}
		if !stopped && counted.n != s.size() {
			yield(datamodel.Report{}, fmt.Errorf("spool: read %d bytes, expected %d: the file was truncated", counted.n, s.size()))
			stopped = true
		}
		if err := r.Close(); err != nil {
			if stopped {
				s.logger.Warn("cannot close a spool after reading it", slog.String("path", s.path), slog.String("error", err.Error()))
				return
			}
			yield(datamodel.Report{}, fmt.Errorf("spool: %w", err))
		}
	}
}

// countingReader counts the bytes read through it.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// readLines decodes the JSON lines of r, one report each, strictly: an unknown
// field, trailing data or a line over spoolMaxLine ends the sequence with an
// error. ctx is checked for each line.
func readLines(ctx context.Context, r io.Reader) iter.Seq2[datamodel.Report, error] {
	return func(yield func(datamodel.Report, error) bool) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64<<10), spoolMaxLine)
		for sc.Scan() {
			if err := ctx.Err(); err != nil {
				yield(datamodel.Report{}, err)
				return
			}
			rep, err := decodeLine(sc.Bytes())
			if !yield(rep, err) || err != nil {
				return
			}
		}
		if err := sc.Err(); err != nil {
			yield(datamodel.Report{}, fmt.Errorf("spool: %w", err))
		}
	}
}

func decodeLine(line []byte) (rep datamodel.Report, err error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&rep); err != nil {
		return datamodel.Report{}, fmt.Errorf("spool: bad line: %w", err)
	}
	if dec.InputOffset() != int64(len(bytes.TrimRight(line, " \t\r"))) {
		return datamodel.Report{}, errors.New("spool: bad line: data after the report")
	}
	return rep, nil
}

// encodeLine is the JSON line of a report, newline included, and the report as
// it was encoded. A report over datamodel.MaxReportSize is bound first, so that
// no line passes spoolMaxLine. On a marshal failure the report is returned as it
// came.
func encodeLine(rep datamodel.Report) ([]byte, datamodel.Report, error) {
	line, err := json.Marshal(rep)
	if err != nil {
		return nil, rep, err
	}
	if len(line) > datamodel.MaxReportSize {
		rep.Bound()
		if line, err = json.Marshal(rep); err != nil {
			return nil, rep, err
		}
	}
	return append(line, '\n'), rep, nil
}

// errorBudget counts, for the whole plugin, the bytes of reports in error held
// in memory.
type errorBudget struct {
	used  atomic.Int64
	limit int64
}

// reserve takes n bytes of the budget if it has them.
func (b *errorBudget) reserve(n int64) bool {
	if b == nil {
		return true
	}
	limit := b.limit
	if limit == 0 {
		limit = maxPendingErrors
	}
	for {
		cur := b.used.Load()
		if cur+n > limit {
			return false
		}
		if b.used.CompareAndSwap(cur, cur+n) {
			return true
		}
	}
}

// force takes n bytes whatever is left: the report in hand when the spool failed
// must not be lost.
func (b *errorBudget) force(n int64) {
	if b != nil {
		b.used.Add(n)
	}
}

func (b *errorBudget) give(n int64) {
	if b != nil {
		b.used.Add(-n)
	}
}
