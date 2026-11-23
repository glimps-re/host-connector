//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"maps"
	"slices"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

// sessionStatus is what the plugin must act on after a write to a session.
type sessionStatus struct {
	// forced is why the session must close at once, and spoolErr the error of
	// its spool when that is the reason.
	forced   forceReason
	spoolErr error
	// spilled is true once, the first time reports in error went to the spool
	// because the memory budget was spent.
	spilled bool
	// encodeErr is the failure to encode a report: the report is kept in memory
	// as it came, and the spool is not at fault.
	encodeErr error
	// works tells that the spool took a write to disk since its last failure.
	works bool
}

// addFileError enters a minimal report for a file that ended in error, unless
// the session already holds one for it. probe asks to check the disk (see
// statusLocked).
func (s *Session) addFileError(filePath, sha256, msg string, probe bool) (bool, sessionStatus) {
	line, rep, encErr := encodeLine(datamodel.Report{Filename: filePath, SHA256: sha256, Error: msg})
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.closed {
		return false, sessionStatus{}
	}
	if _, ok := s.pending[filePath]; !ok {
		s.keepError(rep, line, encErr)
		s.LastActivity = s.nowTime()
	}
	return true, s.statusLocked(probe)
}

// addReport keeps one report per file that failed: a later report of the same
// file replaces it, and a repeated failure is no activity. Reports are kept
// as bound by the scanner. A session that must close (spool full or broken)
// still takes what comes until it is closed: nothing is dropped. A report in
// error that goes to the spool for lack of memory adds a line each time, and
// counts as activity: max_duration bounds it.
func (s *Session) addReport(rep datamodel.Report, probe bool) (bool, sessionStatus) {
	line, rep, encErr := encodeLine(rep)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.closed {
		return false, sessionStatus{}
	}
	_, replaced := s.pending[rep.Filename]
	if replaced {
		s.dropPending(rep.Filename)
	}
	if rep.Error != "" {
		s.keepError(rep, line, encErr)
	} else {
		s.store(rep, line, encErr)
	}
	if !replaced || rep.Error == "" {
		s.LastActivity = s.nowTime()
	}
	return true, s.statusLocked(probe)
}

// keepError holds a report in error in memory while the budget of the plugin
// allows it; past it the report goes to the spool, where a later success of the
// same file will add a second line.
func (s *Session) keepError(rep datamodel.Report, line []byte, encErr error) {
	if encErr != nil {
		s.holdUnencoded(rep, encErr)
		return
	}
	size := int64(len(line)) + pendingOverhead
	if s.limits.budget.reserve(size) {
		s.pending[rep.Filename] = pendingReport{report: rep, size: size}
		return
	}
	s.spilled = true
	s.append(rep, line)
}

// store writes a report to the spool.
func (s *Session) store(rep datamodel.Report, line []byte, encErr error) {
	if encErr != nil {
		s.holdUnencoded(rep, encErr)
		return
	}
	s.append(rep, line)
}

// holdUnencoded keeps a report that cannot be encoded in memory, as it came.
func (s *Session) holdUnencoded(rep datamodel.Report, err error) {
	s.encodeErr = err
	s.pending[rep.Filename] = pendingReport{report: rep}
}

// append adds a line to the spool. When that fails the report is held in
// memory instead, past the budget, and the session is to be closed.
func (s *Session) append(rep datamodel.Report, line []byte) {
	err := s.spoolErr
	if err == nil {
		err = s.write(line)
	}
	if err != nil {
		s.fail(err)
		size := int64(len(line)) + pendingOverhead
		s.limits.budget.force(size)
		s.pending[rep.Filename] = pendingReport{report: rep, size: size}
		return
	}
	s.healthy = len(s.spool.buf) == 0
	if s.limits.maxSize > 0 && s.spool.size() >= s.limits.maxSize && s.forced == "" {
		s.forced = forceSpoolSize
	}
}

func (s *Session) write(line []byte) error {
	if s.spool == nil {
		sp, err := createSpool(s.limits.dir, s.limits.logger)
		if err != nil {
			return err
		}
		s.spool = sp
	}
	return s.spool.append(line)
}

func (s *Session) fail(err error) {
	s.spoolErr = err
	s.healthy = false
	s.forced = forceSpoolError
}

// statusLocked is what the plugin must act on after a write; s.mutex is held.
// With probe set (a spool write failed earlier, the console event is raised)
// the buffered lines are written to disk now, so that the first session that
// really reaches the disk resolves the event, and one that does not fails at
// once: a write that only reached the buffer proves nothing.
func (s *Session) statusLocked(probe bool) sessionStatus {
	if probe && s.spoolErr == nil && s.spool != nil && !s.healthy && len(s.spool.buf) > 0 {
		if err := s.spool.flush(); err != nil {
			s.fail(err)
		} else {
			s.healthy = true
		}
	}
	st := sessionStatus{
		forced:    s.forced,
		spoolErr:  s.spoolErr,
		spilled:   s.spilled && !s.spillNoted,
		encodeErr: s.encodeErr,
		works:     s.healthy,
	}
	s.spillNoted = s.spillNoted || s.spilled
	s.encodeErr = nil
	return st
}

// dropPending forgets a report in error, giving back its share of the budget.
func (s *Session) dropPending(file string) {
	if held, ok := s.pending[file]; ok {
		s.limits.budget.give(held.size)
		delete(s.pending, file)
	}
}

// countLocked is the number of reports of the session; s.mutex is held.
func (s *Session) countLocked() int {
	n := len(s.pending)
	if s.spool != nil {
		n += s.spool.count
	}
	return n
}

// view is what holds the reports of a closed session. The map is not changed
// once the session is closed, so it is read without a lock.
func (s *Session) view() (*spool, map[string]pendingReport) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.spool, s.pending
}

// reports yields every report of the session: the spool first, then the reports
// in error held in memory, by file name. The session must be closed. It can be
// iterated again, which reads the spool again.
func (s *Session) reports(ctx context.Context) iter.Seq2[datamodel.Report, error] {
	sp, held := s.view()
	return func(yield func(datamodel.Report, error) bool) {
		if sp != nil {
			for rep, err := range sp.reports(ctx) {
				if !yield(rep, err) || err != nil {
					return
				}
			}
		}
		for _, file := range slices.Sorted(maps.Keys(held)) {
			if err := ctx.Err(); err != nil {
				yield(datamodel.Report{}, err)
				return
			}
			if !yield(held[file].report, nil) {
				return
			}
		}
	}
}

// copyRaw writes the reports of the session as they are stored, one JSON line
// each: the spool streamed, then the reports held in memory.
func (s *Session) copyRaw(ctx context.Context, w io.Writer) error {
	sp, held := s.view()
	if sp != nil {
		r, err := sp.open()
		if err != nil {
			return err
		}
		n, err := io.Copy(w, &ctxReader{ctx: ctx, r: r})
		err = errors.Join(err, r.Close())
		if err == nil && n != sp.size() {
			err = fmt.Errorf("spool: copied %d bytes, expected %d: the file was truncated", n, sp.size())
		}
		if err != nil {
			return err
		}
	}
	for _, file := range slices.Sorted(maps.Keys(held)) {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, _, err := encodeLine(held[file].report)
		if err != nil {
			return err
		}
		if _, err = w.Write(line); err != nil {
			return err
		}
	}
	return nil
}

// release frees what the session holds once its report is written or lost: the
// memory budget and the spool file. It is safe to call more than once.
func (s *Session) release() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.released {
		return nil
	}
	s.released = true
	for file := range s.pending {
		s.limits.budget.give(s.pending[file].size)
	}
	s.pending = nil
	if s.spool == nil {
		return nil
	}
	return s.spool.remove()
}
