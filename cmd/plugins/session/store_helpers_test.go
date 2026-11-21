package main

import (
	"log/slog"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

// testSession is a closed session holding the given reports in its spool.
func testSession(t testing.TB, id string, start time.Time, paths []string, reports ...datamodel.Report) *Session {
	t.Helper()
	s := &Session{
		ID: id, StartTime: start, Paths: paths,
		InFlight: map[string]*inflightEntry{},
		pending:  map[string]pendingReport{},
		limits:   spoolLimits{dir: t.TempDir(), budget: &errorBudget{}, logger: slog.New(slog.DiscardHandler)},
	}
	for _, r := range reports {
		if !okAdd(s, r) {
			t.Fatal("report refused")
		}
	}
	s.closeSession()
	return s
}

// sessionReports reads back every report of a session.
func sessionReports(t testing.TB, s *Session) []datamodel.Report {
	t.Helper()
	var out []datamodel.Report
	for r, err := range s.reports(t.Context()) {
		if err != nil {
			t.Fatalf("reading the session reports: %v", err)
		}
		out = append(out, r)
	}
	return out
}

// newMockHCC is a connector context that has a work directory, which the
// session plugin requires.
func newMockHCC(t testing.TB) *mock.MockHCContext {
	t.Helper()
	hcc := mock.NewMockHCContext()
	hcc.WorkDir = t.TempDir()
	return hcc
}

func okAdd(s *Session, r datamodel.Report) bool {
	ok, _ := s.addReport(r, false)
	return ok
}

func addedError(s *Session, file, sha, msg string) bool {
	ok, _ := s.addFileError(file, sha, msg, false)
	return ok
}
