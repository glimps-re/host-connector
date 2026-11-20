package scanner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/quarantine"
	quarantinemock "github.com/glimps-re/host-connector/pkg/quarantine/mock"
)

type moveFixture struct {
	src, dst string
	action   *MoveAction
}

func newMoveFixture(t *testing.T) moveFixture {
	t.Helper()
	root := t.TempDir()
	f := moveFixture{src: filepath.Join(root, "in"), dst: filepath.Join(root, "out")}
	for _, d := range []string{f.src, f.dst} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	f.action, err = NewMoveAction(f.dst, f.src)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f moveFixture) deposit(t *testing.T, rel, content string) string {
	t.Helper()
	p := filepath.Join(f.src, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (f moveFixture) move(t *testing.T, path string, malware bool) (datamodel.Report, error) {
	t.Helper()
	var report datamodel.Report
	err := f.action.Handle(t.Context(), testSource(t, path), datamodel.Result{Malware: malware}, &report)
	return report, err
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(p))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMoveAction_neverOverwrites(t *testing.T) {
	f := newMoveFixture(t)
	first := f.deposit(t, "u/report.pdf", "first")
	if rep, err := f.move(t, first, false); err != nil || rep.MovedTo != filepath.Join(f.dst, "u", "report.pdf") || rep.MoveConflictOf != "" {
		t.Fatalf("first move: %+v, %v", rep, err)
	}
	second := f.deposit(t, "u/report.pdf", "second")
	rep, err := f.move(t, second, false)
	if err != nil {
		t.Fatalf("second move error = %v", err)
	}
	if read(t, filepath.Join(f.dst, "u", "report.pdf")) != "first" {
		t.Error("the file already at the destination was overwritten")
	}
	if !strings.Contains(rep.MovedTo, ".conflict-") || !strings.HasSuffix(rep.MovedTo, ".pdf") || read(t, rep.MovedTo) != "second" {
		t.Errorf("MovedTo = %q, want a conflict name holding the second file", rep.MovedTo)
	}
	if rep.MoveConflictOf != filepath.Join("u", "report.pdf") {
		t.Errorf("MoveConflictOf = %q, want the original name", rep.MoveConflictOf)
	}
	if _, err := os.Stat(second); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("source must be gone: %v", err)
	}
}

func TestMoveAction_severalConflictsGetDistinctNames(t *testing.T) {
	f := newMoveFixture(t)
	fixed := time.Date(2026, 11, 19, 20, 0, 0, 0, time.UTC)
	prev := now
	now = func() time.Time { return fixed }
	t.Cleanup(func() { now = prev })
	f.deposit(t, "a.txt", "0")
	if _, err := f.move(t, filepath.Join(f.src, "a.txt"), false); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 1; i <= 4; i++ {
		p := f.deposit(t, "a.txt", strings.Repeat("x", i))
		rep, err := f.move(t, p, false)
		if err != nil {
			t.Fatalf("move %d error = %v", i, err)
		}
		if seen[rep.MovedTo] {
			t.Fatalf("name %q used twice", rep.MovedTo)
		}
		seen[rep.MovedTo] = true
	}
}

func TestMoveAction_conflictsExhausted(t *testing.T) {
	f := newMoveFixture(t)
	p := f.deposit(t, "a.txt", "content")
	prev := moveFile
	attempts := 0
	moveFile = func(quarantine.MoveSource, string, string, func() time.Time, int) (string, error) {
		attempts++
		return "", quarantine.ErrDestinationExists
	}
	t.Cleanup(func() { moveFile = prev })
	_, err := f.move(t, p, false)
	if !errors.Is(err, errPermanentAction) {
		t.Fatalf("error = %v, want errPermanentAction", err)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want one call: the conflict names are tried inside it", attempts)
	}
	if read(t, p) != "content" {
		t.Error("the source must be intact")
	}
}

func TestMoveAction_longNames(t *testing.T) {
	f := newMoveFixture(t)
	name := strings.Repeat("n", 251) + ".txt"
	if len(name) != 255 {
		t.Fatalf("test name is %d bytes", len(name))
	}
	if _, err := f.move(t, f.deposit(t, name, "one"), false); err != nil {
		t.Fatalf("first move error = %v", err)
	}
	rep, err := f.move(t, f.deposit(t, name, "two"), false)
	if err != nil {
		t.Fatalf("conflicting move error = %v, want the base truncated", err)
	}
	if len(filepath.Base(rep.MovedTo)) > 255 || !strings.HasSuffix(rep.MovedTo, ".txt") || !strings.Contains(rep.MovedTo, ".conflict-") {
		t.Errorf("MovedTo = %q (%d bytes)", filepath.Base(rep.MovedTo), len(filepath.Base(rep.MovedTo)))
	}
}

func TestMoveAction_permanentErrors(t *testing.T) {
	t.Run("destination is a directory", func(t *testing.T) {
		f := newMoveFixture(t)
		if err := os.MkdirAll(filepath.Join(f.dst, "u", "a"), 0o750); err != nil {
			t.Fatal(err)
		}
		p := f.deposit(t, "u/a", "file")
		if _, err := f.move(t, p, false); !errors.Is(err, errPermanentAction) {
			t.Fatalf("error = %v, want errPermanentAction", err)
		}
		if read(t, p) != "file" {
			t.Error("source must be intact")
		}
	})
	t.Run("a parent of the destination is a file", func(t *testing.T) {
		f := newMoveFixture(t)
		if err := os.WriteFile(filepath.Join(f.dst, "u"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := f.move(t, f.deposit(t, "u/a", "file"), false); !errors.Is(err, errPermanentAction) {
			t.Fatalf("error = %v, want errPermanentAction", err)
		}
	})
	t.Run("file outside the source", func(t *testing.T) {
		f := newMoveFixture(t)
		outside := filepath.Join(t.TempDir(), "x.txt")
		if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := f.move(t, outside, false); !errors.Is(err, errPermanentAction) {
			t.Fatalf("error = %v, want errPermanentAction", err)
		}
	})
	t.Run("file in the transit directory, in any letter case", func(t *testing.T) {
		for _, dir := range []string{quarantine.StagingDir, strings.ToUpper(quarantine.StagingDir)} {
			f := newMoveFixture(t)
			p := f.deposit(t, dir+"/x.txt", "x")
			if _, err := f.move(t, p, false); !errors.Is(err, errPermanentAction) {
				t.Fatalf("%s: error = %v, want errPermanentAction", dir, err)
			}
		}
	})
	t.Run("ENAMETOOLONG is permanent", func(t *testing.T) {
		if !errors.Is(classifyDestinationError(syscall.ENAMETOOLONG), errPermanentAction) {
			t.Error("ENAMETOOLONG must be permanent")
		}
		if !errors.Is(classifyDestinationError(syscall.EXDEV), errPermanentAction) {
			t.Error("EXDEV at publication must be permanent")
		}
		if errors.Is(classifyDestinationError(syscall.EIO), errPermanentAction) {
			t.Error("an I/O error is not permanent")
		}
	})
}

func TestMoveAction_dotDotNamedFolderIsInsideTheSource(t *testing.T) {
	f := newMoveFixture(t)
	rep, err := f.move(t, f.deposit(t, "..x/f.txt", "content"), false)
	if err != nil {
		t.Fatalf("error = %v: a folder named ..x is not outside the source", err)
	}
	if read(t, rep.MovedTo) != "content" {
		t.Error("file not moved")
	}
}

func TestMoveAction_reservedSessionReportNames(t *testing.T) {
	refused := []string{
		"report-session-x.pdf",
		"user/report-session-x.pdf",
		"user/deep/er/report-session-x.pdf",
		"Report-Session-x.pdf",
		"REPORT-SESSION-x.pdf",
	}
	for _, rel := range refused {
		t.Run(rel, func(t *testing.T) {
			f := newMoveFixture(t)
			p := f.deposit(t, rel, "fake report")
			rep, err := f.move(t, p, false)
			if !errors.Is(err, errPermanentAction) {
				t.Fatalf("error = %v, want errPermanentAction", err)
			}
			if rep.Error == "" || !strings.Contains(rep.Error, "reserved") {
				t.Errorf("Report.Error = %q, want it to say why", rep.Error)
			}
			if rep.MovedTo != "" {
				t.Errorf("MovedTo = %q, the file must not move", rep.MovedTo)
			}
			if read(t, p) != "fake report" {
				t.Error("the file must stay in place")
			}
			assertEmptyTree(t, f.dst)
		})
	}
	t.Run("prefix elsewhere than at the start is moved", func(t *testing.T) {
		f := newMoveFixture(t)
		rep, err := f.move(t, f.deposit(t, "user/mon-report-session-x.pdf", "ok"), false)
		if err != nil || read(t, rep.MovedTo) != "ok" {
			t.Errorf("move = %+v, %v", rep, err)
		}
	})
	t.Run("a malicious file with the reserved name writes nothing to the destination", func(t *testing.T) {
		f := newMoveFixture(t)
		p := f.deposit(t, "user/report-session-x.pdf", "malware")
		rep, err := f.move(t, p, true)
		if err != nil {
			t.Fatalf("error = %v: a detection must not turn into an error that hides its mitigation", err)
		}
		if rep.Error == "" || read(t, p) != "malware" {
			t.Errorf("report = %+v, want Error set and the file left in place", rep)
		}
		assertEmptyTree(t, f.dst)
	})
}

func assertEmptyTree(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			t.Errorf("unexpected file in the destination: %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMoveAction_lockReportsNeverCollide(t *testing.T) {
	f := newMoveFixture(t)
	fixed := time.Date(2026, 11, 19, 20, 30, 0, 0, time.UTC)
	prev := now
	now = func() time.Time { return fixed }
	t.Cleanup(func() { now = prev })
	for range 3 {
		p := f.deposit(t, "u/mal.exe", "malware")
		if _, err := f.move(t, p, true); err != nil {
			t.Fatalf("lockreport error = %v", err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(f.dst, "u"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Errorf("%d lockreports in the same minute, want 3 distinct files: %v", len(entries), entries)
	}
	for _, e := range entries {
		if !strings.Contains(e.Name(), "-lockreport") || len(e.Name()) > 255 {
			t.Errorf("unexpected name %q", e.Name())
		}
	}
}

func TestMoveAction_lockReportWithALongName(t *testing.T) {
	f := newMoveFixture(t)
	p := f.deposit(t, strings.Repeat("m", 250)+".exe", "malware")
	if _, err := f.move(t, p, true); err != nil {
		t.Fatalf("error = %v", err)
	}
	entries, err := os.ReadDir(f.dst)
	if err != nil || len(entries) != 1 || len(entries[0].Name()) > 255 {
		t.Errorf("entries = %v, %v; want one lockreport within 255 bytes", entries, err)
	}
}

type mitigationRecorder struct {
	events.NoopEventHandler
	mu   sync.Mutex
	seen []events.FileInfos
}

func (m *mitigationRecorder) NotifyFileMitigation(_ context.Context, _ events.MitigationAction, _ string, _ events.MitigationReason, info events.FileInfos) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seen = append(m.seen, info)
	return nil
}

func recordMitigations(t *testing.T) *mitigationRecorder {
	t.Helper()
	rec := &mitigationRecorder{}
	prev := EventHandler
	EventHandler = rec
	t.Cleanup(func() { EventHandler = prev })
	return rec
}

type failingAction struct{ err error }

func (f failingAction) Handle(context.Context, Source, datamodel.Result, *datamodel.Report) error {
	return f.err
}

func quarantineSucceeds() *QuarantineAction {
	return NewQuarantineAction(&quarantinemock.QuarantineMock{
		QuarantineMock: func(_ context.Context, _ string, _ *os.File, _ string, _ []string) (string, string, error) {
			return "/q/x.lock", "id-1", nil
		},
	})
}

func TestMultiAction_mitigationIsReportedWhateverTheMoveDoes(t *testing.T) {
	t.Run("malware with a reserved name: quarantined, move leaves the file, mitigation sent", func(t *testing.T) {
		rec := recordMitigations(t)
		f := newMoveFixture(t)
		p := f.deposit(t, "u/report-session-x.pdf", "malware")
		multi := NewMultiAction(&ReportAction{}, quarantineSucceeds(), f.action)
		var report datamodel.Report
		err := multi.Handle(t.Context(), testSource(t, p), datamodel.Result{Malware: true, SHA256: "sha"}, &report)
		if err != nil {
			t.Fatalf("Handle() error = %v", err)
		}
		if len(rec.seen) != 1 || report.Error == "" {
			t.Errorf("mitigations = %d, report.Error = %q; want one mitigation and the error in the report", len(rec.seen), report.Error)
		}
	})
	t.Run("a failing move after a quarantine: mitigation sent, error returned and still classifiable", func(t *testing.T) {
		rec := recordMitigations(t)
		boom := fmt.Errorf("%w: disk full", errPermanentAction)
		multi := NewMultiAction(&ReportAction{}, quarantineSucceeds(), failingAction{err: boom})
		var report datamodel.Report
		// A real file: the quarantine reads it through the source.
		deposit := filepath.Join(t.TempDir(), "f.bin")
		if err := os.WriteFile(deposit, []byte("malware"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := multi.Handle(t.Context(), testSource(t, deposit), datamodel.Result{Malware: true, SHA256: "sha"}, &report)
		if !errors.Is(err, errPermanentAction) {
			t.Fatalf("error = %v, want errPermanentAction through the join", err)
		}
		if len(rec.seen) != 1 {
			t.Errorf("mitigations = %d, want 1 even though a later action failed", len(rec.seen))
		}
	})
	t.Run("a later action still runs after an error", func(t *testing.T) {
		recordMitigations(t)
		ran := false
		multi := NewMultiAction(failingAction{err: errors.New("first")}, actionFunc(func() { ran = true }))
		if err := multi.Handle(t.Context(), testSource(t, "/in/f"), datamodel.Result{}, &datamodel.Report{}); err == nil {
			t.Fatal("the error must be returned")
		}
		if !ran {
			t.Error("the following action did not run")
		}
	})
	t.Run("a failed quarantine is never followed by the removal of the file", func(t *testing.T) {
		rec := recordMitigations(t)
		f := newMoveFixture(t)
		p := f.deposit(t, "mal.bin", "malware")
		failing := NewQuarantineAction(&quarantinemock.QuarantineMock{
			QuarantineMock: func(context.Context, string, *os.File, string, []string) (string, string, error) {
				return "", "", errors.New("quarantine full")
			},
		})
		multi := NewMultiAction(&ReportAction{}, failing, &RemoveFileAction{})
		if err := multi.Handle(t.Context(), testSource(t, p), datamodel.Result{Malware: true, SHA256: "sha"}, &datamodel.Report{}); err == nil {
			t.Fatal("the quarantine error must be returned")
		}
		if read(t, p) != "malware" {
			t.Error("the file was removed after a failed quarantine")
		}
		if len(rec.seen) != 0 {
			t.Errorf("%d mitigation events after a failed quarantine, want none: nothing was mitigated", len(rec.seen))
		}
	})
}

type actionFunc func()

func (f actionFunc) Handle(context.Context, Source, datamodel.Result, *datamodel.Report) error {
	f()
	return nil
}

func TestRemoveFileAction_announcesOnlyARemovalThatHappened(t *testing.T) {
	t.Run("failed removal: no Removed action, error returned, no mitigation event", func(t *testing.T) {
		rec := recordMitigations(t)
		dir := t.TempDir()
		stuck := filepath.Join(dir, "stuck")
		if err := os.Mkdir(stuck, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stuck, "child"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		multi := NewMultiAction(&ReportAction{}, &RemoveFileAction{})
		var report datamodel.Report
		err := multi.Handle(t.Context(), testSource(t, stuck), datamodel.Result{Malware: true, SHA256: "sha"}, &report)
		if err == nil {
			t.Fatal("a failed removal must return its error")
		}
		if report.Action == datamodel.Removed || report.Deleted || report.MitigationID != "" {
			t.Errorf("report = %+v, the removal did not happen", report)
		}
		if len(rec.seen) != 0 {
			t.Errorf("%d mitigation events, want none for a file still in place", len(rec.seen))
		}
	})
	t.Run("successful removal is announced", func(t *testing.T) {
		rec := recordMitigations(t)
		p := filepath.Join(t.TempDir(), "mal.bin")
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		var report datamodel.Report
		multi := NewMultiAction(&ReportAction{}, &RemoveFileAction{})
		if err := multi.Handle(t.Context(), testSource(t, p), datamodel.Result{Malware: true, SHA256: "sha"}, &report); err != nil {
			t.Fatal(err)
		}
		if report.Action != datamodel.Removed || !report.Deleted || len(rec.seen) != 1 {
			t.Errorf("report = %+v, events %d", report, len(rec.seen))
		}
	})
	t.Run("a quarantine already done keeps its action", func(t *testing.T) {
		recordMitigations(t)
		p := filepath.Join(t.TempDir(), "mal.bin")
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		report := datamodel.Report{Action: datamodel.Quarantined}
		if err := (&RemoveFileAction{}).Handle(t.Context(), testSource(t, p), datamodel.Result{Malware: true, SHA256: "sha"}, &report); err != nil {
			t.Fatal(err)
		}
		if report.Action != datamodel.Quarantined {
			t.Errorf("Action = %q, want it kept", report.Action)
		}
	})
}

func TestIsPermanentAction(t *testing.T) {
	permanent := fmt.Errorf("move action: %w: names taken", errPermanentAction)
	transient := errors.New("quarantine action: disk busy")
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"permanent", permanent, true},
		{"transient", transient, false},
		{"a permanent error wrapping its cause", classifyDestinationError(syscall.ENAMETOOLONG), true},
		{"all permanent", joinedErrors{permanent, permanent}, true},
		{"transient quarantine and permanent move", joinedErrors{transient, permanent}, false},
		{"permanent first, transient after", joinedErrors{permanent, transient}, false},
		{"joined error behind a wrap", fmt.Errorf("handle: %w", joinedErrors{transient, permanent}), false},
		{"joined permanent behind a wrap", fmt.Errorf("handle: %w", joinedErrors{permanent}), true},
	}
	for _, tt := range tests {
		if got := IsPermanentAction(tt.err); got != tt.want {
			t.Errorf("%s: IsPermanentAction() = %t, want %t", tt.name, got, tt.want)
		}
	}
}

func TestMultiAction_returnsAllTheFailures(t *testing.T) {
	recordMitigations(t)
	first, second := errors.New("first"), fmt.Errorf("%w: second", errPermanentAction)
	multi := NewMultiAction(failingAction{err: first}, failingAction{err: second})
	err := multi.Handle(t.Context(), testSource(t, "/in/f"), datamodel.Result{}, &datamodel.Report{})
	if !errors.Is(err, first) || !errors.Is(err, errPermanentAction) {
		t.Fatalf("error = %v, want both failures reachable", err)
	}
	if IsPermanentAction(err) {
		t.Error("a transient failure among the errors must keep the action retryable")
	}
}
