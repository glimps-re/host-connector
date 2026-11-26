package scanner

import (
	"context"
	"errors"
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
)

type movedEvents struct {
	events.NoopEventHandler
	mu                  sync.Mutex
	errors, resolutions []events.ErrorEventType
}

func (m *movedEvents) NotifyError(_ context.Context, k events.ErrorEventType, _ error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors = append(m.errors, k)
	return nil
}

func (m *movedEvents) NotifyResolution(_ context.Context, _ string, ks ...events.ErrorEventType) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resolutions = append(m.resolutions, ks...)
	return nil
}

func newCopyMoveFixture(t *testing.T) moveFixture {
	t.Helper()
	f := newMoveFixture(t)
	var err error
	f.action, err = NewMoveActionWithMode(f.dst, f.src, MoveModeCopy, 0)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestMoveAction_copyModeIsTheDefaultOfNewMoveActionWithMode(t *testing.T) {
	a, err := NewMoveActionWithMode(t.TempDir(), t.TempDir(), "", 0)
	if err != nil || a.Mode != MoveModeCopy {
		t.Fatalf("mode = %q, %v, want copy", a.Mode, err)
	}
	if _, err = NewMoveActionWithMode(t.TempDir(), t.TempDir(), "link", 0); err == nil {
		t.Error("an unknown mode must be refused")
	}
}

func TestMoveAction_copyModePublishesAnotherInodeThanTheSource(t *testing.T) {
	f := newCopyMoveFixture(t)
	p := f.deposit(t, "a/doc.txt", "analyzed content")
	src := testSource(t, p)
	// A depositor that keeps the file open for writing.
	writer, err := os.OpenFile(filepath.Clean(p), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	var report datamodel.Report
	if err := f.action.Handle(t.Context(), src, datamodel.Result{}, &report); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteAt([]byte("REWRITTEN BY THE LATE WRITER"), 0); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(f.dst, "a", "doc.txt")
	if report.MovedTo != dest || read(t, dest) != "analyzed content" {
		t.Errorf("moved to %q holding %q, want the analyzed content whatever the late writer does", report.MovedTo, read(t, dest))
	}
	if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the source must be removed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(f.dst, quarantine.StagingDir, "x")); err == nil {
		t.Error("unexpected file in the transit folder")
	}
}

func TestMoveAction_copyModeRefusesAFileRewrittenSinceTheAnalysis(t *testing.T) {
	f := newCopyMoveFixture(t)
	p := f.deposit(t, "doc.txt", "analyzed content")
	src := testSource(t, p)
	if err := os.WriteFile(p, []byte("rewritten, and longer, after the analysis"), 0o600); err != nil {
		t.Fatal(err)
	}
	var report datamodel.Report
	err := f.action.Handle(t.Context(), src, datamodel.Result{}, &report)
	if err == nil || IsPermanentAction(err) {
		t.Fatalf("error = %v, want a retryable refusal", err)
	}
	if _, statErr := os.Lstat(filepath.Join(f.dst, "doc.txt")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("nothing may reach the destination: %v", statErr)
	}
	if read(t, p) != "rewritten, and longer, after the analysis" {
		t.Error("the source must stay")
	}
}

func TestMoveAction_copyModeHashMismatchIsNeverPublished(t *testing.T) {
	f := newCopyMoveFixture(t)
	p := f.deposit(t, "doc.txt", "analyzed content")
	src := testSource(t, p)
	src.SHA256 = "00" + src.SHA256[2:]
	var report datamodel.Report
	err := f.action.Handle(t.Context(), src, datamodel.Result{}, &report)
	if !errors.Is(err, quarantine.ErrContentChanged) {
		t.Fatalf("error = %v, want ErrContentChanged", err)
	}
	if _, statErr := os.Lstat(filepath.Join(f.dst, "doc.txt")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("destination published: %v", statErr)
	}
	if read(t, p) != "analyzed content" {
		t.Error("the source must stay")
	}
}

func TestMoveAction_copyModeEmptyFileIsANewEmptyFile(t *testing.T) {
	f := newCopyMoveFixture(t)
	p := f.deposit(t, "empty.txt", "")
	src := testSource(t, p)
	writer, err := os.OpenFile(filepath.Clean(p), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	var report datamodel.Report
	if err := f.action.Handle(t.Context(), src, datamodel.Result{}, &report); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString("late"); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(f.dst, "empty.txt")
	if got := read(t, dest); got != "" {
		t.Errorf("destination = %q, want an empty file: the writer must not reach it", got)
	}
	if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the source must be removed: %v", err)
	}
}

func TestMoveAction_copyModeAnEmptyFileThatGrewIsNotCreatedEmpty(t *testing.T) {
	f := newCopyMoveFixture(t)
	p := f.deposit(t, "empty.txt", "")
	src := testSource(t, p)
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var report datamodel.Report
	if err := f.action.Handle(t.Context(), src, datamodel.Result{}, &report); err == nil {
		t.Fatal("error = nil, want a refusal")
	}
	if _, err := os.Lstat(filepath.Join(f.dst, "empty.txt")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("destination created: %v", err)
	}
}

func TestMoveAction_copyModeNeverReplacesAndTakesAConflictName(t *testing.T) {
	f := newCopyMoveFixture(t)
	p := f.deposit(t, "doc.txt", "second")
	if err := os.WriteFile(filepath.Join(f.dst, "doc.txt"), []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	var report datamodel.Report
	if err := f.action.Handle(t.Context(), testSource(t, p), datamodel.Result{}, &report); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(f.dst, "doc.txt")) != "first" || report.MovedTo == filepath.Join(f.dst, "doc.txt") || read(t, report.MovedTo) != "second" {
		t.Errorf("moved to %q: the first file must stay and the second take another name", report.MovedTo)
	}
	if report.MoveConflictOf != "doc.txt" {
		t.Errorf("MoveConflictOf = %q", report.MoveConflictOf)
	}
}

func TestMoveAction_renameModeStillMovesTheInode(t *testing.T) {
	f := newMoveFixture(t)
	p := f.deposit(t, "doc.txt", "content")
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.move(t, p, false); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(filepath.Join(f.dst, "doc.txt"))
	if err != nil || !os.SameFile(before, after) {
		t.Errorf("the rename mode must publish the inode of the source (%v)", err)
	}
}

func TestMoveClass_onlyThePipelineSendsAFileByName(t *testing.T) {
	tests := []struct {
		name string
		src  Source
		want moveClass
	}{
		{"empty", Source{Identity: FileIdentity{Size: 0}}, classEmpty},
		{"analyzed", Source{Identity: FileIdentity{Size: 1 << 30}}, classCopy},
		{"too big, not analyzed", Source{Identity: FileIdentity{Size: 1 << 30}, TooBig: true}, classByPath},
	}
	for _, tt := range tests {
		if got := classOf(tt.src); got != tt.want {
			t.Errorf("%s: classOf() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func inodeOf(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestMoveAction_copyModeATooBigSourceGoesByPath(t *testing.T) {
	f := newCopyMoveFixture(t)
	p := f.deposit(t, "big.bin", strings.Repeat("too big to be analyzed ", 10))
	before := inodeOf(t, p)
	src := testSource(t, p)
	src.TooBig = true
	var report datamodel.Report
	if err := f.action.Handle(t.Context(), src, datamodel.Result{}, &report); err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, inodeOf(t, filepath.Join(f.dst, "big.bin"))) {
		t.Error("a file the pipeline declared too big is moved by name")
	}
	if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the source must be removed: %v", err)
	}
}

// A large archive that was extracted and analyzed is not too big: it is copied.
func TestMoveAction_copyModeALargeAnalyzedFileIsCopied(t *testing.T) {
	f := newCopyMoveFixture(t)
	p := f.deposit(t, "big.zip", strings.Repeat("a large archive, extracted and analyzed ", 100))
	before := inodeOf(t, p)
	var report datamodel.Report
	if err := f.action.Handle(t.Context(), testSource(t, p), datamodel.Result{}, &report); err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, inodeOf(t, filepath.Join(f.dst, "big.zip"))) {
		t.Error("the inode of the source reached the destination")
	}
}

// What a result says does not decide: only the field of the pipeline does.
func TestMoveAction_copyModeAResultSayingTooBigIsStillCopied(t *testing.T) {
	f := newCopyMoveFixture(t)
	p := f.deposit(t, "small.zip", "a small archive with a member too big")
	before := inodeOf(t, p)
	var report datamodel.Report
	if err := f.action.Handle(t.Context(), testSource(t, p), datamodel.Result{MalwareReason: datamodel.TooBig}, &report); err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, inodeOf(t, filepath.Join(f.dst, "small.zip"))) {
		t.Error("a result must not send a file by name")
	}
}

func TestMoveAction_theZeroModeCopies(t *testing.T) {
	if !(&MoveAction{}).Mode.copies() || !MoveMode("").copies() || MoveModeRename.copies() {
		t.Error("only the rename mode renames")
	}
}

func TestMoveTimeout(t *testing.T) {
	const mib = int64(1 << 20)
	tests := []struct {
		name        string
		size, floor int64
		want        time.Duration
	}{
		{"empty", 0, 10 * mib, time.Minute},
		{"1 GiB at 10 MiB/s", 1 << 30, 10 * mib, 102*time.Second + time.Minute},
		{"default floor", 100 * mib, 0, 10*time.Second + time.Minute},
		{"huge never overflows", 1 << 62, 1, time.Duration(1<<63 - 1)},
		{"10 GB at 1 B/s saturates", 10 << 30, 1, time.Duration(1<<63 - 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := moveTimeout(tt.size, tt.floor)
			if got != tt.want {
				t.Errorf("moveTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMoveAction_copyModeAFailureOfTheDestinationIsAResourceUntilAFileIsMoved(t *testing.T) {
	prev := EventHandler
	rec := &movedEvents{}
	EventHandler = rec
	t.Cleanup(func() { EventHandler = prev })
	f := newCopyMoveFixture(t)
	p := f.deposit(t, "doc.txt", "analyzed content")
	expired, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	var report datamodel.Report
	err := f.action.Handle(expired, testSource(t, p), datamodel.Result{}, &report)
	if !errors.Is(err, errResourceAction) || !isResourceAction(err) || IsPermanentAction(err) {
		t.Fatalf("error = %v, want a resource failure", err)
	}
	entries, _ := os.ReadDir(filepath.Join(f.dst, quarantine.StagingDir))
	if len(entries) != 0 {
		t.Errorf("%d leftovers in the transit folder", len(entries))
	}
	if read(t, p) != "analyzed content" {
		t.Error("the source must stay")
	}
	// A second failure does not raise the event again.
	if err = f.action.Handle(expired, testSource(t, p), datamodel.Result{}, &report); !errors.Is(err, errResourceAction) {
		t.Fatalf("error = %v", err)
	}
	if len(rec.errors) != 1 || rec.errors[0] != moveResourceEvent || len(rec.resolutions) != 0 {
		t.Fatalf("events: errors %v, resolutions %v, want one error and no resolution yet", rec.errors, rec.resolutions)
	}
	if err = f.action.Handle(t.Context(), testSource(t, p), datamodel.Result{}, &report); err != nil {
		t.Fatal(err)
	}
	if len(rec.resolutions) != 1 || rec.resolutions[0] != moveResourceEvent {
		t.Errorf("resolutions = %v, want the event resolved by the first success", rec.resolutions)
	}
}

func TestMoveAction_classifyCopyError(t *testing.T) {
	a := &MoveAction{}
	tests := []struct {
		name      string
		err       error
		resource  bool
		permanent bool
	}{
		{"deadline", context.DeadlineExceeded, true, false},
		{"disk full", &os.PathError{Op: "write", Err: syscall.ENOSPC}, true, false},
		{"names taken", quarantine.ErrDestinationExists, false, true},
		{"no hash", quarantine.ErrNoExpectedHash, false, true},
		{"source not removable", quarantine.MarkRemovalRefused(syscall.EACCES), false, true},
		{"changed", quarantine.ErrContentChanged, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := a.classifyCopyError(t.Context(), tt.err, "dest")
			if isResourceAction(got) != tt.resource || IsPermanentAction(got) != tt.permanent {
				t.Errorf("classifyCopyError() = %v: resource %v permanent %v, want %v %v", got, isResourceAction(got), IsPermanentAction(got), tt.resource, tt.permanent)
			}
		})
	}
}

func TestConnector_actionTimeoutLeavesRoomForTheCopy(t *testing.T) {
	const gib = int64(1 << 30)
	c := &Connector{config: Config{Actions: Actions{Move: true}}}
	if got, base := c.actionTimeout(5*gib), actionTimeoutForSize(5*gib); got < base+moveTimeout(5*gib, 0) {
		t.Errorf("actionTimeout() = %v, must cover the copy", got)
	}
	c.config.MoveMinThroughput = 1
	if got := c.actionTimeout(10 << 30); got <= 0 {
		t.Errorf("actionTimeout() = %v for a copy that cannot finish in time: it must saturate, not wrap around", got)
	}
	c.config.MoveMode = MoveModeRename
	if got, want := c.actionTimeout(gib), actionTimeoutForSize(gib); got != want {
		t.Errorf("actionTimeout() in rename mode = %v, want %v", got, want)
	}
}
