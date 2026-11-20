package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/quarantine"
	quarantineMock "github.com/glimps-re/host-connector/pkg/quarantine/mock"
)

func TestReportAction_aRestoredFileIsMarkedInTheReport(t *testing.T) {
	report := &datamodel.Report{}
	if err := (&ReportAction{}).Handle(t.Context(), Source{Path: "/in/f.bin"}, datamodel.Result{SHA256: "sha", Restored: true}, report); err != nil {
		t.Fatal(err)
	}
	if !report.HasBeenRestored {
		t.Error("the report of a restored file must say so")
	}
	other := &datamodel.Report{}
	if err := (&ReportAction{}).Handle(t.Context(), Source{Path: "/in/f.bin"}, datamodel.Result{SHA256: "sha"}, other); err != nil || other.HasBeenRestored {
		t.Errorf("HasBeenRestored = %t (%v) for a file that was not restored", other.HasBeenRestored, err)
	}
}

// A content restored between the check of the pipeline and the action is
// refused by the quarantine, the failure is not definitive: at the next pass the
// file is recognized as restored.
func TestQuarantineAction_aRestoredContentIsARetryNotADefinitiveFailure(t *testing.T) {
	a := NewQuarantineAction(&quarantineMock.QuarantineMock{
		QuarantineMock: func(context.Context, string, *os.File, string, []string) (string, string, error) {
			return "", "", quarantine.ErrRestored
		},
	})
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := a.Handle(t.Context(), testSource(t, path), datamodel.Result{Malware: true}, &datamodel.Report{SHA256: "sha"})
	if !errors.Is(err, quarantine.ErrRestored) || IsPermanentAction(err) {
		t.Errorf("Handle() error = %v, want ErrRestored, not a definitive failure", err)
	}
}

// The whole pipeline: the content is restored between the check and the action.
// The quarantine refuses, the file is neither quarantined nor deleted, the
// outcome is a retry, and the next pass handles it as a restored file.
func TestPipeline_contentRestoredBetweenTheCheckAndTheActionIsHandledAsRestoredAtTheNextPass(t *testing.T) {
	noOpenInputs(t)
	in := t.TempDir()
	file := filepath.Join(in, "f.bin")
	if err := os.WriteFile(file, []byte("some content"), 0o600); err != nil {
		t.Fatal(err)
	}
	var restored atomic.Bool // becomes true once the first pass checked
	var quarantined atomic.Int32
	quarantiner := &quarantineMock.QuarantineMock{
		IsRestoredMock: func(context.Context, string, string) (bool, error) { return restored.Load(), nil },
		QuarantineMock: func(context.Context, string, *os.File, string, []string) (string, string, error) {
			quarantined.Add(1)
			return "", "", quarantine.ErrRestored
		},
	}
	submitter := readerTrio(&gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForReaderMock: func(_ context.Context, r io.Reader, _ gdetect.WaitForOptions) (gdetect.Result, error) {
			restored.Store(true) // the content is restored while it is analyzed
			h := sha256.New()
			_, err := io.Copy(h, r)
			return gdetect.Result{SHA256: hex.EncodeToString(h.Sum(nil)), Malware: true, Malwares: []string{"m"}}, err
		},
	})
	c, err := NewConnector(Config{
		Roots: []string{in}, WorkDir: t.TempDir(), Workers: 1,
		Actions: Actions{Quarantine: true, Deleted: true},
	}, quarantiner, submitter)
	if err != nil {
		t.Fatal(err)
	}
	got := &outcomes{}
	c.config.OnFileDone = got.add
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	if err = c.ScanFile(t.Context(), file); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the first pass to end", func() bool { return len(got.get()) == 1 })
	if first := got.get()[0]; first.Kind != OutcomeRetry {
		t.Errorf("first outcome = %+v, want a retry: the content may be restored since", first)
	}
	if _, err = os.Stat(file); err != nil {
		t.Fatalf("the file must be neither quarantined nor deleted: %v", err)
	}
	if err = c.ScanFile(t.Context(), file); err != nil { // the next pass
		t.Fatal(err)
	}
	c.Close(t.Context())
	list := got.get()
	if len(list) != 2 || list[1].Kind != OutcomeFinal {
		t.Errorf("outcomes = %+v, want one retry then a final outcome: handled as restored", list)
	}
	if quarantined.Load() != 1 {
		t.Errorf("the quarantine was asked %d times, want once (the first pass)", quarantined.Load())
	}
	if _, err = os.Stat(file); err != nil {
		t.Errorf("the restored file must stay: %v", err)
	}
}

// After a quarantine refused with ErrRestored the delete action does not run:
// the file stays.
func TestMultiAction_noDeletionAfterAQuarantineRefusedBecauseTheContentWasRestored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &MultiAction{Actions: []Action{
		NewQuarantineAction(&quarantineMock.QuarantineMock{
			QuarantineMock: func(context.Context, string, *os.File, string, []string) (string, string, error) {
				return "", "", quarantine.ErrRestored
			},
		}),
		&RemoveFileAction{},
	}}
	report := &datamodel.Report{SHA256: "sha"}
	err := m.Handle(t.Context(), testSource(t, path), datamodel.Result{Malware: true, Malwares: []string{"m"}}, report)
	if !errors.Is(err, quarantine.ErrRestored) {
		t.Errorf("Handle() error = %v, want ErrRestored", err)
	}
	if _, e := os.Stat(path); e != nil {
		t.Errorf("the file must be left intact: %v", e)
	}
	if report.Deleted {
		t.Error("the report must not claim a deletion")
	}
}

// The pipeline asks about the content and the place: the empty content is matched
// per location.
func TestPrepareFile_asksIfTheContentWasRestoredWithItsLocation(t *testing.T) {
	c, _, file, handled := newPathCheckFixture(t, false)
	var gotLocation, gotSHA string
	c.quarantiner = &quarantineMock.QuarantineMock{
		IsRestoredMock: func(_ context.Context, location, sha256 string) (bool, error) {
			gotLocation, gotSHA = location, sha256
			return true, nil
		},
	}
	info, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	if _, skip := c.prepareFile(file, IdentityOf(info), nil); !skip {
		t.Fatal("a restored content is handled by the restored path, not analyzed")
	}
	if gotLocation != file || gotSHA != shaOf("some content") {
		t.Errorf("IsRestored(%q, %q), want the location and the SHA256 of the content", gotLocation, gotSHA)
	}
	if len(*handled) != 1 {
		t.Errorf("handled = %v, want the restored file handled once", *handled)
	}
}

// A plugin may answer onFileScanned with a result of its own: the file is still
// a restored one, and its report must say so.
func TestHandleRestoredFile_aPluginResultKeepsTheRestoredMark(t *testing.T) {
	c, _, file, _ := newPathCheckFixture(t, false)
	c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
		return &datamodel.Result{Filename: r.Filename, Location: r.Location, SHA256: r.SHA256, Score: -500}
	})
	var got datamodel.Result
	c.action = &MockAction{HandleMock: func(_ context.Context, _ Source, r datamodel.Result, _ *datamodel.Report) error {
		got = r
		return nil
	}}
	if err := c.handleRestoredFile(file, shaOf("some content"), 12, idOf(t, file), nil, nil); err != nil {
		t.Fatal(err)
	}
	if !got.Restored {
		t.Errorf("result given to the actions = %+v, want Restored", got)
	}
}

// With quarantine, deletion and move all active, a quarantine refused because the
// content was restored leaves nothing in the destination on that pass: no
// detection report next to a file that the next pass will deliver as restored.
func TestPipeline_aQuarantineRefusedAsRestoredWritesNoReportAndMovesNothing(t *testing.T) {
	noOpenInputs(t)
	in, dest := t.TempDir(), t.TempDir()
	file := filepath.Join(in, "f.bin")
	if err := os.WriteFile(file, []byte("some content"), 0o600); err != nil {
		t.Fatal(err)
	}
	var restored atomic.Bool
	quarantiner := &quarantineMock.QuarantineMock{
		IsRestoredMock: func(context.Context, string, string) (bool, error) { return restored.Load(), nil },
		QuarantineMock: func(context.Context, string, *os.File, string, []string) (string, string, error) {
			return "", "", quarantine.ErrRestored
		},
	}
	submitter := readerTrio(&gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForReaderMock: func(_ context.Context, r io.Reader, _ gdetect.WaitForOptions) (gdetect.Result, error) {
			restored.Store(true)
			h := sha256.New()
			_, err := io.Copy(h, r)
			return gdetect.Result{SHA256: hex.EncodeToString(h.Sum(nil)), Malware: true, Malwares: []string{"m"}}, err
		},
	})
	c, err := NewConnector(Config{
		Roots: []string{in}, WorkDir: t.TempDir(), Workers: 1, MoveTo: dest, MoveFrom: in,
		Actions: Actions{Quarantine: true, Deleted: true, Move: true},
	}, quarantiner, submitter)
	if err != nil {
		t.Fatal(err)
	}
	got := &outcomes{}
	c.config.OnFileDone = got.add
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	if err = c.ScanFile(t.Context(), file); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the first pass to end", func() bool { return len(got.get()) == 1 })
	if entries := filesUnder(t, dest); len(entries) != 0 {
		t.Fatalf("after the refused pass the destination holds %v, want nothing", entries)
	}
	if _, err = os.Stat(file); err != nil {
		t.Fatalf("the file must stay in place: %v", err)
	}
	if err = c.ScanFile(t.Context(), file); err != nil {
		t.Fatal(err)
	}
	c.Close(t.Context())
	entries := filesUnder(t, dest)
	if len(entries) != 1 || filepath.Base(entries[0]) != "f.bin" {
		t.Errorf("the destination holds %v, want only the restored file", entries)
	}
}

func filesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	if err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			out = append(out, p)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}
