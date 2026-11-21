package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/quarantine"
	quarantineMock "github.com/glimps-re/host-connector/pkg/quarantine/mock"
)

// assertFailureText checks that the report says exactly the fixed text of the
// failed action: nothing else (no path, no system error) can be in it.
func assertFailureText(t *testing.T, report *datamodel.Report, want string) {
	t.Helper()
	if report.Error != want {
		t.Errorf("report.Error = %q, want %q", report.Error, want)
	}
}

// failingQuarantiner fails with an error that names a path, which the report must
// not repeat.
func failingQuarantiner() *quarantineMock.QuarantineMock {
	return &quarantineMock.QuarantineMock{QuarantineMock: func(context.Context, string, *os.File, string, []string) (string, string, error) {
		return "", "", errors.New("write /secret/quarantine/dir/x: no space left on device")
	}}
}

// A file whose action ran on a file that changed since the verification is in
// error in its report, for each of the three actions.
func TestActions_aFileChangedSinceTheVerificationIsInErrorInItsReport(t *testing.T) {
	changed := func(t *testing.T) (string, Source) {
		t.Helper()
		path, src := verifiedFile(t, "verified content")
		if err := os.WriteFile(path, []byte("replaced by something else entirely"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path, src
	}
	tests := []struct {
		name string
		want string
		run  func(t *testing.T, src Source, report *datamodel.Report) error
	}{
		{"quarantine", quarantineFailedText, func(t *testing.T, src Source, report *datamodel.Report) error {
			return NewQuarantineAction(failingQuarantiner()).Handle(t.Context(), src, datamodel.Result{Malware: true}, report)
		}},
		{"removal", removeFailedText, func(t *testing.T, src Source, report *datamodel.Report) error {
			return (&RemoveFileAction{}).Handle(t.Context(), src, datamodel.Result{Malware: true}, report)
		}},
		{"move", moveFailedText, func(t *testing.T, src Source, report *datamodel.Report) error {
			root := filepath.Dir(src.Path)
			a, err := NewMoveAction(t.TempDir(), root)
			if err != nil {
				t.Fatal(err)
			}
			return a.Handle(t.Context(), src, datamodel.Result{}, report)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, src := changed(t)
			report := &datamodel.Report{}
			if err := tt.run(t, src, report); !errors.Is(err, ErrSourceChanged) {
				t.Fatalf("Handle() = %v, want ErrSourceChanged", err)
			}
			assertFailureText(t, report, tt.want)
			if report.Deleted || report.MovedTo != "" || report.Action == datamodel.Quarantined {
				t.Errorf("report = %+v: a failed action is reported as done", report)
			}
		})
	}
}

func TestQuarantineAction_aFailureOfTheQuarantineIsInTheReport(t *testing.T) {
	_, src := verifiedFile(t, "malware bytes")
	report := &datamodel.Report{}
	if err := NewQuarantineAction(failingQuarantiner()).Handle(t.Context(), src, datamodel.Result{Malware: true}, report); err == nil {
		t.Fatal("Handle() succeeded")
	}
	assertFailureText(t, report, quarantineFailedText)
	if report.Action == datamodel.Quarantined {
		t.Error("a failed quarantine is reported as done")
	}
}

// A quarantine refused because the content was restored is a retry by design, not
// a failure: the report says nothing is wrong with the file.
func TestQuarantineAction_aRefusalAsRestoredIsNotAFailureOfTheReport(t *testing.T) {
	_, src := verifiedFile(t, "malware bytes")
	refusing := &quarantineMock.QuarantineMock{QuarantineMock: func(context.Context, string, *os.File, string, []string) (string, string, error) {
		return "", "", quarantine.ErrRestored
	}}
	report := &datamodel.Report{}
	if err := NewQuarantineAction(refusing).Handle(t.Context(), src, datamodel.Result{Malware: true}, report); !errors.Is(err, quarantine.ErrRestored) {
		t.Fatalf("Handle() = %v, want ErrRestored", err)
	}
	if report.Error != "" {
		t.Errorf("report.Error = %q, want none for a refusal as restored", report.Error)
	}
}

// With quarantine and deletion active, the refusal as restored leaves the report
// of the pass without an error.
func TestMultiAction_aRefusalAsRestoredLeavesNoErrorInTheReport(t *testing.T) {
	_, src := verifiedFile(t, "malware bytes")
	refusing := &quarantineMock.QuarantineMock{QuarantineMock: func(context.Context, string, *os.File, string, []string) (string, string, error) {
		return "", "", quarantine.ErrRestored
	}}
	report := &datamodel.Report{}
	err := NewMultiAction(&ReportAction{}, NewQuarantineAction(refusing), &RemoveFileAction{}).Handle(t.Context(), src, datamodel.Result{Malware: true}, report)
	if !errors.Is(err, quarantine.ErrRestored) {
		t.Fatalf("Handle() = %v, want the refusal as restored", err)
	}
	if report.Error != "" {
		t.Errorf("report.Error = %q, want none", report.Error)
	}
}

func TestMoveAction_aFailureIsInTheReport(t *testing.T) {
	newMove := func(t *testing.T) (*MoveAction, string) {
		t.Helper()
		root := t.TempDir()
		a, err := NewMoveAction(t.TempDir(), root)
		if err != nil {
			t.Fatal(err)
		}
		return a, root
	}
	t.Run("the destination cannot be made", func(t *testing.T) {
		a, root := newMove(t)
		path := filepath.Join(root, "sub", "f.bin")
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		src := testSource(t, path)
		prev := mkdirAll
		mkdirAll = func(string, os.FileMode) error { return errors.New("mkdir /secret/dest: permission denied") }
		t.Cleanup(func() { mkdirAll = prev })
		report := &datamodel.Report{}
		if err := a.Handle(t.Context(), src, datamodel.Result{}, report); err == nil {
			t.Fatal("Handle() succeeded")
		}
		assertFailureText(t, report, moveFailedText)
	})
	t.Run("a detection whose lock report cannot be written", func(t *testing.T) {
		a, root := newMove(t)
		path := filepath.Join(root, "bad.exe")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		prev := create
		create = func(string) (*os.File, error) { return nil, errors.New("disk full") }
		t.Cleanup(func() { create = prev })
		report := &datamodel.Report{}
		if err := a.Handle(t.Context(), testSource(t, path), datamodel.Result{Malware: true}, report); err == nil {
			t.Fatal("Handle() succeeded")
		}
		assertFailureText(t, report, moveFailedText)
	})
	t.Run("a move that works leaves the report without an error", func(t *testing.T) {
		a, root := newMove(t)
		path := filepath.Join(root, "ok.bin")
		if err := os.WriteFile(path, []byte("fine"), 0o600); err != nil {
			t.Fatal(err)
		}
		report := &datamodel.Report{}
		if err := a.Handle(t.Context(), testSource(t, path), datamodel.Result{}, report); err != nil {
			t.Fatal(err)
		}
		if report.Error != "" || report.MovedTo == "" {
			t.Errorf("report = %+v, want a destination and no error", report)
		}
	})
}

func TestActions_whatWorksLeavesTheReportWithoutAnError(t *testing.T) {
	t.Run("a quarantine", func(t *testing.T) {
		_, src := verifiedFile(t, "malware bytes")
		ok := &quarantineMock.QuarantineMock{QuarantineMock: func(context.Context, string, *os.File, string, []string) (string, string, error) {
			return "/q/lock", "id", nil
		}}
		report := &datamodel.Report{}
		if err := NewQuarantineAction(ok).Handle(t.Context(), src, datamodel.Result{Malware: true}, report); err != nil {
			t.Fatal(err)
		}
		if report.Error != "" {
			t.Errorf("report.Error = %q after a quarantine that worked", report.Error)
		}
	})
	t.Run("a removal", func(t *testing.T) {
		_, src := verifiedFile(t, "x")
		report := &datamodel.Report{}
		if err := (&RemoveFileAction{}).Handle(t.Context(), src, datamodel.Result{Malware: true}, report); err != nil {
			t.Fatal(err)
		}
		if report.Error != "" || !report.Deleted {
			t.Errorf("report = %+v, want deleted and no error", report)
		}
	})
}

// What the report already says about the file stays: an error of the analysis, or
// a refusal with its own reason, is not replaced by the text of the failed action.
func TestActionFailure_keepsTheFirstCauseOfTheReport(t *testing.T) {
	t.Run("an error of the analysis", func(t *testing.T) {
		_, src := verifiedFile(t, "malware bytes")
		report := &datamodel.Report{Error: "analysis timed out"}
		if err := NewQuarantineAction(failingQuarantiner()).Handle(t.Context(), src, datamodel.Result{Malware: true}, report); err == nil {
			t.Fatal("Handle() succeeded")
		}
		if report.Error != "analysis timed out" {
			t.Errorf("report.Error = %q, want the first cause kept", report.Error)
		}
	})
	t.Run("a refusal with its own reason", func(t *testing.T) {
		root := t.TempDir()
		a, err := NewMoveAction(t.TempDir(), root)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "report-session-x.bin")
		if err = os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		report := &datamodel.Report{}
		if err = a.Handle(t.Context(), testSource(t, path), datamodel.Result{}, report); err == nil {
			t.Fatal("Handle() succeeded")
		}
		if report.Error != "file name reserved for session reports" {
			t.Errorf("report.Error = %q, want its own reason kept", report.Error)
		}
	})
	t.Run("a reserved name over an analysis error", func(t *testing.T) {
		root := t.TempDir()
		a, err := NewMoveAction(t.TempDir(), root)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "report-session-y.bin")
		if err = os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		report := &datamodel.Report{Error: "analysis timed out"}
		if err = a.Handle(t.Context(), testSource(t, path), datamodel.Result{Malware: true}, report); err != nil {
			t.Fatal(err)
		}
		if report.Error != "analysis timed out" {
			t.Errorf("report.Error = %q, want the first cause kept", report.Error)
		}
	})
}

// Through the pipeline: a clean file that cannot be moved reaches the plugins with
// an error in its report, so that a report counts it as in error and not as
// analyzed. The destination is under a file, so that it can never be made.
func TestPipeline_aFileThatCannotBeMovedIsInErrorInItsReport(t *testing.T) {
	in, blocker := t.TempDir(), filepath.Join(t.TempDir(), "not-a-folder")
	src := filepath.Join(in, "f.bin")
	if err := os.WriteFile(src, []byte("clean content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blocker, []byte("a file"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewConnector(Config{
		Roots: []string{in}, WorkDir: t.TempDir(), Workers: 1,
		Actions: Actions{Move: true}, MoveTo: filepath.Join(blocker, "dest"), MoveFrom: in, MoveMode: MoveModeCopy,
	}, nil, cleanSubmitter())
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var reports []datamodel.Report
	c.RegisterOnReport(func(r *datamodel.Report) {
		mu.Lock()
		defer mu.Unlock()
		reports = append(reports, *r)
	})
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	if err = c.ScanFile(t.Context(), src); err != nil {
		t.Fatal(err)
	}
	c.Close(t.Context())
	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 1 {
		t.Fatalf("%d reports, want one", len(reports))
	}
	assertFailureText(t, &reports[0], moveFailedText)
	if reports[0].MovedTo != "" {
		t.Errorf("a file that was not moved has a destination: %q", reports[0].MovedTo)
	}
	if _, statErr := os.Stat(src); statErr != nil {
		t.Errorf("the source of a failed move was removed: %v", statErr)
	}
}

// A restored file whose action fails still has its report sent: it is in error as
// any other file, and not dropped.
func TestHandleRestoredFile_aFailedActionStillSendsTheReportInError(t *testing.T) {
	c, _, file, _ := newPathCheckFixture(t, false)
	c.action = &MockAction{HandleMock: func(_ context.Context, _ Source, _ datamodel.Result, report *datamodel.Report) error {
		report.Error = moveFailedText
		return errors.New("move action: boom")
	}}
	var mu sync.Mutex
	var reports []datamodel.Report
	c.RegisterOnReport(func(r *datamodel.Report) {
		mu.Lock()
		defer mu.Unlock()
		reports = append(reports, *r)
	})
	if err := c.handleRestoredFile(file, shaOf("some content"), 12, idOf(t, file), nil, nil); err == nil {
		t.Fatal("handleRestoredFile() succeeded, want the error of the action")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 1 {
		t.Fatalf("%d reports, want the one of the restored file", len(reports))
	}
	assertFailureText(t, &reports[0], moveFailedText)
}

// A file whose analysis failed, without an error of the pipeline, is in error in
// its report, with a fixed text that does not carry the text of the service; an
// archive that names its failed members is not an error of its own.
func TestReportAction_anAnalysisErrorAloneIsInTheReport(t *testing.T) {
	tests := []struct {
		name   string
		result datamodel.Result
		want   string
	}{
		{"an analysis error alone", datamodel.Result{AnalysisError: "service said: https://svc.example/secret-token timed out"}, analysisFailedText},
		{"an error of the pipeline keeps its own text", datamodel.Result{Error: errors.New("the pipeline failed"), AnalysisError: "service"}, "the pipeline failed"},
		{"no failure", datamodel.Result{}, ""},
		{"an archive that names its failed members", datamodel.Result{AnalysisError: "m.bin: service (and 2 more)", ErrorSubfiles: map[string]string{"m.bin": "service"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &datamodel.Report{}
			if err := (&ReportAction{}).Handle(t.Context(), Source{Path: "/in/f.bin"}, tt.result, report); err != nil {
				t.Fatal(err)
			}
			if report.Error != tt.want {
				t.Errorf("report.Error = %q, want %q", report.Error, tt.want)
			}
		})
	}
}

// A link source: neither the move nor the removal touches the file, and the text
// that says so is kept when the report already said something else.
func TestSymbolicLinkTexts_doNotReplaceAnError(t *testing.T) {
	root := t.TempDir()
	link := Source{Path: filepath.Join(root, "link"), Root: root, Identity: FileIdentity{Ino: 1, Size: 1}, SHA256: "sha", viaLink: true}
	run := map[string]func(report *datamodel.Report) error{
		"move": func(report *datamodel.Report) error {
			a, err := NewMoveAction(t.TempDir(), root)
			if err != nil {
				t.Fatal(err)
			}
			return a.Handle(t.Context(), link, datamodel.Result{}, report)
		},
		"removal": func(report *datamodel.Report) error {
			return (&RemoveFileAction{}).Handle(t.Context(), link, datamodel.Result{Malware: true}, report)
		},
	}
	for name, handle := range run {
		t.Run(name+" with no error before", func(t *testing.T) {
			report := &datamodel.Report{}
			if err := handle(report); !errors.Is(err, errSourceLink) {
				t.Fatalf("Handle() = %v, want errSourceLink", err)
			}
			if report.Error == "" || report.Error == moveFailedText || report.Error == removeFailedText {
				t.Errorf("report.Error = %q, want the text that says the link is left in place", report.Error)
			}
		})
		t.Run(name+" with an error before", func(t *testing.T) {
			report := &datamodel.Report{Error: "x"}
			if err := handle(report); !errors.Is(err, errSourceLink) {
				t.Fatalf("Handle() = %v, want errSourceLink", err)
			}
			if report.Error != "x" {
				t.Errorf("report.Error = %q, want the first cause kept", report.Error)
			}
		})
	}
}

// Through the pipeline: a file the service could not analyze reaches the plugins
// with the fixed text, so that a report counts it as in error and not as analyzed.
func TestPipeline_aFileWhoseAnalysisFailedIsInErrorInItsReport(t *testing.T) {
	in := t.TempDir()
	src := filepath.Join(in, "f.bin")
	if err := os.WriteFile(src, []byte("some content"), 0o600); err != nil {
		t.Fatal(err)
	}
	submitter := echoReader(&gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForFileMock: func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) {
			return gdetect.Result{Error: "engine said /secret/path failed"}, nil
		},
	})
	c, err := NewConnector(Config{Roots: []string{in}, WorkDir: t.TempDir(), Workers: 1}, nil, submitter)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var reports []datamodel.Report
	c.RegisterOnReport(func(r *datamodel.Report) {
		mu.Lock()
		defer mu.Unlock()
		reports = append(reports, *r)
	})
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	if err = c.ScanFile(t.Context(), src); err != nil {
		t.Fatal(err)
	}
	c.Close(t.Context())
	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 1 {
		t.Fatalf("%d reports, want one", len(reports))
	}
	assertFailureText(t, &reports[0], analysisFailedText)
	if reports[0].Malicious {
		t.Error("a file that could not be analyzed is reported as malicious")
	}
}
