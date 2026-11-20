package scanner

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	quarantineMock "github.com/glimps-re/host-connector/pkg/quarantine/mock"
)

func verifiedFile(t *testing.T, content string) (string, Source) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, testSource(t, path)
}

func TestQuarantineAction_readsTheVerifiedFileThroughTheDescriptor(t *testing.T) {
	path, src := verifiedFile(t, "malware bytes")
	var got string
	var gotFile string
	a := NewQuarantineAction(&quarantineMock.QuarantineMock{QuarantineMock: func(_ context.Context, file string, in *os.File, _ string, _ []string) (string, string, error) {
		b, err := io.ReadAll(in)
		got, gotFile = string(b), file
		return "/q/lock", "id", err
	}})
	report := &datamodel.Report{}
	if err := a.Handle(t.Context(), src, datamodel.Result{Malware: true, SHA256: "sha"}, report); err != nil {
		t.Fatal(err)
	}
	if got != "malware bytes" || gotFile != path {
		t.Errorf("Quarantine got %q for %q, want the content read from the descriptor and the deposit path as the name", got, gotFile)
	}
	if report.Action != datamodel.Quarantined {
		t.Errorf("report action = %v", report.Action)
	}
}

func TestQuarantineAction_refusesAFileChangedSinceTheVerification(t *testing.T) {
	path, src := verifiedFile(t, "malware bytes")
	if err := os.WriteFile(path, []byte("replaced by something else entirely"), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	a := NewQuarantineAction(&quarantineMock.QuarantineMock{QuarantineMock: func(context.Context, string, *os.File, string, []string) (string, string, error) {
		called = true
		return "", "", nil
	}})
	err := a.Handle(t.Context(), src, datamodel.Result{Malware: true}, &datamodel.Report{})
	if !errors.Is(err, ErrSourceChanged) || called {
		t.Errorf("Handle() error = %v, Quarantine called = %t, want ErrSourceChanged and no quarantine", err, called)
	}
}

func TestRemoveFileAction_refusesAFileChangedSinceTheVerification(t *testing.T) {
	path, src := verifiedFile(t, "x")
	if err := os.WriteFile(path, []byte("something else"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := (&RemoveFileAction{}).Handle(t.Context(), src, datamodel.Result{Malware: true}, &datamodel.Report{})
	if !errors.Is(err, ErrSourceChanged) {
		t.Errorf("Handle() error = %v, want ErrSourceChanged", err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Errorf("a changed file was deleted: %v", statErr)
	}
}

func TestMoveAction_refusesAFileChangedSinceTheVerification(t *testing.T) {
	root := t.TempDir()
	dest := t.TempDir()
	path := filepath.Join(root, "f.bin")
	if err := os.WriteFile(path, []byte("verified"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := testSource(t, path)
	if err := os.WriteFile(path, []byte("replaced after the verification"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := NewMoveAction(dest, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Handle(t.Context(), src, datamodel.Result{}, &datamodel.Report{}); !errors.Is(err, ErrSourceChanged) {
		t.Errorf("Handle() error = %v, want ErrSourceChanged", err)
	}
	if _, statErr := os.Stat(filepath.Join(dest, "f.bin")); statErr == nil {
		t.Error("a changed file was moved")
	}
}

func TestActionsThatOnlyNameTheFileNeverOpenIt(t *testing.T) {
	// The path does not exist: opening it would fail.
	src := Source{Path: filepath.Join(t.TempDir(), "absent.bin")}
	for name, a := range map[string]Action{
		"report": &ReportAction{},
		"print":  &PrintAction{Out: io.Discard},
		"log":    &LogAction{logger: logger},
	} {
		if err := a.Handle(t.Context(), src, datamodel.Result{Malware: true}, &datamodel.Report{}); err != nil {
			t.Errorf("%s action: Handle() error = %v, want no access to the file", name, err)
		}
	}
}
