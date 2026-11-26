package scanner

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/glimps-re/host-connector/internal/safepath"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/quarantine"
)

func TestSource_openFollowsTheLinkItWasReachedThrough(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "target.bin")
	if err := os.WriteFile(target, []byte("linked content"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symbolic links not available:", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	src := Source{Path: link, Root: root, Identity: IdentityOf(info), SHA256: "sha", viaLink: true}
	f, release, err := src.Open()
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer release()
	if got := readAll(t, f); got != "linked content" {
		t.Errorf("Open() read %q", got)
	}
}

func TestSource_sentinelsAreShared(t *testing.T) {
	if !errors.Is(ErrSourceChanged, quarantine.ErrSourceChanged) {
		t.Error("scanner.ErrSourceChanged is not quarantine.ErrSourceChanged")
	}
	if !errors.Is(errNoHandle, quarantine.ErrNoVerifiedSource) || !IsPermanentAction(errNoHandle) {
		t.Error("errNoHandle must wrap quarantine.ErrNoVerifiedSource and be permanent")
	}
	if !IsPermanentAction(errSourceLink) {
		t.Error("errSourceLink must be permanent")
	}
}

func TestSource_removeOfAReplacedNameIsSourceChanged(t *testing.T) {
	if !holdsHandle {
		t.Skip("no handle on this system")
	}
	root, path, src := newVerified(t)
	h, err := safepath.Open(root, "dir/f.bin")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := h.Close(); e != nil {
			t.Error(e)
		}
	})
	src = src.withHandle(h)
	if err = os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = src.Remove(); !errors.Is(err, ErrSourceChanged) || !errors.Is(err, quarantine.ErrSourceChanged) {
		t.Errorf("Remove() error = %v, want ErrSourceChanged", err)
	}
	if _, err = os.Stat(path); err != nil {
		t.Errorf("the replacement was removed: %v", err)
	}
}

func TestRemoveFileAction_malwareBehindAFollowedLinkIsReported(t *testing.T) {
	src := Source{Path: "/in/link", Identity: FileIdentity{Ino: 1, Size: 1}, SHA256: "sha", viaLink: true}
	report := &datamodel.Report{}
	err := (&RemoveFileAction{}).Handle(t.Context(), src, datamodel.Result{Malware: true}, report)
	if !errors.Is(err, errSourceLink) || !IsPermanentAction(err) {
		t.Fatalf("Handle() error = %v, want errSourceLink", err)
	}
	if report.Error == "" || report.Deleted {
		t.Errorf("report = %+v, want an Error saying the malware is left in place", report)
	}
}
