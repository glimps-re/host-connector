package scanner

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

// A deposited path that is a link (follow_symlinks): the content is elsewhere,
// so what would be removed or moved is the link and not what was analyzed.
func linkedSource(t *testing.T, target string) (link string, src Source) {
	t.Helper()
	dir := t.TempDir()
	link = filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	f, err := openRegular(link, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := f.Close(); e != nil {
			t.Error(e)
		}
	})
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	src = Source{Path: link, Root: dir, Identity: IdentityOf(info), viaLink: true}
	if holdsHandle {
		src.fd = f
	}
	return link, src
}

func TestFollowedLink_removeIsRefusedAndNothingIsDeleted(t *testing.T) {
	target := filepath.Join(t.TempDir(), "malware.bin")
	if err := os.WriteFile(target, []byte("malware"), 0o600); err != nil {
		t.Fatal(err)
	}
	link, src := linkedSource(t, target)
	report := &datamodel.Report{}
	err := (&RemoveFileAction{}).Handle(t.Context(), src, datamodel.Result{Malware: true, SHA256: "sha"}, report)
	if !errors.Is(err, errSourceLink) || !IsPermanentAction(err) {
		t.Errorf("Handle() error = %v, want the permanent error saying the source is a link", err)
	}
	if report.Deleted || report.Action == datamodel.Removed {
		t.Errorf("report = %+v: a link must not be reported as the malware deleted", report)
	}
	for _, p := range []string{link, target} {
		if _, statErr := os.Lstat(p); statErr != nil {
			t.Errorf("%s was removed: %v", p, statErr)
		}
	}
}

func TestFollowedLink_cleanFileBehindALinkIsNotMoved(t *testing.T) {
	target := filepath.Join(t.TempDir(), "clean.txt")
	if err := os.WriteFile(target, []byte("clean"), 0o600); err != nil {
		t.Fatal(err)
	}
	link, src := linkedSource(t, target)
	dest := t.TempDir()
	a, err := NewMoveAction(dest, filepath.Dir(link))
	if err != nil {
		t.Fatal(err)
	}
	report := &datamodel.Report{}
	err = a.Handle(t.Context(), src, datamodel.Result{SHA256: "sha"}, report)
	if !errors.Is(err, errSourceLink) || !IsPermanentAction(err) {
		t.Errorf("Handle() error = %v, want the permanent error saying the source is a link", err)
	}
	if report.MovedTo != "" {
		t.Errorf("MovedTo = %q, want nothing moved", report.MovedTo)
	}
	if entries, _ := os.ReadDir(dest); len(entries) != 0 {
		t.Errorf("destination holds %v", entries)
	}
	for _, p := range []string{link, target} {
		if _, statErr := os.Lstat(p); statErr != nil {
			t.Errorf("%s was removed: %v", p, statErr)
		}
	}
}

func TestFollowedLink_quarantineReadsTheContentThroughTheDescriptor(t *testing.T) {
	if !holdsHandle {
		t.Skip("the descriptor is only kept open during the actions on Linux")
	}
	target := filepath.Join(t.TempDir(), "malware.bin")
	if err := os.WriteFile(target, []byte("malware"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, src := linkedSource(t, target)
	f, release, err := src.Open()
	if err != nil {
		t.Fatalf("Open() error = %v, want the content behind the link readable", err)
	}
	defer release()
	buf := make([]byte, 16)
	n, _ := f.Read(buf)
	if string(buf[:n]) != "malware" {
		t.Errorf("read %q", buf[:n])
	}
}

func TestSource_openWithoutHandleNeverBlocksOnAPipe(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "f.bin")
	if err := mkfifoFile(fifo); err != nil {
		t.Skipf("no named pipes: %v", err)
	}
	for name, src := range map[string]Source{
		"with a root":    {Path: fifo, Root: root},
		"without a root": {Path: fifo},
	} {
		done := make(chan error, 1)
		go func() {
			f, _, err := src.Open()
			if err == nil {
				_ = f.Close()
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s: Open() of a pipe succeeded", name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: Open() blocked on a named pipe", name)
		}
	}
}

func TestPipeline_aPipeInPlaceOfTheFileIsRefusedWithoutBlockingAWorker(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "f.bin")
	if err := mkfifoFile(fifo); err != nil {
		t.Skipf("no named pipes: %v", err)
	}
	c := &Connector{config: Config{Roots: []string{root}}}
	done := make(chan error, 1)
	go func() {
		in, err := c.openInput(fifo)
		if err == nil {
			closeInput(in)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errNotRegular) {
			t.Errorf("openInput() error = %v, want errNotRegular", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("openInput() blocked on a named pipe")
	}
}
