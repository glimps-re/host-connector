package scanner

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

func TestSubmitFile_staleIdentityIsNeitherAnalyzedNorActedUpon(t *testing.T) {
	c, _, file, handled := newPathCheckFixture(t, false)
	var scanned int
	c.RegisterOnFileScanned(func(_, _ string, _ datamodel.Result) *datamodel.Result {
		scanned++
		return nil
	})
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	stale := idOf(t, file)
	stale.Size++
	accepted, err := c.SubmitFile(t.Context(), file, stale)
	if err != nil || !accepted {
		t.Fatalf("SubmitFile() = %t, %v; want the file queued", accepted, err)
	}
	c.Close(t.Context())
	if len(*handled) != 0 || scanned != 0 {
		t.Errorf("handled %v, scanned %d: a file that changed since it was observed must wait for stability again", *handled, scanned)
	}
	if _, loaded := c.ongoingAnalysis.Load(file); loaded {
		t.Error("the entry must be released")
	}
}

func TestSubmitFile_currentIdentityIsProcessed(t *testing.T) {
	c, _, file, handled := newPathCheckFixture(t, false)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	accepted, err := c.SubmitFile(t.Context(), file, idOf(t, file))
	if err != nil || !accepted {
		t.Fatalf("SubmitFile() = %t, %v; want accepted", accepted, err)
	}
	c.Close(t.Context())
	if len(*handled) != 1 {
		t.Errorf("handled = %v, want the file once", *handled)
	}
}

func TestSubmitFile_refusalsWithoutFailure(t *testing.T) {
	c, in, file, _ := newPathCheckFixture(t, false)
	c.config.Unanalyzable.Empty = PolicySkip // the default delivers empty files: skipping them is a choice
	link := filepath.Join(in, "link.bin")
	if err := os.Symlink(file, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	empty := filepath.Join(in, "empty.bin")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"symbolic link": link, "empty file": empty, "directory": in} {
		accepted, err := c.SubmitFile(t.Context(), path, FileIdentity{})
		if accepted || !errors.Is(err, ErrRefused) {
			t.Errorf("%s: SubmitFile() = %t, %v; want a refusal wrapping ErrRefused", name, accepted, err)
		}
		if _, loaded := c.ongoingAnalysis.Load(path); loaded {
			t.Errorf("%s: the entry must be released", name)
		}
	}
	c.Close(t.Context())
}
