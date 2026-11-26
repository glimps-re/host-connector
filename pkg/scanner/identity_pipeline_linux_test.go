//go:build linux

package scanner

import (
	"os"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

func TestPipeline_fileSubstitutedByRenameDuringAnalysisIsNotActedUpon(t *testing.T) {
	c, _, file, handled := newPathCheckFixture(t, false)
	before, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	c.RegisterOnScanFile(func(_, _, _ string, _ bool) *datamodel.Result {
		other := file + ".new"
		if e := os.WriteFile(other, []byte("some content"), 0o600); e != nil {
			t.Error(e)
			return nil
		}
		if e := os.Chtimes(other, time.Time{}, before.ModTime()); e != nil {
			t.Error(e)
			return nil
		}
		if e := os.Rename(other, file); e != nil {
			t.Error(e)
		}
		return nil
	})
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	if err = c.ScanFile(t.Context(), file); err != nil {
		t.Fatal(err)
	}
	c.Close(t.Context())
	if len(*handled) != 0 {
		t.Errorf("an action ran on %v: the file was replaced by one of the same size, time and content", *handled)
	}
}

func TestPipeline_inPlaceWriteWithRestoredTimeIsNotActedUpon(t *testing.T) {
	c, _, file, handled := newPathCheckFixture(t, false)
	before, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	c.RegisterOnScanFile(func(_, _, _ string, _ bool) *datamodel.Result {
		time.Sleep(20 * time.Millisecond)
		if e := os.WriteFile(file, []byte("other bytes!"), 0o600); e != nil {
			t.Error(e)
		}
		if e := os.Chtimes(file, time.Time{}, before.ModTime()); e != nil {
			t.Error(e)
		}
		return nil
	})
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	if err = c.ScanFile(t.Context(), file); err != nil {
		t.Fatal(err)
	}
	c.Close(t.Context())
	if len(*handled) != 0 {
		t.Errorf("an action ran on %v after an in-place write", *handled)
	}
}
