package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

type extractorFixture struct {
	src, dst  string
	conn      *Connector
	submitted atomic.Int32
}

// newExtractorFixture builds a connector that moves clean files from src to
// dst and extracts archives with extract.
func newExtractorFixture(t *testing.T, extract plugins.ExtractFile) *extractorFixture {
	t.Helper()
	root := t.TempDir()
	f := &extractorFixture{src: filepath.Join(root, "in"), dst: filepath.Join(root, "out")}
	for _, d := range []string{f.src, f.dst} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	prevEvents, prevExtract := EventHandler, ExtractFile
	EventHandler = &recordingEventHandler{}
	ExtractFile = extract
	t.Cleanup(func() { EventHandler, ExtractFile = prevEvents, prevExtract })
	c, err := NewConnector(Config{
		Extract:                  true,
		WorkDir:                  t.TempDir(),
		RecursiveExtractMaxDepth: 3,
		ExtractMinThreshold:      1,
		Actions:                  Actions{Move: true},
		MoveFrom:                 f.src,
		MoveTo:                   f.dst,
		Roots:                    []string{f.src},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	submitter := archiveCleanSubmitter()
	submitter.WaitForFileMock = func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) {
		f.submitted.Add(1)
		return gdetect.Result{}, nil
	}
	c.submitter = submitter
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	f.conn = c
	return f
}

func (f *extractorFixture) deposit(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(f.src, name)
	if err := os.WriteFile(p, realZip(t), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// realZip returns the bytes of a small genuine zip: only a real archive is
// handed to the extractor.
func realZip(t *testing.T) []byte {
	t.Helper()
	location, _ := createArchive(t, []string{"content of the archive"})
	b, err := os.ReadFile(filepath.Clean(location))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *extractorFixture) assertLeftInPlace(t *testing.T, deposited string) {
	t.Helper()
	if _, err := os.Stat(deposited); err != nil {
		t.Errorf("the archive must stay in INPUT: %v", err)
	}
	entries, err := os.ReadDir(f.dst)
	if err != nil || len(entries) != 0 {
		t.Errorf("OUTPUT holds %v (err %v), want it empty: nothing may be moved", entries, err)
	}
}

func TestExtractorUnavailable_EMFILEIsNeitherSubmittedNorMoved(t *testing.T) {
	f := newExtractorFixture(t, func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
		return plugins.Extraction{}, fmt.Errorf("fork/exec 7zzs: %w: %w", plugins.ErrExtractorUnavailable, syscall.EMFILE)
	})
	archive := f.deposit(t, "a.zip")
	if err := f.conn.ScanFile(t.Context(), archive); err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}
	f.conn.Close(t.Context())
	if got := f.submitted.Load(); got != 0 {
		t.Errorf("%d submission(s): an archive that could not be extracted must not be submitted as a plain file", got)
	}
	f.assertLeftInPlace(t, archive)
}

func TestExtractorUnavailable_NestedArchiveKeepsTheTopLevelArchiveInPlace(t *testing.T) {
	var calls atomic.Int32
	inner := realZip(t)
	f := newExtractorFixture(t, func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		if calls.Add(1) > 1 {
			return plugins.Extraction{}, fmt.Errorf("7zzs: %w", plugins.ErrExtractorUnavailable)
		}
		var files []string
		for name, content := range map[string][]byte{"inner.zip": inner, "plain.txt": []byte("plain member")} {
			p := filepath.Join(outputDir, name)
			if err := os.WriteFile(p, content, 0o600); err != nil {
				return plugins.Extraction{}, err
			}
			files = append(files, p)
		}
		return plugins.Extraction{Size: uint64(len(inner)) + 12, Files: files}, nil
	})
	archive := f.deposit(t, "outer.zip")
	if err := f.conn.ScanFile(t.Context(), archive); err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}
	f.conn.Close(t.Context())
	if calls.Load() < 2 {
		t.Fatalf("the extractor was called %d time(s), the nested archive was never attempted", calls.Load())
	}
	f.assertLeftInPlace(t, archive)
}

func TestExtractorUnavailable_ClassifiedBeforeAnyOtherError(t *testing.T) {
	for name, cause := range map[string]error{
		"EMFILE":  syscall.EMFILE,
		"ENOMEM":  syscall.ENOMEM,
		"EAGAIN":  syscall.EAGAIN,
		"ENOENT":  syscall.ENOENT,
		"EACCES":  syscall.EACCES,
		"ETXTBSY": syscall.ETXTBSY,
	} {
		t.Run(name, func(t *testing.T) {
			ExtractFilePrev := ExtractFile
			t.Cleanup(func() { ExtractFile = ExtractFilePrev })
			ExtractFile = func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
				return plugins.Extraction{}, fmt.Errorf("start: %w: %w", plugins.ErrExtractorUnavailable, cause)
			}
			c, err := NewConnector(Config{Extract: true, WorkDir: t.TempDir(), RecursiveExtractMaxDepth: 2, ExtractMinThreshold: 1}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close(t.Context()) })
			location := filepath.Join(t.TempDir(), "a.zip")
			if err := os.WriteFile(location, realZip(t), 0o600); err != nil {
				t.Fatal(err)
			}
			var size int64
			var files int
			err = c.recursiveExtract(fileToAnalyze{sha256: "sha", location: location, filename: "a.zip", size: int64(len(realZip(t)))}, 0, &size, &files, logger)
			if !errors.Is(err, plugins.ErrExtractorUnavailable) {
				t.Errorf("recursiveExtract() error = %v, want ErrExtractorUnavailable whatever the cause (%s)", err, name)
			}
		})
	}
}
