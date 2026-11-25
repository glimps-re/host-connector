//go:build linux

package scanner

import (
	"archive/zip"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
)

// An archive larger than max_file_size that is extracted and whose members are
// analysed has been verified: in copy mode it reaches OUTPUT as a private copy
// of the analysed bytes, not by path (which would publish the source inode, that
// a depositor still holding the file open can rewrite).
func TestPipeline_aLargeArchiveExtractedAndAnalysedIsCopiedNotPassedByPath(t *testing.T) {
	const maxFileSize = 100
	root := t.TempDir()
	in, out := filepath.Join(root, "in"), filepath.Join(root, "out")
	for _, d := range []string{in, out} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	archive := filepath.Join(in, "big.zip")
	zf, err := os.Create(filepath.Clean(archive))
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	w, err := zw.Create("padding.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte(strings.Repeat("P", 4*maxFileSize))); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = zf.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(archive)
	if err != nil || info.Size() <= maxFileSize {
		t.Fatalf("the archive must be larger than max_file_size: %v, %v", info, err)
	}
	wantSHA, err := getFileSHA256(archive)
	if err != nil {
		t.Fatal(err)
	}
	srcInode := inoOf(t, archive)

	prev := ExtractFile
	t.Cleanup(func() { ExtractFile = prev })
	var extracted atomic.Bool
	ExtractFile = fakeExtractor(func(outputDir string) (uint64, []string, error) {
		extracted.Store(true)
		p := filepath.Join(outputDir, "member.bin")
		if e := os.WriteFile(p, []byte("a small clean member"), 0o600); e != nil {
			return 0, nil, e
		}
		return 20, []string{p}, nil
	})
	submitter := echoReader(archiveCleanSubmitter())
	submitter.GetResultBySHA256Mock = func(_ context.Context, _ string) (gdetect.Result, error) {
		return gdetect.Result{}, gdetect.HTTPError{Code: 404}
	}
	c, err := NewConnector(Config{
		Extract: true, ExtractMinThreshold: 1, Workers: 2, ExtractWorkers: 1, WorkDir: t.TempDir(),
		MaxFileSize: maxFileSize,
		Actions:     Actions{Move: true},
		MoveFrom:    in, MoveTo: out, MoveMode: MoveModeCopy,
	}, nil, submitter)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	if err = c.ScanFile(t.Context(), archive); err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}
	c.Close(t.Context())

	if !extracted.Load() {
		t.Fatal("the archive was not extracted: the test would not exercise the case")
	}
	dest := filepath.Join(out, "big.zip")
	gotSHA, err := getFileSHA256(dest)
	if err != nil {
		t.Fatalf("the archive did not reach OUTPUT: %v", err)
	}
	if gotSHA != wantSHA {
		t.Errorf("SHA256 of OUTPUT = %s, want %s", gotSHA, wantSHA)
	}
	if inoOf(t, dest) == srcInode {
		t.Error("the source inode of an analysed archive is published: it must be a verified copy")
	}
	if _, err = os.Lstat(archive); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the source must be removed: %v", err)
	}
}
