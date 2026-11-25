//go:build linux

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

type pipelineCapture struct {
	src    scanner.Source
	result datamodel.Result
	report datamodel.Report
}

type pipelineRun struct {
	in, out, qdir string
	captures      []pipelineCapture
	submitted     []string
	scanErr       error
}

// maybe is for the cases where the contract allows the pipeline to stop before
// the actions (a definitive error: the archive stays in INPUT).
func (r *pipelineRun) maybe(name string) (pipelineCapture, bool) {
	for _, c := range r.captures {
		if filepath.Base(c.src.Path) == name {
			return c, true
		}
	}
	return pipelineCapture{}, false
}

func (r *pipelineRun) one(t *testing.T, name string) pipelineCapture {
	t.Helper()
	var got []pipelineCapture
	for _, c := range r.captures {
		if filepath.Base(c.src.Path) == name {
			got = append(got, c)
		}
	}
	if len(got) != 1 {
		t.Fatalf("the actions ran %d time(s) for %s, want once", len(got), name)
	}
	return got[0]
}

func (r *pipelineRun) exists(dir, name string) bool {
	_, err := os.Lstat(filepath.Join(dir, name))
	return err == nil
}

func (r *pipelineRun) submissionsOf(name string) int {
	n := 0
	for _, s := range r.submitted {
		if s == name {
			n++
		}
	}
	return n
}

type pipelineSetup struct {
	policy   scanner.Unanalyzable
	name     string
	content  []byte
	maxFiles int
}

// runPipeline runs the real pipeline with the real extraction plugin and the real
// 7-Zip on one deposited archive.
func runPipeline(t *testing.T, s pipelineSetup) *pipelineRun {
	t.Helper()
	plugin := realPlugin(t)
	plugin.sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
	root := t.TempDir()
	r := &pipelineRun{in: filepath.Join(root, "in"), out: filepath.Join(root, "out"), qdir: t.TempDir()}
	for _, d := range []string{r.in, r.out} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	q, err := quarantine.NewQuarantineHandler(t.Context(), quarantine.Config{Location: r.qdir, LockPassword: "infected"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := q.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	prev := scanner.ExtractFile
	t.Cleanup(func() { scanner.ExtractFile = prev })
	scanner.ExtractFile = plugin.ExtractFile

	var mu sync.Mutex
	record := func(name, sum string) gdetect.Result {
		mu.Lock()
		r.submitted = append(r.submitted, filepath.Base(name))
		mu.Unlock()
		return gdetect.Result{SHA256: sum, Done: true}
	}
	type pending struct {
		rd   io.Reader
		opts gdetect.SubmitOptions
	}
	subs := map[string]pending{}
	submitter := &gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForFileMock: func(_ context.Context, path string, _ gdetect.WaitForOptions) (gdetect.Result, error) {
			b, e := os.ReadFile(filepath.Clean(path))
			if e != nil {
				return gdetect.Result{}, e
			}
			sum := sha256.Sum256(b)
			return record(path, hex.EncodeToString(sum[:])), nil
		},
		GetResultBySHA256Mock: func(context.Context, string) (gdetect.Result, error) {
			return gdetect.Result{}, gdetect.HTTPError{Code: http.StatusNotFound}
		},
		SubmitReaderMock: func(_ context.Context, rd io.Reader, opts gdetect.SubmitOptions) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			id := fmt.Sprintf("uuid-%d", len(subs))
			subs[id] = pending{rd, opts}
			return id, nil
		},
		GetResultByUUIDWithWaitMock: func(_ context.Context, id string, _ int) (gdetect.Result, error) {
			mu.Lock()
			sub := subs[id]
			mu.Unlock()
			h := sha256.New()
			if _, e := io.Copy(h, sub.rd); e != nil {
				return gdetect.Result{}, e
			}
			return record(sub.opts.Filename, hex.EncodeToString(h.Sum(nil))), nil
		},
	}
	maxFiles := s.maxFiles
	if maxFiles == 0 {
		maxFiles = 100
	}
	capture := &scanner.MockAction{HandleMock: func(_ context.Context, src scanner.Source, res datamodel.Result, rep *datamodel.Report) error {
		mu.Lock()
		defer mu.Unlock()
		r.captures = append(r.captures, pipelineCapture{src, res, *rep})
		return nil
	}}
	c, err := scanner.NewConnector(scanner.Config{
		Roots: []string{r.in}, WorkDir: t.TempDir(), Workers: 2, ExtractWorkers: 1,
		Extract: true, ExtractMinThreshold: 1, MaxFileSize: 1 << 20,
		RecursiveExtractMaxDepth: 3, RecursiveExtractMaxSize: 1 << 30, RecursiveExtractMaxFiles: maxFiles,
		Unanalyzable: s.policy,
		Actions:      scanner.Actions{Move: true, Quarantine: true},
		MoveFrom:     r.in, MoveTo: r.out, MoveMode: scanner.MoveModeCopy,
		CustomActions: []scanner.Action{capture},
	}, q, submitter)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(r.in, s.name)
	if err = os.WriteFile(p, s.content, 0o600); err != nil {
		t.Fatal(err)
	}
	r.scanErr = c.ScanFile(t.Context(), p)
	c.Close(t.Context())
	return r
}

func archiveFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(fixture(t, filepath.Join("archives", name)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func zipOf(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for n, c := range members {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(c); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
