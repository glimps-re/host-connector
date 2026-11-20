//go:build linux

package main

import (
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
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

// throughputRun scans a folder of small files, with the real extraction plugin,
// and returns how long it took.
func throughputRun(t *testing.T, plugin *SevenZipExtractPlugin, extract bool, files map[string][]byte) time.Duration {
	t.Helper()
	in := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(in, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	prev := scanner.ExtractFile
	t.Cleanup(func() { scanner.ExtractFile = prev })
	scanner.ExtractFile = plugin.ExtractFile
	var mu sync.Mutex
	type pending struct{ rd io.Reader }
	subs := map[string]pending{}
	submitter := &gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForFileMock: func(_ context.Context, path string, _ gdetect.WaitForOptions) (gdetect.Result, error) {
			b, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				return gdetect.Result{}, err
			}
			sum := sha256.Sum256(b)
			return gdetect.Result{SHA256: hex.EncodeToString(sum[:]), Done: true}, nil
		},
		GetResultBySHA256Mock: func(context.Context, string) (gdetect.Result, error) {
			return gdetect.Result{}, gdetect.HTTPError{Code: http.StatusNotFound}
		},
		SubmitReaderMock: func(_ context.Context, rd io.Reader, _ gdetect.SubmitOptions) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			id := fmt.Sprintf("uuid-%d", len(subs))
			subs[id] = pending{rd}
			return id, nil
		},
		GetResultByUUIDWithWaitMock: func(_ context.Context, id string, _ int) (gdetect.Result, error) {
			mu.Lock()
			sub := subs[id]
			mu.Unlock()
			h := sha256.New()
			if _, err := io.Copy(h, sub.rd); err != nil {
				return gdetect.Result{}, err
			}
			return gdetect.Result{SHA256: hex.EncodeToString(h.Sum(nil)), Done: true}, nil
		},
	}
	c, err := scanner.NewConnector(scanner.Config{
		Roots: []string{in}, WorkDir: t.TempDir(), Workers: 4, ExtractWorkers: 2, Extract: extract,
		RecursiveExtractMaxDepth: 3, RecursiveExtractMaxSize: 1 << 30, RecursiveExtractMaxFiles: 100000,
		CustomActions: []scanner.Action{&scanner.MockAction{HandleMock: func(context.Context, scanner.Source, datamodel.Result, *datamodel.Report) error { return nil }}},
	}, nil, submitter)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err = c.ScanFile(t.Context(), in); err != nil {
		t.Fatal(err)
	}
	c.Close(t.Context())
	return time.Since(start)
}

// Looking at the type of the small files, to find the archives among them, costs
// next to nothing for text and binaries; the small archives that are now
// extracted are what costs, by the real 7-Zip. The numbers are logged; the only
// check is that text and binaries are not slowed down by a large factor.
func TestT17a_throughputOfSmallFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("timed run")
	}
	plugin := realPlugin(t)
	plugin.sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
	const n = 300
	variants := map[string]func(i int) []byte{
		"text":   func(i int) []byte { return []byte(fmt.Sprintf("small text file number %d", i)) },
		"binary": func(i int) []byte { return []byte(fmt.Sprintf("\x7f%04d\xff\xfe\x00\x10\x80", i)) },
		"zip":    func(i int) []byte { return t17Zip(t, map[string][]byte{"m.txt": []byte(fmt.Sprintf("member %d", i))}) },
	}
	for name, content := range variants {
		count := n
		if name == "zip" {
			count = 60
		}
		files := make(map[string][]byte, count)
		for i := range count {
			files[fmt.Sprintf("f%04d.dat", i)] = content(i)
		}
		off := throughputRun(t, plugin, false, files)
		on := throughputRun(t, plugin, true, files)
		t.Logf("%-6s %4d files: extraction off %v, on %v (%.1fx)", name, count, off.Round(time.Millisecond), on.Round(time.Millisecond), float64(on)/float64(off))
		if name != "zip" && on > 5*off+500*time.Millisecond {
			t.Errorf("%s: %v with the extraction on against %v off: the type check must be cheap", name, on, off)
		}
	}
}
