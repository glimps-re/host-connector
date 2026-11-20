package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

// The core hands the extractor a link to the verified descriptor of the
// deposited archive: the real extraction plugin, with the real 7-Zip, must
// extract a sound archive from it, its members must be analyzed, and nothing
// may be reported as an extraction error.
func TestCore_realExtractionPluginExtractsADepositedZipThroughTheDescriptorLink(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("descriptor links need /proc")
	}
	plugin := realPlugin(t)
	in := t.TempDir()
	deposit := filepath.Join(in, "alice", "a.zip")
	if err := os.MkdirAll(filepath.Dir(deposit), 0o750); err != nil {
		t.Fatal(err)
	}
	writeSoundZip(t, deposit, map[string]string{"x.txt": "first member", "dir/y.txt": "second member"})

	var mu sync.Mutex
	var analyzed []string
	submitter := &gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForFileMock: func(_ context.Context, path string, _ gdetect.WaitForOptions) (gdetect.Result, error) {
			b, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				return gdetect.Result{}, err
			}
			sum := sha256.Sum256(b)
			mu.Lock()
			analyzed = append(analyzed, filepath.Base(path))
			mu.Unlock()
			return gdetect.Result{SHA256: hex.EncodeToString(sum[:])}, nil
		},
	}
	prev := scanner.ExtractFile
	t.Cleanup(func() { scanner.ExtractFile = prev })
	scanner.ExtractFile = plugin.ExtractFile

	c, err := scanner.NewConnector(scanner.Config{
		Roots:                    []string{in},
		WorkDir:                  t.TempDir(),
		Workers:                  2,
		ExtractWorkers:           1,
		Extract:                  true,
		ExtractMinThreshold:      1,
		MaxFileSize:              1 << 20,
		RecursiveExtractMaxDepth: 3,
		RecursiveExtractMaxSize:  1 << 20,
		RecursiveExtractMaxFiles: 100,
	}, nil, submitter)
	if err != nil {
		t.Fatal(err)
	}
	var scannedMu sync.Mutex
	var archiveResult *datamodel.Result
	c.RegisterOnFileScanned(func(file, _ string, r datamodel.Result) *datamodel.Result {
		scannedMu.Lock()
		defer scannedMu.Unlock()
		if file == deposit {
			archiveResult = &r
		}
		return nil
	})
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	if err = c.ScanFile(t.Context(), deposit); err != nil {
		t.Fatal(err)
	}
	c.Close(t.Context())

	mu.Lock()
	defer mu.Unlock()
	if len(analyzed) != 2 {
		t.Errorf("analyzed %v, want the two members of the archive", analyzed)
	}
	scannedMu.Lock()
	defer scannedMu.Unlock()
	if archiveResult == nil {
		t.Fatal("the archive was never reported to the plugins")
	}
	if archiveResult.Error != nil || len(archiveResult.ErrorSubfiles) != 0 {
		t.Errorf("archive result = %+v, want no error: a sound archive must not end in extract-error", archiveResult)
	}
}

func writeSoundZip(t *testing.T, path string, members map[string]string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, content := range members {
		w, e := zw.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write([]byte(content)); e != nil {
			t.Fatal(e)
		}
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}
