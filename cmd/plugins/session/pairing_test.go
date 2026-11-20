package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

func zipBytes(t *testing.T, name, content string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// A top-level archive started for the session, then abandoned because the
// extractor went down, must be reported done to the real session plugin: the
// session sees the file finished and can close after its delay, instead of
// staying open for ever.
func TestSession_archiveAbandonedBecauseTheExtractorIsDownDoesNotKeepTheSessionOpen(t *testing.T) {
	root := t.TempDir()
	batch := filepath.Join(root, "user_a", "batch1")
	if err := os.MkdirAll(batch, 0o750); err != nil {
		t.Fatal(err)
	}
	deposit := filepath.Join(batch, "a.zip")
	if err := os.WriteFile(deposit, zipBytes(t, "inner.zip", "content"), 0o600); err != nil {
		t.Fatal(err)
	}

	plugin := &SessionPlugin{}
	hcc := mock.NewMockHCContext()
	plugin.config = Config{ReportTimeout: time.Minute, InflightTimeout: 24 * time.Hour, RootFolder: root, Depth: 2, Delay: 50 * time.Millisecond}
	plugin.sessions = make(map[string]*Session)
	plugin.hcc = hcc
	plugin.stop = make(chan struct{})
	plugin.logger = slog.New(slog.DiscardHandler)
	plugin.consoleLogger = slog.New(slog.DiscardHandler)

	nested := zipBytes(t, "deep.txt", "deep")
	var calls int
	prev := scanner.ExtractFile
	t.Cleanup(func() { scanner.ExtractFile = prev })
	scanner.ExtractFile = func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		calls++
		if calls > 1 {
			return plugins.Extraction{}, plugins.ErrExtractorUnavailable
		}
		member := filepath.Join(outputDir, "inner.zip")
		if err := os.WriteFile(member, nested, 0o600); err != nil {
			return plugins.Extraction{}, err
		}
		return plugins.Extraction{Size: uint64(len(nested)), Files: []string{member}}, nil
	}
	submitter := &gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForFileMock: func(_ context.Context, path string, _ gdetect.WaitForOptions) (gdetect.Result, error) {
			f, err := os.Open(filepath.Clean(path))
			if err != nil {
				return gdetect.Result{}, err
			}
			defer func() { _ = f.Close() }()
			h := sha256.New()
			if _, err = io.Copy(h, f); err != nil {
				return gdetect.Result{}, err
			}
			return gdetect.Result{SHA256: hex.EncodeToString(h.Sum(nil))}, nil
		},
	}
	c, err := scanner.NewConnector(scanner.Config{
		Roots:                    []string{root},
		WorkDir:                  t.TempDir(),
		Workers:                  2,
		ExtractWorkers:           1,
		Extract:                  true,
		ExtractMinThreshold:      1,
		MaxFileSize:              1 << 20,
		RecursiveExtractMaxDepth: 5,
		RecursiveExtractMaxSize:  1 << 20,
		RecursiveExtractMaxFiles: 100,
	}, nil, submitter)
	if err != nil {
		t.Fatal(err)
	}
	c.RegisterOnStartScanFile(plugin.OnStartScanFile)
	c.RegisterOnFileScanned(plugin.OnFileScanned)
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	if err = c.ScanFile(t.Context(), deposit); err != nil {
		t.Fatal(err)
	}
	c.Close(t.Context())

	session, _ := plugin.getSession(deposit, false)
	if session == nil {
		t.Fatal("the plugin never saw the archive start")
	}
	for name := range session.InFlight {
		t.Errorf("%s is still in progress for the session: it would stay open until shutdown", name)
	}
	time.Sleep(2 * plugin.config.Delay)
	if !plugin.readyForClosure(session) {
		t.Error("the session must be ready to close after its delay")
	}
}
