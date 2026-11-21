package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/handler"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

// SESSION_DELAY_3s_AND_ONE_WORKER, scaled down: one worker, a delay shorter than
// the analysis of another user's file. Tom drops three files, the second and
// third wait behind Jerry's slow analysis for longer than the delay: they must
// still end in the one session of Tom, and in one report.
func TestSession_ticketOneWorkerAndASlowNeighbourGiveOneSessionAndOneReport(t *testing.T) {
	root, export := t.TempDir(), t.TempDir()
	for _, u := range []string{"tom", "jerry"} {
		if err := os.MkdirAll(filepath.Join(root, u), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	plugin := &SessionPlugin{tickEvery: 25 * time.Millisecond}
	var monLink atomic.Pointer[handler.Monitor]
	var subMu sync.Mutex
	contents := map[string][]byte{}
	submitter := &gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		GetResultBySHA256Mock: func(context.Context, string) (gdetect.Result, error) {
			return gdetect.Result{}, gdetect.HTTPError{Code: http.StatusNotFound}
		},
		SubmitReaderMock: func(_ context.Context, r io.Reader, _ gdetect.SubmitOptions) (string, error) {
			var buf bytes.Buffer
			if _, err := io.Copy(&buf, io.LimitReader(r, 1<<20)); err != nil {
				return "", err
			}
			b := buf.Bytes()
			subMu.Lock()
			defer subMu.Unlock()
			id := fmt.Sprintf("uuid-%d", len(contents))
			contents[id] = b
			return id, nil
		},
		GetResultByUUIDWithWaitMock: func(_ context.Context, id string, _ int) (gdetect.Result, error) {
			subMu.Lock()
			b := contents[id]
			subMu.Unlock()
			if strings.Contains(string(b), "jerry") {
				time.Sleep(1500 * time.Millisecond)
			}
			sum := sha256.Sum256(b)
			return gdetect.Result{SHA256: hex.EncodeToString(sum[:]), Done: true}, nil
		},
	}
	c, err := scanner.NewConnector(scanner.Config{
		Roots:       []string{root},
		WorkDir:     t.TempDir(),
		Workers:     1,
		MaxFileSize: 1 << 20,
		OnFileDone: func(o scanner.FileOutcome) {
			if m := monLink.Load(); m != nil {
				m.FileDone(o)
			}
		},
		PendingFiles: func(path string) int {
			if m := monLink.Load(); m != nil {
				return m.PendingFiles(path)
			}
			return 0
		},
	}, nil, submitter)
	if err != nil {
		t.Fatal(err)
	}
	var console syncBuffer
	hcc := &sessionContext{Connector: c, logger: slog.New(slog.NewTextHandler(&console, nil))}
	if err = plugin.Init(&Config{
		Depth: 1, Delay: 600 * time.Millisecond, RootFolder: root, Exports: []string{export},
		ReportTimeout: time.Minute, ReportRetries: 3, MaxDuration: 24 * time.Hour, MaxSpoolSize: "1GiB", InflightTimeout: time.Hour,
	}, hcc); err != nil {
		t.Fatal(err)
	}
	var tomScanned atomic.Int32
	c.RegisterOnFileScanned(func(file, _ string, _ datamodel.Result) *datamodel.Result {
		if strings.Contains(file, "/tom/") {
			tomScanned.Add(1)
		}
		return nil
	})
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	mon, err := handler.NewMonitor(func(file string, id scanner.FileIdentity) (bool, error) {
		return c.SubmitFile(t.Context(), file, id)
	}, handler.Config{
		ModDelay: sdk.Duration(100 * time.Millisecond),
		Owners:   c.TrackingOwners(),
		Watched:  []string{root},
	})
	if err != nil {
		t.Fatal(err)
	}
	monLink.Store(mon)
	mon.Start()
	if err = mon.Add(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := mon.Close(); e != nil {
			t.Error(e)
		}
		c.Close(t.Context())
		if e := plugin.Close(t.Context()); e != nil {
			t.Error(e)
		}
	})

	drop := func(user, name string) {
		if e := os.WriteFile(filepath.Join(root, user, name), []byte(user+name), 0o600); e != nil {
			t.Fatal(e)
		}
	}
	drop("tom", "1.txt")
	time.Sleep(150 * time.Millisecond)
	drop("jerry", "slow.txt")
	time.Sleep(150 * time.Millisecond)
	drop("tom", "2.txt")
	time.Sleep(150 * time.Millisecond)
	drop("tom", "3.txt")

	// Once the three files of Tom are processed, a second session would have
	// been opened for the files that waited behind the slow analysis of Jerry.
	waitFor(t, 30*time.Second, func() bool { return tomScanned.Load() >= 3 })
	if n := strings.Count(console.String(), `session \"tom\" started`); n != 1 {
		t.Fatalf("%d sessions were started for Tom, want one: the files that waited opened another", n)
	}
	waitFor(t, 30*time.Second, func() bool {
		return reportsIn(t, filepath.Join(export, "tom")) >= 1 && reportsIn(t, filepath.Join(export, "jerry")) >= 1
	})
	tomReports := filesIn(t, filepath.Join(export, "tom"))
	if len(tomReports) != 1 {
		t.Fatalf("Tom has %d reports %v, want exactly one session and one report", len(tomReports), tomReports)
	}
	b, err := os.ReadFile(filepath.Clean(tomReports[0]))
	if err != nil {
		t.Fatal(err)
	}
	var reps []datamodel.Report
	if err = json.Unmarshal(b, &reps); err != nil {
		t.Fatal(err)
	}
	if len(reps) != 3 {
		t.Errorf("the report has %d files, want the 3 of Tom: %s", len(reps), b)
	}
}
