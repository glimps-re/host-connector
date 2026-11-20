package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

// e2e wires a real Connector to a real Monitor the way apply does: the monitor
// hands files over with their identity, the connector reports every outcome.
type e2e struct {
	dir         string
	analyses    atomic.Int32
	submittedAt []time.Time
	mu          sync.Mutex
	fail        atomic.Bool
	conn        *scanner.Connector
	mon         *Monitor
}

func newE2E(t *testing.T, period time.Duration, extractor plugins.ExtractFile) *e2e {
	t.Helper()
	e := &e2e{dir: t.TempDir()}
	if extractor != nil {
		prev := scanner.ExtractFile
		scanner.ExtractFile = extractor
		t.Cleanup(func() { scanner.ExtractFile = prev })
	}
	var uuids atomic.Int32
	var shas sync.Map
	submitter := &gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForFileMock: func(_ context.Context, path string, _ gdetect.WaitForOptions) (gdetect.Result, error) {
			b, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				return gdetect.Result{}, err
			}
			sum := sha256.Sum256(b)
			return gdetect.Result{Done: true, SHA256: hex.EncodeToString(sum[:])}, nil
		},
		GetResultBySHA256Mock: func(context.Context, string) (gdetect.Result, error) {
			return gdetect.Result{}, gdetect.HTTPError{Code: http.StatusNotFound}
		},
		SubmitReaderMock: func(_ context.Context, r io.Reader, _ gdetect.SubmitOptions) (string, error) {
			h := sha256.New()
			if _, err := io.Copy(h, r); err != nil {
				return "", err
			}
			e.analyses.Add(1)
			e.mu.Lock()
			e.submittedAt = append(e.submittedAt, time.Now())
			e.mu.Unlock()
			if e.fail.Load() {
				return "", errors.New("service unreachable")
			}
			id := fmt.Sprintf("uuid-%d", uuids.Add(1))
			shas.Store(id, hex.EncodeToString(h.Sum(nil)))
			return id, nil
		},
		GetResultByUUIDWithWaitMock: func(_ context.Context, id string, _ int) (gdetect.Result, error) {
			sha, _ := shas.Load(id)
			s, _ := sha.(string)
			return gdetect.Result{Done: true, SHA256: s}, nil
		},
	}
	conn, err := scanner.NewConnector(scanner.Config{
		Roots:                    []string{e.dir},
		WorkDir:                  t.TempDir(),
		Workers:                  2,
		ExtractWorkers:           1,
		Extract:                  extractor != nil,
		ExtractMinThreshold:      1,
		RecursiveExtractMaxDepth: 3,
		RecursiveExtractMaxFiles: 100,
		RecursiveExtractMaxSize:  1 << 20,
		MaxFileSize:              1 << 20,
		CustomActions:            []scanner.Action{&scanner.MockAction{HandleMock: func(context.Context, string, datamodel.Result, *datamodel.Report) error { return nil }}},
		OnFileDone: func(o scanner.FileOutcome) {
			if e.mon != nil {
				e.mon.FileDone(o)
			}
		},
	}, nil, submitter)
	if err != nil {
		t.Fatal(err)
	}
	e.conn = conn
	if err = conn.Start(); err != nil {
		t.Fatal(err)
	}
	mon, err := NewMonitor(func(path string, id scanner.FileIdentity) (bool, error) {
		return conn.SubmitFile(context.Background(), path, id)
	}, Config{
		DisableWatcher: true,
		Period:         sdk.Duration(period),
		ModDelay:       sdk.Duration(5 * time.Millisecond),
		Watched:        []string{e.dir},
		PreScan:        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.mon = mon
	t.Cleanup(func() {
		if err := mon.Close(); err != nil {
			t.Errorf("monitor Close() error = %v", err)
		}
		conn.Close(context.Background())
	})
	mon.Start()
	if err = mon.Add(e.dir); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *e2e) write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(e.dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestT11_E2E_anUnchangedFileLeftInInputIsAnalyzedOnceOverManyRescans(t *testing.T) {
	e := newE2E(t, 15*time.Millisecond, nil)
	e.write(t, "left-behind.bin", "stays in INPUT, the action does not move it")
	waitFor(t, "the first analysis", func() bool { return e.analyses.Load() >= 1 })
	time.Sleep(400 * time.Millisecond) // about 25 rescans
	if got := e.analyses.Load(); got != 1 {
		t.Errorf("%d analyses of an unchanged file over about 25 rescans, want 1", got)
	}
}

func TestT11_E2E_aModifiedFileIsAnalyzedAgain(t *testing.T) {
	e := newE2E(t, 15*time.Millisecond, nil)
	p := e.write(t, "changing.bin", "version one")
	waitFor(t, "the first analysis", func() bool { return e.analyses.Load() >= 1 })
	time.Sleep(60 * time.Millisecond)
	if err := os.WriteFile(p, []byte("version two, longer"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the second analysis", func() bool { return e.analyses.Load() >= 2 })
	time.Sleep(200 * time.Millisecond)
	if got := e.analyses.Load(); got != 2 {
		t.Errorf("%d analyses, want exactly 2 (one per version)", got)
	}
}

func TestT11_E2E_aTransientFailureIsRetriedWithGrowingDelaysAndNeverTooOften(t *testing.T) {
	const period = 20 * time.Millisecond
	e := newE2E(t, period, nil)
	e.fail.Store(true)
	e.write(t, "flaky.bin", "the service is down")
	waitFor(t, "two attempts", func() bool { return e.analyses.Load() >= 2 })
	waitFor(t, "three attempts", func() bool { return e.analyses.Load() >= 3 })
	e.mu.Lock()
	at := append([]time.Time(nil), e.submittedAt...)
	e.mu.Unlock()
	for i := 1; i < len(at); i++ {
		gap := at[i].Sub(at[i-1])
		minimum := time.Duration(float64(period) * float64(uint(1)<<min(i-1, 6)) * 0.8 * 0.8)
		if gap < minimum {
			t.Errorf("attempt %d came %v after the previous one, want at least about %v: a retry must wait for its backoff", i+1, gap, minimum)
		}
	}
	if len(at) >= 3 && at[2].Sub(at[1]) <= at[1].Sub(at[0])/2 {
		t.Errorf("delays %v then %v: the backoff must grow", at[1].Sub(at[0]), at[2].Sub(at[1]))
	}
}

func TestT11_E2E_anArchiveWithATooBigMemberIsExtractedOnlyOnce(t *testing.T) {
	var extractions atomic.Int32
	e := newE2E(t, 15*time.Millisecond, func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		extractions.Add(1)
		ok := filepath.Join(outputDir, "ok.txt")
		if err := os.WriteFile(ok, []byte("a normal member"), 0o600); err != nil {
			return plugins.Extraction{}, err
		}
		return plugins.Extraction{
			Size:         15,
			Files:        []string{ok},
			Skipped:      []datamodel.NotAnalyzedFile{{FileName: "huge.bin", Size: 1 << 40, Reason: datamodel.NotAnalyzedTooBig}},
			SkippedCount: 1,
		}, nil
	})
	archive, _ := createZip(t)
	if err := os.WriteFile(filepath.Join(e.dir, "bomb.zip"), archive, 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the extraction", func() bool { return extractions.Load() >= 1 })
	time.Sleep(400 * time.Millisecond)
	if got := extractions.Load(); got != 1 {
		t.Errorf("%d extractions of an archive whose outcome is final, want 1: a 50 GB archive must not be extracted at every rescan", got)
	}
}

func createZip(t *testing.T) ([]byte, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "a.zip")
	z, err := os.Create(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	// A stored zip with one empty member: enough for the type detection.
	if _, err = z.WriteString("PK\x03\x04\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00a" +
		"PK\x01\x02\x14\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00a" +
		"PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00\x33\x00\x00\x00\x25\x00\x00\x00\x00\x00"); err != nil {
		t.Fatal(err)
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return b, path
}
