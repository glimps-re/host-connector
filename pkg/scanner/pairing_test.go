//go:build linux

package scanner

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// TestPipeline_everyOnStartScanFileIsFollowedByExactlyOneOnFileScanned runs one
// deposited file through each way out of the pipeline and checks the pairing
// the session plugin relies on to close its sessions.
func TestPipeline_everyOnStartScanFileIsFollowedByExactlyOneOnFileScanned(t *testing.T) {
	failing := func() *gdetectMock.MockGDetectSubmitter {
		fail := errors.New("service unreachable")
		return &gdetectMock.MockGDetectSubmitter{
			ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
			WaitForFileMock: func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) {
				return gdetect.Result{}, fail
			},
			WaitForReaderMock: func(context.Context, io.Reader, gdetect.WaitForOptions) (gdetect.Result, error) {
				return gdetect.Result{}, fail
			},
		}
	}
	archiveRun := func(extract plugins.ExtractFile) func(t *testing.T, f *swapFixture) {
		return func(t *testing.T, f *swapFixture) {
			t.Helper()
			prev := ExtractFile
			t.Cleanup(func() { ExtractFile = prev })
			ExtractFile = extract
			f.c.typesToExtract = map[string]struct{}{"text/plain; charset=utf-8": {}}
			f.c.config.Extract, f.c.config.ExtractMinThreshold, f.c.config.ExtractWorkers = true, 1, 1
			f.c.config.RecursiveExtractMaxFiles, f.c.config.RecursiveExtractMaxSize, f.c.config.MaxFileSize, f.c.config.RecursiveExtractMaxDepth = 10, 1<<20, 1<<20, 3
		}
	}
	tests := []struct {
		name       string
		submitter  func(f **swapFixture) *gdetectMock.MockGDetectSubmitter
		setup      func(t *testing.T, f *swapFixture)
		wantErrors bool
	}{
		{name: "clean file", submitter: func(f **swapFixture) *gdetectMock.MockGDetectSubmitter { return serviceSubmitter(f, nil) }},
		{name: "malware", submitter: func(f **swapFixture) *gdetectMock.MockGDetectSubmitter { return serviceSubmitter(f, nil) }},
		{name: "waived by a plugin", submitter: func(f **swapFixture) *gdetectMock.MockGDetectSubmitter { return serviceSubmitter(f, nil) }, setup: func(_ *testing.T, f *swapFixture) {
			f.c.RegisterOnScanFile(func(name, location, sha string, _ bool) *datamodel.Result {
				return &datamodel.Result{Filename: name, Location: location, SHA256: sha, Score: -500}
			})
		}},
		{name: "submission failure", submitter: func(**swapFixture) *gdetectMock.MockGDetectSubmitter { return failing() }, wantErrors: true},
		{name: "action failure", submitter: func(f **swapFixture) *gdetectMock.MockGDetectSubmitter { return serviceSubmitter(f, nil) }, setup: func(_ *testing.T, f *swapFixture) {
			f.c.action = &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error {
				return errors.New("move failed")
			}}
		}},
		{name: "file rewritten during the analysis", submitter: func(f **swapFixture) *gdetectMock.MockGDetectSubmitter {
			return serviceSubmitter(f, func() {
				if err := os.WriteFile((*f).file, []byte("rewritten while it was analyzed"), 0o600); err != nil {
					t.Error(err)
				}
			})
		}, wantErrors: true},
		{
			name: "archive, extractor unavailable", submitter: func(f **swapFixture) *gdetectMock.MockGDetectSubmitter { return serviceSubmitter(f, nil) },
			setup: archiveRun(func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
				return plugins.Extraction{}, errors.Join(plugins.ErrExtractorUnavailable, errors.New("7zzs missing"))
			}), wantErrors: true,
		},
		{
			name: "archive, extraction error", submitter: func(f **swapFixture) *gdetectMock.MockGDetectSubmitter { return serviceSubmitter(f, nil) },
			setup: archiveRun(func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
				return plugins.Extraction{}, errors.New("corrupted archive")
			}), wantErrors: true,
		},
		{
			name: "archive, plain file after all", submitter: func(f **swapFixture) *gdetectMock.MockGDetectSubmitter { return serviceSubmitter(f, nil) },
			setup: archiveRun(func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
				return plugins.Extraction{}, plugins.ErrUnsupportedFormat
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f *swapFixture
			f = newSwapFixture(t, tt.submitter(&f))
			if tt.setup != nil {
				tt.setup(t, f)
			}
			var starts, scanned, scannedWithError atomic.Int32
			var mu sync.Mutex
			f.c.RegisterOnStartScanFile(func(string, string) { starts.Add(1) })
			f.c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
				scanned.Add(1)
				if r.Error != nil || r.AnalysisError != "" {
					mu.Lock()
					scannedWithError.Add(1)
					mu.Unlock()
				}
				return nil
			})
			f.run(t)
			if starts.Load() == 0 {
				t.Skipf("onStartScanFile was never called: the file left the pipeline before it started")
			}
			if starts.Load() != scanned.Load() {
				t.Errorf("onStartScanFile called %d time(s), onFileScanned %d: every start needs exactly one end or the session stays open", starts.Load(), scanned.Load())
			}
			if tt.wantErrors && scannedWithError.Load() == 0 {
				t.Errorf("the abandoned file was reported to onFileScanned without any error")
			}
		})
	}
}
