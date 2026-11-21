package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

type outcomes struct {
	mu   sync.Mutex
	list []FileOutcome
}

func (o *outcomes) add(out FileOutcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.list = append(o.list, out)
}

func (o *outcomes) get() []FileOutcome {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]FileOutcome(nil), o.list...)
}

func TestOnFileDone_exactlyOnceWithTheRightVerdict(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(t *testing.T, c *Connector, file string)
		submit       func(t *testing.T, c *Connector, file string) (accepted bool)
		want         OutcomeKind
		wantOutcomes int
	}{
		{
			name:         "clean file, action done",
			want:         OutcomeFinal,
			wantOutcomes: 1,
		},
		{
			name: "waived by a plugin",
			setup: func(t *testing.T, c *Connector, _ string) {
				c.RegisterOnScanFile(func(name, location, sha string, _ bool) *datamodel.Result {
					return &datamodel.Result{Filename: name, Location: location, SHA256: sha, Score: -500}
				})
			},
			want:         OutcomeFinal,
			wantOutcomes: 1,
		},
		{
			name: "analysis error is final",
			setup: func(t *testing.T, c *Connector, _ string) {
				c.submitter = echoReader(&gdetectMock.MockGDetectSubmitter{
					ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
					WaitForFileMock: func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) {
						return gdetect.Result{Error: "engine failure"}, nil
					},
				})
			},
			want:         OutcomeFinal,
			wantOutcomes: 1,
		},
		{
			name: "submission failure is retried",
			setup: func(t *testing.T, c *Connector, _ string) {
				c.submitter = readerTrio(&gdetectMock.MockGDetectSubmitter{
					ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
					WaitForReaderMock: func(context.Context, io.Reader, gdetect.WaitForOptions) (gdetect.Result, error) {
						return gdetect.Result{}, errors.New("network down")
					},
				})
			},
			want:         OutcomeRetry,
			wantOutcomes: 1,
		},
		{
			name: "permanent action failure is final",
			setup: func(t *testing.T, c *Connector, _ string) {
				c.action = &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error {
					return errPermanentAction
				}}
			},
			want:         OutcomeFinal,
			wantOutcomes: 1,
		},
		{
			name: "other action failure is retried",
			setup: func(t *testing.T, c *Connector, _ string) {
				c.action = &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error {
					return errors.New("transient")
				}}
			},
			want:         OutcomeRetry,
			wantOutcomes: 1,
		},
		{
			name: "slow storage is a resource failure",
			setup: func(t *testing.T, c *Connector, _ string) {
				c.action = &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error {
					return context.DeadlineExceeded
				}}
			},
			want:         OutcomeResource,
			wantOutcomes: 1,
		},
		{
			name: "full disk is a resource failure",
			setup: func(t *testing.T, c *Connector, _ string) {
				c.action = &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error {
					return &os.PathError{Op: "write", Path: "x", Err: syscall.ENOSPC}
				}}
			},
			want:         OutcomeResource,
			wantOutcomes: 1,
		},
		{
			name: "a file that changed since it was observed is retried without being analyzed",
			submit: func(t *testing.T, c *Connector, file string) bool {
				stale := idOf(t, file)
				stale.Size++
				accepted, err := c.SubmitFile(t.Context(), file, stale)
				if err != nil {
					t.Fatal(err)
				}
				return accepted
			},
			want:         OutcomeRetry,
			wantOutcomes: 1,
		},
		{
			name: "extractor down is a resource failure",
			setup: func(t *testing.T, c *Connector, _ string) {
				c.config.Extract, c.config.ExtractMinThreshold, c.config.ExtractWorkers = true, 1, 1
				c.config.RecursiveExtractMaxFiles, c.config.RecursiveExtractMaxSize, c.config.MaxFileSize, c.config.RecursiveExtractMaxDepth = 10, 1<<20, 1<<20, 3
				c.typesToExtract = map[string]struct{}{"text/plain; charset=utf-8": {}}
				prev := ExtractFile
				ExtractFile = func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
					return plugins.Extraction{}, plugins.ErrExtractorUnavailable
				}
				t.Cleanup(func() { ExtractFile = prev })
			},
			want:         OutcomeResource,
			wantOutcomes: 1,
		},
		{
			name: "extraction error is retried",
			setup: func(t *testing.T, c *Connector, _ string) {
				c.config.Extract, c.config.ExtractMinThreshold, c.config.ExtractWorkers = true, 1, 1
				c.config.RecursiveExtractMaxFiles, c.config.RecursiveExtractMaxSize, c.config.MaxFileSize, c.config.RecursiveExtractMaxDepth = 10, 1<<20, 1<<20, 3
				c.typesToExtract = map[string]struct{}{"text/plain; charset=utf-8": {}}
				prev := ExtractFile
				ExtractFile = func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
					return plugins.Extraction{}, errors.New("corrupt")
				}
				t.Cleanup(func() { ExtractFile = prev })
			},
			want:         OutcomeRetry,
			wantOutcomes: 1,
		},
		{
			name: "a timeout of the analysis is a plain retry, not a resource failure",
			setup: func(t *testing.T, c *Connector, _ string) {
				c.submitter = readerTrio(&gdetectMock.MockGDetectSubmitter{
					ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
					WaitForReaderMock: func(context.Context, io.Reader, gdetect.WaitForOptions) (gdetect.Result, error) {
						return gdetect.Result{}, context.DeadlineExceeded
					},
				})
			},
			want:         OutcomeRetry,
			wantOutcomes: 1,
		},
		{
			name: "a path refused before the action is final",
			setup: func(t *testing.T, c *Connector, file string) {
				c.RegisterOnScanFile(func(string, string, string, bool) *datamodel.Result {
					dir := filepath.Dir(file)
					if err := os.Rename(dir, dir+".real"); err != nil {
						t.Error(err)
						return nil
					}
					if err := os.Symlink(dir+".real", dir); err != nil {
						t.Error(err)
					}
					return nil
				})
			},
			want:         OutcomeFinal,
			wantOutcomes: 1,
		},
		{
			name: "a link is refused: nobody is told",
			submit: func(t *testing.T, c *Connector, file string) bool {
				link := file + ".lnk"
				if err := os.Symlink(file, link); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				accepted, err := c.SubmitFile(t.Context(), link, FileIdentity{})
				if !errors.Is(err, ErrRefused) {
					t.Fatalf("SubmitFile() error = %v, want ErrRefused", err)
				}
				return accepted
			},
			want:         OutcomeFinal,
			wantOutcomes: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			noOpenInputs(t)
			c, _, file, _ := newPathCheckFixture(t, false)
			got := &outcomes{}
			c.config.OnFileDone = got.add
			var pairMu sync.Mutex
			var starts, scans, abandoned int
			c.RegisterOnStartScanFile(func(string, string) {
				pairMu.Lock()
				starts++
				pairMu.Unlock()
			})
			c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
				pairMu.Lock()
				scans++
				if errors.Is(r.Error, errAbandoned) {
					abandoned++
				}
				pairMu.Unlock()
				return nil
			})
			if tt.setup != nil {
				tt.setup(t, c, file)
			}
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			if tt.submit != nil {
				tt.submit(t, c, file)
			} else if err := c.ScanFile(t.Context(), file); err != nil {
				t.Fatal(err)
			}
			c.Close(t.Context())
			pairMu.Lock()
			if starts != scans || starts > 1 {
				t.Errorf("the plugins saw %d starts and %d scans, want each start followed by exactly one scan", starts, scans)
			}
			pairMu.Unlock()
			list := got.get()
			if len(list) != tt.wantOutcomes {
				t.Fatalf("OnFileDone called %d times, want %d: %+v", len(list), tt.wantOutcomes, list)
			}
			if tt.wantOutcomes == 0 {
				return
			}
			if list[0].Kind != tt.want {
				t.Errorf("outcome = %+v, want kind %d", list[0], tt.want)
			}
			if list[0].Location != file {
				t.Errorf("Location = %q, want %q", list[0].Location, file)
			}
		})
	}
}

// A top-level archive whose extraction is cut short by an extractor that goes
// down after the archive started is abandoned: the plugins that were told it
// started are told it ended, with an Error, exactly once, and the file is
// reported done (a resource failure, retried without cap).
func TestPairing_archiveAbandonedAfterItStartedIsScannedOnce(t *testing.T) {
	noOpenInputs(t)
	c, _, file, _ := newPathCheckFixture(t, false)
	c.config.Extract, c.config.ExtractMinThreshold, c.config.ExtractWorkers = true, 1, 1
	c.config.RecursiveExtractMaxFiles, c.config.RecursiveExtractMaxSize, c.config.MaxFileSize, c.config.RecursiveExtractMaxDepth = 10, 1<<20, 1<<20, 3
	c.typesToExtract = map[string]struct{}{"text/plain; charset=utf-8": {}}
	var calls int
	prev := ExtractFile
	t.Cleanup(func() { ExtractFile = prev })
	ExtractFile = func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		calls++
		if calls > 1 {
			return plugins.Extraction{}, plugins.ErrExtractorUnavailable
		}
		member := filepath.Join(outputDir, "inner.txt")
		if err := os.WriteFile(member, []byte("inner archive content"), 0o600); err != nil {
			return plugins.Extraction{}, err
		}
		return plugins.Extraction{Size: 21, Files: []string{member}}, nil
	}
	var mu sync.Mutex
	var starts, scans int
	var scannedErr error
	c.RegisterOnStartScanFile(func(string, string) {
		mu.Lock()
		starts++
		mu.Unlock()
	})
	c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
		mu.Lock()
		scans++
		scannedErr = r.Error
		mu.Unlock()
		return nil
	})
	got := &outcomes{}
	c.config.OnFileDone = got.add
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.ScanFile(t.Context(), file); err != nil {
		t.Fatal(err)
	}
	c.Close(t.Context())
	mu.Lock()
	defer mu.Unlock()
	if starts != 1 || scans != 1 {
		t.Fatalf("%d starts and %d scans, want one of each", starts, scans)
	}
	if !errors.Is(scannedErr, errAbandoned) {
		t.Errorf("Error = %v, want errAbandoned", scannedErr)
	}
	if list := got.get(); len(list) != 1 || list[0].Kind != OutcomeResource {
		t.Errorf("outcomes = %+v, want one resource outcome: the extractor is down, the file is not at fault, no cap", list)
	}
}

// An archive that vanished from the handler while its members were processed
// must not leave the plugins waiting nor the file in progress.
func TestPairing_archiveNotFoundInTheHandlerIsScannedOnce(t *testing.T) {
	noOpenInputs(t)
	c, _, file, _ := newPathCheckFixture(t, false)
	var mu sync.Mutex
	var scans int
	var scannedErr error
	c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
		mu.Lock()
		scans++
		scannedErr = r.Error
		mu.Unlock()
		return nil
	})
	got := &outcomes{}
	c.config.OnFileDone = got.add
	// the file is in progress and its plugins were told it started
	c.ongoingAnalysis.Store(file, &ongoing{})
	c.scansWg.Add(1)
	c.startScan(file, nil, "sha")
	in := fileToAnalyze{archiveID: "gone", archiveLocation: file, archiveTopLocation: file, location: file + ".member", filename: "member", sha256: "sha"}
	if err := c.analyzeArchiveFile(in); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if scans != 1 || !errors.Is(scannedErr, errAbandoned) {
		t.Errorf("%d scans (Error %v), want one with errAbandoned", scans, scannedErr)
	}
	if list := got.get(); len(list) != 1 {
		t.Errorf("outcomes = %+v, want exactly one", list)
	}
	if _, loaded := c.ongoingAnalysis.Load(file); loaded {
		t.Error("the file must not stay in progress")
	}
}

// A deposit folder the owner made read-only: the link to the destination works,
// the removal of the source is refused, the link is undone. The change time of
// the source moved, but the file did not change: the outcome is final, once.
func TestOutcome_moveFromAReadOnlyDepositFolderIsFinalAndNotReopened(t *testing.T) {
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("permissions cannot be tested as root or on Windows")
	}
	noOpenInputs(t)
	in := t.TempDir()
	dest := t.TempDir()
	dir := filepath.Join(in, "alice")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "f.bin")
	if err := os.WriteFile(file, []byte("some content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, dirReadOnly); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, dirOwnerRWX); err != nil {
			t.Error(err)
		}
	})
	c, err := NewConnector(Config{
		Roots: []string{in}, WorkDir: t.TempDir(), Workers: 1, MoveTo: dest, MoveFrom: in,
		Actions: Actions{Move: true},
	}, nil, cleanSubmitter())
	if err != nil {
		t.Fatal(err)
	}
	got := &outcomes{}
	c.config.OnFileDone = got.add
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	if err = c.ScanFile(t.Context(), file); err != nil {
		t.Fatal(err)
	}
	c.Close(t.Context())
	list := got.get()
	if len(list) != 1 || list[0].Kind != OutcomeFinal {
		t.Fatalf("outcomes = %+v, want exactly one, final: retrying cannot make the owner's folder writable", list)
	}
	info, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	if !IdentityOf(info).Equal(list[0].Identity) {
		t.Errorf("outcome identity %+v differs from the file's %+v: the monitor would take our own trace for a change", list[0].Identity, IdentityOf(info))
	}
	var files []string
	if e := filepath.WalkDir(dest, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, p)
		}
		return err
	}); e != nil {
		t.Fatal(e)
	}
	if len(files) != 0 {
		t.Errorf("destination holds %v, want no file: the move was rolled back", files)
	}
}

// An action that fails after touching the source, with a failure that may go
// away: the outcome applies to the state the connector left the file in, and a
// rewrite by someone else (time or size) is not mistaken for that trace.
func TestOutcome_identityReportsOurOwnTraceButNotAnotherWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no change time on Windows")
	}
	tests := []struct {
		name     string
		touch    func(t *testing.T, file string)
		wantSame bool // the identity of the outcome is the file's current one
	}{
		{
			name: "change time only (a link then an unlink)",
			touch: func(t *testing.T, file string) {
				if err := os.Chmod(file, 0o400); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(file, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantSame: true,
		},
		{
			name: "content rewritten by someone else",
			touch: func(t *testing.T, file string) {
				time.Sleep(10 * time.Millisecond)
				if err := os.WriteFile(file, []byte("rewritten with more content"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantSame: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			noOpenInputs(t)
			c, _, file, _ := newPathCheckFixture(t, false)
			c.action = &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error {
				tt.touch(t, file)
				return errors.New("transient failure at the deletion")
			}}
			got := &outcomes{}
			c.config.OnFileDone = got.add
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			if err := c.ScanFile(t.Context(), file); err != nil {
				t.Fatal(err)
			}
			c.Close(t.Context())
			list := got.get()
			if len(list) != 1 || list[0].Kind != OutcomeRetry {
				t.Fatalf("outcomes = %+v, want one retry", list)
			}
			info, err := os.Lstat(file)
			if err != nil {
				t.Fatal(err)
			}
			if same := IdentityOf(info).Equal(list[0].Identity); same != tt.wantSame {
				t.Errorf("outcome identity equals the current one: %t, want %t", same, tt.wantSame)
			}
		})
	}
}

// Modes of a deposit folder: read-only for its owner, then restored so that the
// test directory can be cleaned.
const (
	dirReadOnly fs.FileMode = 0o500
	dirOwnerRWX fs.FileMode = 0o700
)

// An archive abandoned while one of its members is still being analyzed waits for
// it: its run does not end (nothing is concluded, the descriptor stays open) until
// that member is back, since a detection may come with it. Then the run ends as a
// retry, the monitor submits the path again, and each run has its one OnFileDone
// and its one onFileScanned, in order.
func TestRuns_anAbandonedArchiveWaitsForItsMembersInFlightThenEndsItsRun(t *testing.T) {
	noOpenInputs(t)
	c, _, file, _ := newPathCheckFixture(t, false)
	zipBytes := realZip(t)
	if err := os.WriteFile(file, zipBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	c.config.Workers, c.config.Extract, c.config.ExtractMinThreshold, c.config.ExtractWorkers = 4, true, 1, 2
	c.config.RecursiveExtractMaxFiles, c.config.RecursiveExtractMaxSize, c.config.MaxFileSize, c.config.RecursiveExtractMaxDepth = 10, 1<<20, 1<<20, 3
	c.typesToExtract = map[string]struct{}{"application/zip": {}}

	memberHeld := make(chan struct{})
	releaseMember := make(chan struct{})
	run2Held := make(chan struct{})
	releaseRun2 := make(chan struct{})
	var calls atomic.Int32
	prev := ExtractFile
	t.Cleanup(func() { ExtractFile = prev })
	ExtractFile = func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		switch calls.Add(1) {
		case 1: // the top-level archive: a plain member, held in analysis, then a sub-archive
			plain := filepath.Join(outputDir, "a-plain.txt")
			inner := filepath.Join(outputDir, "b-inner.zip")
			if err := os.WriteFile(plain, []byte("plain member"), 0o600); err != nil {
				return plugins.Extraction{}, err
			}
			if err := os.WriteFile(inner, zipBytes, 0o600); err != nil {
				return plugins.Extraction{}, err
			}
			return plugins.Extraction{Size: uint64(len(zipBytes)) + 12, Files: []string{plain, inner}}, nil
		case 2: // the sub-archive: the extractor goes down
			return plugins.Extraction{}, plugins.ErrExtractorUnavailable
		default: // the second run of the top-level file: nothing to extract after all
			return plugins.Extraction{}, nil
		}
	}
	c.submitter = readerTrio(&gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForFileMock: func(_ context.Context, path string, _ gdetect.WaitForOptions) (gdetect.Result, error) {
			close(memberHeld)
			<-releaseMember
			sha, err := getFileSHA256(path)
			return gdetect.Result{SHA256: sha}, err
		},
		WaitForReaderMock: func(_ context.Context, r io.Reader, _ gdetect.WaitForOptions) (gdetect.Result, error) {
			close(run2Held)
			<-releaseRun2
			h := sha256.New()
			_, err := io.Copy(h, r)
			return gdetect.Result{SHA256: hex.EncodeToString(h.Sum(nil))}, err
		},
	})

	var mu sync.Mutex
	var events []string
	c.RegisterOnStartScanFile(func(f, _ string) {
		if f == file {
			mu.Lock()
			events = append(events, "start")
			mu.Unlock()
		}
	})
	c.RegisterOnFileScanned(func(f, _ string, r datamodel.Result) *datamodel.Result {
		if f == file {
			mu.Lock()
			if r.Error != nil {
				events = append(events, "scanned-error")
			} else {
				events = append(events, "scanned")
			}
			mu.Unlock()
		}
		return nil
	})
	done := &outcomes{}
	c.config.OnFileDone = func(o FileOutcome) {
		done.add(o)
		mu.Lock()
		events = append(events, "done")
		mu.Unlock()
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.ScanFile(t.Context(), file); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the member of the first run to be held", func() bool {
		select {
		case <-memberHeld:
			return true
		default:
			return false
		}
	})
	waitUntil(t, "the extractor to fail on the sub-archive", func() bool { return calls.Load() >= 2 })
	time.Sleep(200 * time.Millisecond)
	if n := len(done.get()); n != 0 {
		t.Fatalf("%d outcomes while a member of the abandoned archive is still in analysis, want none: its detection could still come", n)
	}
	if _, running := c.ongoingAnalysis.Load(file); !running {
		t.Fatal("the run ended while a member was in flight")
	}
	close(releaseMember)
	waitUntil(t, "the first run to end once its member is back", func() bool { return len(done.get()) == 1 })
	if err := c.ScanFile(t.Context(), file); err != nil { // the monitor submits the path again
		t.Fatal(err)
	}
	waitUntil(t, "the second run to reach its analysis", func() bool {
		select {
		case <-run2Held:
			return true
		default:
			return false
		}
	})
	if n := len(done.get()); n != 1 {
		t.Fatalf("%d outcomes while the second run is still in progress, want only the first run's", n)
	}
	close(releaseRun2)
	c.Close(t.Context())
	list := done.get()
	if len(list) != 2 || list[0].Kind != OutcomeResource || list[1].Kind != OutcomeFinal {
		t.Errorf("outcomes = %+v, want the first run abandoned (resource) then the second final", list)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"start", "scanned-error", "done", "start", "scanned", "done"}
	if !slices.Equal(events, want) {
		t.Errorf("events = %v, want %v: one start, one scan and one end per run, in order", events, want)
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// Once the plugins were told a run ended, nothing tells them again: a member
// coming back late, or the end of the run itself.
func TestFileScanned_isCalledOncePerStartEvenOnAClosedRun(t *testing.T) {
	c := &Connector{}
	var scans int
	c.RegisterOnFileScanned(func(string, string, datamodel.Result) *datamodel.Result {
		scans++
		return nil
	})
	const loc = "/in/f.bin"
	run := &ongoing{}
	c.ongoingAnalysis.Store(loc, run)
	c.scansWg.Add(1)
	c.startScan(loc, run, "sha")
	c.fileScanned(loc, run, "sha", datamodel.Result{})
	c.fileScanned(loc, run, "sha", datamodel.Result{})
	c.finishRun(loc, run) // the run ends: already told
	c.fileScanned(loc, run, "sha", datamodel.Result{Error: errAbandoned})
	if scans != 1 {
		t.Errorf("onFileScanned called %d times, want once for the one start", scans)
	}
}
