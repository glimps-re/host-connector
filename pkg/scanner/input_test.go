package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

func noOpenInputs(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		if n := openInputs.Load(); n != 0 {
			t.Errorf("%d descriptors left open on deposited files", n)
		}
	})
}

func shaOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// A malicious file is replaced by a harmless one while the service reads it: what
// is analyzed must be the file that was identified, and the action must see it.
func TestAnalysis_readsTheVerifiedDescriptorNotThePath(t *testing.T) {
	noOpenInputs(t)
	c, in, file, _ := newPathCheckFixture(t, false)
	dir := filepath.Dir(file)
	other := filepath.Join(in, "alice2")
	if err := os.Mkdir(other, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "f.bin"), []byte("harmless!!!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	var read string
	c.submitter = readerTrio(&gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForReaderMock: func(_ context.Context, r io.Reader, _ gdetect.WaitForOptions) (gdetect.Result, error) {
			swap := dir + ".tmp"
			for _, step := range [][2]string{{dir, swap}, {other, dir}, {swap, other}} {
				if err := os.Rename(step[0], step[1]); err != nil {
					t.Error(err)
				}
			}
			b, err := io.ReadAll(r)
			if err != nil {
				return gdetect.Result{}, err
			}
			read = string(b)
			for _, step := range [][2]string{{dir, swap}, {other, dir}, {swap, other}} {
				if err = os.Rename(step[0], step[1]); err != nil {
					t.Error(err)
				}
			}
			return gdetect.Result{SHA256: shaOf(read), Malware: read == "some content"}, nil
		},
	})
	var scanned datamodel.Result
	c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
		scanned = r
		return nil
	})
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.ScanFile(t.Context(), file); err != nil {
		t.Fatal(err)
	}
	c.Close(t.Context())
	if read != "some content" {
		t.Errorf("the service read %q: the content of the file that was identified was expected", read)
	}
	if !scanned.Malware {
		t.Errorf("result = %+v, want the verdict on the identified file", scanned)
	}
}

func TestAnalysis_aDifferentHashFromTheServiceIsAnError(t *testing.T) {
	noOpenInputs(t)
	c, _, file, _ := newPathCheckFixture(t, false)
	c.submitter = readerTrio(&gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForReaderMock: func(context.Context, io.Reader, gdetect.WaitForOptions) (gdetect.Result, error) {
			return gdetect.Result{SHA256: "deadbeef"}, nil
		},
	})
	var scanned datamodel.Result
	c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
		scanned = r
		return nil
	})
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.ScanFile(t.Context(), file); err != nil {
		t.Fatal(err)
	}
	c.Close(t.Context())
	if !errors.Is(scanned.Error, errSubmitContentMismatch) {
		t.Errorf("Error = %v, want errSubmitContentMismatch: the file must not pass for analyzed", scanned.Error)
	}
}

func TestAnalysis_noHashFromTheServiceIsAnError(t *testing.T) {
	noOpenInputs(t)
	c, _, file, _ := newPathCheckFixture(t, false)
	c.submitter = readerTrio(&gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForReaderMock: func(context.Context, io.Reader, gdetect.WaitForOptions) (gdetect.Result, error) {
			return gdetect.Result{}, nil
		},
	})
	var scanned datamodel.Result
	c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
		scanned = r
		return nil
	})
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.ScanFile(t.Context(), file); err != nil {
		t.Fatal(err)
	}
	c.Close(t.Context())
	if !errors.Is(scanned.Error, errSubmitContentMismatch) {
		t.Errorf("Error = %v, want errSubmitContentMismatch", scanned.Error)
	}
}

// Plugins are given a path backed by the verified descriptor, and the file they
// read is the one identified even when the folder is swapped meanwhile.
func TestOnScanFile_locationIsBackedByTheDescriptor(t *testing.T) {
	noOpenInputs(t)
	c, in, file, _ := newPathCheckFixture(t, false)
	dir := filepath.Dir(file)
	other := filepath.Join(in, "alice2")
	if err := os.Mkdir(other, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "f.bin"), []byte("harmless!!!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	var gotName, gotLocation, content string
	c.RegisterOnScanFile(func(name, location, _ string, _ bool) *datamodel.Result {
		gotName, gotLocation = name, location
		swap := dir + ".tmp"
		for _, step := range [][2]string{{dir, swap}, {other, dir}} {
			if err := os.Rename(step[0], step[1]); err != nil {
				t.Error(err)
			}
		}
		b, err := os.ReadFile(filepath.Clean(location))
		if err != nil {
			t.Error(err)
		}
		content = string(b)
		for _, step := range [][2]string{{dir, other}, {swap, dir}} {
			if err = os.Rename(step[0], step[1]); err != nil {
				t.Error(err)
			}
		}
		return nil
	})
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.ScanFile(t.Context(), file); err != nil {
		t.Fatal(err)
	}
	c.Close(t.Context())
	if gotName != file {
		t.Errorf("filename = %q, want the logical path %q", gotName, file)
	}
	if descriptorPathUsable(t) && !strings.HasPrefix(gotLocation, "/proc/") {
		t.Errorf("location = %q, want a path backed by the descriptor", gotLocation)
	}
	if content != "some content" {
		t.Errorf("the plugin read %q through location, want the identified file", content)
	}
}

func descriptorPathUsable(t *testing.T) bool {
	t.Helper()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := f.Close(); e != nil {
			t.Error(e)
		}
	}()
	_, ok := descriptorPath(f)
	return ok
}

// The extractor receives a link to the verified descriptor: swapping the
// folder during the extraction cannot make it extract another archive.
func TestExtraction_readsTheVerifiedDescriptor(t *testing.T) {
	noOpenInputs(t)
	if !descriptorPathUsable(t) {
		t.Skip("no usable /proc")
	}
	c, in, file, _ := newPathCheckFixture(t, false)
	c.config.Extract, c.config.ExtractMinThreshold, c.config.ExtractWorkers = true, 1, 1
	c.config.RecursiveExtractMaxFiles, c.config.RecursiveExtractMaxSize, c.config.MaxFileSize, c.config.RecursiveExtractMaxDepth = 10, 1<<20, 1<<20, 3
	c.typesToExtract = map[string]struct{}{"text/plain; charset=utf-8": {}}
	dir := filepath.Dir(file)
	other := filepath.Join(in, "alice2")
	if err := os.Mkdir(other, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "f.bin"), []byte("harmless!!!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	var source, content, outputDirSeen string
	var outputEntries int
	prev := ExtractFile
	t.Cleanup(func() { ExtractFile = prev })
	ExtractFile = func(archiveLocation, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		source, outputDirSeen = archiveLocation, outputDir
		if entries, e := os.ReadDir(outputDir); e == nil {
			outputEntries = len(entries)
		}
		swap := dir + ".tmp"
		for _, step := range [][2]string{{dir, swap}, {other, dir}} {
			if err := os.Rename(step[0], step[1]); err != nil {
				t.Error(err)
			}
		}
		b, err := os.ReadFile(filepath.Clean(archiveLocation))
		if err != nil {
			t.Error(err)
		}
		content = string(b)
		for _, step := range [][2]string{{dir, other}, {swap, dir}} {
			if err = os.Rename(step[0], step[1]); err != nil {
				t.Error(err)
			}
		}
		return plugins.Extraction{}, plugins.ErrUnsupportedFormat
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.ScanFile(t.Context(), file); err != nil {
		t.Fatal(err)
	}
	c.Close(t.Context())
	if filepath.Base(source) != "f.bin" || !strings.HasPrefix(filepath.Base(filepath.Dir(source)), "src-") {
		t.Errorf("the extractor was given %q, want a link <src-folder>/<base name>", source)
	}
	if strings.HasPrefix(source, outputDirSeen+string(filepath.Separator)) || outputEntries != 0 {
		t.Errorf("the output folder %q must be empty and not hold the source (%q, %d entries)", outputDirSeen, source, outputEntries)
	}
	if _, err := os.Lstat(source); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the link must be removed once the extraction is over (stat error = %v)", err)
	}
	if content != "some content" {
		t.Errorf("the extractor read %q, want the identified archive", content)
	}
}

func TestStart_refusesWithoutUsableDescriptorLinks(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("descriptor links need /proc")
	}
	prev := descriptorPath
	t.Cleanup(func() { descriptorPath = prev })
	descriptorPath = func(*os.File) (string, bool) { return "", false }
	c, _, _, _ := newPathCheckFixture(t, false)
	if err := c.Start(); !errors.Is(err, errNoDescriptorLinks) {
		t.Errorf("Start() error = %v, want errNoDescriptorLinks: the connector must fail closed", err)
	}
}

// The verified descriptor stays open during the actions where they use it
// (Linux), and is closed before them elsewhere (Windows cannot move an open
// file). Either way none is left once the file is done, the descriptors handed
// out by Source.Open included.
func TestPipeline_descriptorLifetimeAroundTheAction(t *testing.T) {
	noOpenInputs(t)
	t.Cleanup(func() {
		if n := openSourceFiles.Load(); n != 0 {
			t.Errorf("%d descriptors handed out by Source.Open were not released", n)
		}
	})
	c, _, file, _ := newPathCheckFixture(t, false)
	var openAtAction atomic.Int64
	openAtAction.Store(-1)
	var sawHandle atomic.Bool
	c.action = &MockAction{HandleMock: func(_ context.Context, src Source, _ datamodel.Result, _ *datamodel.Report) error {
		openAtAction.Store(openInputs.Load())
		sawHandle.Store(src.handle != nil && src.Root != "")
		f, release, err := src.Open()
		if err != nil {
			return err
		}
		defer release()
		if _, err := io.ReadAll(f); err != nil {
			return err
		}
		return nil
	}}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.ScanFile(t.Context(), file); err != nil {
		t.Fatal(err)
	}
	c.Close(t.Context())
	want := int64(0)
	if holdsHandle {
		want = 1
	}
	if got := openAtAction.Load(); got != want {
		t.Errorf("%d descriptors open when the action ran, want %d", got, want)
	}
	if sawHandle.Load() != holdsHandle {
		t.Errorf("the source had a handle and a root = %t, want %t", sawHandle.Load(), holdsHandle)
	}
}

func TestPipeline_aFileCannotKeepAWorkerReadingForever(t *testing.T) {
	path := filepath.Join(t.TempDir(), "growing.bin")
	if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := f.Close(); e != nil {
			t.Error(e)
		}
	}()
	if _, err = hashSection(f, 5); !errors.Is(err, errSizeChanged) {
		t.Errorf("hashSection(5 of 10 bytes) error = %v, want errSizeChanged", err)
	}
	if _, err = hashSection(f, 20); !errors.Is(err, errSizeChanged) {
		t.Errorf("hashSection(20 of 10 bytes) error = %v, want errSizeChanged", err)
	}
	if got, e := hashSection(f, 10); e != nil || got != shaOf("0123456789") {
		t.Errorf("hashSection(10) = %q, %v", got, e)
	}
}

func TestPrepareFile_staleIdentityClosesTheDescriptor(t *testing.T) {
	noOpenInputs(t)
	c, _, file, _ := newPathCheckFixture(t, false)
	if _, skip := c.prepareFile(file, FileIdentity{}, nil); !skip {
		t.Error("prepareFile() must skip a file that changed")
	}
	if n := openInputs.Load(); n != 0 {
		t.Errorf("%d descriptors open after a skipped file", n)
	}
}

func TestHandleRestoredFile_changedFileIsNotActedUpon(t *testing.T) {
	c, _, file, handled := newPathCheckFixture(t, false)
	stale := idOf(t, file)
	stale.Size++
	if err := c.handleRestoredFile(file, "sha", 12, stale, nil, nil); !errors.Is(err, errFileReplaced) {
		t.Errorf("handleRestoredFile() error = %v, want errFileReplaced", err)
	}
	if len(*handled) != 0 {
		t.Errorf("an action ran on %v", *handled)
	}
	if err := c.handleRestoredFile(file, "sha", 12, idOf(t, file), nil, nil); err != nil || len(*handled) != 1 {
		t.Errorf("handleRestoredFile() = %v, handled %v; want the action on an unchanged file", err, *handled)
	}
}

func TestFinishArchiveAnalysis_changedArchiveIsNotActedUpon(t *testing.T) {
	var actionCalled bool
	var scanned datamodel.Result
	c := &Connector{
		action: &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error {
			actionCalled = true
			return nil
		}},
		archiveStatus: newArchiveStatusHandler(),
	}
	c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
		scanned = r
		return nil
	})
	location, sha := createTestFile(t, t.TempDir(), "archive content")
	stale := idOf(t, location)
	stale.Size++
	id := c.archiveStatus.addStatus(archiveStatus{
		archiveLocation: location, identity: stale, tmpFolder: t.TempDir(), total: 1, analyzed: 1, finished: true,
		result: datamodel.Result{SHA256: sha},
	})
	if err := c.finishArchiveAnalysis(id); err != nil {
		t.Fatal(err)
	}
	if actionCalled {
		t.Error("an archive that changed during its analysis must not be acted upon")
	}
	if !errors.Is(scanned.Error, errInnerTransient) {
		t.Errorf("Error = %v, want the archive in transient error", scanned.Error)
	}
}

// The core makes the three calls itself: the client's WaitForReader would copy
// the file to the temporary directory first.
func TestAnalysis_usesThePublicCallsNotWaitForReader(t *testing.T) {
	noOpenInputs(t)
	tests := []struct {
		name       string
		lookup     func(sha string) (gdetect.Result, error)
		wantSubmit bool
		wantWait   bool
	}{
		{
			name:       "unknown file: submitted, then waited for",
			lookup:     func(string) (gdetect.Result, error) { return gdetect.Result{}, gdetect.HTTPError{Code: 404} },
			wantSubmit: true,
			wantWait:   true,
		},
		{
			name: "known and done: answered from the cache",
			lookup: func(sha string) (gdetect.Result, error) {
				return gdetect.Result{Done: true, SHA256: sha, Malware: true}, nil
			},
		},
		{
			name: "known, analysis in progress: waited for, not submitted again",
			lookup: func(sha string) (gdetect.Result, error) {
				return gdetect.Result{UUID: "running", SHA256: sha}, nil
			},
			wantWait: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _, file, _ := newPathCheckFixture(t, false)
			var submitted, waited bool
			var sent string
			c.submitter = &gdetectMock.MockGDetectSubmitter{
				ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
				GetResultBySHA256Mock: func(_ context.Context, sha string) (gdetect.Result, error) {
					return tt.lookup(sha)
				},
				SubmitReaderMock: func(_ context.Context, r io.Reader, _ gdetect.SubmitOptions) (string, error) {
					b, err := io.ReadAll(r)
					submitted, sent = true, string(b)
					return "uuid-1", err
				},
				GetResultByUUIDWithWaitMock: func(_ context.Context, _ string, _ int) (gdetect.Result, error) {
					waited = true
					return gdetect.Result{Done: true, SHA256: shaOf("some content")}, nil
				},
			}
			var scanned datamodel.Result
			c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
				scanned = r
				return nil
			})
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			if err := c.ScanFile(t.Context(), file); err != nil {
				t.Fatal(err)
			}
			c.Close(t.Context())
			if submitted != tt.wantSubmit || waited != tt.wantWait {
				t.Errorf("submitted %t, waited %t; want %t, %t", submitted, waited, tt.wantSubmit, tt.wantWait)
			}
			if submitted && sent != "some content" {
				t.Errorf("the service was given %q, want the content of the file", sent)
			}
			if scanned.Error != nil {
				t.Errorf("Error = %v, want none", scanned.Error)
			}
		})
	}
}

func TestAnalysis_aDifferentHashIsAnErrorForAnExtractedMemberToo(t *testing.T) {
	c := &Connector{config: Config{MaxFileSize: 1 << 20}}
	c.submitter = &gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForFileMock: func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) {
			return gdetect.Result{SHA256: "deadbeef"}, nil
		},
	}
	res := c.analyzeFile(fileToAnalyze{location: "/work/x/y.bin", filename: "y.bin", sha256: shaOf("y"), size: 1})
	if !errors.Is(res.Error, errSubmitContentMismatch) {
		t.Errorf("Error = %v, want errSubmitContentMismatch for a member of an archive", res.Error)
	}
}

// With descriptors in use, a path that cannot be built is a file in error: the
// deposit path must never be handed to the plugins in its place.
func TestOnScanFile_failsClosedWhenTheDescriptorPathCannotBeBuilt(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("descriptor links need /proc")
	}
	noOpenInputs(t)
	c, _, file, handled := newPathCheckFixture(t, false)
	var pluginCalls int
	c.RegisterOnScanFile(func(string, string, string, bool) *datamodel.Result {
		pluginCalls++
		return &datamodel.Result{Score: -500} // a waiver
	})
	var scanned datamodel.Result
	c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
		scanned = r
		return nil
	})
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	prev := descriptorPath
	t.Cleanup(func() { descriptorPath = prev })
	descriptorPath = func(*os.File) (string, bool) { return "", false }
	if err := c.ScanFile(t.Context(), file); err != nil {
		t.Fatal(err)
	}
	c.Close(t.Context())
	if pluginCalls != 0 {
		t.Errorf("plugins were called %d times with a path they could be fooled with", pluginCalls)
	}
	if len(*handled) != 0 {
		t.Errorf("an action ran on %v", *handled)
	}
	if !errors.Is(scanned.Error, errNoDescriptorPath) {
		t.Errorf("Error = %v, want errNoDescriptorPath", scanned.Error)
	}
}

// In SynDetect mode the client does not send the wait parameter and polls; the
// connector must send what the client sends, no more.
func TestWaitForResult_requestsMatchTheClientInEachMode(t *testing.T) {
	for _, syndetect := range []bool{false, true} {
		name := "detect"
		if syndetect {
			name = "syndetect"
		}
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			var queries []string
			var times []time.Time
			polls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				queries = append(queries, r.URL.RawQuery)
				times = append(times, time.Now())
				polls++
				done := polls >= 3
				mu.Unlock()
				_, _ = w.Write([]byte(`{"done":` + strconv.FormatBool(done) + `}`))
			}))
			defer srv.Close()
			client, err := gdetect.NewClientFromConfig(gdetect.ClientConfig{Endpoint: srv.URL, Token: "01234567-89abcdef-01234567-89abcdef-01234567", HTTPClient: srv.Client()})
			if err != nil {
				t.Fatal(err)
			}
			if syndetect {
				client.SetSyndetect()
			}
			// A wide margin: the spacing is checked at a quarter of the pull time, so
			// that a handler delayed under load cannot make the test fail.
			const pull = 200 * time.Millisecond
			c := &Connector{submitter: client}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			id := "analysis-1"
			if !syndetect {
				id = "01234567-89ab-cdef-0123-456789abcdef"
			}
			res, err := c.waitForResult(ctx, id, pull)
			if err != nil || !res.Done {
				t.Fatalf("waitForResult() = %+v, %v", res, err)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, q := range queries {
				hasWait := strings.Contains(q, "wait=")
				if syndetect && hasWait {
					t.Errorf("request %q: the wait parameter must not be sent in SynDetect mode", q)
				}
				if !syndetect && !hasWait {
					t.Errorf("request %q: the wait parameter is expected in Detect mode", q)
				}
			}
			if syndetect {
				for i := 1; i < len(times); i++ {
					if gap := times[i].Sub(times[i-1]); gap < pull/4 {
						t.Errorf("polls %d and %d are %v apart, want them spaced by the pull time", i, i+1, gap)
					}
				}
			}
		})
	}
}
