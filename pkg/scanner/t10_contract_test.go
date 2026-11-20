//go:build linux

package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

const (
	originalContent = "ORIGINAL-MALICIOUS-BYTES: this file is the one that was observed and hashed"
	swappedContent  = "swapped-in clean file with the same name"
)

// dirSwap exchanges folder in/alice with a folder holding a clean file of the
// same name, and undoes it, like an attacker racing the pipeline.
type dirSwap struct {
	t           *testing.T
	dir, parked string
	file        string
}

func newDirSwap(t *testing.T, file string) *dirSwap {
	t.Helper()
	dir := filepath.Dir(file)
	return &dirSwap{t: t, dir: dir, parked: dir + "2", file: filepath.Base(file)}
}

func (s *dirSwap) swap() {
	s.t.Helper()
	if err := os.Rename(s.dir, s.parked); err != nil {
		s.t.Error(err)
		return
	}
	if err := os.Mkdir(s.dir, 0o750); err != nil {
		s.t.Error(err)
		return
	}
	if err := os.WriteFile(filepath.Join(s.dir, s.file), []byte(swappedContent), 0o600); err != nil {
		s.t.Error(err)
	}
}

func (s *dirSwap) undo() {
	s.t.Helper()
	if err := os.RemoveAll(s.dir); err != nil {
		s.t.Error(err)
		return
	}
	if err := os.Rename(s.parked, s.dir); err != nil {
		s.t.Error(err)
	}
}

type swapFixture struct {
	c        *Connector
	file     string
	mu       sync.Mutex
	acted    []datamodel.Result
	received []string
}

func newSwapFixture(t *testing.T, submitter *gdetectMock.MockGDetectSubmitter) *swapFixture {
	t.Helper()
	readerTrio(submitter)
	in := t.TempDir()
	dir := filepath.Join(in, "alice")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	f := &swapFixture{file: filepath.Join(dir, "f.bin")}
	if err := os.WriteFile(f.file, []byte(originalContent), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewConnector(Config{Roots: []string{in}, WorkDir: t.TempDir(), Workers: 1, Extract: true, ExtractMinThreshold: 1 << 30}, nil, submitter)
	if err != nil {
		t.Fatal(err)
	}
	c.action = &MockAction{HandleMock: func(_ context.Context, _ string, r datamodel.Result, _ *datamodel.Report) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.acted = append(f.acted, r)
		return nil
	}}
	f.c = c
	return f
}

func (f *swapFixture) run(t *testing.T) {
	t.Helper()
	if err := f.c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := f.c.ScanFile(t.Context(), f.file); err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}
	f.c.Close(t.Context())
}

// serviceSubmitter plays the analysis service: it records the bytes it is
// given, whether by path or by reader, runs hook while it "analyzes", and says
// malware when it received the original bytes.
func serviceSubmitter(f **swapFixture, hook func()) *gdetectMock.MockGDetectSubmitter {
	verdict := func(content string) (gdetect.Result, error) {
		(*f).mu.Lock()
		(*f).received = append((*f).received, content)
		(*f).mu.Unlock()
		sum := sha256.Sum256([]byte(content))
		return gdetect.Result{Malware: content == originalContent, SHA256: hex.EncodeToString(sum[:])}, nil
	}
	return &gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForFileMock: func(_ context.Context, path string, _ gdetect.WaitForOptions) (gdetect.Result, error) {
			if hook != nil {
				hook()
			}
			b, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				return gdetect.Result{}, err
			}
			return verdict(string(b))
		},
		WaitForReaderMock: func(_ context.Context, r io.Reader, _ gdetect.WaitForOptions) (gdetect.Result, error) {
			if hook != nil {
				hook()
			}
			b, err := io.ReadAll(r)
			if err != nil {
				return gdetect.Result{}, err
			}
			return verdict(string(b))
		},
	}
}

func skipWithoutProc(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("descriptor links need /proc")
	}
}

// afterService runs fn once the service has answered, which is when an attacker
// would put the folders back.
func afterService(t *testing.T, f *swapFixture, fn func()) {
	t.Helper()
	m, ok := f.c.submitter.(*gdetectMock.MockGDetectSubmitter)
	if !ok {
		t.Fatalf("submitter is %T", f.c.submitter)
	}
	inner := m.GetResultByUUIDWithWaitMock
	m.GetResultByUUIDWithWaitMock = func(ctx context.Context, id string, wait int) (gdetect.Result, error) {
		res, err := inner(ctx, id, wait)
		fn()
		return res, err
	}
}

// The folders are exchanged while the service reads the file and put back as soon
// as it answered: the service must have been given the original bytes, and what
// the actions then receive is the verdict on those bytes (malware), never a clean
// verdict on the swapped-in file.
func TestT10_D1_directorySwapUndoneAfterTheAnalysisSendsTheOriginalBytesAndActsOnTheirVerdict(t *testing.T) {
	skipWithoutProc(t)
	var f *swapFixture
	var swapper *dirSwap
	var once sync.Once
	f = newSwapFixture(t, serviceSubmitter(&f, func() { once.Do(swapper.swap) }))
	swapper = newDirSwap(t, f.file)
	afterService(t, f, swapper.undo)
	f.run(t)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.received) != 1 || f.received[0] != originalContent {
		t.Fatalf("the service received %q, want exactly the bytes of the file that was hashed: the analysis must read the descriptor, never the path", f.received)
	}
	if len(f.acted) == 0 {
		t.Fatal("no action ran although the folders were put back: the check below would prove nothing")
	}
	for _, r := range f.acted {
		if !r.Malware {
			t.Errorf("an action ran with a clean verdict on the original path: the malicious file would leave as clean")
		}
	}
}

// The folders are exchanged during the analysis and left exchanged: the identity
// check stops the file before any action. It is observed explicitly: no action,
// a retry outcome, and the file at the path is left where it is.
func TestT10_D1_directorySwapLeftInPlaceStopsTheFileBeforeAnyAction(t *testing.T) {
	skipWithoutProc(t)
	var f *swapFixture
	var swapper *dirSwap
	var once sync.Once
	f = newSwapFixture(t, serviceSubmitter(&f, func() { once.Do(swapper.swap) }))
	swapper = newDirSwap(t, f.file)
	var mu sync.Mutex
	var outcomes []FileOutcome
	f.c.config.OnFileDone = func(o FileOutcome) {
		mu.Lock()
		defer mu.Unlock()
		outcomes = append(outcomes, o)
	}
	f.run(t)
	f.mu.Lock()
	acted := len(f.acted)
	f.mu.Unlock()
	if acted != 0 {
		t.Errorf("%d action(s) ran on a path whose folders were exchanged during the analysis", acted)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(outcomes) != 1 || outcomes[0].Kind != OutcomeRetry {
		t.Errorf("outcomes = %+v, want exactly one retry: the changed file is reopened, not final", outcomes)
	}
	if b, err := os.ReadFile(filepath.Clean(f.file)); err != nil || string(b) != swappedContent {
		t.Errorf("the file at the path = %q (%v), want it left untouched", b, err)
	}
}

func TestT10_D1_directorySwapDuringOnScanFileLetsTheFilterReadTheOriginal(t *testing.T) {
	skipWithoutProc(t)
	var f *swapFixture
	f = newSwapFixture(t, serviceSubmitter(&f, nil))
	swapper := newDirSwap(t, f.file)
	var mu sync.Mutex
	var read []string
	f.c.RegisterOnScanFile(func(filename, location, _ string, _ bool) *datamodel.Result {
		swapper.swap()
		defer swapper.undo()
		b, err := os.ReadFile(filepath.Clean(location))
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			read = append(read, "error: "+err.Error())
			return nil
		}
		read = append(read, string(b))
		return nil
	})
	f.run(t)
	mu.Lock()
	defer mu.Unlock()
	if len(read) != 1 {
		t.Fatalf("the filter ran %d time(s), want 1", len(read))
	}
	if read[0] != originalContent {
		t.Errorf("the filter read %q through location, want the original file: a dispensed type must never be read from a swapped folder", read[0])
	}
}

func TestT10_D1_directorySwapDuringExtractionExtractsTheOriginalArchive(t *testing.T) {
	skipWithoutProc(t)
	original, _ := createArchive(t, []string{"original member"})
	originalBytes, err := os.ReadFile(filepath.Clean(original))
	if err != nil {
		t.Fatal(err)
	}
	other, _ := createArchive(t, []string{"swapped member"})
	otherBytes, err := os.ReadFile(filepath.Clean(other))
	if err != nil {
		t.Fatal(err)
	}
	if string(originalBytes) == string(otherBytes) {
		t.Fatal("the two archives must differ")
	}
	var seenMu sync.Mutex
	var seen [][]byte
	var swapper *dirSwap
	prev := ExtractFile
	t.Cleanup(func() { ExtractFile = prev })
	ExtractFile = func(archive, _ string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		swapper.swap()
		defer swapper.undo()
		b, rerr := os.ReadFile(filepath.Clean(archive))
		seenMu.Lock()
		defer seenMu.Unlock()
		if rerr != nil {
			return plugins.Extraction{}, rerr
		}
		seen = append(seen, b)
		return plugins.Extraction{}, plugins.ErrUnsupportedFormat
	}
	var f *swapFixture
	f = newSwapFixture(t, serviceSubmitter(&f, nil))
	f.c.config.ExtractMinThreshold = 1
	copyInto(t, f.file, original)
	swapper = newDirSwap(t, f.file)
	// The swapped folder holds another archive under the same name.
	swapper.swap()
	copyInto(t, filepath.Join(swapper.dir, swapper.file), other)
	swapper.undo()
	f.run(t)
	seenMu.Lock()
	defer seenMu.Unlock()
	if len(seen) == 0 {
		t.Fatal("the extractor was never called")
	}
	for _, got := range seen {
		if string(got) != string(originalBytes) {
			t.Errorf("the extractor read an archive of %d bytes, want the original of %d: it must read the hashed file itself", len(got), len(originalBytes))
		}
	}
}

func TestT10_D1_aShaReturnedByTheServiceThatDiffersIsAnErrorWithoutAction(t *testing.T) {
	submitter := &gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForFileMock: func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) {
			return gdetect.Result{SHA256: strings.Repeat("0", 64)}, nil
		},
		WaitForReaderMock: func(context.Context, io.Reader, gdetect.WaitForOptions) (gdetect.Result, error) {
			return gdetect.Result{SHA256: strings.Repeat("0", 64)}, nil
		},
	}
	f := newSwapFixture(t, submitter)
	f.run(t)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.acted) != 0 {
		t.Errorf("%d action(s) ran although the service answered about another file (different SHA256)", len(f.acted))
	}
}

func openDescriptors(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc: %v", err)
	}
	return len(entries)
}

func TestT10_noDescriptorIsLeftOpenAfterEachFileWhateverTheOutcome(t *testing.T) {
	skipWithoutProc(t)
	outcomes := map[string]func(f **swapFixture) *gdetectMock.MockGDetectSubmitter{
		"clean": func(f **swapFixture) *gdetectMock.MockGDetectSubmitter { return serviceSubmitter(f, nil) },
		"analysis error": func(**swapFixture) *gdetectMock.MockGDetectSubmitter {
			return &gdetectMock.MockGDetectSubmitter{
				ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
				WaitForFileMock: func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) {
					return gdetect.Result{}, errors.New("service unreachable")
				},
				WaitForReaderMock: func(context.Context, io.Reader, gdetect.WaitForOptions) (gdetect.Result, error) {
					return gdetect.Result{}, errors.New("service unreachable")
				},
			}
		},
		"file changed during the analysis": func(f **swapFixture) *gdetectMock.MockGDetectSubmitter {
			return serviceSubmitter(f, func() {
				if err := os.WriteFile((*f).file, []byte("rewritten while it was analyzed"), 0o600); err != nil {
					t.Error(err)
				}
			})
		},
	}
	for name, mk := range outcomes {
		t.Run(name, func(t *testing.T) {
			before := openDescriptors(t)
			var f *swapFixture
			f = newSwapFixture(t, mk(&f))
			if err := os.WriteFile(f.file, []byte(originalContent), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := f.c.Start(); err != nil {
				t.Fatal(err)
			}
			if err := f.c.ScanFile(t.Context(), f.file); err != nil {
				t.Fatalf("ScanFile() error = %v", err)
			}
			f.c.Close(t.Context())
			time.Sleep(50 * time.Millisecond)
			if after := openDescriptors(t); after > before {
				t.Errorf("%d descriptor(s) still open after the file was handled (%s), was %d before", after, name, before)
			}
		})
	}
}

func TestT10_aFifoSwappedInIsNeverOpenedForReading(t *testing.T) {
	in := t.TempDir()
	file := filepath.Join(in, "f.bin")
	if err := os.WriteFile(file, []byte("regular"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	want := IdentityOf(info)
	if err = os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err = syscall.Mkfifo(file, 0o600); err != nil {
		t.Skipf("no FIFO here: %v", err)
	}
	c, err := NewConnector(Config{Roots: []string{in}, WorkDir: t.TempDir(), Workers: 1}, nil, cleanSubmitter())
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var accepted bool
	go func() {
		defer close(done)
		accepted, _ = c.SubmitFile(t.Context(), file, want)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SubmitFile blocked on a FIFO that replaced the regular file")
	}
	if accepted {
		t.Error("a FIFO must never be accepted for analysis")
	}
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		c.Close(t.Context())
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked: a worker is stuck opening the FIFO")
	}
}

func TestT10_aDirectoryLinkIsNeverWalkedEvenWithFollowSymlinks(t *testing.T) {
	in := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.bin"), []byte("outside the monitored tree"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in, "inside.bin"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(in, "to-outside")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(in, filepath.Join(in, "loop")); err != nil {
		t.Fatal(err)
	}
	c, err := NewConnector(Config{Roots: []string{in}, FollowSymlinks: true, WorkDir: t.TempDir(), Workers: 1}, nil, cleanSubmitter())
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var handled []string
	c.action = &MockAction{HandleMock: func(_ context.Context, p string, _ datamodel.Result, _ *datamodel.Report) error {
		mu.Lock()
		defer mu.Unlock()
		handled = append(handled, filepath.Base(p))
		return nil
	}}
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.ScanFile(t.Context(), in) }()
	select {
	case err = <-done:
		if err != nil {
			t.Logf("ScanFile() error = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ScanFile did not return: a directory link loop was followed")
	}
	c.Close(t.Context())
	mu.Lock()
	defer mu.Unlock()
	for _, name := range handled {
		if name == "secret.bin" {
			t.Errorf("a file behind a directory link was scanned: %v", handled)
		}
	}
}

// copyInto replaces the content of dst with the bytes of src.
func copyInto(t *testing.T, dst, src string) {
	t.Helper()
	in, err := os.Open(filepath.Clean(src))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := in.Close(); e != nil {
			t.Error(e)
		}
	}()
	out, err := os.OpenFile(filepath.Clean(dst), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestT10_procUnusableRefusesToStart(t *testing.T) {
	skipWithoutProc(t)
	prev := descriptorPath
	t.Cleanup(func() { descriptorPath = prev })
	descriptorPath = func(*os.File) (string, bool) { return "", false }
	var f *swapFixture
	f = newSwapFixture(t, serviceSubmitter(&f, nil))
	if err := f.c.Start(); !errors.Is(err, errNoDescriptorLinks) {
		t.Errorf("Start() error = %v, want errNoDescriptorLinks (fail closed, no silent fallback)", err)
	}
}
