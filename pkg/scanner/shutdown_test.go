package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// shutdownPlugin records how it was stopped.
type shutdownPlugin struct {
	interrupts  atomic.Int32
	closes      atomic.Int32
	closeAlive  atomic.Bool
	deadline    atomic.Bool // Close got a context with a Deadline
	closeDelay  time.Duration
	interrupted atomic.Bool // Interrupt came before Close
	block       chan struct{}
}

func (p *shutdownPlugin) GetDefaultConfig() any             { return nil }
func (p *shutdownPlugin) Init(any, plugins.HCContext) error { return nil }
func (p *shutdownPlugin) Interrupt()                        { p.interrupts.Add(1) }
func (p *shutdownPlugin) Close(ctx context.Context) error {
	p.closes.Add(1)
	p.closeAlive.Store(ctx.Err() == nil)
	_, hasDeadline := ctx.Deadline()
	p.deadline.Store(hasDeadline)
	time.Sleep(p.closeDelay)
	p.interrupted.Store(p.interrupts.Load() > 0)
	if p.block != nil {
		<-p.block
	}
	return nil
}

type shutdownFixture struct {
	c       *Connector
	file    string
	plugin  *shutdownPlugin
	started chan struct{}

	mu      sync.Mutex
	starts  []string
	scanned []datamodel.Result
}

// newShutdownFixture builds a connector with a file to scan and a plugin that
// counts the stops; the analysis of the file blocks until its context ends when
// blocked is true.
func newShutdownFixture(t *testing.T, blocked bool) *shutdownFixture {
	t.Helper()
	f := &shutdownFixture{plugin: &shutdownPlugin{}, started: make(chan struct{}, 1)}
	in := t.TempDir()
	f.file = filepath.Join(in, "f.bin")
	if err := os.WriteFile(f.file, []byte("some content"), 0o600); err != nil {
		t.Fatal(err)
	}
	submitter := echoReader(&gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForFileMock: func(ctx context.Context, _ string, _ gdetect.WaitForOptions) (gdetect.Result, error) {
			if !blocked {
				return gdetect.Result{}, nil
			}
			select {
			case f.started <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return gdetect.Result{}, ctx.Err()
		},
	})
	var err error
	f.c, err = NewConnector(Config{Roots: []string{in}, WorkDir: t.TempDir(), Workers: 2}, nil, submitter)
	if err != nil {
		t.Fatal(err)
	}
	f.c.action = &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error { return nil }}
	f.c.RegisterOnStartScanFile(func(file, _ string) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.starts = append(f.starts, file)
	})
	f.c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.scanned = append(f.scanned, r)
		return nil
	})
	f.c.loadedPlugins = append(f.c.loadedPlugins, f.plugin)
	if err = f.c.Start(); err != nil {
		t.Fatal(err)
	}
	if err = f.c.ScanFile(t.Context(), f.file); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *shutdownFixture) waitStarted(t *testing.T) {
	t.Helper()
	select {
	case <-f.started:
	case <-time.After(10 * time.Second):
		t.Fatal("the analysis did not start")
	}
}

func expired() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// A drain that is over cuts the analysis, which ends through the normal path
// (the plugins are told once per start, with an error), then the plugins are
// closed with a context that is alive and the work directory is removed.
func TestShutdown_aDrainThatEndedCutsTheAnalysisAndClosesCleanly(t *testing.T) {
	f := newShutdownFixture(t, true)
	f.waitStarted(t)
	work := f.c.work.path
	summary := f.c.Shutdown(expired(), context.Background())
	if summary.Abandoned != 1 || summary.StillRunning != 0 || summary.PluginErrors != 0 || !summary.WorkDirRemoved {
		t.Errorf("summary = %+v, want 1 abandoned and a clean close", summary)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.starts) != 1 || len(f.scanned) != 1 || f.scanned[0].Error == nil {
		t.Errorf("%d starts and %d ends (%+v), want one end with an error per start", len(f.starts), len(f.scanned), f.scanned)
	}
	if f.plugin.closes.Load() != 1 || !f.plugin.closeAlive.Load() {
		t.Errorf("plugin closed %d times, alive = %v: it must get the closing context, not the drain", f.plugin.closes.Load(), f.plugin.closeAlive.Load())
	}
	if f.plugin.interrupts.Load() != 1 || !f.plugin.interrupted.Load() {
		t.Errorf("Interrupt called %d times, before Close = %v, want once and before", f.plugin.interrupts.Load(), f.plugin.interrupted.Load())
	}
	if _, err := os.Stat(work); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the work directory is still there: %v", err)
	}
	if _, err := os.Stat(f.file); err != nil {
		t.Errorf("the file was not left in place: %v", err)
	}
}

func TestShutdown_aDrainThatSufficesLetsTheFilesFinish(t *testing.T) {
	f := newShutdownFixture(t, false)
	summary := f.c.Shutdown(context.Background(), context.Background())
	if summary.Abandoned != 0 || summary.StillRunning != 0 || !summary.WorkDirRemoved {
		t.Errorf("summary = %+v, want nothing abandoned", summary)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.scanned) != 1 || f.scanned[0].Error != nil {
		t.Errorf("results = %+v, want one without error", f.scanned)
	}
	if f.plugin.interrupts.Load() != 0 {
		t.Error("Interrupt must not be called when nothing was cut")
	}
}

// A plugin whose Close never returns holds up the stop until closing ends, no
// longer.
func TestShutdown_aPluginThatNeverClosesIsGivenUpOnAtTheEndOfClosing(t *testing.T) {
	f := newShutdownFixture(t, false)
	f.plugin.block = make(chan struct{})
	t.Cleanup(func() { close(f.plugin.block) })
	closing, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	summary := f.c.Shutdown(context.Background(), closing)
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("Shutdown took %s with a plugin that never closes", took)
	}
	if summary.PluginErrors != 1 {
		t.Errorf("summary = %+v, want one plugin in error", summary)
	}
}

func TestShutdown_aSecondCallDoesNothing(t *testing.T) {
	f := newShutdownFixture(t, false)
	f.c.Shutdown(context.Background(), context.Background())
	if got := f.c.Shutdown(context.Background(), context.Background()); got != (ShutdownSummary{}) {
		t.Errorf("second Shutdown() = %+v, want nothing", got)
	}
	if f.plugin.closes.Load() != 1 {
		t.Errorf("plugin closed %d times, want once", f.plugin.closes.Load())
	}
}

// The context of an action is cut with the others: a move interrupted at the
// end of the drain rolls back (see the MoveAction tests with an expired context)
// and the file stays in INPUT.
func TestShutdown_aDrainThatEndedCutsTheActionOfAFile(t *testing.T) {
	h := newActionBlockedFixture(t)
	summary := h.c.Shutdown(expired(), context.Background())
	if summary.Abandoned != 1 {
		t.Errorf("summary = %+v, want the file in its action abandoned", summary)
	}
	if err := h.actionErr.Load(); err == nil || !errors.Is(*err, context.Canceled) {
		t.Errorf("the action ended with %v, want its context cancelled", err)
	}
	if _, err := os.Stat(h.file); err != nil {
		t.Errorf("the file was not left in place: %v", err)
	}
}

type actionBlockedFixture struct {
	c         *Connector
	file      string
	actionErr atomic.Pointer[error]
}

func newActionBlockedFixture(t *testing.T) *actionBlockedFixture {
	t.Helper()
	h := &actionBlockedFixture{}
	in := t.TempDir()
	h.file = filepath.Join(in, "f.bin")
	if err := os.WriteFile(h.file, []byte("some content"), 0o600); err != nil {
		t.Fatal(err)
	}
	var err error
	h.c, err = NewConnector(Config{Roots: []string{in}, WorkDir: t.TempDir(), Workers: 2}, nil, cleanSubmitter())
	if err != nil {
		t.Fatal(err)
	}
	inAction := make(chan struct{})
	h.c.action = &MockAction{HandleMock: func(ctx context.Context, _ Source, _ datamodel.Result, _ *datamodel.Report) error {
		close(inAction)
		<-ctx.Done()
		err := ctx.Err()
		h.actionErr.Store(&err)
		return err
	}}
	if err = h.c.Start(); err != nil {
		t.Fatal(err)
	}
	if err = h.c.ScanFile(t.Context(), h.file); err != nil {
		t.Fatal(err)
	}
	select {
	case <-inAction:
	case <-time.After(10 * time.Second):
		t.Fatal("the action did not start")
	}
	return h
}

// Acceptance of the second path of the ticket: an archive that is replaced, or
// deleted, while its members are analyzed leaves no extraction folder, and no
// action runs on it.
func TestArchiveChangedWhileItsMembersAreAnalyzedLeavesNoExtractionFolder(t *testing.T) {
	changes := map[string]func(t *testing.T, archive string){
		"replaced": func(t *testing.T, archive string) {
			if err := os.WriteFile(archive, []byte("another content altogether"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"deleted": func(t *testing.T, archive string) {
			if err := os.Remove(archive); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			prev := ExtractFile
			t.Cleanup(func() { ExtractFile = prev })
			ExtractFile = fakeExtractor(func(outputDir string) (uint64, []string, error) {
				root, err := os.OpenRoot(outputDir)
				if err != nil {
					return 0, nil, err
				}
				defer func() {
					if e := root.Close(); e != nil {
						t.Logf("close root: %v", e)
					}
				}()
				if err = root.WriteFile("m.bin", []byte("member"), 0o600); err != nil {
					return 0, nil, err
				}
				return 6, []string{filepath.Join(outputDir, "m.bin")}, nil
			})
			var actions atomic.Int32
			c, err := NewConnector(Config{Extract: true, WorkDir: t.TempDir(), ExtractMinThreshold: 1, Workers: 2}, nil, archiveCleanSubmitter())
			if err != nil {
				t.Fatal(err)
			}
			c.action = &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error {
				actions.Add(1)
				return nil
			}}
			t.Cleanup(func() { c.Close(t.Context()) })
			location, sha := createArchive(t, []string{"content"})
			info, err := os.Stat(location)
			if err != nil {
				t.Fatal(err)
			}
			var size int64
			var files int
			archive := fileToAnalyze{sha256: sha, location: location, filename: filepath.Base(location), identity: IdentityOf(info), size: info.Size()}
			if err = c.recursiveExtract(archive, 0, &size, &files, logger); err != nil {
				t.Fatal(err)
			}
			change(t, location)
			select {
			case in := <-c.analysisChan:
				c.processFile(in)
			default:
				t.Fatal("the member must be waiting for analysis")
			}
			entries, err := os.ReadDir(c.work.extractDir())
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Errorf("%d extraction folders left, want none", len(entries))
			}
			if actions.Load() != 0 {
				t.Error("an action ran on an archive that changed during its analysis")
			}
		})
	}
}

// A console stop whose context is already over still closes the plugins with a
// live context.
func TestClose_withAnExpiredContextClosesThePluginsWithALiveOne(t *testing.T) {
	f := newShutdownFixture(t, false)
	f.c.Close(expired())
	if f.plugin.closes.Load() != 1 || !f.plugin.closeAlive.Load() {
		t.Errorf("plugin closed %d times, alive = %v", f.plugin.closes.Load(), f.plugin.closeAlive.Load())
	}
}

// The plugins get the closing context as it is, deadline included: the session
// plugin keeps part of it for its fallbacks.
func TestShutdown_thePluginsGetTheDeadlineOfClosing(t *testing.T) {
	f := newShutdownFixture(t, false)
	closing, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f.c.Shutdown(context.Background(), closing)
	if !f.plugin.deadline.Load() {
		t.Error("Close was not given the deadline of the closing time")
	}
}

// A plugin answering a little after the closing time is not abandoned: what it
// was finishing (a fallback report) is kept.
func TestShutdown_aPluginAnsweringJustAfterTheClosingTimeIsWaitedFor(t *testing.T) {
	f := newShutdownFixture(t, false)
	f.plugin.closeDelay = 500 * time.Millisecond
	closing, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	summary := f.c.Shutdown(context.Background(), closing)
	if summary.PluginErrors != 0 {
		t.Errorf("summary = %+v, want the plugin waited for within the grace", summary)
	}
}

type mitigationContexts struct {
	events.NoopEventHandler
	alive atomic.Bool
	calls atomic.Int32
}

func (m *mitigationContexts) NotifyFileMitigation(ctx context.Context, _ events.MitigationAction, _ string, _ events.MitigationReason, _ events.FileInfos) error {
	m.calls.Add(1)
	m.alive.Store(ctx.Err() == nil)
	return nil
}

// The console is told of a mitigation done just before the drain ended.
func TestNotifyMitigation_usesAContextOfItsOwn(t *testing.T) {
	prev := EventHandler
	rec := &mitigationContexts{}
	EventHandler = rec
	t.Cleanup(func() { EventHandler = prev })
	a := &MultiAction{}
	a.notifyMitigation(expired(), "/in/f", datamodel.Result{Malware: true}, &datamodel.Report{Action: datamodel.Removed})
	if rec.calls.Load() != 1 || !rec.alive.Load() {
		t.Errorf("%d calls, context alive = %v, want one with a live context", rec.calls.Load(), rec.alive.Load())
	}
}

// A file left in a queue behind the last worker ends with the stop: the runs of
// the files still queued, in each of the three queues, are ended once the
// workers are gone. The workers are not started here: the queues are what they
// would have left.
func TestShutdown_filesLeftInTheQueuesDoNotHoldTheStop(t *testing.T) {
	c, err := NewConnector(Config{WorkDir: t.TempDir(), Workers: 4, ExtractWorkers: 4}, nil, cleanSubmitter())
	if err != nil {
		t.Fatal(err)
	}
	queue := func(location string) *ongoing {
		run := &ongoing{}
		c.ongoingAnalysis.Store(location, run)
		c.scansWg.Add(1)
		return run
	}
	c.dispatchChan <- submission{location: "/in/dispatch", run: queue("/in/dispatch")}
	c.extractChan <- archiveToAnalyze{location: "/in/extract", run: queue("/in/extract")}
	c.analysisChan <- fileToAnalyze{location: "/in/analysis", run: queue("/in/analysis")}
	c.analysisChan <- fileToAnalyze{archiveID: "id", archiveTopLocation: "/in/top", run: queue("/in/top")}

	done := make(chan ShutdownSummary, 1)
	go func() { done <- c.Shutdown(expired(), context.Background()) }()
	select {
	case summary := <-done:
		if summary.Abandoned != 4 || summary.StillRunning != 0 {
			t.Errorf("summary = %+v, want the 4 queued files abandoned and none running", summary)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the stop is held by files left in the queues")
	}
	if n := c.countOngoing(); n != 0 {
		t.Errorf("%d runs left", n)
	}
}

// slowPlugin answers Close after a delay, or never.
type slowPlugin struct {
	delay time.Duration
	never chan struct{}
}

func (p *slowPlugin) GetDefaultConfig() any             { return nil }
func (p *slowPlugin) Init(any, plugins.HCContext) error { return nil }
func (p *slowPlugin) Close(context.Context) error {
	if p.never != nil {
		<-p.never
		return nil
	}
	time.Sleep(p.delay)
	return nil
}

// The plugins close at the same time, under one deadline: a plugin that never
// returns does not use the time of the one that finishes a little after the end
// of the closing time (a fallback report).
func TestShutdown_thePluginsCloseConcurrentlyUnderOneDeadline(t *testing.T) {
	c, err := NewConnector(Config{WorkDir: t.TempDir(), Workers: 1}, nil, cleanSubmitter())
	if err != nil {
		t.Fatal(err)
	}
	never := &slowPlugin{never: make(chan struct{})}
	t.Cleanup(func() { close(never.never) })
	late := &slowPlugin{delay: 300 * time.Millisecond}
	c.loadedPlugins = append(c.loadedPlugins, never, late)
	closing, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	summary := c.Shutdown(context.Background(), closing)
	if summary.PluginErrors != 1 {
		t.Errorf("PluginErrors = %d, want only the plugin that never returns", summary.PluginErrors)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("Shutdown took %s: the plugins were closed one after the other", took)
	}
}
