package handler

import (
	"context"
	"errors"
	"io"
	"iter"
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
	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

type fakeQuarantiner struct {
	mu        sync.Mutex
	failFor   string
	calls     []quarantine.Config
	current   quarantine.Config
	closeOnce sync.Once
}

func (f *fakeQuarantiner) Reconfigure(_ context.Context, c quarantine.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
	if f.failFor != "" && c.Location == f.failFor {
		return errors.New("injected reconfigure failure")
	}
	f.current = c
	return nil
}

func (*fakeQuarantiner) Quarantine(context.Context, string, *os.File, string, []string) (string, string, error) {
	return "", "", errors.New("not used")
}
func (*fakeQuarantiner) Restore(context.Context, string) error { return errors.New("not used") }
func (*fakeQuarantiner) IsRestored(context.Context, string, string) (bool, error) {
	return false, nil
}

func (*fakeQuarantiner) ListQuarantinedFiles(context.Context) iter.Seq2[*quarantine.QuarantinedFile, error] {
	return func(func(*quarantine.QuarantinedFile, error) bool) {}
}
func (f *fakeQuarantiner) Close() error { f.closeOnce.Do(func() {}); return nil }

func TestApplyContract_step3FailureRollsBackQuarantineToo(t *testing.T) {
	rec := recordEvents(t)
	quarantineRoot := t.TempDir()
	t.Setenv("TMPDIR", t.TempDir())
	watched := t.TempDir()
	good := validConf(t, watched)
	good.Actions.Quarantine = true
	good.Quarantine.Location = filepath.Join(quarantineRoot, "quarantine")
	good.Quarantine.Password = "old"
	h := newRunningHandler(t, good)
	oldQConf := h.qConf

	realQuarantiner := h.Quarantiner
	t.Cleanup(func() {
		if err := realQuarantiner.Close(); err != nil {
			t.Errorf("real quarantiner Close() error = %v", err)
		}
	})
	fake := &fakeQuarantiner{current: oldQConf}
	h.Quarantiner = fake

	next := validConf(t, watched)
	next.Actions.Quarantine = true
	next.Quarantine.Location = filepath.Join(quarantineRoot, "new-quarantine")
	next.Quarantine.Password = "new"
	fake.failFor = next.Quarantine.Location

	if err := h.Configure(t.Context(), rawConf(t, next)); err == nil {
		t.Fatal("Configure() error = nil, want the step 3 failure")
	}
	if got := h.Status(); got != sdk.Started {
		t.Errorf("Status() = %v, want Started after the rollback", got)
	}
	if h.conf != good {
		t.Error("h.conf must be the previous configuration")
	}
	fake.mu.Lock()
	current := fake.current
	fake.mu.Unlock()
	if current.Location != oldQConf.Location || current.LockPassword != "old" {
		t.Errorf("quarantine in service = %+v, want the previous location and password", current)
	}
	if h.qConf.Location != oldQConf.Location || h.qConf.LockPassword != "old" {
		t.Errorf("h.qConf = %+v, want the previous one", h.qConf)
	}
	if got := rec.find("error", HostConfigRejected); len(got) != 1 {
		t.Errorf("host-config-rejected events = %d, want 1", len(got))
	}
}

func TestApplyContract_rollbackFailureEventSaysStopped(t *testing.T) {
	rec := recordEvents(t)
	watched := t.TempDir()
	h := newRunningHandler(t, validConf(t, watched))
	if err := os.RemoveAll(watched); err != nil {
		t.Fatal(err)
	}
	if err := h.Configure(t.Context(), rawConf(t, validConf(t, filepath.Join(t.TempDir(), "missing")))); err == nil {
		t.Fatal("Configure() error = nil")
	}
	if got := h.Status(); got != sdk.Stopped {
		t.Fatalf("Status() = %v, want Stopped", got)
	}
	events := rec.find("error", HostConfigRejected)
	if len(events) == 0 {
		t.Fatal("no host-config-rejected event")
	}
	last := events[len(events)-1].msg
	if !strings.Contains(last, "processing is STOPPED") {
		t.Errorf("event %q must say \"processing is STOPPED\"", last)
	}
	if strings.Contains(last, "stays in service") {
		t.Errorf("event %q must not claim the previous configuration stays in service", last)
	}
}

func TestApplyContract_stoppedConnectorMissingWatchedPath(t *testing.T) {
	recordEvents(t)
	good := validConf(t, t.TempDir())
	h := newRunningHandler(t, good)
	if err := h.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	bad := validConf(t, filepath.Join(t.TempDir(), "missing"))
	if err := h.Configure(t.Context(), rawConf(t, bad)); err == nil {
		t.Fatal("Configure() on a stopped connector with a missing watched path: error = nil, want a refusal")
	}
	if h.conf != good {
		t.Error("h.conf must stay the previous configuration")
	}
	if err := h.Start(t.Context()); err != nil {
		t.Fatalf("Start() with the previous configuration error = %v", err)
	}
	if got := h.Status(); got != sdk.Started {
		t.Errorf("Status() = %v, want Started", got)
	}
}

func TestApplyContract_refusedConfigureKeepsProcessingWithOldConfig(t *testing.T) {
	recordEvents(t)
	watched := t.TempDir()
	good := validConf(t, watched)
	h := newRunningHandler(t, good)

	var submitted atomic.Int32
	mock, ok := h.submitter.(*gdetectMock.MockGDetectSubmitter)
	if !ok {
		t.Fatalf("submitter is %T", h.submitter)
	}
	waitFile := func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) {
		submitted.Add(1)
		return gdetect.Result{}, nil
	}
	mock.ExtractExpertViewURLMock = func(*gdetect.Result) (string, error) { return "", nil }
	mock.ExtractTokenViewURLMock = func(*gdetect.Result) (string, error) { return "", nil }
	mock.WaitForFileMock = waitFile
	mock.GetResultBySHA256Mock = func(context.Context, string) (gdetect.Result, error) {
		return gdetect.Result{}, gdetect.HTTPError{Code: http.StatusNotFound}
	}
	mock.SubmitReaderMock = func(context.Context, io.Reader, gdetect.SubmitOptions) (string, error) {
		submitted.Add(1)
		return "uuid", nil
	}
	mock.GetResultByUUIDWithWaitMock = func(context.Context, string, int) (gdetect.Result, error) {
		return gdetect.Result{Done: true}, nil
	}

	bad := validConf(t, watched)
	bad.UnanalyzablePolicy.ExtractError = "pass"
	if err := h.Configure(t.Context(), rawConf(t, bad)); err == nil {
		t.Fatal("Configure() error = nil, want a refusal")
	}
	if err := os.WriteFile(filepath.Join(watched, "after.bin"), []byte("after the refusal"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for submitted.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if submitted.Load() == 0 {
		t.Error("a file dropped after a refused Configure was not processed with the previous configuration")
	}
}

func TestApplyContract_prepareRefusals(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(c *config.Config)
		want   string
	}{
		{"unparsable max file size", func(c *config.Config) { c.MaxFileSize = "lots" }, "max-file-size"},
		{"unparsable extract min size", func(c *config.Config) { c.ExtractMinSize = "lots" }, "extract-min-size"},
		{"unparsable recursive extract max size", func(c *config.Config) { c.RecursiveExtractMaxSize = "lots" }, "recursive-extract-max-size"},
		{"missing plugins file", func(c *config.Config) { c.PluginsConfig = filepath.Join(t.TempDir(), "none.yml") }, "plugins config"},
		{"plugins file is a directory", func(c *config.Config) { c.PluginsConfig = t.TempDir() }, "plugins config"},
		{"invalid plugins file", func(c *config.Config) {
			p := filepath.Join(t.TempDir(), "p.yml")
			if err := os.WriteFile(p, []byte("a: [unclosed"), 0o600); err != nil {
				t.Fatal(err)
			}
			c.PluginsConfig = p
		}, "plugins config"},
		{"unknown move mode", func(c *config.Config) { c.Move.Mode = "rnme" }, "mode"},
		{"unparsable move throughput", func(c *config.Config) { c.Move.MinThroughput = "fast" }, "move.min_throughput"},
		{"zero move throughput", func(c *config.Config) { c.Move.MinThroughput = "0" }, "move.min_throughput"},
		{"unknown extract_error policy", func(c *config.Config) { c.UnanalyzablePolicy.ExtractError = "pass" }, "extract_error"},
		{"unknown analysis_error policy", func(c *config.Config) { c.UnanalyzablePolicy.AnalysisError = "skip" }, "analysis_error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := validConf(t, t.TempDir())
			tt.mutate(conf)
			p, err := new(Handler).prepare(conf)
			if err == nil || p != nil {
				t.Fatalf("prepare() = (%v, %v), want a refusal", p, err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("prepare() error = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestApplyContract_installReportFileErrors(t *testing.T) {
	recordEvents(t)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := map[string]string{
		"report directory cannot be created": filepath.Join(blocker, "sub", "report.log"),
		"report location is a directory":     t.TempDir(),
	}
	for name, location := range tests {
		t.Run(name, func(t *testing.T) {
			h := newRunningHandler(t, validConf(t, t.TempDir()))
			conn := h.Conn
			bad := validConf(t, t.TempDir())
			bad.Print.Location = location
			if err := h.Configure(t.Context(), rawConf(t, bad)); err == nil {
				t.Fatal("Configure() error = nil, want a failure")
			}
			if got := h.Status(); got != sdk.Started {
				t.Errorf("Status() = %v, want Started (the report location is refused before anything is touched)", got)
			}
			if h.Conn != conn {
				t.Error("an unusable report location is refused at validation: nothing may be stopped or rebuilt")
			}
		})
	}
}

func TestUnanalyzablePolicy_carriesEveryKey(t *testing.T) {
	var conf config.Config
	conf.UnanalyzablePolicy.TooBig, conf.UnanalyzablePolicy.Empty, conf.UnanalyzablePolicy.Encrypted = "a", "b", "c"
	conf.UnanalyzablePolicy.ExtractError, conf.UnanalyzablePolicy.AnalysisError = "d", "e"
	if got, want := unanalyzablePolicy(&conf), (scanner.Unanalyzable{TooBig: "a", Empty: "b", Encrypted: "c", ExtractError: "d", AnalysisError: "e"}); got != want {
		t.Errorf("unanalyzablePolicy() = %+v, want %+v", got, want)
	}
}
