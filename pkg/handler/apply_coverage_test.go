package handler

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

type failingEvents struct {
	events.NoopEventHandler
	errors atomic.Int32
}

func (f *failingEvents) NotifyError(context.Context, events.ErrorEventType, error) error {
	f.errors.Add(1)
	return errors.New("console unreachable")
}

func (f *failingEvents) NotifyResolution(context.Context, string, ...events.ErrorEventType) error {
	f.errors.Add(1)
	return errors.New("console unreachable")
}

type failingCloser struct{ closed atomic.Bool }

func (f *failingCloser) Write(p []byte) (int, error) { return len(p), nil }

func (f *failingCloser) Close() error {
	f.closed.Store(true)
	return errors.New("close failed")
}

func TestApplyCoverage_prepareClampsMaxFileSize(t *testing.T) {
	tests := []struct {
		name      string
		size      string
		syndetect bool
		want      int64
	}{
		{"above 100MiB without syndetect", "200MiB", false, maxFileSizeDetect},
		{"above 100MiB with syndetect is kept", "200MiB", true, 200 << 20},
		{"above 2GiB with syndetect", "3GiB", true, maxFileSizeSynDetect},
		{"within limits", "10MiB", false, 10 << 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := validConf(t, t.TempDir())
			conf.MaxFileSize = tt.size
			conf.GMalwareSyndetect = tt.syndetect
			p, err := new(Handler).prepare(conf)
			if err != nil {
				t.Fatalf("prepare() error = %v", err)
			}
			if p.maxFileSize != tt.want {
				t.Errorf("maxFileSize = %d, want %d", p.maxFileSize, tt.want)
			}
		})
	}
}

func TestApplyCoverage_prepareParsesOptionalSizes(t *testing.T) {
	conf := validConf(t, t.TempDir())
	conf.ExtractMinSize = "1KiB"
	conf.RecursiveExtractMaxSize = "2MiB"
	p, err := new(Handler).prepare(conf)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	if p.extractMinSize != 1<<10 || p.recursiveExtractMaxSize != 2<<20 {
		t.Errorf("sizes = %d, %d, want 1KiB and 2MiB", p.extractMinSize, p.recursiveExtractMaxSize)
	}
}

func writePluginsFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "plugins.yml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestApplyCoverage_validatePluginsConfig(t *testing.T) {
	watched := t.TempDir()
	t.Run("validation failure", func(t *testing.T) {
		conf := validConf(t, watched)
		conf.PluginsConfig = writePluginsFile(t, "bogus:\n  file: /nonexistent.so\n")
		h := &Handler{validatePlugins: func([]scanner.PluginConfig, *scanner.ValidationContext) error {
			return errors.New("plugin refuses its configuration")
		}}
		_, err := h.prepare(conf)
		if err == nil || !strings.Contains(err.Error(), "plugins validation") {
			t.Fatalf("prepare() error = %v, want a plugins validation failure", err)
		}
	})
	t.Run("output directory under a watched path is refused", func(t *testing.T) {
		conf := validConf(t, watched)
		conf.PluginsConfig = writePluginsFile(t, "bogus:\n  file: /nonexistent.so\n")
		h := &Handler{validatePlugins: func(_ []scanner.PluginConfig, vc *scanner.ValidationContext) error {
			return vc.DeclareOutputDir(filepath.Join(watched, "results"))
		}}
		if _, err := h.prepare(conf); err == nil {
			t.Fatal("prepare() error = nil, want the declared output directory refused")
		}
	})
	t.Run("no plugin means nothing to validate", func(t *testing.T) {
		called := false
		h := &Handler{validatePlugins: func([]scanner.PluginConfig, *scanner.ValidationContext) error {
			called = true
			return nil
		}}
		if _, err := h.prepare(validConf(t, watched)); err != nil {
			t.Fatal(err)
		}
		if called {
			t.Error("validatePlugins must not run without plugins")
		}
	})
}

func TestApplyCoverage_installPluginLoadFailureRollsBack(t *testing.T) {
	recordEvents(t)
	h := newRunningHandler(t, validConf(t, t.TempDir()))
	h.validatePlugins = func([]scanner.PluginConfig, *scanner.ValidationContext) error { return nil }
	conn := h.Conn

	next := validConf(t, t.TempDir())
	next.PluginsConfig = writePluginsFile(t, "bogus:\n  file: /nonexistent/plugin.so\n")
	if err := h.Configure(t.Context(), rawConf(t, next)); err == nil {
		t.Fatal("Configure() error = nil, want a plugin load failure")
	}
	if got := h.Status(); got != sdk.Started {
		t.Errorf("Status() = %v, want Started after the rollback", got)
	}
	if h.Conn == nil || h.Conn == conn {
		t.Error("the rollback must rebuild a connector from the previous configuration")
	}
}

func TestApplyCoverage_installGMalwareReconfigureFailureRollsBack(t *testing.T) {
	rec := recordEvents(t)
	h := newRunningHandler(t, validConf(t, t.TempDir()))
	mock, ok := h.submitter.(*gdetectMock.MockGDetectSubmitter)
	if !ok {
		t.Fatalf("submitter is %T", h.submitter)
	}
	var calls atomic.Int32
	mock.ReconfigureMock = func(context.Context, gdetect.ClientConfig) error {
		if calls.Add(1) == 1 {
			return errors.New("gmalware unreachable")
		}
		return nil
	}
	if err := h.Configure(t.Context(), rawConf(t, validConf(t, t.TempDir()))); err == nil {
		t.Fatal("Configure() error = nil, want the GMalware failure")
	}
	if got := h.Status(); got != sdk.Started {
		t.Errorf("Status() = %v, want Started after the rollback", got)
	}
	if got := rec.find("error", events.GMalwareConfigError); len(got) == 0 && len(rec.find("error", HostConfigRejected)) == 0 {
		t.Error("the failure must reach the console")
	}
}

func TestApplyCoverage_closeRunningReleasesEverythingEvenWhenCloseFails(t *testing.T) {
	h := newRunningHandler(t, validConf(t, t.TempDir()))
	dest := &failingCloser{}
	h.informDest = dest
	h.closeRunning(t.Context())
	if h.monitor != nil || h.Conn != nil || h.informDest != nil {
		t.Errorf("closeRunning left monitor=%v conn=%v informDest=%v", h.monitor, h.Conn, h.informDest)
	}
	if !dest.closed.Load() {
		t.Error("the report destination must be closed")
	}
	h.closeRunning(t.Context())
}

func TestApplyCoverage_consoleErrorsNeverBreakTheFlow(t *testing.T) {
	failing := &failingEvents{}
	prev := eventHandler
	eventHandler = failing
	t.Cleanup(func() { eventHandler = prev })
	var logs bytes.Buffer
	prevLogger := logger
	logger = slog.New(slog.NewTextHandler(&logs, nil))
	t.Cleanup(func() { logger = prevLogger })

	h := newRunningHandler(t, validConf(t, t.TempDir()))
	h.reportUnknownKeys(t.Context(), nil)
	h.reportUnknownKeys(t.Context(), []string{"future_key"})
	h.resolveRejected(t.Context())
	bad := validConf(t, t.TempDir())
	bad.Move.Mode = "copy"
	if err := h.Configure(t.Context(), rawConf(t, bad)); err == nil {
		t.Fatal("Configure() error = nil")
	}
	if got := h.Status(); got != sdk.Started {
		t.Errorf("Status() = %v, want Started: an unreachable console must not change the state", got)
	}
	if failing.errors.Load() < 4 {
		t.Errorf("console calls = %d, want every event attempted", failing.errors.Load())
	}
	for _, want := range []string{"future_key", "console"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("logs miss %q: the failures must be logged", want)
		}
	}
}

var _ io.WriteCloser = (*failingCloser)(nil)
