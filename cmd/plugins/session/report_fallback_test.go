//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"iter"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

type syncLogs struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *syncLogs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *syncLogs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type reportFixture struct {
	p      *SessionPlugin
	hcc    *mock.MockHCContext
	logs   *syncLogs
	root   string
	export string
	now    atomic.Pointer[time.Time]
}

func newReportFixture(t *testing.T, cfg Config) *reportFixture {
	t.Helper()
	f := &reportFixture{logs: &syncLogs{}, root: t.TempDir(), export: t.TempDir()}
	start := time.Unix(1_700_000_000, 0)
	f.now.Store(&start)
	f.hcc = newMockHCC(t)
	cfg.RootFolder, cfg.Depth, cfg.Exports = f.root, 1, []string{f.export}
	if cfg.ReportTimeout == 0 {
		cfg.ReportTimeout = time.Minute
	}
	if cfg.InflightTimeout == 0 {
		cfg.InflightTimeout = 24 * time.Hour
	}
	if cfg.Delay == 0 {
		cfg.Delay = time.Minute
	}
	f.p = &SessionPlugin{
		config: cfg, sessions: map[string]*Session{}, known: map[string]string{}, hcc: f.hcc, workDir: t.TempDir(),
		now: func() time.Time { return *f.now.Load() },
	}
	f.p.stop, f.p.done = make(chan struct{}), make(chan struct{})
	f.p.logger = slog.New(slog.NewTextHandler(f.logs, nil))
	f.p.consoleLogger = slog.New(slog.DiscardHandler)
	return f
}

func (f *reportFixture) advance(d time.Duration) {
	n := f.now.Load().Add(d)
	f.now.Store(&n)
}

func (f *reportFixture) scanned(user, name string) {
	p := filepath.Join(f.root, user, name)
	f.p.OnStartScanFile(p, "sha-"+name)
	f.p.OnFileScanned(p, "sha-"+name, datamodel.Result{})
	f.p.OnReport(&datamodel.Report{Filename: p, SHA256: "sha-" + name})
}

func (f *reportFixture) exported(user string) []string {
	entries, err := os.ReadDir(filepath.Join(f.export, user))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		out = append(out, filepath.Join(f.export, user, e.Name()))
	}
	return out
}

func TestReportGeneration_theFallbackEventIsRaisedOnceForSeveralSessions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		users []string
	}{
		{name: "tom, jerry and spike", users: []string{"tom", "jerry", "spike"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newReportFixture(t, Config{ReportRetries: 0})
			f.hcc.GenerateReportFunc = func(context.Context, datamodel.ScanContext, iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
				return plugins.GeneratedReport{}, errors.New("no browser")
			}
			var fallbacks atomic.Int32
			f.hcc.NotifyErrorFunc = func(_ context.Context, key string, _ error) {
				if key == fallbackEvent {
					fallbacks.Add(1)
				}
			}
			for _, u := range tt.users {
				f.scanned(u, "a.txt")
			}
			f.advance(2 * time.Minute)
			for range 4 {
				f.p.checkAndCloseSessions(f.p.baseCtx())
			}
			if got := fallbacks.Load(); got != 1 {
				t.Errorf("fallback events = %d for %d sessions, want 1", got, len(tt.users))
			}
		})
	}
}

// A generator is a plugin: whatever it hands back (no content, an extension that
// names another place) never writes outside the export and falls back to JSON.
func TestReportGeneration_aHostileOrEmptyGeneratorResultFallsBackToJSONInsideTheExport(t *testing.T) {
	tests := map[string]plugins.GeneratedReport{
		"no content":            {Extension: ".pdf"},
		"extension with a path": {Content: io.NopCloser(strings.NewReader("x")), Extension: "/../../escaped"},
		"extension up":          {Content: io.NopCloser(strings.NewReader("x")), Extension: ".pdf/../../escaped"},
		"no dot":                {Content: io.NopCloser(strings.NewReader("x")), Extension: "pdf"},
		"nul in extension":      {Content: io.NopCloser(strings.NewReader("x")), Extension: ".pd\x00f"},
		"huge extension":        {Content: io.NopCloser(strings.NewReader("x")), Extension: "." + strings.Repeat("a", 5000)},
	}
	for name, generated := range tests {
		t.Run(name, func(t *testing.T) {
			f := newReportFixture(t, Config{ReportRetries: 0})
			f.hcc.GenerateReportFunc = func(context.Context, datamodel.ScanContext, iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
				return generated, nil
			}
			f.scanned("tom", "a.txt")
			f.advance(2 * time.Minute)
			for range 3 {
				f.p.checkAndCloseSessions(f.p.baseCtx())
			}
			files := f.exported("tom")
			if len(files) != 1 || !strings.HasSuffix(files[0], ".json") {
				t.Fatalf("exported %v, want one JSON fallback", files)
			}
			var inside int
			_ = filepath.WalkDir(f.export, func(_ string, d os.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					inside++
				}
				return nil
			})
			if inside != 1 {
				t.Errorf("%d files under the export, want only the fallback", inside)
			}
			parent, err := os.ReadDir(filepath.Dir(f.export))
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range parent {
				if strings.Contains(e.Name(), "escaped") {
					t.Errorf("%s was written outside the export", e.Name())
				}
			}
		})
	}
}
