package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"iter"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
	"github.com/glimps-re/host-connector/pkg/quarantine"
)

type t20Fixture struct {
	p      *SessionPlugin
	hcc    *mock.MockHCContext
	logs   *t20Logs
	root   string
	export string
	now    atomic.Pointer[time.Time]

	mu       sync.Mutex
	events   []string
	resolved []string
}

func newT20Fixture(t *testing.T, cfg Config) *t20Fixture {
	t.Helper()
	f := &t20Fixture{logs: &t20Logs{}, root: t.TempDir(), export: t.TempDir()}
	start := time.Unix(1_700_000_000, 0)
	f.now.Store(&start)
	f.hcc = newMockHCC(t)
	f.hcc.NotifyErrorFunc = func(_ context.Context, key string, _ error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.events = append(f.events, key)
	}
	f.hcc.NotifyResolutionFunc = func(_ context.Context, key, _ string) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.resolved = append(f.resolved, key)
	}
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

func (f *t20Fixture) advance(d time.Duration) {
	n := f.now.Load().Add(d)
	f.now.Store(&n)
}

func (f *t20Fixture) scanned(user, name string) {
	p := filepath.Join(f.root, user, name)
	f.p.OnStartScanFile(p, "sha-"+name)
	f.p.OnFileScanned(p, "sha-"+name, datamodel.Result{})
	f.p.OnReport(&datamodel.Report{Filename: p, SHA256: "sha-" + name})
}

func (f *t20Fixture) exported(user string) []string {
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

func (f *t20Fixture) eventCount(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, e := range f.events {
		if e == key {
			n++
		}
	}
	return n
}

func drain(t *testing.T, reports iter.Seq2[datamodel.Report, error]) []datamodel.Report {
	t.Helper()
	var out []datamodel.Report
	for r, err := range reports {
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func pdfContent(s string) plugins.GeneratedReport {
	return plugins.GeneratedReport{Content: io.NopCloser(strings.NewReader(s)), Extension: ".pdf"}
}

// A generator that fails N times: up to report_retries failures the report is
// retried and finally generated; one more and the JSON fallback is written,
// with the same files, and the console event is raised once.
func TestT20a_aGeneratorThatFailsNTimesGivesTheReportOrTheJSONFallback(t *testing.T) {
	const retries = 3
	tests := []struct {
		name         string
		failures     int
		wantExt      string
		wantEvent    int
		wantAttempts int
	}{
		{"fewer failures than retries", retries - 1, ".pdf", 0, retries},
		{"exactly the retries", retries, ".pdf", 0, retries + 1},
		{"one more than the retries", retries + 1, ".json", 1, retries + 1},
		{"always fails", 1000, ".json", 1, retries + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newT20Fixture(t, Config{ReportRetries: retries})
			var calls atomic.Int32
			f.hcc.GenerateReportFunc = func(_ context.Context, _ datamodel.ScanContext, reports iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
				if int(calls.Add(1)) <= tt.failures {
					return plugins.GeneratedReport{}, errors.New("chrome crashed")
				}
				drain(t, reports)
				return pdfContent("%PDF generated"), nil
			}
			f.scanned("tom", "a.txt")
			f.scanned("tom", "b.txt")
			f.advance(2 * time.Minute)
			for range retries + 3 {
				f.p.checkAndCloseSessions(f.p.baseCtx())
			}
			files := f.exported("tom")
			if len(files) != 1 || !strings.HasSuffix(files[0], tt.wantExt) {
				t.Fatalf("exported %v, want exactly one %s report", files, tt.wantExt)
			}
			if tt.wantExt == ".json" {
				b, err := os.ReadFile(filepath.Clean(files[0]))
				if err != nil {
					t.Fatal(err)
				}
				var reps []datamodel.Report
				if err = json.Unmarshal(b, &reps); err != nil || len(reps) != 2 {
					t.Errorf("fallback = %d entries, %v, want the 2 files of the session as valid JSON", len(reps), err)
				}
			}
			if got := f.eventCount(fallbackEvent); got != tt.wantEvent {
				t.Errorf("fallback events = %d, want %d", got, tt.wantEvent)
			}
			if got := int(calls.Load()); got != tt.wantAttempts {
				t.Errorf("generator called %d times, want %d: failures are retried report_retries times, once per tick", got, tt.wantAttempts)
			}
			f.p.closeMu.Lock()
			left := len(f.p.closing)
			f.p.closeMu.Unlock()
			if left != 0 {
				t.Errorf("%d sessions still wait for their report", left)
			}
		})
	}
}

// Several sessions whose generator fails give one console event, not one per
// session, and each one still gets its own JSON report.
func TestT20a_theFallbackEventIsRaisedOnceForSeveralSessions(t *testing.T) {
	f := newT20Fixture(t, Config{ReportRetries: 0})
	f.hcc.GenerateReportFunc = func(context.Context, datamodel.ScanContext, iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
		return plugins.GeneratedReport{}, errors.New("no browser")
	}
	for _, u := range []string{"tom", "jerry", "spike"} {
		f.scanned(u, "a.txt")
	}
	f.advance(2 * time.Minute)
	for range 4 {
		f.p.checkAndCloseSessions(f.p.baseCtx())
	}
	for _, u := range []string{"tom", "jerry", "spike"} {
		if files := f.exported(u); len(files) != 1 || !strings.HasSuffix(files[0], ".json") {
			t.Errorf("%s: exported %v, want one JSON report", u, files)
		}
	}
	if got := f.eventCount(fallbackEvent); got != 1 {
		t.Errorf("fallback events = %d, want 1", got)
	}
}

// A generator is a plugin: whatever it hands back (no content, an extension that
// names another place) never writes outside the export and falls back to JSON.
func TestT20a_aHostileOrEmptyGeneratorResultFallsBackToJSONInsideTheExport(t *testing.T) {
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
			f := newT20Fixture(t, Config{ReportRetries: 0})
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

// A file already present under the name of the report is never opened, truncated
// or written through, whatever it is: a regular file, or a link to somewhere
// else. The report is not lost, it is written under a conflict name, with an
// Error.
func TestT20a_anExistingFileAtTheNameOfTheReportIsLeftIntact(t *testing.T) {
	kinds := map[string]func(t *testing.T, final, outside string){
		"regular file": func(t *testing.T, final, _ string) {
			if err := os.WriteFile(final, []byte("PRECIOUS"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"link to a file elsewhere": func(t *testing.T, final, outside string) {
			if err := os.WriteFile(outside, []byte("PRECIOUS"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, final); err != nil {
				t.Fatal(err)
			}
		},
		"dangling link": func(t *testing.T, final, outside string) {
			if err := os.Symlink(outside, final); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range kinds {
		t.Run(name, func(t *testing.T) {
			f := newT20Fixture(t, Config{})
			outside := filepath.Join(t.TempDir(), "outside.pdf")
			f.hcc.GenerateReportFunc = func(_ context.Context, _ datamodel.ScanContext, reports iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
				drain(t, reports)
				return pdfContent("THE NEW REPORT"), nil
			}
			f.scanned("tom", "a.txt")
			s := f.p.sessions["tom"]
			dir := filepath.Join(f.export, "tom")
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			final := filepath.Join(dir, "report-session-tom-"+strconv.FormatInt(s.StartTime.Unix(), 10)+".pdf")
			setup(t, final, outside)

			f.advance(2 * time.Minute)
			f.p.checkAndCloseSessions(f.p.baseCtx())

			if b, err := os.ReadFile(filepath.Clean(outside)); err == nil && string(b) != "PRECIOUS" {
				t.Errorf("the target of the link = %q, it was written through", b)
			}
			if fi, err := os.Lstat(final); err != nil {
				t.Fatalf("the file at the name of the report is gone: %v", err)
			} else if name == "regular file" {
				if b, _ := os.ReadFile(filepath.Clean(final)); string(b) != "PRECIOUS" {
					t.Errorf("existing file = %q, want it intact", b)
				}
			} else if fi.Mode()&os.ModeSymlink == 0 {
				t.Error("the link was replaced")
			}
			var written string
			for _, p := range f.exported("tom") {
				if p == final || strings.Contains(filepath.Base(p), quarantine.TempPrefix) {
					continue
				}
				written = p
			}
			if written == "" {
				t.Fatalf("exported %v, want the report written under another name", f.exported("tom"))
			}
			if b, _ := os.ReadFile(filepath.Clean(written)); string(b) != "THE NEW REPORT" {
				t.Errorf("report = %q, want the generated one: it must not be lost", b)
			}
			if !strings.Contains(f.logs.String(), "level=ERROR") {
				t.Error("an existing file at the name of a report is an anomaly: Error expected")
			}
			for _, p := range f.exported("tom") {
				if strings.Contains(filepath.Base(p), quarantine.TempPrefix) {
					t.Errorf("temporary file %s left behind", p)
				}
			}
		})
	}
}
