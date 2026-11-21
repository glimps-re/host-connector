package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/handler"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

type t20Logs struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *t20Logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *t20Logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type t20Context struct {
	*scanner.Connector
	logger *slog.Logger
}

func (c *t20Context) GetLogger() *slog.Logger        { return c.logger }
func (c *t20Context) GetConsoleLogger() *slog.Logger { return c.logger }

type t20Opts struct {
	workers                 int
	delay, inflight, modDel time.Duration
	slow                    time.Duration
}

// t20Rig is the chain of the ticket: the core, the monitor and the session
// plugin, with a service that is slow for the files of "jerry".
type t20Rig struct {
	root, export string
	plugin       *SessionPlugin
	mon          *handler.Monitor
	logs         *t20Logs
	slowRunning  atomic.Int32
	slowDone     atomic.Int32
}

func newT20Rig(t *testing.T, o t20Opts) *t20Rig {
	t.Helper()
	r := &t20Rig{root: t.TempDir(), export: t.TempDir(), logs: &t20Logs{}}
	for _, u := range []string{"tom", "jerry"} {
		if err := os.MkdirAll(filepath.Join(r.root, u), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if o.workers == 0 {
		o.workers = 1
	}
	if o.inflight == 0 {
		o.inflight = time.Hour
	}
	if o.modDel == 0 {
		o.modDel = 50 * time.Millisecond
	}
	r.plugin = &SessionPlugin{tickEvery: 25 * time.Millisecond}
	var monLink atomic.Pointer[handler.Monitor]
	var subMu sync.Mutex
	contents := map[string][]byte{}
	submitter := &gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		GetResultBySHA256Mock: func(context.Context, string) (gdetect.Result, error) {
			return gdetect.Result{}, gdetect.HTTPError{Code: http.StatusNotFound}
		},
		SubmitReaderMock: func(_ context.Context, rd io.Reader, _ gdetect.SubmitOptions) (string, error) {
			var buf bytes.Buffer
			if _, err := io.Copy(&buf, io.LimitReader(rd, 1<<20)); err != nil {
				return "", err
			}
			b := buf.Bytes()
			subMu.Lock()
			defer subMu.Unlock()
			id := fmt.Sprintf("uuid-%d", len(contents))
			contents[id] = b
			return id, nil
		},
		GetResultByUUIDWithWaitMock: func(_ context.Context, id string, _ int) (gdetect.Result, error) {
			subMu.Lock()
			b := contents[id]
			subMu.Unlock()
			if strings.Contains(string(b), "jerry") {
				r.slowRunning.Add(1)
				time.Sleep(o.slow)
				r.slowDone.Add(1)
			}
			sum := sha256.Sum256(b)
			return gdetect.Result{SHA256: hex.EncodeToString(sum[:]), Done: true}, nil
		},
	}
	c, err := scanner.NewConnector(scanner.Config{
		Roots:       []string{r.root},
		WorkDir:     t.TempDir(),
		Workers:     o.workers,
		MaxFileSize: 1 << 20,
		OnFileDone: func(out scanner.FileOutcome) {
			if m := monLink.Load(); m != nil {
				m.FileDone(out)
			}
		},
		PendingFiles: func(path string) int {
			if m := monLink.Load(); m != nil {
				return m.PendingFiles(path)
			}
			return 0
		},
	}, nil, submitter)
	if err != nil {
		t.Fatal(err)
	}
	hcc := &t20Context{Connector: c, logger: slog.New(slog.NewTextHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	if err = r.plugin.Init(&Config{
		Depth: 1, Delay: o.delay, RootFolder: r.root, Exports: []string{r.export},
		ReportTimeout: time.Minute, ReportRetries: 3, MaxDuration: 24 * time.Hour, MaxSpoolSize: "1GiB", InflightTimeout: o.inflight,
	}, hcc); err != nil {
		t.Fatal(err)
	}
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	r.mon, err = handler.NewMonitor(func(file string, id scanner.FileIdentity) (bool, error) {
		return c.SubmitFile(t.Context(), file, id)
	}, handler.Config{ModDelay: sdk.Duration(o.modDel), Owners: c.TrackingOwners(), Watched: []string{r.root}})
	if err != nil {
		t.Fatal(err)
	}
	monLink.Store(r.mon)
	r.mon.Start()
	if err = r.mon.Add(r.root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := r.mon.Close(); e != nil {
			t.Error(e)
		}
		c.Close(t.Context())
		if e := r.plugin.Close(t.Context()); e != nil {
			t.Error(e)
		}
	})
	return r
}

func (r *t20Rig) drop(t *testing.T, rel, content string) string {
	t.Helper()
	p := filepath.Join(r.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (r *t20Rig) sessions() int {
	r.plugin.mutex.RLock()
	defer r.plugin.mutex.RUnlock()
	return len(r.plugin.sessions)
}

func (r *t20Rig) reportFiles(user string) []string {
	var out []string
	entries, err := os.ReadDir(filepath.Join(r.export, user))
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), datamodel.SessionReportPrefix) {
			out = append(out, filepath.Join(r.export, user, e.Name()))
		}
	}
	return out
}

func (r *t20Rig) entries(t *testing.T, user string) []datamodel.Report {
	t.Helper()
	all := make([]datamodel.Report, 0, 16)
	for _, p := range r.reportFiles(user) {
		b, err := os.ReadFile(filepath.Clean(p))
		if err != nil {
			t.Fatal(err)
		}
		var reps []datamodel.Report
		if err = json.Unmarshal(b, &reps); err != nil {
			t.Fatalf("%s is not a JSON report: %v", p, err)
		}
		all = append(all, reps...)
	}
	return all
}

func t20Wait(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("not reached in %s: %s", d, what)
}

// A deposit of several hundred small files (a .git folder) split by a slow
// analysis of someone else's file, with the only worker saturated, is one
// session and one report: not one per burst, not one per file.
func TestT20a_aDepositOfSeveralHundredFilesBehindASaturatedWorkerIsOneSessionAndOneReport(t *testing.T) {
	r := newT20Rig(t, t20Opts{workers: 1, delay: 500 * time.Millisecond, slow: 1500 * time.Millisecond})
	const half = 150
	for i := range half {
		r.drop(t, fmt.Sprintf("tom/.git/objects/%02x/a%03d", i%256, i), fmt.Sprintf("tom blob %d", i))
	}
	time.Sleep(300 * time.Millisecond)
	r.drop(t, "jerry/slow.txt", "jerry slow")
	t20Wait(t, 10*time.Second, "the slow analysis of Jerry holds the worker", func() bool { return r.slowRunning.Load() > 0 })
	for i := half; i < 2*half; i++ {
		r.drop(t, fmt.Sprintf("tom/.git/objects/%02x/b%03d", i%256, i), fmt.Sprintf("tom blob %d", i))
	}

	t20Wait(t, 90*time.Second, "the report of Tom", func() bool { return len(r.reportFiles("tom")) >= 1 })
	t20Wait(t, 30*time.Second, "all the sessions are closed", func() bool { return r.sessions() == 0 })
	time.Sleep(2 * time.Second)
	files := r.reportFiles("tom")
	if len(files) != 1 {
		t.Fatalf("Tom has %d reports %v, want one session and one report", len(files), files)
	}
	if got := len(r.entries(t, "tom")); got != 2*half {
		t.Errorf("the report has %d files, want %d", got, 2*half)
	}
}

// A file waiting for a worker that is deleted, rewritten, or replaced by a
// refused one (a link, an empty file) before it is taken must not hold the
// session of its owner: the session closes after the delay, a report is written
// and the monitor counts nothing pending.
func TestT20a_aPendingFileThatChangesBeforeBeingTakenNeverBlocksTheSession(t *testing.T) {
	tests := []struct {
		name   string
		change func(t *testing.T, r *t20Rig, p string)
	}{
		{"deleted", func(t *testing.T, _ *t20Rig, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
		}},
		{"rewritten", func(t *testing.T, _ *t20Rig, p string) {
			if err := os.WriteFile(p, []byte("tom rewritten content"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"replaced by a link", func(t *testing.T, r *t20Rig, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(r.root, "tom", "1.txt"), p); err != nil {
				t.Fatal(err)
			}
		}},
		{"emptied", func(t *testing.T, _ *t20Rig, p string) {
			if err := os.Truncate(p, 0); err != nil {
				t.Fatal(err)
			}
		}},
		{"deleted then recreated", func(t *testing.T, _ *t20Rig, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			time.Sleep(30 * time.Millisecond)
			if err := os.WriteFile(p, []byte("tom recreated"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newT20Rig(t, t20Opts{workers: 1, delay: 300 * time.Millisecond, slow: 1500 * time.Millisecond})
			r.drop(t, "tom/1.txt", "tom first")
			t20Wait(t, 10*time.Second, "the session of Tom", func() bool { return r.sessions() == 1 })
			r.drop(t, "jerry/slow.txt", "jerry slow")
			t20Wait(t, 10*time.Second, "the worker is held", func() bool { return r.slowRunning.Load() > 0 })
			p := r.drop(t, "tom/2.txt", "tom second")
			time.Sleep(150 * time.Millisecond)
			tt.change(t, r, p)

			t20Wait(t, 30*time.Second, "the session of Tom is closed", func() bool {
				return r.sessions() == 0 && len(r.reportFiles("tom")) >= 1
			})
			t20Wait(t, 10*time.Second, "nothing pending under Tom", func() bool {
				return r.mon.PendingFiles(filepath.Join(r.root, "tom")) == 0
			})
			if len(r.entries(t, "tom")) == 0 {
				t.Error("the reports of Tom are empty")
			}
		})
	}
}

// The queue is saturated for longer than inflight_timeout: the session of Tom is
// closed while files of its folder still wait, with a Warn that gives their
// number, and the files that waited open a new session with their own report:
// none is lost.
func TestT20a_aQueueSaturatedBeyondTheInflightTimeoutClosesTheSessionWithAWarn(t *testing.T) {
	r := newT20Rig(t, t20Opts{workers: 1, delay: 200 * time.Millisecond, inflight: 700 * time.Millisecond, slow: 3 * time.Second})
	r.drop(t, "tom/1.txt", "tom first")
	t20Wait(t, 10*time.Second, "the session of Tom", func() bool { return r.sessions() == 1 })
	r.drop(t, "jerry/slow.txt", "jerry slow")
	t20Wait(t, 10*time.Second, "the worker is held", func() bool { return r.slowRunning.Load() > 0 })
	r.drop(t, "tom/2.txt", "tom second")
	r.drop(t, "tom/3.txt", "tom third")

	t20Wait(t, 30*time.Second, "the first report of Tom", func() bool { return len(r.reportFiles("tom")) >= 1 })
	if r.slowDone.Load() != 0 {
		t.Fatal("the slow analysis ended before the session was closed: the saturation was not held long enough")
	}
	if !regexp.MustCompile(`level=WARN.*pending=[1-9]`).MatchString(r.logs.String()) {
		t.Errorf("no Warn with the number of waiting files in the logs:\n%s", r.logs.String())
	}
	t20Wait(t, 60*time.Second, "the three files of Tom are in a report", func() bool {
		return len(r.entries(t, "tom")) >= 3
	})
	seen := map[string]int{}
	for _, e := range r.entries(t, "tom") {
		seen[filepath.Base(e.Filename)]++
	}
	for _, name := range []string{"1.txt", "2.txt", "3.txt"} {
		if seen[name] != 1 {
			t.Errorf("%s appears %d times in the reports of Tom %v, want once", name, seen[name], seen)
		}
	}
}
