package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

func TestNewMonitor_disabledWatcherNeedsPeriod(t *testing.T) {
	_, err := NewMonitor(func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{DisableWatcher: true})
	if !errors.Is(err, config.ErrWatcherNeedsPeriod) {
		t.Errorf("NewMonitor() error = %v, want ErrWatcherNeedsPeriod", err)
	}
}

func TestMonitor_disabledWatcherPlacesNoWatch(t *testing.T) {
	root := t.TempDir()
	var mu sync.Mutex
	got := map[string]struct{}{}
	m, err := NewMonitor(func(path string, _ scanner.FileIdentity) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		got[filepath.Base(path)] = struct{}{}
		return true, nil
	}, Config{DisableWatcher: true, Period: sdk.Duration(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := m.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	if m.watcher != nil {
		t.Fatal("watcher created while disabled")
	}
	m.Start()
	if err := m.Add(root); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	writeTestFile(t, filepath.Join(root, "new.txt"))
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 0 {
		t.Errorf("file discovered without watcher nor rescan: %v", got)
	}
}

func TestMonitor_disabledWatcherRescanFindsFile(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "a.txt"))
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	m, err := NewMonitor(func(path string, _ scanner.FileIdentity) (bool, error) {
		if filepath.Base(path) == "a.txt" {
			cancel()
		}
		return true, nil
	}, Config{DisableWatcher: true, Period: sdk.Duration(10 * time.Millisecond)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := m.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	m.Start()
	if err := m.Add(root); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	<-ctx.Done()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Error("file not discovered by the rescan")
	}
}

func TestHandler_ConfigureAppliesDisableFSWatcher(t *testing.T) {
	const base = `"gmalware_api_url":"https://127.0.0.1:1","gmalware_api_token":"00000000-00000000-00000000-00000000-00000000","max_file_size":"100MiB","actions":{"log":true}`
	tests := []struct {
		name        string
		json        string
		wantWatcher bool
		wantErr     error
	}{
		{"key set", `{` + base + `,"monitoring":{"disable_fs_watcher":true,"period":"1h"}}`, false, nil},
		{"key absent = default", `{` + base + `,"monitoring":{"period":"1h"}}`, true, nil},
		{"key false", `{` + base + `,"monitoring":{"disable_fs_watcher":false}}`, true, nil},
		{"key set without period", `{` + base + `,"monitoring":{"disable_fs_watcher":true}}`, false, config.ErrWatcherNeedsPeriod},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{stopped: true}
			err := h.Configure(t.Context(), json.RawMessage(tt.json))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Configure() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Configure() error = %v", err)
			}
			mon, ok := h.monitor.(*Monitor)
			if !ok {
				t.Fatalf("monitor is %T", h.monitor)
			}
			if (mon.watcher != nil) != tt.wantWatcher {
				t.Errorf("watcher present = %t, want %t", mon.watcher != nil, tt.wantWatcher)
			}
			if err := mon.Close(); err != nil {
				t.Errorf("Close() error = %v", err)
			}
		})
	}
}

// console_defaults_v0.10.0.json is the configuration the console form sends
// when every field keeps its default (SDK v0.10.0 schema). Only the keys bound
// to the machine (token, paths, quarantine location) are replaced.
func TestHandler_ConfigureFullConsoleDefaults(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "console_defaults_v0.10.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		monitoring  map[string]any
		wantWatcher bool
	}{
		{"as sent by the console", nil, true},
		{"disable_fs_watcher with period", map[string]any{"disable_fs_watcher": true, "period": "1h"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var conf map[string]any
			if err := json.Unmarshal(raw, &conf); err != nil {
				t.Fatal(err)
			}
			conf["gmalware_api_token"] = "00000000-00000000-00000000-00000000-00000000"
			conf["paths"] = []string{t.TempDir()}
			quarantine, ok := conf["quarantine"].(map[string]any)
			if !ok {
				t.Fatalf("quarantine section missing: %v", conf["quarantine"])
			}
			quarantine["location"] = filepath.Join(t.TempDir(), "quarantine")
			if tt.monitoring != nil {
				monitoring, ok := conf["monitoring"].(map[string]any)
				if !ok {
					t.Fatalf("monitoring section missing: %v", conf["monitoring"])
				}
				maps.Copy(monitoring, tt.monitoring)
			}
			payload, err := json.Marshal(conf)
			if err != nil {
				t.Fatal(err)
			}
			h := &Handler{stopped: true}
			if err := h.Configure(t.Context(), payload); err != nil {
				t.Fatalf("Configure() error = %v", err)
			}
			mon, ok := h.monitor.(*Monitor)
			if !ok {
				t.Fatalf("monitor is %T", h.monitor)
			}
			if (mon.watcher != nil) != tt.wantWatcher {
				t.Errorf("watcher present = %t, want %t", mon.watcher != nil, tt.wantWatcher)
			}
			if err := mon.Close(); err != nil {
				t.Errorf("Close() error = %v", err)
			}
		})
	}
}

func TestHandler_ConsoleDefaultsFileAcceptedAsIs(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "console_defaults_v0.10.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	conf := new(config.Config)
	if err := json.Unmarshal(raw, conf); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(config.Validate(conf), config.CheckImplemented(conf)); err != nil {
		t.Errorf("console defaults refused by the connector: %v", err)
	}
}

func TestMonitor_disabledWatcherAddMissingPath(t *testing.T) {
	m, err := NewMonitor(func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{DisableWatcher: true, Period: sdk.Duration(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := m.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	missing := filepath.Join(t.TempDir(), "typo")
	if err := m.Add(missing); err == nil {
		t.Error("Add() of a missing path = nil, want an error: nothing would be watched")
	}
	if _, ok := m.paths.Load(missing); ok {
		t.Error("missing path was registered")
	}
}

func TestMonitor_ownersDeclaredByPluginsReachTheTable(t *testing.T) {
	root := t.TempDir()
	m, err := NewMonitor(func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{
		DisableWatcher: true,
		Period:         sdk.Duration(time.Hour),
		ModDelay:       sdk.Duration(time.Hour),
		Owners:         []scanner.OwnerRule{{Root: root, Depth: 2}},
		Watched:        []string{root},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := m.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	for _, p := range []string{"a/x/f.bin", "a/y/f.bin", "b/x/f.bin"} {
		path := filepath.Join(root, p)
		writeTestFile(t, path)
		m.discover(path, true)
	}
	if got := m.table.Owners(); got != 3 {
		t.Errorf("owners = %d, want 3 (depth 2 declared)", got)
	}
}

func TestMonitor_eventOnlyModeReportsPressureOncePerMinute(t *testing.T) {
	rec := recordEvents(t)
	root := t.TempDir()
	m, err := NewMonitor(func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{
		MaxTrackedBytes: 1200,
		ModDelay:        sdk.Duration(time.Hour),
		Watched:         []string{root},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := m.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	flood := func(prefix string) {
		for i := range 20 {
			path := filepath.Join(root, "owner", fmt.Sprintf("%s%d.bin", prefix, i))
			writeTestFile(t, path)
			m.discover(path, true)
		}
	}
	flood("a")
	if got := len(rec.find("error", HostMonitorPressure)); got != 1 {
		t.Fatalf("pressure events = %d, want 1", got)
	}
	flood("b")
	if got := len(rec.find("error", HostMonitorPressure)); got != 1 {
		t.Errorf("pressure events within a minute = %d, want 1", got)
	}
	m.repMu.Lock()
	m.lastReport = time.Now().Add(-2 * minReportInterval)
	m.repMu.Unlock()
	flood("c")
	if got := len(rec.find("error", HostMonitorPressure)); got != 2 {
		t.Errorf("pressure events after a minute = %d, want 2", got)
	}
}

func TestMonitor_eventOnlyModeReportsTheEndOfThePressure(t *testing.T) {
	rec := recordEvents(t)
	root := t.TempDir()
	m, err := NewMonitor(func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{
		MaxTrackedBytes: 1200,
		ModDelay:        sdk.Duration(time.Hour),
		Watched:         []string{root},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := m.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	for i := range 20 {
		path := filepath.Join(root, "owner", fmt.Sprintf("f%d.bin", i))
		writeTestFile(t, path)
		m.discover(path, true)
	}
	if got := len(rec.find("error", HostMonitorPressure)); got != 1 {
		t.Fatalf("pressure events = %d, want 1", got)
	}
	m.table.TakePressure()
	now := time.Now()
	m.reportPressureIfDue(now.Add(30 * time.Second))
	if got := len(rec.find("resolution", HostMonitorPressure)); got != 0 {
		t.Errorf("resolutions after 30s = %d, want 0", got)
	}
	m.reportPressureIfDue(now.Add(2 * minReportInterval))
	if got := len(rec.find("resolution", HostMonitorPressure)); got != 1 {
		t.Errorf("resolutions after 2 minutes without pressure = %d, want 1", got)
	}
	m.reportPressureIfDue(now.Add(4 * minReportInterval))
	if got := len(rec.find("resolution", HostMonitorPressure)); got != 1 {
		t.Errorf("resolutions = %d, want it raised once", got)
	}
}

func TestNewMonitor_relativeWatchedPathsAreResolved(t *testing.T) {
	t.Chdir(t.TempDir())
	m, err := NewMonitor(func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{DisableWatcher: true, Period: sdk.Duration(time.Hour), Watched: []string{"in"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := m.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	abs, err := filepath.Abs("in")
	if err != nil {
		t.Fatal(err)
	}
	m.table.Track(filepath.Join(abs, "alice", "f.bin"), scanner.FileIdentity{}, time.Now(), time.Now())
	if _, ok := m.table.owners[filepath.Join(abs, "alice")]; !ok {
		t.Errorf("owners = %v, want the folder of alice: the relative watched path must be resolved", m.table.owners)
	}
}

type fakeInfo struct{}

func (fakeInfo) Name() string       { return "f" }
func (fakeInfo) Size() int64        { return 1 }
func (fakeInfo) Mode() fs.FileMode  { return 0o600 }
func (fakeInfo) ModTime() time.Time { return time.Unix(1000, 0) }
func (fakeInfo) IsDir() bool        { return false }
func (fakeInfo) Sys() any           { return nil }

func TestMonitor_goroutinesDoNotGrowWithTheFiles(t *testing.T) {
	root := t.TempDir()
	m, err := NewMonitor(func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{
		DisableWatcher: true,
		Period:         sdk.Duration(time.Hour),
		ModDelay:       sdk.Duration(time.Hour),
		Watched:        []string{root},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := m.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	m.stat = func(string) (fs.FileInfo, error) { return fakeInfo{}, nil }
	m.Start()
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()
	for i := range 50_000 {
		m.discover(filepath.Join(root, fmt.Sprintf("u%d", i%50), fmt.Sprintf("f%d", i)), true)
	}
	if after := runtime.NumGoroutine(); after > before+1 {
		t.Errorf("goroutines went from %d to %d with 50 000 waiting files", before, after)
	}
	if m.table.Len() != 50_000 {
		t.Errorf("tracked = %d, want 50000", m.table.Len())
	}
}

func TestMonitor_relativeRootKeepsAUserAsOneOwner(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, p := range []string{"in/alice/a.txt", "in/alice/sub/b.txt", "in/bob/c.txt"} {
		writeTestFile(t, p)
	}
	m, err := NewMonitor(func(string, scanner.FileIdentity) (bool, error) { return true, nil }, Config{
		DisableWatcher: true,
		Period:         sdk.Duration(time.Hour),
		ModDelay:       sdk.Duration(time.Hour),
		Watched:        []string{"in"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := m.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	if err = m.Add("in"); err != nil {
		t.Fatal(err)
	}
	m.rescan()
	if got := m.table.Owners(); got != 2 {
		t.Errorf("owners = %d, want 2 (alice and bob): sub-folders must not become owners", got)
	}
}
