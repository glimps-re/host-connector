package handler

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/host-connector/pkg/config"
)

func TestNewMonitor_disabledWatcherNeedsPeriod(t *testing.T) {
	_, err := NewMonitor(func(string) error { return nil }, Config{DisableWatcher: true})
	if !errors.Is(err, config.ErrWatcherNeedsPeriod) {
		t.Errorf("NewMonitor() error = %v, want ErrWatcherNeedsPeriod", err)
	}
}

func TestMonitor_disabledWatcherPlacesNoWatch(t *testing.T) {
	root := t.TempDir()
	var mu sync.Mutex
	got := map[string]struct{}{}
	m, err := NewMonitor(func(path string) error {
		mu.Lock()
		defer mu.Unlock()
		got[filepath.Base(path)] = struct{}{}
		return nil
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
	m, err := NewMonitor(func(path string) error {
		if filepath.Base(path) == "a.txt" {
			cancel()
		}
		return nil
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
			quarantine["location"] = t.TempDir()
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
	m, err := NewMonitor(func(string) error { return nil }, Config{DisableWatcher: true, Period: sdk.Duration(time.Hour)})
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
