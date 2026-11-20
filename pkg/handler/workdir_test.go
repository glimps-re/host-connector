package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

func captureHandlerLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevLogger, prevConsole := logger, consoleLogger
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	logger, consoleLogger = slog.New(h), slog.New(h)
	t.Cleanup(func() { logger, consoleLogger = prevLogger, prevConsole })
	return &buf
}

func TestCheckWorkDir(t *testing.T) {
	watched := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(watched, link); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		workDir  string
		paths    []string
		move     string
		quar     string
		wantErr  bool
		wantWarn string
	}{
		{name: "default base, no watched path", paths: []string{watched}},
		{name: "base is a watched path", workDir: watched, paths: []string{watched}, wantErr: true},
		{name: "base is a watched path through a symlink", workDir: link, paths: []string{watched}, wantErr: true},
		{name: "base is one of several watched paths", workDir: watched, paths: []string{t.TempDir(), watched}, wantErr: true},
		{name: "base under a watched path", workDir: filepath.Join(watched, "work"), paths: []string{watched}, wantErr: true},
		{name: "base under a watched path through a symlink", workDir: filepath.Join(link, "work"), paths: []string{watched}, wantErr: true},
		{name: "similar prefix is not under", workDir: watched + "x", paths: []string{watched}},
		{name: "move destination under a watched path", paths: []string{watched}, move: filepath.Join(watched, "out"), wantWarn: "move.destination"},
		{name: "quarantine under a watched path is not this check's business", paths: []string{watched}, quar: filepath.Join(watched, "q")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := captureHandlerLogs(t)
			conf := &config.Config{}
			conf.WorkDir = tt.workDir
			conf.Paths = tt.paths
			conf.Move.Destination = tt.move
			conf.Quarantine.Location = tt.quar
			err := checkWorkDir(conf)
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkWorkDir() error = %v, wantErr %t", err, tt.wantErr)
			}
			out := buf.String()
			if tt.wantWarn != "" && (!strings.Contains(out, tt.wantWarn) || !strings.Contains(out, `"level":"WARN"`)) {
				t.Errorf("log = %q, want a Warn containing %q", out, tt.wantWarn)
			}
			if tt.wantWarn == "" && out != "" {
				t.Errorf("unexpected warning: %q", out)
			}
		})
	}
}

func TestMonitor_skipsInternalPaths(t *testing.T) {
	root := t.TempDir()
	internal := filepath.Join(root, "gmhost-work")
	writeTestFile(t, filepath.Join(internal, "extract", "x-1", "hidden.bin"))
	writeTestFile(t, filepath.Join(root, "regular.bin"))

	var mu sync.Mutex
	got := map[string]struct{}{}
	m, err := NewMonitor(func(path string, _ scanner.FileIdentity) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		got[filepath.Base(path)] = struct{}{}
		return true, nil
	}, Config{
		Period: sdk.Duration(5 * time.Millisecond),
		Skip:   func(p string) bool { return p == internal || strings.HasPrefix(p, internal+string(filepath.Separator)) },
	})
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
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(internal, "created-later.bin"))
	writeTestFile(t, filepath.Join(root, "created.bin"))

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		mu.Lock()
		_, a := got["regular.bin"]
		_, b := got["created.bin"]
		mu.Unlock()
		if a && b {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if _, ok := got["hidden.bin"]; ok {
		t.Error("rescan reported a file under the work directory")
	}
	if _, ok := got["created-later.bin"]; ok {
		t.Error("an event under the work directory reached the callback")
	}
	if len(got) != 2 {
		t.Errorf("callbacks = %v, want regular.bin and created.bin", got)
	}
}

func TestHandler_ConfigureAppliesWorkDir(t *testing.T) {
	const base = `"gmalware_api_url":"https://127.0.0.1:1","gmalware_api_token":"00000000-00000000-00000000-00000000-00000000","max_file_size":"100MiB","actions":{"log":true}`
	workBase := t.TempDir()
	watched := t.TempDir()
	tests := []struct {
		name     string
		json     string
		wantBase string
		wantErr  bool
	}{
		{"work_dir set", `{` + base + `,"work_dir":` + jsonString(workBase) + `}`, workBase, false},
		{"work_dir absent = system temporary directory", `{` + base + `}`, os.TempDir(), false},
		{"work_dir is a watched path", `{` + base + `,"paths":[` + jsonString(watched) + `],"work_dir":` + jsonString(watched) + `}`, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{stopped: true}
			err := h.Configure(t.Context(), json.RawMessage(tt.json))
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "work_dir") {
					t.Fatalf("Configure() error = %v, want a refusal naming work_dir", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Configure() error = %v", err)
			}
			wd := h.Conn.GetWorkDir()
			if filepath.Dir(wd) != filepath.Clean(tt.wantBase) {
				t.Errorf("work directory %q is not directly under %q", wd, tt.wantBase)
			}
			if mon, ok := h.monitor.(*Monitor); ok {
				if e := mon.Close(); e != nil {
					t.Errorf("Close() error = %v", e)
				}
			}
			h.Conn.Close(t.Context())
			if _, err := os.Stat(wd); !os.IsNotExist(err) {
				t.Errorf("work directory not removed at Close: %v", err)
			}
		})
	}
}

func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}
