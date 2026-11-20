package handler

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

func TestNewMonitor(t *testing.T) {
	type cbExpectation struct {
		count int
		err   error
	}
	type fields struct {
		preScan  bool
		period   sdk.Duration
		modDelay sdk.Duration
	}
	tests := []struct {
		name              string
		fields            fields
		createAndAddPath  func(t *testing.T, m *Monitor)
		wantErrAtCreation bool
		wantCbCalledOn    map[string]*cbExpectation
	}{
		{
			name:   "ok",
			fields: fields{},
			wantCbCalledOn: map[string]*cbExpectation{
				"test.txt":  {count: 1, err: nil},
				"test2.txt": {count: 1, err: nil},
			},
			createAndAddPath: func(t *testing.T, m *Monitor) {
				t.Helper()
				tmpDir := t.TempDir()
				if e := m.Add(tmpDir); e != nil {
					t.Fatalf("could not add %s, error: %v", tmpDir, e)
				}
				f, err := os.Create(filepath.Clean(filepath.Join(tmpDir, "test.txt")))
				if err != nil {
					t.Fatalf("could not create file, error: %v", err)
				}
				defer func() {
					if e := f.Close(); e != nil {
						t.Errorf("error closing file, error: %v", e)
					}
				}()
				if _, e := fmt.Fprint(f, "test"); e != nil {
					t.Fatalf("could not create file, error: %v", e)
				}
				if e := os.Mkdir(filepath.Join(tmpDir, "folder"), 0o750); e != nil {
					t.Fatalf("could not create test folder, error: %v", e)
				}
				f2, err := os.Create(filepath.Clean(filepath.Join(tmpDir, "folder", "test2.txt")))
				if err != nil {
					t.Fatalf("could not create file, error: %v", err)
				}
				defer func() {
					if e := f2.Close(); e != nil {
						t.Errorf("error closing file, error: %v", e)
					}
				}()
				if _, e := fmt.Fprint(f2, "test"); e != nil {
					t.Fatalf("could not create file, error: %v", e)
				}
			},
		},
		{
			name:   "single file creation",
			fields: fields{},
			wantCbCalledOn: map[string]*cbExpectation{
				"test1": {count: 1, err: nil},
			},
			createAndAddPath: func(t *testing.T, m *Monitor) {
				t.Helper()
				tmpDir := t.TempDir()
				if e := m.Add(tmpDir); e != nil {
					t.Fatalf("could not add %s, error: %v", tmpDir, e)
				}
				f, err := os.Create(filepath.Clean(filepath.Join(tmpDir, "test1")))
				if err != nil {
					t.Fatalf("could not create file, error: %v", err)
				}
				defer func() {
					if e := f.Close(); e != nil {
						t.Errorf("error closing file, error: %v", e)
					}
				}()
				if _, e := fmt.Fprint(f, "test content"); e != nil {
					t.Fatalf("could not write to file, error: %v", e)
				}
			},
		},
		{
			name:   "move file into monitored directory",
			fields: fields{},
			wantCbCalledOn: map[string]*cbExpectation{
				"test11": {count: 1, err: nil},
			},
			createAndAddPath: func(t *testing.T, m *Monitor) {
				t.Helper()
				tmpDir := t.TempDir()
				if e := m.Add(tmpDir); e != nil {
					t.Fatalf("could not add %s, error: %v", tmpDir, e)
				}
				f, err := os.CreateTemp(os.TempDir(), "test1_*")
				if err != nil {
					t.Fatalf("could not create temp file, error: %v", err)
				}
				if _, e := fmt.Fprint(f, "test content"); e != nil {
					t.Fatalf("could not write to file, error: %v", e)
				}
				if e := f.Close(); e != nil {
					t.Fatalf("could not close file, error: %v", e)
				}
				if e := os.Rename(f.Name(), filepath.Clean(filepath.Join(tmpDir, "test11"))); e != nil {
					t.Fatalf("could not rename file, error: %v", e)
				}
			},
		},
		{
			name: "pre-scan existing files",
			fields: fields{
				preScan: true,
			},
			wantCbCalledOn: map[string]*cbExpectation{
				"test1": {count: 1, err: nil},
			},
			createAndAddPath: func(t *testing.T, m *Monitor) {
				t.Helper()
				tmpDir := t.TempDir()
				f, err := os.Create(filepath.Clean(filepath.Join(tmpDir, "test1")))
				if err != nil {
					t.Fatalf("could not create file, error: %v", err)
				}
				if _, e := fmt.Fprint(f, "test content"); e != nil {
					t.Fatalf("could not write to file, error: %v", e)
				}
				if e := f.Close(); e != nil {
					t.Fatalf("could not close file, error: %v", e)
				}
				if e := m.Add(tmpDir); e != nil {
					t.Fatalf("could not add %s, error: %v", tmpDir, e)
				}
			},
		},
		{
			name: "periodic scan",
			fields: fields{
				period: sdk.Duration(time.Millisecond),
			},
			wantCbCalledOn: map[string]*cbExpectation{
				"test1": {count: 5, err: nil},
			},
			createAndAddPath: func(t *testing.T, m *Monitor) {
				t.Helper()
				tmpDir := t.TempDir()
				f, err := os.Create(filepath.Clean(filepath.Join(tmpDir, "test1")))
				if err != nil {
					t.Fatalf("could not create file, error: %v", err)
				}
				if _, e := fmt.Fprint(f, "test content"); e != nil {
					t.Fatalf("could not write to file, error: %v", e)
				}
				if e := f.Close(); e != nil {
					t.Fatalf("could not close file, error: %v", e)
				}
				if e := m.Add(tmpDir); e != nil {
					t.Fatalf("could not add %s, error: %v", tmpDir, e)
				}
			},
		},
		{
			name: "modification delay",
			fields: fields{
				modDelay: sdk.Duration(time.Millisecond * 100),
			},
			wantCbCalledOn: map[string]*cbExpectation{
				"test1": {count: 1, err: nil},
			},
			createAndAddPath: func(t *testing.T, m *Monitor) {
				t.Helper()
				tmpDir := t.TempDir()
				if e := m.Add(tmpDir); e != nil {
					t.Fatalf("could not add %s, error: %v", tmpDir, e)
				}
				f, err := os.Create(filepath.Clean(filepath.Join(tmpDir, "test1")))
				if err != nil {
					t.Fatalf("could not create file, error: %v", err)
				}
				if _, e := fmt.Fprint(f, "test content"); e != nil {
					t.Fatalf("could not write to file, error: %v", e)
				}
				if e := f.Close(); e != nil {
					t.Fatalf("could not close file, error: %v", e)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()

			cbCalledOnMu := new(sync.Mutex)

			cb := func(path string, _ scanner.FileIdentity) (bool, error) {
				cbCalledOnMu.Lock()
				defer cbCalledOnMu.Unlock()
				name := filepath.Base(path)
				if exp, ok := tt.wantCbCalledOn[name]; ok && exp.count > 0 {
					exp.count--
					if exp.count == 0 {
						delete(tt.wantCbCalledOn, name)
					}
					if len(tt.wantCbCalledOn) == 0 {
						cancel()
					}
					return true, exp.err
				}
				return true, nil
			}

			m, err := NewMonitor(cb, Config{
				PreScan:  tt.fields.preScan,
				Period:   tt.fields.period,
				ModDelay: tt.fields.modDelay,
			})
			if tt.wantErrAtCreation != (err != nil) {
				t.Errorf("NewMonitor() error=%v, want error %t", err, tt.wantErrAtCreation)
			}
			if err != nil {
				return
			}
			defer func() {
				if e := m.Close(); e != nil {
					t.Errorf("error closing monitor, error: %v", e)
				}
			}()

			m.Start()
			tt.createAndAddPath(t, m)

			<-ctx.Done()
			if ctx.Err() == context.DeadlineExceeded {
				t.Error("timeout waiting for callbacks")
			}

			cbCalledOnMu.Lock()
			defer cbCalledOnMu.Unlock()
			for name, exp := range tt.wantCbCalledOn {
				t.Errorf("callback not called enough times on %s, remaining: %d", name, exp.count)
			}
		})
	}
}

func newTestMonitor(t *testing.T, period time.Duration, cb OnNewFileFunc) *Monitor {
	t.Helper()
	m, err := NewMonitor(cb, Config{Period: sdk.Duration(period)})
	if err != nil {
		t.Fatalf("could not create monitor, error: %v", err)
	}
	t.Cleanup(func() {
		if e := m.Close(); e != nil {
			t.Errorf("error closing monitor, error: %v", e)
		}
	})
	return m
}

func writeTestFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("could not create dir, error: %v", err)
	}
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatalf("could not write file, error: %v", err)
	}
}

// ownerRWX lets t.TempDir cleanup remove the directory made unreadable by the test.
const ownerRWX fs.FileMode = 0o700

func TestMonitor_periodicalScanContinuesAfterWalkError(t *testing.T) {
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("permission denied cannot be triggered as root or on windows")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "a-locked")
	writeTestFile(t, filepath.Join(locked, "hidden.txt"))
	writeTestFile(t, filepath.Join(root, "b-sibling", "ok1.txt"))
	writeTestFile(t, filepath.Join(root, "c-sibling", "ok2.txt"))
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("could not chmod, error: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(locked, ownerRWX); err != nil {
			t.Errorf("could not restore permissions, error: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	var mu sync.Mutex
	got := map[string]struct{}{}
	m := newTestMonitor(t, time.Millisecond, func(path string, _ scanner.FileIdentity) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		got[filepath.Base(path)] = struct{}{}
		if len(got) == 2 {
			cancel()
		}
		return true, nil
	})
	m.Start()
	m.paths.Store(root, struct{}{})

	<-ctx.Done()
	mu.Lock()
	defer mu.Unlock()
	for _, name := range []string{"ok1.txt", "ok2.txt"} {
		if _, ok := got[name]; !ok {
			t.Errorf("%s not scanned after a sibling directory failed, got %v", name, got)
		}
	}
	if _, ok := got["hidden.txt"]; ok {
		t.Error("file in unreadable directory must not be reported")
	}
}

func TestMonitor_walkRoot(t *testing.T) {
	t.Run("missing root is partial", func(t *testing.T) {
		m := newTestMonitor(t, 0, func(string, scanner.FileIdentity) (bool, error) { return true, nil })
		missing := filepath.Join(t.TempDir(), "missing")
		unreadable, _ := m.walkRoot(missing, maxUnreadableDirs)
		if m.table.Len() != 0 {
			t.Errorf("tracked = %d, want none", m.table.Len())
		}
		if len(unreadable) != 1 || unreadable[0] != missing {
			t.Errorf("unreadable = %v, want the missing root", unreadable)
		}
	})
	t.Run("complete walk is not partial, trailing slash root", func(t *testing.T) {
		root := t.TempDir()
		f := filepath.Join(root, "d", "f.txt")
		writeTestFile(t, f)
		m := newTestMonitor(t, 0, func(string, scanner.FileIdentity) (bool, error) { return true, nil })
		if u, _ := m.walkRoot(root+string(filepath.Separator), maxUnreadableDirs); len(u) != 0 {
			t.Errorf("unreadable = %v, want none", u)
		}
		if _, ok := m.table.Get(f); !ok || m.table.Len() != 1 {
			t.Errorf("tracked = %d, want only %s", m.table.Len(), f)
		}
	})
	t.Run("a directory removed before the walk reaches it is not partial", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, "a1.txt"))
		writeTestFile(t, filepath.Join(root, "c", "last.txt"))
		m := newTestMonitor(t, 0, func(string, scanner.FileIdentity) (bool, error) { return true, nil })
		unreadable, _ := m.walkRoot(root, maxUnreadableDirs)
		if m.table.Len() != 2 || len(unreadable) != 0 {
			t.Errorf("tracked = %d, unreadable = %v", m.table.Len(), unreadable)
		}
	})
	t.Run("closed monitor interrupts the walk as partial", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, "f.txt"))
		m := newTestMonitor(t, 0, func(string, scanner.FileIdentity) (bool, error) { return true, nil })
		if err := m.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		unreadable, _ := m.walkRoot(root, maxUnreadableDirs)
		if len(unreadable) == 0 {
			t.Error("an interrupted walk must protect the root from the purge")
		}
	})
	t.Run("symlinks", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlinks need privileges on windows")
		}
		root := t.TempDir()
		target := t.TempDir()
		writeTestFile(t, filepath.Join(target, "inside.txt"))
		writeTestFile(t, filepath.Join(root, "real.txt"))
		links := map[string]string{
			"dirlink":  target,
			"dangling": filepath.Join(root, "nowhere"),
			"loop":     root,
		}
		for name, dest := range links {
			if err := os.Symlink(dest, filepath.Join(root, name)); err != nil {
				t.Fatalf("could not create symlink, error: %v", err)
			}
		}
		m := newTestMonitor(t, 0, func(string, scanner.FileIdentity) (bool, error) { return true, nil })
		if u, _ := m.walkRoot(root, maxUnreadableDirs); len(u) != 0 {
			t.Errorf("unreadable = %v, want none", u)
		}
		var queued []string
		for _, name := range []string{"dangling", "dirlink", "loop", "real.txt"} {
			if _, ok := m.table.Get(filepath.Join(root, name)); ok {
				queued = append(queued, name)
			}
		}
		sort.Strings(queued)
		want := []string{"dangling", "dirlink", "loop", "real.txt"}
		if !slices.Equal(queued, want) {
			t.Errorf("queued %v, want %v: symlinks are handed over as files, never followed", queued, want)
		}
	})
}

func TestMonitor_Add_cleansPath(t *testing.T) {
	dir := t.TempDir()
	m := newTestMonitor(t, 0, func(string, scanner.FileIdentity) (bool, error) { return true, nil })
	if err := m.Add(dir + string(filepath.Separator) + "."); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if _, ok := m.paths.Load(dir); !ok {
		t.Errorf("paths must hold the cleaned path %q", dir)
	}
}

func TestMonitor_ignoresQuarantineTempFiles(t *testing.T) {
	t.Run("rescan", func(t *testing.T) {
		root := t.TempDir()
		realFile := filepath.Join(root, "real.txt")
		writeTestFile(t, realFile)
		writeTestFile(t, filepath.Join(root, quarantine.TempPrefix+"real.txt-0123456789abcdef"))
		m := newTestMonitor(t, 0, func(string, scanner.FileIdentity) (bool, error) { return true, nil })
		if u, _ := m.walkRoot(root, maxUnreadableDirs); len(u) != 0 {
			t.Errorf("unreadable = %v, want none", u)
		}
		if _, ok := m.table.Get(realFile); !ok || m.table.Len() != 1 {
			t.Errorf("tracked = %d, want only the real file", m.table.Len())
		}
	})
	t.Run("events", func(t *testing.T) {
		root := t.TempDir()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		var mu sync.Mutex
		var got []string
		m := newTestMonitor(t, 0, func(path string, _ scanner.FileIdentity) (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, filepath.Base(path))
			if filepath.Base(path) == "real.txt" {
				cancel()
			}
			return true, nil
		})
		m.Start()
		if err := m.Add(root); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(root, quarantine.TempPrefix+"real.txt-0123456789abcdef"))
		writeTestFile(t, filepath.Join(root, "real.txt"))
		<-ctx.Done()
		mu.Lock()
		defer mu.Unlock()
		for _, name := range got {
			if strings.HasPrefix(name, quarantine.TempPrefix) {
				t.Errorf("temporary file %q was scanned", name)
			}
		}
		if len(got) == 0 {
			t.Error("real file was never scanned")
		}
	})
}
