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

			cb := func(path string) error {
				cbCalledOnMu.Lock()
				defer cbCalledOnMu.Unlock()
				t.Helper()
				info, err := os.Stat(path)
				if err != nil {
					t.Errorf("could not stat %s, error: %v", path, err)
				}
				// skip dir
				if !info.IsDir() {
					name := filepath.Base(path)
					if exp, ok := tt.wantCbCalledOn[name]; ok && exp.count > 0 {
						exp.count--
						if exp.count == 0 {
							delete(tt.wantCbCalledOn, name)
						}
						if len(tt.wantCbCalledOn) == 0 {
							cancel()
						}
						return exp.err
					}
				}
				err = filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if d.IsDir() {
						return nil
					}
					name := filepath.Base(path)
					if exp, ok := tt.wantCbCalledOn[name]; ok && exp.count > 0 {
						exp.count--
						if exp.count == 0 {
							delete(tt.wantCbCalledOn, name)
						}
						if len(tt.wantCbCalledOn) == 0 {
							cancel()
						}
						return exp.err
					}
					return nil
				})
				if err != nil {
					t.Errorf("error walk dir, error: %v", err)
				}
				return nil
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
	m := newTestMonitor(t, time.Millisecond, func(path string) error {
		mu.Lock()
		defer mu.Unlock()
		got[filepath.Base(path)] = struct{}{}
		if len(got) == 2 {
			cancel()
		}
		return nil
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
		m := newTestMonitor(t, 0, func(string) error { return nil })
		seen := map[string]struct{}{}
		if !m.walkRoot(filepath.Join(t.TempDir(), "missing"), seen) {
			t.Error("walkRoot() = false, want true for a missing root")
		}
		if len(seen) != 0 {
			t.Errorf("seen = %v, want empty", seen)
		}
	})
	t.Run("complete walk is not partial, trailing slash root", func(t *testing.T) {
		root := t.TempDir()
		f := filepath.Join(root, "d", "f.txt")
		writeTestFile(t, f)
		m := newTestMonitor(t, 0, func(string) error { return nil })
		seen := map[string]struct{}{}
		done := make(chan bool)
		go func() { done <- m.walkRoot(root+string(filepath.Separator), seen) }()
		if got := <-m.filesToScan; got != f {
			t.Errorf("queued %q, want %q", got, f)
		}
		if <-done {
			t.Error("walkRoot() = true, want false")
		}
		if _, ok := seen[f]; !ok {
			t.Errorf("seen = %v, want %s", seen, f)
		}
	})
	t.Run("subdirectory removed during the walk is not partial", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, "a1.txt"))
		writeTestFile(t, filepath.Join(root, "a2.txt"))
		gone := filepath.Join(root, "b", "gone.txt")
		writeTestFile(t, gone)
		writeTestFile(t, filepath.Join(root, "c", "last.txt"))
		m := newTestMonitor(t, 0, func(string) error { return nil })
		seen := map[string]struct{}{}
		done := make(chan bool)
		go func() { done <- m.walkRoot(root, seen) }()
		<-m.filesToScan // a1.txt: root is listed, and the walk blocks on a2.txt before reaching b
		if err := os.RemoveAll(filepath.Join(root, "b")); err != nil {
			t.Fatalf("could not remove dir, error: %v", err)
		}
		<-m.filesToScan // a2.txt
		if got := <-m.filesToScan; filepath.Base(got) != "last.txt" {
			t.Errorf("queued %q, want last.txt", got)
		}
		if <-done {
			t.Error("walkRoot() = true, want false: removed directory is not a partial walk")
		}
		if _, ok := seen[gone]; ok {
			t.Error("file of the removed directory must not be seen")
		}
	})
	t.Run("closed monitor interrupts the walk as partial", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, "f.txt"))
		m := newTestMonitor(t, 0, func(string) error { return nil })
		if err := m.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		if !m.walkRoot(root, map[string]struct{}{}) {
			t.Error("walkRoot() = false, want true after Close")
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
		m := newTestMonitor(t, 0, func(string) error { return nil })
		seen := map[string]struct{}{}
		done := make(chan bool)
		go func() { done <- m.walkRoot(root, seen) }()
		var queued []string
		for range 4 {
			queued = append(queued, filepath.Base(<-m.filesToScan))
		}
		if <-done {
			t.Error("walkRoot() = true, want false: symlinks are entries, not errors")
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
	m := newTestMonitor(t, 0, func(string) error { return nil })
	if err := m.Add(dir + string(filepath.Separator) + "."); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if _, ok := m.paths.Load(dir); !ok {
		t.Errorf("paths must hold the cleaned path %q", dir)
	}
}

func TestMonitor_purgeStates(t *testing.T) {
	sep := string(filepath.Separator)
	m := newTestMonitor(t, 0, func(string) error { return nil })
	seenFile := sep + "r" + sep + "seen"
	keptPartial := sep + "p" + sep + "d" + sep + "f"
	goneComplete := sep + "r" + sep + "gone"
	otherPrefix := sep + "p-other" + sep + "f"
	for _, k := range []string{seenFile, keptPartial, goneComplete, otherPrefix} {
		m.states.Store(k, fileState{})
	}
	m.purgeStates(map[string]struct{}{seenFile: {}}, []string{sep + "p"})
	for k, wantKept := range map[string]bool{seenFile: true, keptPartial: true, goneComplete: false, otherPrefix: false} {
		if _, ok := m.states.Load(k); ok != wantKept {
			t.Errorf("state %s kept = %t, want %t", k, ok, wantKept)
		}
	}
}

func TestUnderAny(t *testing.T) {
	sep := string(filepath.Separator)
	tests := []struct {
		name  string
		path  string
		roots []string
		want  bool
	}{
		{name: "no roots", path: sep + "a" + sep + "f", want: false},
		{name: "under root", path: sep + "a" + sep + "f", roots: []string{sep + "a"}, want: true},
		{name: "root itself", path: sep + "a", roots: []string{sep + "a"}, want: true},
		{name: "sibling with same prefix", path: sep + "ab" + sep + "f", roots: []string{sep + "a"}, want: false},
		{name: "other root", path: sep + "b" + sep + "f", roots: []string{sep + "a"}, want: false},
		{name: "root with trailing separator", path: sep + "a" + sep + "d" + sep + "f", roots: []string{sep + "a" + sep}, want: true},
		{name: "filesystem root", path: sep + "x" + sep + "f", roots: []string{sep}, want: true},
		{name: "relative root", path: "in" + sep + "d" + sep + "f", roots: []string{"in"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := underAny(tt.path, tt.roots); got != tt.want {
				t.Errorf("underAny() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestMonitor_ignoresQuarantineTempFiles(t *testing.T) {
	t.Run("rescan", func(t *testing.T) {
		root := t.TempDir()
		realFile := filepath.Join(root, "real.txt")
		writeTestFile(t, realFile)
		writeTestFile(t, filepath.Join(root, quarantine.TempPrefix+"real.txt-0123456789abcdef"))
		m := newTestMonitor(t, 0, func(string) error { return nil })
		seen := map[string]struct{}{}
		done := make(chan bool)
		go func() { done <- m.walkRoot(root, seen) }()
		if got := <-m.filesToScan; got != realFile {
			t.Errorf("queued %q, want %q", got, realFile)
		}
		if <-done {
			t.Error("walkRoot() = true, want false")
		}
		if len(seen) != 1 {
			t.Errorf("seen = %v, want only the real file", seen)
		}
	})
	t.Run("events", func(t *testing.T) {
		root := t.TempDir()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		var mu sync.Mutex
		var got []string
		m := newTestMonitor(t, 0, func(path string) error {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, filepath.Base(path))
			if filepath.Base(path) == "real.txt" {
				cancel()
			}
			return nil
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
