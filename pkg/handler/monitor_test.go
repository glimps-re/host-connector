package handler

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
)

func TestNewMonitor(t *testing.T) {
	type cbExpectation struct {
		count int
		err   error
	}
	type fields struct {
		preScan  bool
		reScan   bool
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
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
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
				ReScan:   tt.fields.reScan,
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
