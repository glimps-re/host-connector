package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/filesystem"
)

func TestMonitor_work(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "test",
			test: func(t *testing.T) {
				tmpDir := t.TempDir()
				sb := &strings.Builder{}
				cb := func(path string) error {
					if _, err := fmt.Fprintf(sb, "event %s\n", filepath.Base(path)); err != nil {
						t.Errorf("error writing to string builder, error: %v", err)
					}
					return nil
				}
				monitor, err := NewMonitor(filesystem.NewLocalFileSystem(), cb, false, time.Millisecond, 0)
				if err != nil {
					t.Errorf("could not create new monitor, error: %s", err)
					return
				}
				defer monitor.Close()
				monitor.Start()
				if err := monitor.Add(tmpDir); err != nil {
					t.Errorf("could not add tmpDir watcher, error = %v", err)
					return
				}
				f, err := os.Create(filepath.Join(tmpDir, "test1")) //nolint:gosec // test file only
				if err != nil {
					t.Errorf("could not create test file test1, error: %s", err)
					return
				}
				if _, err = f.WriteString("test content"); err != nil {
					t.Errorf("could not write content to file: %v", err)
				}
				if err := f.Close(); err != nil {
					t.Errorf("could not close test file, err: %v", err)
				}
				time.Sleep(time.Millisecond * 10)
				monitor.Close()
				got := sb.String()
				want := "event test1\n"
				if got != want {
					t.Errorf("invalid callback output, got: %s, want: %s", got, want)
				}
			},
		},
		{
			name: "test move",
			test: func(t *testing.T) {
				// temp dir
				tmpDir := t.TempDir()
				sb := &strings.Builder{}
				cb := func(path string) error {
					if _, err := fmt.Fprintf(sb, "event %s\n", filepath.Base(path)); err != nil {
						t.Errorf("error writing to string builder, error: %v", err)
					}
					return nil
				}
				monitor, err := NewMonitor(filesystem.NewLocalFileSystem(), cb, false, time.Millisecond, 0)
				if err != nil {
					t.Errorf("could not create new monitor, error: %s", err)
					return
				}
				defer monitor.Close()
				monitor.Start()
				if err := monitor.Add(tmpDir); err != nil {
					t.Errorf("could not add tmpDir watcher, error = %v", err)
					return
				}
				f, err := os.CreateTemp(t.TempDir(), "test1_*")
				if err != nil {
					t.Errorf("could not create test file test1, error: %s", err)
					return
				}
				if _, err = f.WriteString("test content"); err != nil {
					t.Errorf("could not write content to file, error: %v", err)
				}
				if err := f.Close(); err != nil {
					t.Errorf("could not close test file, error: %v", err)
				}

				if err := os.Rename(f.Name(), filepath.Join(tmpDir, "test11")); err != nil {
					t.Errorf("could not rename test file, error: %s", err)
				}
				time.Sleep(time.Millisecond * 10)
				monitor.Close()
				got := sb.String()
				want := "event test11\n"
				if got != want {
					t.Errorf("invalid callback output, got: %s, want: %s", got, want)
				}
			},
		},
		{
			name: "test remove",
			test: func(t *testing.T) {
				// temp dir
				tmpDir := t.TempDir()
				sb := &strings.Builder{}
				cb := func(path string) error {
					if _, err := fmt.Fprintf(sb, "event %s\n", filepath.Base(path)); err != nil {
						t.Errorf("error writing to string builder, error: %v", err)
					}
					return nil
				}
				monitor, err := NewMonitor(filesystem.NewLocalFileSystem(), cb, false, time.Millisecond, 0)
				if err != nil {
					t.Errorf("could not create new monitor, error: %s", err)
					return
				}
				defer monitor.Close()
				monitor.Start()
				if err := monitor.Add(tmpDir); err != nil {
					t.Errorf("could not add tmpDir watcher, error = %v", err)
					return
				}
				f, err := os.Create(filepath.Join(tmpDir, "test1")) //nolint:gosec // test file only
				if err != nil {
					t.Errorf("could not create test file test1, error: %s", err)
					return
				}
				if _, err = f.WriteString("test content"); err != nil {
					t.Errorf("could not write content to file: %v", err)
				}
				if err := f.Close(); err != nil {
					t.Errorf("could not close test file, err: %v", err)
				}

				time.Sleep(time.Millisecond * 10)
				if err := monitor.Remove(tmpDir); err != nil {
					t.Errorf("could not remove tmpDir from monitor, err: %s", err)
				}
				f2, err := os.Create(filepath.Join(tmpDir, "test2")) //nolint:gosec // test file only
				if err != nil {
					t.Errorf("could not create test file test2, error: %s", err)
					return
				}
				if _, err := f2.WriteString("test2 content"); err != nil {
					t.Errorf("could not write content to file test 2, error: %v", err)
				}
				if err := f2.Close(); err != nil {
					t.Errorf("could not close file test 2, error: %v", err)
				}
				time.Sleep(time.Millisecond * 10)
				monitor.Close()
				got := sb.String()
				want := "event test1\n"
				if got != want {
					t.Errorf("invalid callback output, got: %s, want: %s", got, want)
				}
			},
		},
		{
			name: "test pre-scan",
			test: func(t *testing.T) {
				// temp dir
				tmpDir := t.TempDir()
				f, err := os.Create(filepath.Join(tmpDir, "test1")) //nolint:gosec // test file only
				if err != nil {
					t.Errorf("could not create test file test1, error: %s", err)
					return
				}
				if _, err = f.WriteString("test content"); err != nil {
					t.Errorf("could not write content to file: %v", err)
				}
				if err := f.Close(); err != nil {
					t.Errorf("could not close test file, err: %v", err)
				}

				sb := &strings.Builder{}
				cb := func(path string) error {
					if _, err := fmt.Fprintf(sb, "event %s\n", filepath.Base(path)); err != nil {
						t.Errorf("error writing to string builder, error: %v", err)
					}
					return nil
				}
				monitor, err := NewMonitor(filesystem.NewLocalFileSystem(), cb, true, time.Millisecond, 0)
				if err != nil {
					t.Errorf("could not create new monitor, error: %s", err)
					return
				}
				defer monitor.Close()
				monitor.Start()
				if err := monitor.Add(tmpDir); err != nil {
					t.Errorf("could not add tmpDir watcher, error = %v", err)
					return
				}

				time.Sleep(time.Millisecond * 10)
				monitor.Close()
				got := sb.String()
				fields := strings.Split(tmpDir, "/")
				want := "event " + fields[len(fields)-1]
				if !strings.HasPrefix(got, want) {
					t.Errorf("invalid callback output, got: %s, want: %s", got, want)
				}
			},
		},
		{
			name: "test modDelay file stability",
			test: func(t *testing.T) {
				tmpDir := t.TempDir()
				sb := &strings.Builder{}
				callbackCount := 0

				cb := func(path string) error {
					callbackCount++
					if _, err := fmt.Fprintf(sb, "event %s\n", filepath.Base(path)); err != nil {
						t.Errorf("error writing to string builder, error: %v", err)
					}
					return nil
				}

				// Configure monitor with 200ms modDelay
				modDelay := time.Millisecond * 20
				monitor, err := NewMonitor(filesystem.NewLocalFileSystem(), cb, false, time.Millisecond, modDelay)
				if err != nil {
					t.Errorf("could not create new monitor, error: %s", err)
					return
				}
				defer monitor.Close()

				monitor.Start()
				if err := monitor.Add(tmpDir); err != nil {
					t.Errorf("could not add tmpDir watcher, error = %v", err)
					return
				}

				// Create a file - it should be detected but not processed immediately due to modDelay
				f, err := os.Create(filepath.Join(tmpDir, "test_moddelay")) //nolint:gosec // test file only
				if err != nil {
					t.Errorf("could not create test file, error: %s", err)
					return
				}
				if _, err = f.WriteString("test content"); err != nil {
					t.Errorf("could not write content to file: %v", err)
				}
				if err := f.Close(); err != nil {
					t.Errorf("could not close test file, err: %v", err)
				}

				// Wait less than modDelay - file should not be processed yet
				time.Sleep(time.Millisecond * 10)
				if callbackCount != 0 {
					t.Errorf("file processed too early, callback count: %d, expected: 0", callbackCount)
				}

				// Wait for modDelay to pass - file should now be processed
				time.Sleep(modDelay + time.Millisecond*10)

				monitor.Close()

				if callbackCount != 1 {
					t.Errorf("callback not called after modDelay, count: %d, expected: 1", callbackCount)
				}

				got := sb.String()
				want := "event test_moddelay\n"
				if got != want {
					t.Errorf("invalid callback output, got: %s, want: %s", got, want)
				}
			},
		},
		{
			name: "test modDelay with file modification",
			test: func(t *testing.T) {
				tmpDir := t.TempDir()
				sb := &strings.Builder{}
				callbackCount := 0

				cb := func(path string) error {
					callbackCount++
					if _, err := fmt.Fprintf(sb, "event %s count:%d\n", filepath.Base(path), callbackCount); err != nil {
						t.Errorf("error writing to string builder, error: %v", err)
					}
					return nil
				}

				// Configure monitor with 30ms modDelay and faster scan period
				modDelay := time.Millisecond * 30
				monitor, err := NewMonitor(filesystem.NewLocalFileSystem(), cb, false, time.Millisecond, modDelay)
				if err != nil {
					t.Errorf("could not create new monitor, error: %s", err)
					return
				}
				defer monitor.Close()

				monitor.Start()
				if err := monitor.Add(tmpDir); err != nil {
					t.Errorf("could not add tmpDir watcher, error = %v", err)
					return
				}

				// Create and immediately modify a file multiple times
				testFile := filepath.Join(tmpDir, "test_moddelay_modify")
				f, err := os.Create(testFile) //nolint:gosec // test file only
				if err != nil {
					t.Errorf("could not create test file, error: %s", err)
					return
				}
				if _, err = f.WriteString("initial content"); err != nil {
					t.Errorf("could not write initial content to file: %v", err)
				}
				if err := f.Close(); err != nil {
					t.Errorf("could not close test file, err: %v", err)
				}

				// Wait a bit and modify the file again (within modDelay period)
				time.Sleep(time.Millisecond * 10)

				f, err = os.OpenFile(testFile, os.O_RDWR, 0o600) //nolint:gosec // it's the test file
				if err != nil {
					t.Errorf("could not reopen test file, error: %s", err)
					return
				}
				if _, err = f.WriteString(" modified"); err != nil {
					t.Errorf("could not write modified content to file: %v", err)
				}
				if err := f.Close(); err != nil {
					t.Errorf("could not close test file, err: %v", err)
				}

				// File should still not be processed due to recent modification
				time.Sleep(time.Millisecond * 10)
				if callbackCount != 0 {
					t.Errorf("file processed despite recent modification, callback count: %d, expected: 0", callbackCount)
				}

				// Wait for modDelay to pass after last modification
				time.Sleep(modDelay + time.Millisecond*10)

				monitor.Close()

				// File should be processed exactly once after stability period
				if callbackCount != 1 {
					t.Errorf("unexpected callback count after modDelay, got: %d, expected: 1", callbackCount)
				}

				got := sb.String()
				want := "event test_moddelay_modify count:1\n"
				if got != want {
					t.Errorf("invalid callback output, got: %s, want: %s", got, want)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}
