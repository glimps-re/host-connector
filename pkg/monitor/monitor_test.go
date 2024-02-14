package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMonitor_work(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "test",
			test: func(t *testing.T) {
				// temp dir
				tmpDir, err := os.MkdirTemp(os.TempDir(), "test_monitor_*")
				if err != nil {
					t.Errorf("could not create temp dir for test, error: %s", err)
					return
				}
				defer os.RemoveAll(tmpDir)
				sb := &strings.Builder{}
				cb := func(path string) error {
					fmt.Fprintf(sb, "event %s\n", filepath.Base(path))
					return nil
				}
				monitor, err := NewMonitor(cb, false, 0, 0)
				if err != nil {
					t.Errorf("could not create new monitor, error: %s", err)
					return
				}
				defer monitor.Close()
				if err != nil {
					t.Errorf("could not create new Monitor, error: %s", err)
					return
				}
				monitor.Start()
				monitor.Add(tmpDir)
				f, err := os.Create(filepath.Join(tmpDir, "test1"))
				if err != nil {
					t.Errorf("could not create test file test1, error: %s", err)
					return
				}
				f.WriteString("test content")
				f.Close()
				time.Sleep(time.Millisecond * 100)
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
				tmpDir, err := os.MkdirTemp(os.TempDir(), "test_monitor_*")
				if err != nil {
					t.Errorf("could not create temp dir for test, error: %s", err)
					return
				}
				defer os.RemoveAll(tmpDir)
				sb := &strings.Builder{}
				cb := func(path string) error {
					fmt.Fprintf(sb, "event %s\n", filepath.Base(path))
					return nil
				}
				monitor, err := NewMonitor(cb, false, 0, 0)
				if err != nil {
					t.Errorf("could not create new monitor, error: %s", err)
					return
				}
				defer monitor.Close()
				if err != nil {
					t.Errorf("could not create new Monitor, error: %s", err)
					return
				}
				monitor.Start()
				monitor.Add(tmpDir)
				f, err := os.CreateTemp(os.TempDir(), "test1_*")
				if err != nil {
					t.Errorf("could not create test file test1, error: %s", err)
					return
				}
				f.WriteString("test content")
				f.Close()
				os.Rename(f.Name(), filepath.Join(tmpDir, "test11"))
				time.Sleep(time.Millisecond * 100)
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
				tmpDir, err := os.MkdirTemp(os.TempDir(), "test_monitor_*")
				if err != nil {
					t.Errorf("could not create temp dir for test, error: %s", err)
					return
				}
				defer os.RemoveAll(tmpDir)
				sb := &strings.Builder{}
				cb := func(path string) error {
					fmt.Fprintf(sb, "event %s\n", filepath.Base(path))
					return nil
				}
				monitor, err := NewMonitor(cb, false, 0, 0)
				if err != nil {
					t.Errorf("could not create new monitor, error: %s", err)
					return
				}
				defer monitor.Close()
				if err != nil {
					t.Errorf("could not create new Monitor, error: %s", err)
					return
				}
				monitor.Start()
				monitor.Add(tmpDir)
				f, err := os.Create(filepath.Join(tmpDir, "test1"))
				if err != nil {
					t.Errorf("could not create test file test1, error: %s", err)
					return
				}
				f.WriteString("test content")
				f.Close()
				time.Sleep(time.Millisecond * 100)
				monitor.Remove(tmpDir)
				f2, err := os.Create(filepath.Join(tmpDir, "test2"))
				if err != nil {
					t.Errorf("could not create test file test2, error: %s", err)
					return
				}
				f2.WriteString("test2 content")
				f2.Close()
				time.Sleep(time.Millisecond * 100)
				monitor.Remove(tmpDir)
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
				tmpDir, err := os.MkdirTemp(os.TempDir(), "test_monitor_*")
				if err != nil {
					t.Errorf("could not create temp dir for test, error: %s", err)
					return
				}
				defer os.RemoveAll(tmpDir)
				f, err := os.Create(filepath.Join(tmpDir, "test1"))
				if err != nil {
					t.Errorf("could not create test file test1, error: %s", err)
					return
				}
				f.WriteString("test content")
				f.Close()

				sb := &strings.Builder{}
				cb := func(path string) error {
					fmt.Fprintf(sb, "event %s\n", filepath.Base(path))
					return nil
				}
				monitor, err := NewMonitor(cb, true, 0, 0)
				if err != nil {
					t.Errorf("could not create new monitor, error: %s", err)
					return
				}
				defer monitor.Close()
				if err != nil {
					t.Errorf("could not create new Monitor, error: %s", err)
					return
				}
				monitor.Start()
				monitor.Add(tmpDir)

				time.Sleep(time.Millisecond * 100)
				monitor.Close()
				got := sb.String()
				want := "event test_monitor"
				if !strings.HasPrefix(got, want) {
					t.Errorf("invalid callback output, got: %s, want: %s", got, want)
				}
			},
		},
		{
			name: "test period",
			test: func(t *testing.T) {
				// temp dir
				tmpDir, err := os.MkdirTemp(os.TempDir(), "test_monitor_*")
				if err != nil {
					t.Errorf("could not create temp dir for test, error: %s", err)
					return
				}
				defer os.RemoveAll(tmpDir)
				f, err := os.Create(filepath.Join(tmpDir, "test1"))
				if err != nil {
					t.Errorf("could not create test file test1, error: %s", err)
					return
				}
				f.WriteString("test content")
				f.Close()

				sb := &strings.Builder{}
				cb := func(path string) error {
					fmt.Fprintf(sb, "event %s\n", filepath.Base(path))
					return nil
				}
				monitor, err := NewMonitor(cb, false, time.Millisecond*60, 0)
				if err != nil {
					t.Errorf("could not create new monitor, error: %s", err)
					return
				}
				defer monitor.Close()
				if err != nil {
					t.Errorf("could not create new Monitor, error: %s", err)
					return
				}
				monitor.Start()
				monitor.Add(tmpDir)

				time.Sleep(time.Millisecond * 100)
				monitor.Close()
				got := sb.String()
				want := "event test_monitor"
				if !strings.HasPrefix(got, want) {
					t.Errorf("invalid callback output, got: %s, want: %s", got, want)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}
