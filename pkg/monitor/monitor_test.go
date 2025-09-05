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
				tmpDir := t.TempDir()
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
				monitor.Start()
				err = monitor.Add(tmpDir)
				if err != nil {
					t.Fatalf("test monitor, could not add path : %s", err)
				}
				f, err := os.Create(filepath.Join(filepath.Clean(tmpDir), "test1"))
				if err != nil {
					t.Errorf("could not create test file test1, error: %s", err)
					return
				}
				_, err = f.WriteString("test content")
				if err != nil {
					t.Fatalf("test monitor, could not write string : %s", err)
				}
				err = f.Close()
				if err != nil {
					t.Fatalf("test monitor, could not close file : %s", err)
				}
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
				tmpDir := t.TempDir()
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
				monitor.Start()
				err = monitor.Add(tmpDir)
				if err != nil {
					t.Fatalf("test monitor, could not add path : %s", err)
				}
				f, err := os.CreateTemp(os.TempDir(), "test1_*")
				if err != nil {
					t.Errorf("could not create test file test1, error: %s", err)
					return
				}
				_, err = f.WriteString("test content")
				if err != nil {
					t.Fatalf("test monitor, could not write string : %s", err)
				}
				err = f.Close()
				if err != nil {
					t.Fatalf("test monitor, could not close file : %s", err)
				}
				err = os.Rename(f.Name(), filepath.Join(filepath.Clean(tmpDir), "test11"))
				if err != nil {
					t.Fatalf("test monitor, could not rename file : %s", err)
				}
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
				tmpDir := t.TempDir()
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
				monitor.Start()
				err = monitor.Add(tmpDir)
				if err != nil {
					t.Fatalf("test monitor, could not add path : %s", err)
				}
				f, err := os.Create(filepath.Join(filepath.Clean(tmpDir), "test1"))
				if err != nil {
					t.Errorf("could not create test file test1, error: %s", err)
					return
				}
				_, err = f.WriteString("test content")
				if err != nil {
					t.Fatalf("test monitor, could not add path : %s", err)
				}
				err = f.Close()
				if err != nil {
					t.Fatalf("test monitor, could not add path : %s", err)
				}
				time.Sleep(time.Millisecond * 100)
				err = monitor.Remove(tmpDir)
				if err != nil {
					t.Fatalf("test monitor, could not remove tmp dir : %s", err)
				}
				f2, err := os.Create(filepath.Join(filepath.Clean(tmpDir), "test2"))
				if err != nil {
					t.Errorf("could not create test file test2, error: %s", err)
					return
				}
				_, err = f2.WriteString("test2 content")
				if err != nil {
					t.Fatalf("test monitor, could not write string : %s", err)
				}
				err = f2.Close()
				if err != nil {
					t.Fatalf("test monitor, could not close file : %s", err)
				}
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
			name: "test pre-scan",
			test: func(t *testing.T) {
				// temp dir
				tmpDir := t.TempDir()
				f, err := os.Create(filepath.Join(filepath.Clean(tmpDir), "test1"))
				if err != nil {
					t.Errorf("could not create test file test1, error: %s", err)
					return
				}
				_, err = f.WriteString("test content")
				if err != nil {
					t.Fatalf("test monitor, could not write string : %s", err)
				}
				err = f.Close()
				if err != nil {
					t.Fatalf("test monitor, could not close file : %s", err)
				}

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
				monitor.Start()
				err = monitor.Add(tmpDir)
				if err != nil {
					t.Fatalf("test monitor, could not add path : %s", err)
				}

				time.Sleep(time.Millisecond * 100)
				monitor.Close()
				got := sb.String()
				want := "event 001"
				if !strings.HasPrefix(got, want) {
					t.Errorf("invalid callback output, got: %s, want: %s", got, want)
				}
			},
		},
		{
			name: "test period",
			test: func(t *testing.T) {
				// temp dir
				tmpDir := t.TempDir()
				f, err := os.Create(filepath.Join(filepath.Clean(tmpDir), "test1"))
				if err != nil {
					t.Errorf("could not create test file test1, error: %s", err)
					return
				}
				_, err = f.WriteString("test content")
				if err != nil {
					t.Fatalf("test monitor, could not write string : %s", err)
				}
				err = f.Close()
				if err != nil {
					t.Fatalf("test monitor, could not close file : %s", err)
				}

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
				monitor.Start()
				err = monitor.Add(tmpDir)
				if err != nil {
					t.Fatalf("test monitor, could not add path : %s", err)
				}

				time.Sleep(time.Millisecond * 100)
				monitor.Close()
				got := sb.String()
				want := "event 001"
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
