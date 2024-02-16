package scanner

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/cache"
)

func TestReportAction_Handle(t *testing.T) {
	type args struct {
		path   string
		sha256 string
		result gdetect.Result
		report *Report
	}
	tests := []struct {
		name       string
		a          *ReportAction
		args       args
		wantErr    bool
		wantReport Report
	}{
		{
			name: "test",
			args: args{
				path:   "/tmp/test1",
				sha256: "123456789",
				result: gdetect.Result{Malware: true},
				report: &Report{
					FileName: "test",
					Deleted:  true,
				},
			},
			a:       &ReportAction{},
			wantErr: false,
			wantReport: Report{
				FileName:  "/tmp/test1",
				Sha256:    "123456789",
				Deleted:   true,
				Malicious: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &ReportAction{}
			if err := a.Handle(tt.args.path, tt.args.sha256, tt.args.result, tt.args.report); (err != nil) != tt.wantErr {
				t.Errorf("ReportAction.Handle() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(tt.wantReport, *tt.args.report) {
				t.Errorf("ReportAction.Handle() report = %#v, want %#v", *tt.args.report, tt.wantReport)
			}
		})
	}
}

func TestLogAction_Handle(t *testing.T) {
	type args struct {
		path   string
		sha256 string
		result gdetect.Result
		report *Report
	}
	tests := []struct {
		name     string
		args     args
		wantErr  bool
		wantLog  string
		logLevel slog.Level
	}{
		{
			name: "test",
			args: args{
				path:   "/tmp/test1",
				sha256: "123456789",
				result: gdetect.Result{Malware: true},
				report: &Report{
					FileName: "test",
					Deleted:  true,
				},
			},
			logLevel: slog.LevelDebug,
			wantLog: `{"time":"2024-01-25T12:55:00Z","level":"INFO","msg":"info scanned","file":"/tmp/test1","sha256":"123456789","malware":true,"malwares":[]}
`,
		},
		{
			name: "test debug false",
			args: args{
				path:   "/tmp/test1",
				sha256: "123456789",
				result: gdetect.Result{Malware: false},
				report: &Report{
					FileName: "test",
					Deleted:  true,
				},
			},
			logLevel: slog.LevelInfo,
			wantLog:  ``,
		},
		{
			name: "test debug true",
			args: args{
				path:   "/tmp/test1",
				sha256: "123456789",
				result: gdetect.Result{Malware: false},
				report: &Report{
					FileName: "test",
					Deleted:  true,
				},
			},
			logLevel: slog.LevelDebug,
			wantLog: `{"time":"2024-01-25T12:55:00Z","level":"DEBUG","msg":"info scanned","file":"/tmp/test1","sha256":"123456789","malware":false}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buffer bytes.Buffer
			refTime, err := time.Parse(time.RFC3339, "2024-01-25T12:55:00Z")
			if err != nil {
				t.Errorf("LogAction.Handle() could not parse ref time, error = %v", err)
				return
			}

			a := &LogAction{
				logger: slog.New(slog.NewJSONHandler(&buffer, &slog.HandlerOptions{
					Level: tt.logLevel,
					ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
						if a.Key == "time" {
							return slog.Attr{
								Key:   a.Key,
								Value: slog.TimeValue(refTime),
							}
						}
						return a
					},
				})),
			}
			if err := a.Handle(tt.args.path, tt.args.sha256, tt.args.result, tt.args.report); (err != nil) != tt.wantErr {
				t.Errorf("LogAction.Handle() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			result := buffer.String()
			if result != tt.wantLog {
				t.Errorf("LogAction.Handle() log = %v, want %v", result, tt.wantLog)
			}
		})
	}
}

func TestRemoveFileAction_Handle(t *testing.T) {
	type args struct {
		path   string
		sha256 string
		result gdetect.Result
		report *Report
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "test malware",
			args: args{
				path:   "test_malware",
				result: gdetect.Result{Malware: true},
				report: &Report{},
			},
		},
		{
			name: "test not malware",
			args: args{
				path:   "test_malware",
				result: gdetect.Result{Malware: false},
				report: &Report{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &RemoveFileAction{}
			if tt.args.path != "" {
				f, err := os.CreateTemp(os.TempDir(), fmt.Sprintf("test-action-%s-*", tt.args.path))
				if err != nil {
					t.Errorf("RemoveFileAction.Handle() could not create tmp file, error = %v", err)
					return
				}
				f.WriteString("test 1234")
				f.Close()
				defer os.Remove(f.Name())
				tt.args.path = f.Name()
			}
			if err := a.Handle(tt.args.path, tt.args.sha256, tt.args.result, tt.args.report); (err != nil) != tt.wantErr {
				t.Errorf("RemoveFileAction.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.args.path == "" {
				return
			}

			_, err := os.Stat(tt.args.path)
			switch {
			case tt.args.result.Malware && !errors.Is(err, os.ErrNotExist):
				t.Errorf("RemoveFileAction.Handle() temp file found for malware, error = %v", err)
			case !tt.args.result.Malware && err != nil:
				t.Errorf("RemoveFileAction.Handle() temp file not found for legit")
			case tt.args.result.Malware && !tt.args.report.Deleted:
				t.Errorf("RemoveFileAction.Handle() report not updated after deletion")
			}
		})
	}
}

func TestQuarantineAction_Handle(t *testing.T) {
	type fields struct {
		cache  cache.Cacher
		root   string
		locker Locker
	}
	type args struct {
		path   string
		sha256 string
		result gdetect.Result
		report *Report
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test legit",
			fields: fields{
				cache:  &cache.MockCache{},
				locker: &MockLock{},
				root:   "quarantine",
			},
			args: args{
				path:   "test_quarantine",
				sha256: "123456",
			},
		},
		{
			name: "test error",
			fields: fields{
				cache: &cache.MockCache{},
				locker: &MockLock{
					LockFileMock: func(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error {
						return fmt.Errorf("test")
					},
				},
				root: "quarantine",
			},
			args: args{
				path:   "test_quarantine",
				sha256: "123456",
				result: gdetect.Result{Malware: true},
			},
			wantErr: true,
		},
		{
			name: "test error 2",
			fields: fields{
				cache: &cache.MockCache{
					SetMock: func(entry *cache.Entry) error {
						return fmt.Errorf("test")
					},
				},
				locker: &MockLock{
					LockFileMock: func(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error {
						return nil
					},
				},
				root: "quarantine",
			},
			args: args{
				path:   "test_quarantine",
				sha256: "123456",
				result: gdetect.Result{Malware: true},
			},
			wantErr: true,
		},
		{
			name: "test malware",
			fields: fields{
				cache: &cache.MockCache{
					SetMock: func(entry *cache.Entry) error {
						if entry.Sha256 != "123456" {
							return fmt.Errorf("invalid sha256: %s", entry.Sha256)
						}
						return nil
					},
				},
				locker: &MockLock{
					LockFileMock: func(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error {
						if !strings.Contains(file, "test_quarantine1234") {
							return fmt.Errorf("invalid file: %s", file)
						}
						if reason != "malware: unknown" {
							return fmt.Errorf("invalid reason: %s", reason)
						}
						return nil
					},
				},
				root: "quarantine",
			},
			args: args{
				path:   "test_quarantine1234",
				sha256: "123456",
				result: gdetect.Result{Malware: true},
				report: &Report{},
			},
		},
		{
			name: "test malware 2",
			fields: fields{
				cache: &cache.MockCache{
					SetMock: func(entry *cache.Entry) error {
						if entry.Sha256 != "123456" {
							return fmt.Errorf("invalid sha256: %s", entry.Sha256)
						}
						return nil
					},
				},
				locker: &MockLock{
					LockFileMock: func(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error {
						if !strings.Contains(file, "test_quarantine1234") {
							return fmt.Errorf("invalid file: %s", file)
						}
						if reason != "malware: eicar" {
							return fmt.Errorf("invalid reason: %s", reason)
						}
						return nil
					},
				},
				root: "quarantine",
			},
			args: args{
				path:   "test_quarantine1234",
				sha256: "123456",
				result: gdetect.Result{Malware: true, Malwares: []string{"eicar"}},
				report: &Report{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.args.path != "" {
				f, err := os.CreateTemp(os.TempDir(), fmt.Sprintf("test-action-%s-*", tt.args.path))
				if err != nil {
					t.Errorf("QuarantineAction.Handle() could not create tmp file, error = %v", err)
					return
				}
				f.WriteString("test 1234")
				defer f.Close()
				defer os.Remove(f.Name())
				tt.args.path = f.Name()
			}
			if tt.fields.root != "" {
				f, err := os.MkdirTemp(os.TempDir(), fmt.Sprintf("test-action-%s-*", tt.fields.root))
				if err != nil {
					t.Errorf("QuarantineAction.Handle() could not create tmp dir, error = %v", err)
					return
				}
				defer os.Remove(f)
				tt.fields.root = f
			}
			a := &QuarantineAction{
				cache:  tt.fields.cache,
				root:   tt.fields.root,
				locker: tt.fields.locker,
			}
			if err := a.Handle(tt.args.path, tt.args.sha256, tt.args.result, tt.args.report); (err != nil) != tt.wantErr {
				t.Errorf("QuarantineAction.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestInformAction_Handle(t *testing.T) {
	type fields struct {
		Verbose bool
	}
	type args struct {
		path   string
		sha256 string
		result gdetect.Result
		report *Report
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		wantOut string
	}{
		{
			name: "test empty",
			fields: fields{
				Verbose: false,
			},
			args: args{
				result: gdetect.Result{
					Malware: false,
				},
				report: &Report{},
			},
			wantOut: ``,
		},
		{
			name: "test legit verbose",
			fields: fields{
				Verbose: true,
			},
			args: args{
				result: gdetect.Result{
					Malware: false,
				},
				path:   "test_file.bin",
				report: &Report{},
			},
			wantOut: `file test_file.bin no malware found`,
		},
		{
			name: "test malware",
			fields: fields{
				Verbose: true,
			},
			args: args{
				result: gdetect.Result{
					Malware: true,
				},
				path:   "test_file.bin",
				report: &Report{},
			},
			wantOut: `file test_file.bin seems malicious`,
		},
		{
			name: "test malware quarantine",
			fields: fields{
				Verbose: true,
			},
			args: args{
				result: gdetect.Result{
					Malware:  true,
					Malwares: []string{"eicar", "test_eicar"},
				},
				path: "test_file.bin",
				report: &Report{
					Deleted:            true,
					QuarantineLocation: "/tmp/q/test.lock",
				},
			},
			wantOut: `file test_file.bin seems malicious [[eicar test_eicar]], it has been quarantine to /tmp/q/test.lock, it has been deleted`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			a := &InformAction{
				Verbose: tt.fields.Verbose,
				Out:     &out,
			}
			if err := a.Handle(tt.args.path, tt.args.sha256, tt.args.result, tt.args.report); (err != nil) != tt.wantErr {
				t.Errorf("InformAction.Handle() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got := strings.TrimSuffix(out.String(), "\n")
			if tt.wantOut != "" && got != tt.wantOut {
				t.Errorf("InformAction.Handle() got = %v, want %v", got, tt.wantOut)
				return
			}
		})
	}
}

func TestQuarantineAction_ListQuarantinedFiles(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "test",
			test: func(t *testing.T) {
				tmpDir, err := os.MkdirTemp(os.TempDir(), "test_list_quarantine_*")
				if err != nil {
					t.Errorf("could not create test dir, error: %s", err)
					return
				}
				defer os.RemoveAll(tmpDir)

				a := NewQuarantineAction(
					&cache.MockCache{},
					tmpDir,
					&MockLock{
						GetHeaderMock: func(in io.Reader) (entry LockEntry, err error) {
							var buffer bytes.Buffer
							io.Copy(&buffer, in)
							if buffer.String() != "test_content" {
								return entry, fmt.Errorf("invalid locked content: %s", buffer.String())
							}
							return LockEntry{Filepath: "test.bin", Reason: "malicious"}, nil
						},
					},
				)
				os.MkdirTemp(tmpDir, "folder")
				f, err := os.CreateTemp(tmpDir, "test_*.lock")
				if err != nil {
					t.Errorf("could not create test file, error: %s", err)
					return
				}
				f.WriteString("test_content")
				f.Close()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
				defer cancel()
				qfiles, err := a.ListQuarantinedFiles(ctx)
				if err != nil {
					t.Errorf("QuarantineAction.ListQuarantinedFiles, error: %s", err)
					return
				}
				select {
				case e := <-qfiles:
					if e.Filepath != "test.bin" {
						t.Errorf("QuarantineAction.ListQuarantinedFiles, invalid filepath. got: %v want %v", e.Filepath, "test.bin")
					}
					if e.Reason != "malicious" {
						t.Errorf("QuarantineAction.ListQuarantinedFiles, invalid reason. got: %v want %v", e.Reason, "malicious")
					}
					if !strings.Contains(f.Name(), e.ID) {
						t.Errorf("QuarantineAction.ListQuarantinedFiles, invalid ID. got: %v", e.ID)
					}
				case <-ctx.Done():
					t.Errorf("QuarantineAction.ListQuarantinedFiles, not files returned before timeout")
				}
			},
		},
		{
			name: "test invalid root folder",
			test: func(t *testing.T) {
				a := NewQuarantineAction(
					&cache.MockCache{},
					"",
					&MockLock{},
				)

				_, err := a.ListQuarantinedFiles(context.Background())
				if err != nil {
					t.Errorf("QuarantineAction.ListQuarantinedFiles, error not expected")
					return
				}
			},
		},
		{
			name: "test cancelled ctx",
			test: func(t *testing.T) {
				a := NewQuarantineAction(
					&cache.MockCache{},
					os.TempDir(),
					&MockLock{},
				)
				ctx, cancel := context.WithCancel(context.Background())
				cancel()

				_, err := a.ListQuarantinedFiles(ctx)
				if err != nil {
					t.Errorf("QuarantineAction.ListQuarantinedFiles, error not expected")
					return
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}

func TestQuarantineAction_Restore(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "test",
			test: func(t *testing.T) {
				tmpDir, err := os.MkdirTemp(os.TempDir(), "test_list_quarantine_*")
				if err != nil {
					t.Errorf("could not create test dir, error: %s", err)
					return
				}
				defer os.RemoveAll(tmpDir)
				Now = func() time.Time {
					return time.UnixMilli(1707568762557)
				}
				defer func() {
					Now = time.Now
				}()

				a := NewQuarantineAction(
					&cache.MockCache{
						GetMock: func(id string) (entry *cache.Entry, err error) {
							entry = &cache.Entry{
								QuarantineLocation: "/tmp/xxx",
							}
							return
						},
						SetMock: func(entry *cache.Entry) error {
							if entry.QuarantineLocation != "" {
								return fmt.Errorf("invalid quarantine location, %v", entry.QuarantineLocation)
							}
							if entry.RestoredAt != time.UnixMilli(1707568762557) {
								return fmt.Errorf("invalid restored at, %v", entry.RestoredAt)
							}
							return nil
						},
					},
					tmpDir,
					&MockLock{
						GetHeaderMock: func(in io.Reader) (entry LockEntry, err error) {
							var buffer bytes.Buffer
							io.Copy(&buffer, in)
							if buffer.String() != "test_content" {
								return entry, fmt.Errorf("invalid locked content: %s", buffer.String())
							}
							return LockEntry{Filepath: filepath.Join(tmpDir, "test.bin"), Reason: "malicious"}, nil
						},
						UnlockFileMock: func(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error) {
							if _, err = out.Write([]byte("test")); err != nil {
								return
							}
							h := &tar.Header{
								Name:       "test",
								Mode:       0o752,
								ModTime:    time.UnixMilli(1707568762557),
								AccessTime: time.UnixMilli(1707568763557),
							}
							info = h.FileInfo()
							return
						},
					},
				)
				f, err := os.CreateTemp(tmpDir, "test_*.lock")
				if err != nil {
					t.Errorf("could not create test file, error: %s", err)
					return
				}
				f.WriteString("test_content")
				f.Close()
				err = a.Restore(strings.TrimSuffix(filepath.Base(f.Name()), ".lock"))
				if err != nil {
					t.Errorf("QuarantineAction.Restore, error: %s", err)
					return
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}
