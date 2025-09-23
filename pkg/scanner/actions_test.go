package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/quarantine/mock"
	"github.com/google/go-cmp/cmp"
)

func TestReportAction_Handle(t *testing.T) {
	type args struct {
		path   string
		result datamodel.Result
		report *datamodel.Report
	}
	tests := []struct {
		name       string
		a          *ReportAction
		args       args
		wantErr    bool
		wantReport datamodel.Report
	}{
		{
			name: "test",
			args: args{
				path: "/tmp/test1",
				result: datamodel.Result{
					Malware: true,
					SHA256:  "123456789",
				},
				report: &datamodel.Report{
					Filename: "test",
					Deleted:  true,
				},
			},
			a:       &ReportAction{},
			wantErr: false,
			wantReport: datamodel.Report{
				Filename:  "/tmp/test1",
				SHA256:    "123456789",
				Deleted:   true,
				Malicious: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &ReportAction{}
			if err := a.Handle(t.Context(), tt.args.path, tt.args.result, tt.args.report); (err != nil) != tt.wantErr {
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
		result datamodel.Result
		report *datamodel.Report
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
				result: datamodel.Result{Malware: true, SHA256: "123456789"},
				report: &datamodel.Report{
					Filename: "test",
					Deleted:  true,
				},
			},
			logLevel: slog.LevelDebug,
			wantLog: `{"time":"2024-01-25T12:55:00Z","level":"INFO","msg":"info scanned","file":"/tmp/test1","sha256":"123456789","malware":true,"malwares":[]}
`,
		},
		{
			name: "test subfiles",
			args: args{
				path: "/tmp/test1",
				result: datamodel.Result{
					Malware:  true,
					Malwares: []string{"MALWARE-1"},
					SHA256:   "123456789",
					MaliciousSubfiles: map[string]datamodel.Result{
						"test/test.txt": {
							SHA256:        "8f20eb58d3348fa7ca9341048a1c7b2eed2fb3e2189b362341e9cbf66f00b4cc",
							Malware:       true,
							Malwares:      []string{"MALWARE-1"},
							MalwareReason: datamodel.MalwareDetected,
						},
					},
					MalwareReason: datamodel.MalwareDetected,
				},
				report: &datamodel.Report{
					Filename: "test",
					Deleted:  true,
				},
			},
			logLevel: slog.LevelDebug,
			wantLog:  `{"time":"2024-01-25T12:55:00Z","level":"INFO","msg":"info scanned","file":"/tmp/test1","sha256":"123456789","malware":true,"malwares":["MALWARE-1"],"reason":"malware-detected","malicious-subfiles":{"sha256":"8f20eb58d3348fa7ca9341048a1c7b2eed2fb3e2189b362341e9cbf66f00b4cc","malwares":["MALWARE-1"]}}` + "\n",
		},
		{
			name: "test debug false",
			args: args{
				path:   "/tmp/test1",
				result: datamodel.Result{Malware: false, SHA256: "123456789"},
				report: &datamodel.Report{
					Filename: "test",
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
				result: datamodel.Result{Malware: false, SHA256: "123456789"},
				report: &datamodel.Report{
					Filename: "test",
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
			if err := a.Handle(t.Context(), tt.args.path, tt.args.result, tt.args.report); (err != nil) != tt.wantErr {
				t.Errorf("LogAction.Handle() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			result := buffer.String()
			if diff := cmp.Diff(result, tt.wantLog); diff != "" {
				t.Errorf("LogAction.Handle() log(got-want) = %s", diff)
			}
		})
	}
}

func TestRemoveFileAction_Handle(t *testing.T) {
	type args struct {
		path   string
		result datamodel.Result
		report *datamodel.Report
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
				result: datamodel.Result{Malware: true},
				report: &datamodel.Report{},
			},
		},
		{
			name: "test not malware",
			args: args{
				path:   "test_malware",
				result: datamodel.Result{Malware: false},
				report: &datamodel.Report{},
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
				_, err = f.WriteString("test 1234")
				if err != nil {
					panic(fmt.Sprintf("TestRemoveFileAction, cannot write string : %s", err))
				}
				err = f.Close()
				if err != nil {
					panic(fmt.Sprintf("TestRemoveFileAction, cannot close file : %s", err))
				}
				defer func() {
					err := os.Remove(f.Name())
					if err != nil {
						logger.Error("TestRemoveFileAction, cannot remove file", "error", err)
					}
				}()
				tt.args.path = f.Name()
			}
			if err := a.Handle(t.Context(), tt.args.path, tt.args.result, tt.args.report); (err != nil) != tt.wantErr {
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

func TestInformAction_Handle(t *testing.T) {
	type fields struct {
		Verbose bool
	}
	type args struct {
		path   string
		result datamodel.Result
		report *datamodel.Report
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
				result: datamodel.Result{
					Malware: false,
				},
				report: &datamodel.Report{},
			},
			wantOut: ``,
		},
		{
			name: "test legit verbose",
			fields: fields{
				Verbose: true,
			},
			args: args{
				result: datamodel.Result{
					Malware: false,
				},
				path:   "test_file.bin",
				report: &datamodel.Report{},
			},
			wantOut: `file test_file.bin no malware found`,
		},
		{
			name: "test malware",
			fields: fields{
				Verbose: true,
			},
			args: args{
				result: datamodel.Result{
					Malware: true,
				},
				path:   "test_file.bin",
				report: &datamodel.Report{},
			},
			wantOut: `file test_file.bin seems malicious`,
		},
		{
			name: "test malware quarantine",
			fields: fields{
				Verbose: true,
			},
			args: args{
				result: datamodel.Result{
					Malware:  true,
					Malwares: []string{"eicar", "test_eicar"},
				},
				path: "test_file.bin",
				report: &datamodel.Report{
					Deleted:            true,
					QuarantineLocation: "/tmp/q/test.lock",
				},
			},
			wantOut: `file test_file.bin seems malicious [[eicar test_eicar]], it has been quarantined to /tmp/q/test.lock, it has been deleted`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			a := &PrintAction{
				Verbose: tt.fields.Verbose,
				Out:     &out,
			}
			if err := a.Handle(t.Context(), tt.args.path, tt.args.result, tt.args.report); (err != nil) != tt.wantErr {
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

func TestMoveAction_Handle(t *testing.T) {
	tests := []struct {
		name         string
		samplePath   string
		isMalware    bool
		wantErr      bool
		srcPath      string
		destPath     string
		wantedReport datamodel.Report
	}{
		{
			name:         "malware",
			isMalware:    true,
			samplePath:   "/media/test/e/test.txt",
			wantedReport: datamodel.Report{},
		},
		{
			name:       "unexpected path",
			wantErr:    true,
			samplePath: "/a/b/c",
		},
		{
			name:       "move legit",
			samplePath: "/media/test/e/test.txt",
			wantedReport: datamodel.Report{
				MovedTo: "/path/to/move/e/test.txt",
			},
		},
		{
			name:       "move legit /",
			samplePath: "/media/test/e/test.txt",
			wantedReport: datamodel.Report{
				MovedTo: "/legit/media/test/e/test.txt",
			},
			srcPath:  "/",
			destPath: "/legit",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempReport, err := os.CreateTemp(os.TempDir(), "report*")
			if err != nil {
				t.Errorf("MoveAction.Handle() could not create temp file for report, error: %s", err)
				return
			}
			defer func() {
				err = tempReport.Close()
				if err != nil {
					logger.Error("TestMoveAction cannot close tmp report", "error", err)
				}
				err = os.Remove(tempReport.Name())
				if err != nil {
					logger.Error("TestMoveAction cannot remove tmp report", "error", err)
				}
			}()
			Rename = func(oldpath, newpath string) error {
				if oldpath != tt.samplePath {
					return fmt.Errorf("invalid oldpath: %s != %s", oldpath, tt.samplePath)
				}
				if newpath != tt.wantedReport.MovedTo {
					return fmt.Errorf("invalid newpath: %s != %s", newpath, tt.wantedReport.MovedTo)
				}
				return nil
			}
			MkdirAll = func(path string, perm os.FileMode) error {
				return nil
			}
			Create = func(name string) (*os.File, error) {
				return tempReport, nil
			}
			defer func() {
				Rename = os.Rename
				MkdirAll = os.MkdirAll
				Create = os.Create
			}()
			dst := "/path/to/move"
			src := "/mnt/../media/test"
			if tt.srcPath != "" {
				src = tt.srcPath
			}
			if tt.destPath != "" {
				dst = tt.destPath
			}
			a, err := NewMoveAction(dst, src)
			if err != nil {
				t.Errorf("MoveAction.Handle() could not get new move action, error: %v", err)
				return
			}
			report := datamodel.Report{}
			if err := a.Handle(t.Context(), tt.samplePath, datamodel.Result{Malware: tt.isMalware}, &report); (err != nil) != tt.wantErr {
				t.Errorf("MoveAction.Handle() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !cmp.Equal(report, tt.wantedReport) {
				t.Errorf("MoveAction.Handle() report = %v, want report %v, %s", report, tt.wantedReport, cmp.Diff(report, tt.wantedReport))
				return
			}
		})
	}
}

func Test_moveFile(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) (src, dst string)
		wantErr bool
	}{
		{
			name: "successful move within same filesystem",
			setup: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				src := filepath.Join(tmpDir, "source.txt")
				dst := filepath.Join(tmpDir, "dest.txt")

				if err := os.WriteFile(src, []byte("test content"), 0o600); err != nil {
					t.Fatalf("failed to create source file: %v", err)
				}
				return src, dst
			},
			wantErr: false,
		},
		{
			name: "source file does not exist",
			setup: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				src := filepath.Join(tmpDir, "nonexistent.txt")
				dst := filepath.Join(tmpDir, "dest.txt")
				return src, dst
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, dst := tt.setup(t)
			err := moveFile(src, dst)

			if (err != nil) != tt.wantErr {
				t.Errorf("moveFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify destination exists and source doesn't
				if _, err := os.Stat(dst); err != nil {
					t.Errorf("destination file should exist: %v", err)
				}
				if _, err := os.Stat(src); !os.IsNotExist(err) {
					t.Errorf("source file should not exist after move")
				}
			}
		})
	}
}

func Test_copyAndDelete(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T) (src, dst string)
		wantErr     bool
		checkResult func(t *testing.T, src, dst string)
	}{
		{
			name: "successful copy and delete",
			setup: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				src := filepath.Join(tmpDir, "source.txt")
				dst := filepath.Join(tmpDir, "dest.txt")

				content := []byte("test file content")
				if err := os.WriteFile(src, content, 0o600); err != nil {
					t.Fatalf("failed to create source file: %v", err)
				}
				return src, dst
			},
			wantErr: false,
			checkResult: func(t *testing.T, src, dst string) {
				// Verify destination exists with correct content
				// #nosec G304 - dst is controlled by test code
				content, err := os.ReadFile(dst)
				if err != nil {
					t.Errorf("failed to read destination file: %v", err)
				}
				if string(content) != "test file content" {
					t.Errorf("content mismatch: got %s, want 'test file content'", string(content))
				}

				// Verify source was deleted
				if _, err := os.Stat(src); !os.IsNotExist(err) {
					t.Errorf("source file should not exist after copyAndDelete")
				}

				// Verify permissions were preserved
				info, err := os.Stat(dst)
				if err != nil {
					t.Errorf("failed to stat destination: %v", err)
				}
				if info.Mode().Perm() != 0o600 {
					t.Errorf("permissions not preserved: got %o, want 0600", info.Mode().Perm())
				}
			},
		},
		{
			name: "source file does not exist",
			setup: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				src := filepath.Join(tmpDir, "nonexistent.txt")
				dst := filepath.Join(tmpDir, "dest.txt")
				return src, dst
			},
			wantErr: true,
		},
		{
			name: "destination directory does not exist",
			setup: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				src := filepath.Join(tmpDir, "source.txt")
				dst := filepath.Join(tmpDir, "nonexistent", "dest.txt")

				if err := os.WriteFile(src, []byte("content"), 0o600); err != nil {
					t.Fatalf("failed to create source file: %v", err)
				}
				return src, dst
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, dst := tt.setup(t)
			err := copyAndDelete(src, dst)

			if (err != nil) != tt.wantErr {
				t.Errorf("copyAndDelete() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.checkResult != nil {
				tt.checkResult(t, src, dst)
			}
		})
	}
}

func TestQuarantineAction_Handle(t *testing.T) {
	tests := []struct {
		name          string
		malware       bool
		quarantineErr bool
		path          string
		wantErr       bool
	}{
		{
			name: "ok not malware",
			path: "toto",
		},
		{
			name: "ok malware",
			path: "toto",
		},
		{
			name:          "error quarantine",
			malware:       true,
			quarantineErr: true,
			wantErr:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			quarantiner := mock.QuarantineMock{
				QuarantineMock: func(ctx context.Context, file, fileSHA256 string, malwares []string) (quarantineLocation string, entryID string, err error) {
					if !tt.malware {
						t.Fatal("unexpected Quarantine() call")
					}
					if tt.quarantineErr {
						err = errors.New("error")
					}
					return
				},
			}
			a := NewQuarantineAction(&quarantiner)
			gotErr := a.Handle(t.Context(), tt.path, datamodel.Result{Malware: tt.malware}, &datamodel.Report{})
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Handle() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Handle() succeeded unexpectedly")
			}
		})
	}
}
