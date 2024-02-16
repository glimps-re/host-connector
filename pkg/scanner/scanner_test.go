package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/cache"
)

func TestNewConnector(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "test one file",
			test: func(t *testing.T) {
				buffer := bytes.Buffer{}
				conn := NewConnector(Config{
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
						InformDest: &buffer,
					},
					Submitter: &MockSubmitter{
						GetResultBySHA256Mock: func(ctx context.Context, sha256 string) (result gdetect.Result, err error) {
							if sha256 == "3fc6540b6002f7622d978ea8c6fcb6a661089de0f4952f42390a694107269893" {
								return gdetect.Result{
									Malware: true,
									SHA256:  "3fc6540b6002f7622d978ea8c6fcb6a661089de0f4952f42390a694107269893",
								}, nil
							}
							return result, fmt.Errorf("test")
						},
						WaitForReaderMock: func(ctx context.Context, r io.Reader, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
							return gdetect.Result{
								Malware: false,
							}, nil
						},
					},
					Cache: &cache.MockCache{
						SetMock: func(entry *cache.Entry) error {
							return nil
						},
						GetMock: func(id string) (entry *cache.Entry, err error) {
							if id == "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72" {
								return &cache.Entry{
									Sha256: "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72",
								}, nil
							}
							return nil, cache.ErrEntryNotFound
						},
					},
				})
				defer conn.Close()
				if conn.config.Workers != 1 {
					t.Errorf("invalid workers %v", conn.config.Workers)
				}

				if a, ok := conn.Action.(*MultiAction); !ok {
					t.Errorf("invalid action: %v", conn.Action)
				} else {
					if len(a.Actions) != 5 {
						t.Errorf("invalid actions %#v", a.Actions)
					}
				}

				if err := conn.Start(); err != nil {
					t.Errorf("could not start connector, error: %v", err)
				}

				// scan invalid file
				if err := conn.ScanFile(context.Background(), "/az/et/test"); err == nil {
					t.Errorf("err wanted")
				}

				// prepare test files
				testDir, err := os.MkdirTemp(os.TempDir(), "scanfile_test_folder_*")
				if err != nil {
					t.Errorf("could not create test folder, error: %s", err)
					return
				}
				defer os.RemoveAll(testDir)
				testFile, err := os.CreateTemp(testDir, "ScanFile_test_*")
				if err != nil {
					t.Errorf("could not create test file, error: %s", err)
					return
				}
				testFile.WriteString("test content")
				testFile.Close()
				testFile2, err := os.CreateTemp(testDir, "ScanFile_test2_*")
				if err != nil {
					t.Errorf("could not create test file2, error: %s", err)
					return
				}
				testFile2.WriteString("test content2")
				testFile2.Close()
				// scan cancelled
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				conn.ScanFile(ctx, testFile.Name())

				ctx, cancel = context.WithTimeout(context.Background(), time.Second*30)
				defer cancel()
				if err := conn.ScanFile(ctx, testFile.Name()); err != nil {
					t.Errorf("unwanted error: %v", err)
				}

				if buffer.String() != "" {
					t.Errorf("invalid output: %v", buffer.String())
				}

				if err := conn.ScanFile(ctx, testFile2.Name()); err != nil {
					t.Errorf("unwanted error: %v", err)
				}

				conn.Close()

				if !strings.HasSuffix(buffer.String(), "3fc6540b6002f7622d978ea8c6fcb6a661089de0f4952f42390a694107269893.lock, it has been deleted\n") {
					t.Errorf("invalid output: %v", buffer.String())
				}
			},
		},
		{
			name: "test folder",
			test: func(t *testing.T) {
				buffer := bytes.Buffer{}
				conn := NewConnector(Config{
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
						InformDest: &buffer,
					},
					Submitter: &MockSubmitter{
						GetResultBySHA256Mock: func(ctx context.Context, sha256 string) (result gdetect.Result, err error) {
							if sha256 == "3fc6540b6002f7622d978ea8c6fcb6a661089de0f4952f42390a694107269893" {
								return gdetect.Result{
									Malware: true,
									SHA256:  "3fc6540b6002f7622d978ea8c6fcb6a661089de0f4952f42390a694107269893",
								}, nil
							}
							return result, fmt.Errorf("test")
						},
						WaitForReaderMock: func(ctx context.Context, r io.Reader, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
							return gdetect.Result{
								Malware: false,
							}, nil
						},
					},
					Cache: &cache.MockCache{
						SetMock: func(entry *cache.Entry) error {
							return nil
						},
						GetMock: func(id string) (entry *cache.Entry, err error) {
							if id == "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72" {
								return &cache.Entry{
									Sha256: "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72",
								}, nil
							}
							return nil, cache.ErrEntryNotFound
						},
					},
				})
				defer conn.Close()
				if conn.config.Workers != 1 {
					t.Errorf("invalid workers %v", conn.config.Workers)
				}

				if a, ok := conn.Action.(*MultiAction); !ok {
					t.Errorf("invalid action: %v", conn.Action)
				} else {
					if len(a.Actions) != 5 {
						t.Errorf("invalid actions %#v", a.Actions)
					}
				}

				if err := conn.Start(); err != nil {
					t.Errorf("could not start connector, error: %v", err)
				}

				// prepare test files
				testDir, err := os.MkdirTemp(os.TempDir(), "scanfile_test_folder_*")
				if err != nil {
					t.Errorf("could not create test folder, error: %s", err)
					return
				}
				defer os.RemoveAll(testDir)
				testFile, err := os.CreateTemp(testDir, "ScanFile_test_*")
				if err != nil {
					t.Errorf("could not create test file, error: %s", err)
					return
				}
				testFile.WriteString("test content")
				testFile.Close()
				testFile2, err := os.CreateTemp(testDir, "ScanFile_test2_*")
				if err != nil {
					t.Errorf("could not create test file2, error: %s", err)
					return
				}
				testFile2.WriteString("test content2")
				testFile2.Close()

				ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
				defer cancel()
				if err := conn.ScanFile(ctx, testDir); err != nil {
					t.Errorf("unwanted error: %v", err)
				}

				conn.Close()

				if !strings.HasSuffix(buffer.String(), "3fc6540b6002f7622d978ea8c6fcb6a661089de0f4952f42390a694107269893.lock, it has been deleted\n") {
					t.Errorf("invalid output: %v", buffer.String())
				}
			},
		},
		{
			name: "test folder",
			test: func(t *testing.T) {
				buffer := bytes.Buffer{}
				conn := NewConnector(Config{
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
						Verbose:    true,
						InformDest: &buffer,
					},
					Submitter: &MockSubmitter{
						GetResultBySHA256Mock: func(ctx context.Context, sha256 string) (result gdetect.Result, err error) {
							return result, fmt.Errorf("test")
						},
						WaitForReaderMock: func(ctx context.Context, r io.Reader, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
							return gdetect.Result{
								Malware: false,
							}, nil
						},
					},
					Cache: &cache.MockCache{
						SetMock: func(entry *cache.Entry) error {
							return nil
						},
						GetMock: func(id string) (entry *cache.Entry, err error) {
							if id == "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72" {
								return &cache.Entry{
									Sha256: "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72",
								}, nil
							}
							return nil, cache.ErrEntryNotFound
						},
					},
				})
				defer conn.Close()
				if conn.config.Workers != 1 {
					t.Errorf("invalid workers %v", conn.config.Workers)
				}

				if a, ok := conn.Action.(*MultiAction); !ok {
					t.Errorf("invalid action: %v", conn.Action)
				} else {
					if len(a.Actions) != 5 {
						t.Errorf("invalid actions %#v", a.Actions)
					}
				}

				if err := conn.Start(); err != nil {
					t.Errorf("could not start connector, error: %v", err)
				}

				// prepare test files
				testDir, err := os.MkdirTemp(os.TempDir(), "scanfile_test_folder_*")
				if err != nil {
					t.Errorf("could not create test folder, error: %s", err)
					return
				}
				defer os.RemoveAll(testDir)
				testFile, err := os.CreateTemp(testDir, "ScanFile_test_*")
				if err != nil {
					t.Errorf("could not create test file, error: %s", err)
					return
				}
				testFile.WriteString("test content")
				testFile.Close()
				testFile2, err := os.CreateTemp(testDir, "ScanFile_test2_*")
				if err != nil {
					t.Errorf("could not create test file2, error: %s", err)
					return
				}
				testFile2.WriteString("test content2")
				testFile2.Close()

				ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
				defer cancel()
				if err := conn.ScanFile(ctx, testDir); err != nil {
					t.Errorf("unwanted error: %v", err)
				}

				conn.Close()

				if !strings.HasSuffix(buffer.String(), "no malware found\n") {
					t.Errorf("invalid output: %v", buffer.String())
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}

func TestConnector_ScanFile(t *testing.T) {
	type args struct {
		cancelled bool
		inputSize int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "test unknown file",
			args: args{
				inputSize: -1,
			},
			wantErr: true,
		},
		{
			name: "empty file",
			args: args{
				inputSize: 0,
			},
			wantErr: false,
		},
		{
			name: "too large file",
			args: args{
				inputSize: 200 * 1024 * 1024,
			},
			wantErr: false,
		},
		{
			name: "cancelled file",
			args: args{
				inputSize: 200 * 1024,
				cancelled: true,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			if tt.args.cancelled {
				cancel()
			} else {
				defer cancel()
			}
			c := &Connector{
				done:   ctx,
				cancel: cancel,
			}
			var input string
			if tt.args.inputSize < 0 {
				input = "test_1234"
			} else {
				f, err := os.CreateTemp(os.TempDir(), "test_*")
				if err != nil {
					t.Errorf("could not create temp file, error: %s", err)
					return
				}
				defer f.Close()
				data := make([]byte, tt.args.inputSize)
				rand.Read(data)
				f.Write(data)
				defer os.Remove(f.Name())
				input = f.Name()
			}
			if err := c.ScanFile(ctx, input); (err != nil) != tt.wantErr {
				t.Errorf("Connector.ScanFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
