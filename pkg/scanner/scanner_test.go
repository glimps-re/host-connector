package scanner

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"sync"
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
						WaitForReaderMock: func(ctx context.Context, r io.Reader, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
							hash := sha256.New()
							if _, err = io.Copy(hash, r); err != nil {
								return
							}
							fileSHA256 := hex.EncodeToString(hash.Sum(nil))
							if fileSHA256 == "3fc6540b6002f7622d978ea8c6fcb6a661089de0f4952f42390a694107269893" {
								return gdetect.Result{
									Malware: true,
									SHA256:  "3fc6540b6002f7622d978ea8c6fcb6a661089de0f4952f42390a694107269893",
									Done:    true,
								}, nil
							}
							return gdetect.Result{
								Malware: false,
								Done:    true,
							}, nil
						},
					},
					Cache: &cache.MockCache{
						SetMock: func(ctx context.Context, entry *cache.Entry) error {
							return nil
						},
						GetBySha256Mock: func(ctx context.Context, id string) (entry *cache.Entry, err error) {
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

				if a, ok := conn.action.(*MultiAction); !ok {
					t.Errorf("invalid action: %v", conn.action)
				} else if len(a.Actions) != 5 {
					t.Errorf("invalid actions %#v", a.Actions)
				}

				if err := conn.Start(t.Context()); err != nil {
					t.Errorf("could not start connector, error: %v", err)
				}

				// scan invalid file
				if err := conn.ScanFile(context.Background(), "/az/et/test"); err == nil {
					t.Errorf("err wanted")
				}

				// prepare test files
				testDir := t.TempDir()
				testFile, err := os.CreateTemp(testDir, "ScanFile_test_*")
				if err != nil {
					t.Errorf("could not create test file, error: %s", err)
					return
				}
				_, err = testFile.WriteString("test content")
				if err != nil {
					t.Fatalf("cound not write test string : %s", err)
				}
				err = testFile.Close()
				if err != nil {
					t.Fatalf("could not close test file : %s", err)
				}
				testFile2, err := os.CreateTemp(testDir, "ScanFile_test2_*")
				if err != nil {
					t.Errorf("could not create test file2, error: %s", err)
					return
				}
				_, err = testFile2.WriteString("test content2")
				if err != nil {
					t.Fatalf("could not write test string : %s", err)
				}
				err = testFile2.Close()
				if err != nil {
					t.Fatalf("could not close test file : %s", err)
				}
				// scan cancelled
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				err = conn.ScanFile(ctx, testFile.Name())
				if err != nil && err.Error() != "context canceled" {
					t.Errorf("scan file error : %s", err)
				}

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

				if !strings.HasSuffix(buffer.String(), cache.ComputeCacheID(testFile2.Name())+".lock, it has been deleted\n") {
					t.Errorf("invalid output: %v", buffer.String())
				}
			},
		},
		{
			name: "test one archive (extract all)",
			test: func(t *testing.T) {
				buffer := bytes.Buffer{}
				conn := NewConnector(Config{
					MaxFileSize: 200,
					Extract:     true,
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
						InformDest: &buffer,
					},
					Submitter: &MockSubmitter{
						WaitForReaderMock: func(ctx context.Context, r io.Reader, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
							hash := sha256.New()
							if _, err = io.Copy(hash, r); err != nil {
								return
							}
							sha256 := hex.EncodeToString(hash.Sum(nil))
							switch sha256 {
							case "3fc6540b6002f7622d978ea8c6fcb6a661089de0f4952f42390a694107269893":
								return gdetect.Result{
									Malware:  true,
									Malwares: []string{"MALWARE-1"},
									SHA256:   "3fc6540b6002f7622d978ea8c6fcb6a661089de0f4952f42390a694107269893",
									Done:     true,
								}, nil
							case "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72":
								return gdetect.Result{
									Malware:  true,
									Malwares: []string{"MALWARE-2"},
									SHA256:   "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72",
									Done:     true,
								}, nil
							default:
								return gdetect.Result{
									Malware: false,
									Done:    true,
								}, nil
							}
						},
					},
					Cache: &cache.MockCache{
						SetMock: func(ctx context.Context, entry *cache.Entry) error {
							return nil
						},
						GetBySha256Mock: func(ctx context.Context, id string) (entry *cache.Entry, err error) {
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

				if a, ok := conn.action.(*MultiAction); !ok {
					t.Errorf("invalid action: %v", conn.action)
				} else if len(a.Actions) != 5 {
					t.Errorf("invalid actions %#v", a.Actions)
				}

				if err := conn.Start(t.Context()); err != nil {
					t.Errorf("could not start connector, error: %v", err)
				}

				// prepare test files
				testDir := t.TempDir()
				testFile, err := os.CreateTemp(testDir, "ScanFile_test_*")
				if err != nil {
					t.Errorf("could not create test file, error: %s", err)
					return
				}
				_, err = testFile.WriteString("test content")
				if err != nil {
					t.Fatalf("could not write test string : %s", err)
				}
				_, err = testFile.Seek(0, io.SeekStart)
				if err != nil {
					t.Fatalf("could not seek test file : %s", err)
				}

				testFile2, err := os.CreateTemp(testDir, "ScanFile_test2_*")
				if err != nil {
					t.Errorf("could not create test file2, error: %s", err)
					return
				}
				_, err = testFile2.WriteString("test content2")
				if err != nil {
					t.Fatalf("could not create test file, error : %s", err)
				}
				_, err = testFile2.Seek(0, io.SeekStart)
				if err != nil {
					t.Fatalf("could not seek test file, error : %s", err)
				}

				archive, err := os.CreateTemp(os.TempDir(), "archive_*.zip")
				if err != nil {
					panic(err)
				}

				zipWriter := zip.NewWriter(archive)

				f1, err := zipWriter.Create("file1")
				if err != nil {
					panic(err)
				}
				_, err = io.Copy(f1, testFile)
				if err != nil {
					t.Fatalf("could not copy test file : %s", err)
				}
				f2, err := zipWriter.Create("file2")
				if err != nil {
					panic(err)
				}
				_, err = io.Copy(f2, testFile2)
				if err != nil {
					t.Fatalf("could not copy test file : %s", err)
				}

				f3, err := zipWriter.Create("file3")
				if err != nil {
					panic(err)
				}
				_, err = io.Copy(f3, bytes.NewReader([]byte{}))
				if err != nil {
					t.Fatalf("could not copy test file : %s", err)
				}

				err = testFile.Close()
				if err != nil {
					t.Fatalf("could not close test file : %s", err)
				}
				err = testFile2.Close()
				if err != nil {
					t.Fatalf("could not close test file : %s", err)
				}
				err = zipWriter.Close()
				if err != nil {
					t.Fatalf("could not close test file : %s", err)
				}
				err = archive.Close()
				if err != nil {
					t.Fatalf("could not close test file : %s", err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
				defer cancel()
				if err := conn.ScanFile(ctx, archive.Name()); err != nil {
					t.Errorf("unwanted error: %v", err)
				}
				conn.Close()
				if !strings.Contains(buffer.String(), "MALWARE-2") {
					t.Errorf("invalid output: %v", buffer.String())
				}

				if !strings.HasSuffix(buffer.String(), cache.ComputeCacheID(archive.Name())+".lock, it has been deleted\n") {
					t.Errorf("invalid output: %v", buffer.String())
				}
			},
		},
		{
			name: "test one archive",
			test: func(t *testing.T) {
				buffer := bytes.Buffer{}
				conn := NewConnector(Config{
					MaxFileSize: 200,
					Extract:     true,
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
						InformDest: &buffer,
					},
					Submitter: &MockSubmitter{
						WaitForReaderMock: func(ctx context.Context, r io.Reader, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
							hash := sha256.New()
							if _, err = io.Copy(hash, r); err != nil {
								return
							}
							sha256 := hex.EncodeToString(hash.Sum(nil))
							switch sha256 {
							case "3fc6540b6002f7622d978ea8c6fcb6a661089de0f4952f42390a694107269893":
								return gdetect.Result{
									Malware:  true,
									Malwares: []string{"MALWARE-1"},
									SHA256:   "3fc6540b6002f7622d978ea8c6fcb6a661089de0f4952f42390a694107269893",
									Done:     true,
								}, nil
							case "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72":
								return gdetect.Result{
									Malware:  true,
									Malwares: []string{"MALWARE-2"},
									SHA256:   "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72",
									Done:     true,
								}, nil
							default:
								return gdetect.Result{
									Malware: false,
									Done:    true,
								}, nil
							}
						},
					},
					Cache: &cache.MockCache{
						SetMock: func(ctx context.Context, entry *cache.Entry) error {
							return nil
						},
						GetBySha256Mock: func(ctx context.Context, id string) (entry *cache.Entry, err error) {
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

				if a, ok := conn.action.(*MultiAction); !ok {
					t.Errorf("invalid action: %v", conn.action)
				} else if len(a.Actions) != 5 {
					t.Errorf("invalid actions %#v", a.Actions)
				}

				if err := conn.Start(t.Context()); err != nil {
					t.Errorf("could not start connector, error: %v", err)
				}

				// prepare test files
				testDir := t.TempDir()
				testFile, err := os.CreateTemp(testDir, "ScanFile_test_*")
				if err != nil {
					t.Errorf("could not create test file, error: %s", err)
					return
				}
				_, err = testFile.WriteString("test content")
				if err != nil {
					t.Fatalf("could not write test string : %s", err)
				}
				_, err = testFile.Seek(0, io.SeekStart)
				if err != nil {
					t.Fatalf("could not seek test string : %s", err)
				}

				testFile2, err := os.CreateTemp(testDir, "ScanFile_test2_*")
				if err != nil {
					t.Errorf("could not create test file2, error: %s", err)
					return
				}
				_, err = testFile2.WriteString("test content2")
				if err != nil {
					t.Fatalf("could not write test string : %s", err)
				}
				_, err = testFile2.Seek(0, io.SeekStart)
				if err != nil {
					t.Fatalf("could not seek test file : %s", err)
				}

				archive, err := os.CreateTemp(os.TempDir(), "archive_*.zip")
				if err != nil {
					panic(err)
				}

				zipWriter := zip.NewWriter(archive)

				f1, err := zipWriter.Create("file1")
				if err != nil {
					panic(err)
				}
				_, err = io.Copy(f1, testFile)
				if err != nil {
					t.Fatalf("could not copy test file : %s", err)
				}
				f2, err := zipWriter.Create("file2")
				if err != nil {
					panic(err)
				}
				_, err = io.Copy(f2, testFile2)
				if err != nil {
					t.Fatalf("could not copy test file : %s", err)
				}

				err = testFile.Close()
				if err != nil {
					t.Fatalf("could not close test file : %s", err)
				}
				err = testFile2.Close()
				if err != nil {
					t.Fatalf("could not close test file : %s", err)
				}

				err = zipWriter.Close()
				if err != nil {
					t.Fatalf("could not close zip writer : %s", err)
				}
				err = archive.Close()
				if err != nil {
					t.Fatalf("could not close archive : %s", err)
				}

				ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
				defer cancel()
				if err := conn.ScanFile(ctx, archive.Name()); err != nil {
					t.Errorf("unwanted error: %v", err)
				}
				conn.Close()
				if strings.Contains(buffer.String(), "MALWARE-1") != strings.Contains(buffer.String(), "MALWARE-2") {
					t.Errorf("invalid output: %v", buffer.String())
				}

				if !strings.HasSuffix(buffer.String(), cache.ComputeCacheID(archive.Name())+".lock, it has been deleted\n") {
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
						WaitForReaderMock: func(ctx context.Context, r io.Reader, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
							hash := sha256.New()
							if _, err = io.Copy(hash, r); err != nil {
								return
							}
							sha256 := hex.EncodeToString(hash.Sum(nil))
							if sha256 == "3fc6540b6002f7622d978ea8c6fcb6a661089de0f4952f42390a694107269893" {
								return gdetect.Result{
									Malware: true,
									SHA256:  "3fc6540b6002f7622d978ea8c6fcb6a661089de0f4952f42390a694107269893",
									Done:    true,
								}, nil
							}
							return gdetect.Result{
								Malware: false,
							}, nil
						},
					},
					Cache: &cache.MockCache{
						SetMock: func(ctx context.Context, entry *cache.Entry) error {
							return nil
						},
						GetBySha256Mock: func(ctx context.Context, id string) (entry *cache.Entry, err error) {
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

				if a, ok := conn.action.(*MultiAction); !ok {
					t.Errorf("invalid action: %v", conn.action)
				} else if len(a.Actions) != 5 {
					t.Errorf("invalid actions %#v", a.Actions)
				}

				if err := conn.Start(t.Context()); err != nil {
					t.Errorf("could not start connector, error: %v", err)
				}

				// prepare test files
				testDir := t.TempDir()
				testFile, err := os.CreateTemp(testDir, "ScanFile_test_*")
				if err != nil {
					t.Errorf("could not create test file, error: %s", err)
					return
				}
				_, err = testFile.WriteString("test content")
				if err != nil {
					t.Fatalf("could not write test string : %s", err)
				}
				err = testFile.Close()
				if err != nil {
					t.Fatalf("could not close test file : %s", err)
				}
				testFile2, err := os.CreateTemp(testDir, "ScanFile_test2_*")
				if err != nil {
					t.Errorf("could not create test file2, error: %s", err)
					return
				}
				_, err = testFile2.WriteString("test content2")
				if err != nil {
					t.Fatalf("could not write test string : %s", err)
				}
				err = testFile2.Close()
				if err != nil {
					t.Fatalf("could not close test file : %s", err)
				}

				ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
				defer cancel()
				if err := conn.ScanFile(ctx, testDir); err != nil {
					t.Errorf("unwanted error: %v", err)
				}

				conn.Close()

				if !strings.HasSuffix(buffer.String(), cache.ComputeCacheID(testFile2.Name())+".lock, it has been deleted\n") {
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
						WaitForReaderMock: func(ctx context.Context, r io.Reader, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
							return gdetect.Result{
								Malware: false,
							}, nil
						},
					},
					Cache: &cache.MockCache{
						SetMock: func(ctx context.Context, entry *cache.Entry) error {
							return nil
						},
						GetBySha256Mock: func(ctx context.Context, id string) (entry *cache.Entry, err error) {
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

				if a, ok := conn.action.(*MultiAction); !ok {
					t.Errorf("invalid action: %v", conn.action)
				} else if len(a.Actions) != 5 {
					t.Errorf("invalid actions %#v", a.Actions)
				}

				if err := conn.Start(t.Context()); err != nil {
					t.Errorf("could not start connector, error: %v", err)
				}

				// prepare test files
				testDir := t.TempDir()
				testFile, err := os.CreateTemp(testDir, "ScanFile_test_*")
				if err != nil {
					t.Errorf("could not create test file, error: %s", err)
					return
				}
				_, err = testFile.WriteString("test content")
				if err != nil {
					t.Fatalf("could not write test string : %s", err)
				}
				err = testFile.Close()
				if err != nil {
					t.Fatalf("could not close test file : %s", err)
				}
				testFile2, err := os.CreateTemp(testDir, "ScanFile_test2_*")
				if err != nil {
					t.Errorf("could not create test file2, error: %s", err)
					return
				}
				_, err = testFile2.WriteString("test content2")
				if err != nil {
					t.Fatalf("could not write test string : %s", err)
				}
				err = testFile2.Close()
				if err != nil {
					t.Fatalf("could not close test file : %s", err)
				}

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
		// do all test in dedicated tmp dir that will be removed after
		sysTmpDir := os.Getenv("TMPDIR")
		testTmpDir := t.TempDir()
		t.Setenv("TMPDIR", testTmpDir)
		defer t.Setenv("TMPDIR", sysTmpDir)
		t.Run(tt.name, tt.test)
	}
}

//go:embed test_rsc/test.zip
var zipFile []byte

//go:embed test_rsc/test.txt
var txtFile []byte

//go:embed test_rsc/test_big_file.zip
var bigZipFile []byte

func TestConnector_ScanFile(t *testing.T) {
	type fields struct {
		unknownFile bool
		maxFileSize int64
		extract     bool
	}
	type args struct {
		cancelled   bool
		fileContent []byte
		extension   string
	}
	tests := []struct {
		name              string
		fields            fields
		args              args
		wantFileRetrieved int
		wantErr           bool
	}{
		{
			name: "error unknown file",
			fields: fields{
				unknownFile: true,
			},
			wantErr: true,
		},
		{
			name:   "error cancelled file",
			fields: fields{},
			args: args{
				fileContent: txtFile,
				cancelled:   true,
			},
			wantErr: true,
		},
		{
			name: "error cancelled archive",
			fields: fields{
				maxFileSize: 5,
				extract:     true,
			},
			args: args{
				fileContent: zipFile,
				extension:   "zip",
				cancelled:   true,
			},
			wantErr: true,
		},
		{
			name:   "ok",
			fields: fields{},
			args: args{
				fileContent: txtFile,
			},
			wantFileRetrieved: 1,
		},
		{
			name: "ok empty file",
			args: args{},
		},
		{
			name: "ok too large file",
			fields: fields{
				maxFileSize: 1,
			},
			args: args{
				fileContent: txtFile,
			},
			wantErr: false,
		},
		{
			name: "ok too large file and not archive",
			fields: fields{
				maxFileSize: 1,
				extract:     true,
			},
			args: args{
				fileContent: txtFile,
			},
			wantErr: false,
		},
		{
			name: "ok too large file in archive",
			fields: fields{
				maxFileSize: 1024 / 2,
				extract:     true,
			},
			args: args{
				fileContent: bigZipFile,
				extension:   "zip",
			},
			wantErr: false,
		},
		{
			name: "ok archive",
			fields: fields{
				extract:     true,
				maxFileSize: 5,
			},
			args: args{
				fileContent: zipFile,
				extension:   "zip",
			},
			wantFileRetrieved: 1,
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

			if tt.fields.maxFileSize == 0 {
				tt.fields.maxFileSize = MaxFileSize
			}

			c := &Connector{
				fileChan: make(chan fileToAnalyze),
				config: Config{
					Extract:     tt.fields.extract,
					MaxFileSize: tt.fields.maxFileSize,
				},
				done:           ctx,
				cancel:         cancel,
				archivesStatus: make(map[string]archiveStatus),
			}
			var input string

			// do all test in dedicated tmp dir that will be removed after
			sysTmpDir := os.Getenv("TMPDIR")
			testTmpDir := t.TempDir()
			t.Setenv("TMPDIR", testTmpDir)
			defer func() {
				err := os.RemoveAll(testTmpDir)
				if err != nil {
					Logger.Error("could not remove test tmp dir", "error", err)
				}
				t.Setenv("TMPDIR", sysTmpDir)
			}()

			if !tt.fields.unknownFile {
				f, err := os.CreateTemp(os.TempDir(), "test_*."+tt.args.extension)
				if err != nil {
					t.Errorf("could not create temp file, error: %s", err)
					return
				}
				defer func() {
					err = f.Close()
					if err != nil {
						Logger.Error("could not close test file", "error", err)
					}
				}()
				_, err = f.Write(tt.args.fileContent)
				if err != nil {
					t.Fatalf("could not write test file : %s", err)
				}
				defer func() {
					err = os.Remove(f.Name())
					if err != nil {
						Logger.Error("could not remove file", "file", f.Name(), "error", err)
					}
				}()
				input = f.Name()
			} else {
				input = "test_1234"
			}

			fileRetrieved := 0
			wg := &sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case <-c.fileChan:
					fileRetrieved++
				case <-ctx.Done():
					return
				}
			}()

			if err := c.ScanFile(ctx, input); (err != nil) != tt.wantErr {
				t.Errorf("Connector.ScanFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			time.Sleep(time.Millisecond * 1)
			cancel()
			wg.Wait()

			if fileRetrieved != tt.wantFileRetrieved {
				t.Errorf("Connector.ScanFile() retrieved %d file, want %d", fileRetrieved, tt.wantFileRetrieved)
				return
			}
		})
	}
}
