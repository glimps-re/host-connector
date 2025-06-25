package scanner

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/cache"
	"github.com/glimps-re/host-connector/pkg/filesystem"
	"github.com/glimps-re/host-connector/pkg/filesystem/mock"
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
					QuarantineFolder: t.TempDir(),
					Cache: &cache.MockCache{
						SetMock: func(entry *cache.Entry) error {
							return nil
						},
						GetBySha256Mock: func(id string) (entry *cache.Entry, err error) {
							if id == "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72" {
								return &cache.Entry{
									Sha256: "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72",
								}, nil
							}
							return nil, cache.ErrEntryNotFound
						},
					},
				}, filesystem.NewLocalFileSystem())
				defer conn.Close()
				if conn.config.Workers != 1 {
					t.Errorf("invalid workers %v", conn.config.Workers)
				}

				if a, ok := conn.action.(*MultiAction); !ok {
					t.Errorf("invalid action: %v", conn.action)
				} else if len(a.Actions) != 5 {
					t.Errorf("invalid actions %#v", a.Actions)
				}

				if err := conn.Start(); err != nil {
					t.Errorf("could not start connector, error: %v", err)
				}

				// scan invalid file
				if err := conn.ScanFile(t.Context(), "/az/et/test"); err == nil {
					t.Errorf("err wanted")
				}

				// prepare test files
				testDir := t.TempDir()
				testFile, err := os.CreateTemp(testDir, "ScanFile_test_*")
				if err != nil {
					t.Errorf("could not create test file, error: %s", err)
					return
				}
				if _, err := testFile.WriteString("test content"); err != nil {
					t.Errorf("could not write test file content, err: %v", err)
					return
				}
				if err = testFile.Close(); err != nil {
					t.Errorf("could not close testfile, err: %v", err)
					return
				}
				testFile2, err := os.CreateTemp(testDir, "ScanFile_test2_*")
				if err != nil {
					t.Errorf("could not create test file2, error: %s", err)
					return
				}
				if _, err := testFile2.WriteString("test content2"); err != nil {
					t.Errorf("could not write test file 2 content, err: %v", err)
				}
				if e := testFile2.Close(); e != nil {
					t.Errorf("could not close test file 2, error: %s", e)
				}

				ctx, cancel := context.WithTimeout(t.Context(), time.Second*30)
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
					QuarantineFolder: t.TempDir(),
					Cache: &cache.MockCache{
						SetMock: func(entry *cache.Entry) error {
							return nil
						},
						GetBySha256Mock: func(id string) (entry *cache.Entry, err error) {
							if id == "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72" {
								return &cache.Entry{
									Sha256: "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72",
								}, nil
							}
							return nil, cache.ErrEntryNotFound
						},
					},
				}, filesystem.NewLocalFileSystem())
				defer conn.Close()
				if conn.config.Workers != 1 {
					t.Errorf("invalid workers %v", conn.config.Workers)
				}

				if a, ok := conn.action.(*MultiAction); !ok {
					t.Errorf("invalid action: %v", conn.action)
				} else if len(a.Actions) != 5 {
					t.Errorf("invalid actions %#v", a.Actions)
				}

				if err := conn.Start(); err != nil {
					t.Errorf("could not start connector, error: %v", err)
				}

				// prepare test files
				testDir := t.TempDir()
				testFile, err := os.CreateTemp(testDir, "ScanFile_test_*")
				if err != nil {
					t.Errorf("could not create test file, error: %s", err)
					return
				}
				if _, err := testFile.WriteString("test content"); err != nil {
					t.Errorf("could not write test file content, err: %v", err)
				}
				if _, err := testFile.Seek(0, io.SeekStart); err != nil {
					t.Errorf("could not seek test file start, err: %v", err)
				}

				testFile2, err := os.CreateTemp(testDir, "ScanFile_test2_*")
				if err != nil {
					t.Errorf("could not create test file2, error: %s", err)
					return
				}
				if _, err := testFile2.WriteString("test content2"); err != nil {
					t.Errorf("could not write test file 2 content, err: %v", err)
				}
				if _, err := testFile2.Seek(0, io.SeekStart); err != nil {
					t.Errorf("could not seek test file start, err: %v", err)
				}

				archive, err := os.CreateTemp(t.TempDir(), "archive_*.zip")
				if err != nil {
					t.Errorf("could not create temp archive, err: %v", err)
				}

				zipWriter := zip.NewWriter(archive)
				f1, err := zipWriter.Create("file1")
				if err != nil {
					t.Errorf("could not create file1, err: %v", err)
				}
				if _, err := io.Copy(f1, testFile); err != nil {
					t.Errorf("could not copy test file to archive file1, err: %v", err)
				}
				f2, err := zipWriter.Create("file2")
				if err != nil {
					t.Errorf("could not create file2, err: %v", err)
				}
				if _, err := io.Copy(f2, testFile2); err != nil {
					t.Errorf("could not copy test file 2 to archive file 2, err: %v", err)
				}

				f3, err := zipWriter.Create("file3")
				if err != nil {
					t.Errorf("could not create file3, err: %v", err)
				}
				if _, err := io.Copy(f3, bytes.NewReader([]byte{})); err != nil {
					t.Errorf("could not copy test file 3 to archive file 3, err: %v", err)
				}

				if err = testFile.Close(); err != nil {
					t.Errorf("could not close testfile, err: %v", err)
				}
				if e := testFile2.Close(); e != nil {
					t.Errorf("could not close test file 2, error: %s", e)
				}

				if e := zipWriter.Close(); e != nil {
					t.Errorf("could not close zip writer, error: %s", e)
				}

				if e := archive.Close(); e != nil {
					t.Errorf("could not close archive, error: %s", e)
				}

				ctx, cancel := context.WithTimeout(t.Context(), time.Second*60)
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
					QuarantineFolder: t.TempDir(),
					Cache: &cache.MockCache{
						SetMock: func(entry *cache.Entry) error {
							return nil
						},
						GetBySha256Mock: func(id string) (entry *cache.Entry, err error) {
							if id == "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72" {
								return &cache.Entry{
									Sha256: "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72",
								}, nil
							}
							return nil, cache.ErrEntryNotFound
						},
					},
				}, filesystem.NewLocalFileSystem())
				defer conn.Close()
				if conn.config.Workers != 1 {
					t.Errorf("invalid workers %v", conn.config.Workers)
				}

				if a, ok := conn.action.(*MultiAction); !ok {
					t.Errorf("invalid action: %v", conn.action)
				} else if len(a.Actions) != 5 {
					t.Errorf("invalid actions %#v", a.Actions)
				}

				if err := conn.Start(); err != nil {
					t.Errorf("could not start connector, error: %v", err)
				}

				// prepare test files
				testDir := t.TempDir()
				testFile, err := os.CreateTemp(testDir, "ScanFile_test_*")
				if err != nil {
					t.Errorf("could not create test file, error: %s", err)
					return
				}
				if _, err := testFile.WriteString("test content"); err != nil {
					t.Errorf("could not write test file content, error: %s", err)
				}
				if _, err := testFile.Seek(0, io.SeekStart); err != nil {
					t.Errorf("could not seek test file start,error: %s", err)
				}

				testFile2, err := os.CreateTemp(testDir, "ScanFile_test2_*")
				if err != nil {
					t.Errorf("could not create test file2, error: %s", err)
					return
				}
				if _, err := testFile2.WriteString("test content2"); err != nil {
					t.Errorf("could not write test file 2 content, err: %v", err)
				}
				if _, err := testFile2.Seek(0, io.SeekStart); err != nil {
					t.Errorf("could not seek test file 2 start, error: %v", err)
				}

				archive, err := os.CreateTemp(t.TempDir(), "archive_*.zip")
				if err != nil {
					t.Errorf("could not create archive, error: %v", err)
					return
				}
				zipWriter := zip.NewWriter(archive)

				f1, err := zipWriter.Create("file1")
				if err != nil {
					t.Errorf("could not create archive file1, error: %v", err)
					return
				}
				if _, err := io.Copy(f1, testFile); err != nil {
					t.Errorf("could not copy content to archive file1, error: %v", err)
					return
				}
				f2, err := zipWriter.Create("file2")
				if err != nil {
					t.Errorf("could not create archive file2, error: %v", err)
					return
				}
				if _, err := io.Copy(f2, testFile2); err != nil {
					t.Errorf("could not copy content to archive file 2, error: %v", err)
					return
				}

				if err = testFile.Close(); err != nil {
					t.Errorf("could not close testfile, err: %v", err)
				}
				if e := testFile2.Close(); e != nil {
					t.Errorf("could not close test file 2, error: %s", e)
				}

				if e := zipWriter.Close(); e != nil {
					t.Errorf("could not close zip writer, error: %s", e)
				}
				if e := archive.Close(); e != nil {
					t.Errorf("could not close archive, error: %s", e)
				}

				ctx, cancel := context.WithTimeout(t.Context(), time.Second*60)
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
					QuarantineFolder: t.TempDir(),
					Cache: &cache.MockCache{
						SetMock: func(entry *cache.Entry) error {
							return nil
						},
						GetBySha256Mock: func(id string) (entry *cache.Entry, err error) {
							if id == "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72" {
								return &cache.Entry{
									Sha256: "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72",
								}, nil
							}
							return nil, cache.ErrEntryNotFound
						},
					},
				}, filesystem.NewLocalFileSystem())
				defer conn.Close()
				if conn.config.Workers != 1 {
					t.Errorf("invalid workers %v", conn.config.Workers)
				}

				if a, ok := conn.action.(*MultiAction); !ok {
					t.Errorf("invalid action: %v", conn.action)
				} else if len(a.Actions) != 5 {
					t.Errorf("invalid actions %#v", a.Actions)
				}

				if err := conn.Start(); err != nil {
					t.Errorf("could not start connector, error: %v", err)
				}

				// prepare test files
				testDir := t.TempDir()
				testFile, err := os.CreateTemp(testDir, "ScanFile_test_*")
				if err != nil {
					t.Errorf("could not create test file, error: %s", err)
					return
				}
				if _, err := testFile.WriteString("test content"); err != nil {
					t.Errorf("could not write test file content, err: %v", err)
					return
				}
				if err = testFile.Close(); err != nil {
					t.Errorf("could not close testfile, err: %v", err)
				}
				testFile2, err := os.CreateTemp(testDir, "ScanFile_test2_*")
				if err != nil {
					t.Errorf("could not create test file2, error: %s", err)
					return
				}
				if _, err := testFile2.WriteString("test content2"); err != nil {
					t.Errorf("could not write test file 2 content, err: %v", err)
				}
				if e := testFile2.Close(); e != nil {
					t.Errorf("could not close test file 2, error: %s", e)
				}

				ctx, cancel := context.WithTimeout(t.Context(), time.Second*30)
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
					QuarantineFolder: t.TempDir(),
					Cache: &cache.MockCache{
						SetMock: func(entry *cache.Entry) error {
							return nil
						},
						GetBySha256Mock: func(id string) (entry *cache.Entry, err error) {
							if id == "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72" {
								return &cache.Entry{
									Sha256: "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72",
								}, nil
							}
							return nil, cache.ErrEntryNotFound
						},
					},
				}, filesystem.NewLocalFileSystem())
				defer conn.Close()
				if conn.config.Workers != 1 {
					t.Errorf("invalid workers %v", conn.config.Workers)
				}

				if a, ok := conn.action.(*MultiAction); !ok {
					t.Errorf("invalid action: %v", conn.action)
				} else if len(a.Actions) != 5 {
					t.Errorf("invalid actions %#v", a.Actions)
				}

				if err := conn.Start(); err != nil {
					t.Errorf("could not start connector, error: %v", err)
				}

				// prepare test files
				testDir := t.TempDir()
				testFile, err := os.CreateTemp(testDir, "ScanFile_test_*")
				if err != nil {
					t.Errorf("could not create test file, error: %s", err)
					return
				}
				if _, err := testFile.WriteString("test content"); err != nil {
					t.Errorf("could not write test file content, err: %v", err)
					return
				}
				if err = testFile.Close(); err != nil {
					t.Errorf("could not close testfile, err: %v", err)
				}
				testFile2, err := os.CreateTemp(testDir, "ScanFile_test2_*")
				if err != nil {
					t.Errorf("could not create test file2, error: %s", err)
					return
				}
				if _, err := testFile2.WriteString("test content2"); err != nil {
					t.Errorf("could not write test file 2 content, err: %v", err)
				}
				if e := testFile2.Close(); e != nil {
					t.Errorf("could not close test file 2, error: %s", e)
				}

				ctx, cancel := context.WithTimeout(t.Context(), time.Second*30)
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
		testTmpDir := t.TempDir()
		t.Setenv("TMPDIR", testTmpDir)
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
		filesystem  filesystem.FileSystem
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
		{
			name: "ok too large archive on non-local filesystem",
			fields: fields{
				maxFileSize: 5,
				extract:     true,
				filesystem: &mock.FileSystemMock{
					IsLocalMock: func() bool {
						return false
					},
					LstatMock: func(ctx context.Context, name string) (fs.FileInfo, error) {
						return &testFileInfo{
							name: "test.zip",
							size: 1024, // File too large
							mode: 0o644,
						}, nil
					},
					OpenMock: func(ctx context.Context, name string) (io.ReadSeekCloser, error) {
						return &testReadSeekCloser{
							Reader: bytes.NewReader(zipFile),
							data:   zipFile,
						}, nil
					},
				},
			},
			args: args{
				fileContent: zipFile,
				extension:   "zip",
			},
			wantFileRetrieved: 1,
		},
		{
			name: "error open file on non-local filesystem",
			fields: fields{
				maxFileSize: 5,
				extract:     true,
				filesystem: &mock.FileSystemMock{
					IsLocalMock: func() bool {
						return false
					},
					LstatMock: func(ctx context.Context, name string) (fs.FileInfo, error) {
						return &testFileInfo{
							name: "test.zip",
							size: 1024, // File too large
							mode: 0o644,
						}, nil
					},
					OpenMock: func(ctx context.Context, name string) (io.ReadSeekCloser, error) {
						return nil, errors.New("failed to open file")
					},
				},
			},
			args: args{
				fileContent: zipFile,
				extension:   "zip",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			if tt.args.cancelled {
				cancel()
			} else {
				defer cancel()
			}

			if tt.fields.maxFileSize == 0 {
				tt.fields.maxFileSize = MaxFileSize
			}

			// Use provided filesystem or default to local filesystem
			fs := tt.fields.filesystem
			if fs == nil {
				fs = filesystem.NewLocalFileSystem()
			}

			c := &Connector{
				fs:       fs,
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

			if !tt.fields.unknownFile {
				if tt.fields.filesystem != nil {
					// For filesystem mock, use a dummy path
					input = "test_file." + tt.args.extension
				} else {
					// For local filesystem, create actual temp file
					f, err := os.CreateTemp(t.TempDir(), "test_*."+tt.args.extension)
					if err != nil {
						t.Errorf("could not create temp file, error: %s", err)
						return
					}
					defer func() {
						if err := f.Close(); err != nil {
							t.Errorf("could not close test file, err: %v", err)
						}
					}()
					if _, err := f.Write(tt.args.fileContent); err != nil {
						t.Errorf("could not write temp file content, error: %v", err)
					}
					input = f.Name()
				}
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

// Helper types for testing
type testFileInfo struct {
	name string
	size int64
	mode fs.FileMode
}

func (tfi *testFileInfo) Name() string       { return tfi.name }
func (tfi *testFileInfo) Size() int64        { return tfi.size }
func (tfi *testFileInfo) Mode() fs.FileMode  { return tfi.mode }
func (tfi *testFileInfo) ModTime() time.Time { return time.Now() }
func (tfi *testFileInfo) IsDir() bool        { return false }
func (tfi *testFileInfo) Sys() interface{}   { return nil }

type testReadSeekCloser struct {
	*bytes.Reader
	data []byte
}

func (trsc *testReadSeekCloser) Close() error { return nil }
