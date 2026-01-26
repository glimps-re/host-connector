package scanner

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/quarantine"
	quarantinemock "github.com/glimps-re/host-connector/pkg/quarantine/mock"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func createTestFile(t *testing.T, dir string, content string) (file string, fileSHA256 string) {
	testFile, err := os.CreateTemp(dir, "test*")
	if err != nil {
		t.Errorf("could not create test file, error: %s", err)
		return
	}
	defer func() {
		if e := testFile.Close(); e != nil {
			t.Fatalf("could not close test file: %v", e)
		}
	}()
	h := sha256.New()
	mw := io.MultiWriter(testFile, h)
	if _, e := mw.Write([]byte(content)); e != nil {
		t.Fatalf("could not write test file: %v", e)
	}

	file = testFile.Name()
	fileSHA256 = hex.EncodeToString(h.Sum(nil))
	return
}

func createArchiveWithRawFiles(t *testing.T, files map[string][]byte) (archive string, archiveSHA256 string) {
	testFile, err := os.CreateTemp(t.TempDir(), "archive_*.zip")
	if err != nil {
		t.Fatalf("failed to create archive temp file, error: %v", err)
	}
	defer func() {
		if e := testFile.Close(); e != nil {
			t.Fatalf("could not close archive, error: %v", e)
		}
	}()

	h := sha256.New()
	mw := io.MultiWriter(testFile, h)
	zipWriter := zip.NewWriter(mw)
	for filename, content := range files {
		subFile, err := zipWriter.Create(filename)
		if err != nil {
			t.Fatalf("could not create zip subfile, error: %v", err)
		}
		if _, e := subFile.Write(content); e != nil {
			t.Fatalf("could not write zip subfile, error: %v", e)
		}
	}
	if e := zipWriter.Close(); e != nil {
		t.Fatalf("could not close zip writer, error: %v", e)
	}
	archive = testFile.Name()
	archiveSHA256 = hex.EncodeToString(h.Sum(nil))
	return
}

func createArchive(t *testing.T, contents []string) (archive string, archiveSHA256 string) {
	testFile, err := os.CreateTemp(t.TempDir(), "archive_*.zip")
	if err != nil {
		t.Fatalf("failed to create archive temp file, error: %v", err)
	}
	defer func() {
		if e := testFile.Close(); e != nil {
			t.Fatalf("could not close archive, error: %v", err)
		}
	}()

	h := sha256.New()
	mw := io.MultiWriter(testFile, h)
	zipWriter := zip.NewWriter(mw)
	for i, content := range contents {
		subFile, err := zipWriter.Create(fmt.Sprintf("file-%d", i))
		if err != nil {
			t.Fatalf("could not create zip subfile, error: %v", err)
		}
		if _, e := subFile.Write([]byte(content)); e != nil {
			t.Fatalf("could not write zip subfile, error: %v", e)
		}
	}
	if e := zipWriter.Close(); e != nil {
		t.Fatalf("could not close zip writer, error: %v", e)
	}
	archive = testFile.Name()
	archiveSHA256 = hex.EncodeToString(h.Sum(nil))
	return
}

func assertFileDeleted(t *testing.T, buff *bytes.Buffer, file, cacheID string) {
	t.Helper()
	if !strings.HasSuffix(buff.String(), cacheID+".lock, it has been deleted\n") {
		t.Errorf("invalid output: %v, want suffix: %v", buff.String(), cacheID+".lock, it has been deleted")
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file %s is still here", file)
	}
}

func assertNoOutput(t *testing.T, buff *bytes.Buffer) {
	t.Helper()
	if buff.String() != "" {
		t.Errorf("scan file result: %s, want nothing", buff.String())
	}
}

func TestNewConnector(t *testing.T) {
	const (
		badFileContent = "bad content"
		badFileSHA256  = "a25deb99f1e7af7df190f5a433ff46c551edd82b4cad734f3457bc3fbc09e417"
	)
	type waitForResp struct {
		result gdetect.Result
		err    error
	}
	type fields struct {
		config          Config
		errQuarantine   bool
		isRestoredResps map[string]struct {
			restored bool
			err      error
		}
		submitterWaitForResps   map[string]waitForResp
		errExtractExpertViewURL bool
	}
	tests := []struct {
		name   string
		fields fields
		assert func(t *testing.T, c *Connector, buff *bytes.Buffer)
	}{
		{
			name: "ok connector config",
			fields: fields{
				config: Config{
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
					},
					QuarantineFolder: t.TempDir(),
				},
			},
			assert: func(t *testing.T, c *Connector, buff *bytes.Buffer) {
				if c.config.Workers != defaultWorkers {
					t.Errorf("invalid workers %v", c.config.Workers)
				}
				if a, ok := c.action.(*MultiAction); !ok {
					t.Errorf("invalid action: %v", c.action)
				} else if len(a.Actions) != 5 {
					t.Errorf("invalid actions %#v", a.Actions)
				}

				testFile, _ := createTestFile(t, t.TempDir(), "test content")
				err := c.ScanFile(t.Context(), testFile)
				if err != nil {
					t.Errorf("scan file error : %s", err)
				}
				c.Close(t.Context())
				assertNoOutput(t, buff)
			},
		},
		{
			name: "ok one malware file",
			fields: fields{
				config: Config{
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
					},
					QuarantineFolder: t.TempDir(),
				},
			},
			assert: func(t *testing.T, c *Connector, buff *bytes.Buffer) {
				testFile, fileSHA256 := createTestFile(t, t.TempDir(), badFileContent)
				if err := c.ScanFile(t.Context(), testFile); err != nil {
					t.Errorf("unwanted error: %v", err)
				}
				// Wait for workers to finish processing
				c.Close(t.Context())
				cacheID := quarantine.ComputeCacheID(testFile, fileSHA256)
				assertFileDeleted(t, buff, testFile, cacheID)
			},
		},
		{
			name: "ok archive clean",
			fields: fields{
				config: Config{
					MaxFileSize:         200,
					ExtractMinThreshold: 1,
					Extract:             true,
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
					},
					QuarantineFolder: t.TempDir(),
				},
			},
			assert: func(t *testing.T, c *Connector, buff *bytes.Buffer) {
				archive, _ := createArchive(t, []string{"content1", "content2"})
				if e := c.ScanFile(t.Context(), archive); e != nil {
					t.Errorf("unwanted error: %v", e)
				}
				c.Close(t.Context())
				assertNoOutput(t, buff)
			},
		},
		{
			name: "ok archive with malware",
			fields: fields{
				config: Config{
					MaxFileSize:         200,
					ExtractMinThreshold: 1,
					Extract:             true,
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
					},
					QuarantineFolder: t.TempDir(),
				},
			},
			assert: func(t *testing.T, c *Connector, buff *bytes.Buffer) {
				archive, archiveSHA256 := createArchive(t, []string{"content1", "content2", badFileContent})
				if e := c.ScanFile(t.Context(), archive); e != nil {
					t.Errorf("unwanted error: %v", e)
				}
				// Wait for workers to finish processing
				c.Close(t.Context())
				cacheID := quarantine.ComputeCacheID(archive, archiveSHA256)
				assertFileDeleted(t, buff, archive, cacheID)
			},
		},
		{
			name: "test folder",
			fields: fields{
				config: Config{
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
					},
					QuarantineFolder: t.TempDir(),
				},
			},
			assert: func(t *testing.T, c *Connector, buff *bytes.Buffer) {
				folder, err := os.MkdirTemp(t.TempDir(), "testfolder") //nolint:usetesting // we want to check if we analyze the created folder
				if err != nil {
					t.Fatalf("error creating folder, error: %v", err)
				}
				createTestFile(t, folder, "content1")
				badFile, _ := createTestFile(t, folder, badFileContent)

				if e := c.ScanFile(t.Context(), folder); e != nil {
					t.Errorf("unwanted error: %v", e)
				}
				// Wait for workers to finish processing
				c.Close(t.Context())
				cacheID := quarantine.ComputeCacheID(badFile, badFileSHA256)
				assertFileDeleted(t, buff, badFile, cacheID)
			},
		},
		{
			name: "test folder verbose",
			fields: fields{
				config: Config{
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
						Verbose:    true,
					},
					QuarantineFolder: t.TempDir(),
				},
			},
			assert: func(t *testing.T, c *Connector, buff *bytes.Buffer) {
				folder, err := os.MkdirTemp(t.TempDir(), "otherfolder") //nolint:usetesting // we want to check if we analyze the created folder
				if err != nil {
					t.Fatalf("error creating folder, error: %v", err)
				}
				createTestFile(t, folder, "content1")
				createTestFile(t, folder, "content2")

				if e := c.ScanFile(t.Context(), folder); e != nil {
					t.Errorf("unwanted error: %v", e)
				}
				c.Close(t.Context())

				if !strings.HasSuffix(buff.String(), "no malware found\n") {
					t.Errorf("invalid output: %v", buff.String())
				}
			},
		},
		{
			name: "test folder with symlink followed",
			fields: fields{
				config: Config{
					FollowSymlinks: true,
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
					},
					QuarantineFolder: t.TempDir(),
				},
			},
			assert: func(t *testing.T, c *Connector, buff *bytes.Buffer) {
				folder, err := os.MkdirTemp(t.TempDir(), "testfolder") //nolint:usetesting // we want to check if we analyze the created folder
				if err != nil {
					t.Fatalf("error creating folder, error: %v", err)
				}
				// Create a regular file
				createTestFile(t, folder, "clean content")

				// Create a target file for symlink in a different directory
				targetDir := t.TempDir()
				targetFile, _ := createTestFile(t, targetDir, badFileContent)

				// Create symlink in the folder pointing to the bad file
				symlinkPath := filepath.Join(folder, "symlink_to_bad")
				if err := os.Symlink(targetFile, symlinkPath); err != nil {
					t.Fatalf("could not create symlink: %v", err)
				}

				if e := c.ScanFile(t.Context(), folder); e != nil {
					t.Errorf("unwanted error: %v", e)
				}
				c.Close(t.Context())

				// The symlink should be followed and scanned, and the symlink itself should be deleted
				cacheID := quarantine.ComputeCacheID(symlinkPath, badFileSHA256)
				assertFileDeleted(t, buff, symlinkPath, cacheID)
				// Target file should still exist
				if _, err := os.Stat(targetFile); err != nil {
					t.Errorf("target file should still exist but got error: %v", err)
				}
			},
		},
		{
			name: "test folder with symlink not followed",
			fields: fields{
				config: Config{
					FollowSymlinks: false,
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
						Verbose:    true,
					},
					QuarantineFolder: t.TempDir(),
				},
			},
			assert: func(t *testing.T, c *Connector, buff *bytes.Buffer) {
				folder, err := os.MkdirTemp(t.TempDir(), "testfolder") //nolint:usetesting // we want to check if we analyze the created folder
				if err != nil {
					t.Fatalf("error creating folder, error: %v", err)
				}
				// Create a regular clean file
				createTestFile(t, folder, "clean content")

				// Create a target file for symlink in a different directory
				targetDir := t.TempDir()
				targetFile, _ := createTestFile(t, targetDir, badFileContent)

				// Create symlink in the folder pointing to the bad file
				symlinkPath := filepath.Join(folder, "symlink_to_bad")
				if err := os.Symlink(targetFile, symlinkPath); err != nil {
					t.Fatalf("could not create symlink: %v", err)
				}

				if e := c.ScanFile(t.Context(), folder); e != nil {
					t.Errorf("unwanted error: %v", e)
				}
				c.Close(t.Context())

				// The symlink should be skipped, so only the clean file is scanned
				if !strings.HasSuffix(buff.String(), "no malware found\n") {
					t.Errorf("invalid output: %v", buff.String())
				}
				// Target file should still exist (not deleted)
				if _, err := os.Stat(targetFile); err != nil {
					t.Errorf("target file should still exist but got error: %v", err)
				}
			},
		},
		{
			name: "test folder with broken symlink followed",
			fields: fields{
				config: Config{
					FollowSymlinks: true,
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
					},
					QuarantineFolder: t.TempDir(),
				},
			},
			assert: func(t *testing.T, c *Connector, buff *bytes.Buffer) {
				// Create symlink pointing to non-existent file
				nonExistentPath := filepath.Join(t.TempDir(), "nonexistent")
				symlinkPath := filepath.Join(t.TempDir(), "broken_symlink")
				if err := os.Symlink(nonExistentPath, symlinkPath); err != nil {
					t.Fatalf("could not create symlink: %v", err)
				}

				// ScanFile on folder will fail because broken symlink cannot be stat'ed
				err := c.ScanFile(t.Context(), symlinkPath)
				if err == nil {
					t.Errorf("expected error for broken symlink, got nil")
				}
				if !strings.Contains(err.Error(), "no such file or directory") {
					t.Errorf("expected 'no such file or directory' error, got: %v", err)
				}
				c.Close(t.Context())
			},
		},
		{
			name: "test one archive with callbacks",
			fields: fields{
				config: Config{
					MaxFileSize:         200,
					ExtractMinThreshold: 1,
					Extract:             true,
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
					},
					QuarantineFolder: t.TempDir(),
				},
			},
			assert: func(t *testing.T, c *Connector, buff *bytes.Buffer) {
				archive, archiveSHA256 := createArchive(t, []string{"content1", "content2", badFileContent})

				// atomic because callbacks are called from worker goroutines
				var onStartCalled atomic.Int64
				var onScanCalled atomic.Int64

				c.onStartScanFileCbs = append(c.onStartScanFileCbs, func(file string, sha256 string) {
					onStartCalled.Add(1)
				})
				c.onScanFileCbs = append(c.onScanFileCbs, func(filename string, location string, sha256 string, isArchive bool) (res *datamodel.Result) {
					onScanCalled.Add(1)
					return
				})

				if e := c.ScanFile(t.Context(), archive); e != nil {
					t.Errorf("unwanted error: %v", e)
				}
				// Wait for workers to finish processing
				c.Close(t.Context())
				cacheID := quarantine.ComputeCacheID(archive, archiveSHA256)
				assertFileDeleted(t, buff, archive, cacheID)

				if onStartCalled.Load() != 1 {
					t.Fatalf("start scan call %d time(s), want 1", onStartCalled.Load())
				}
				if onScanCalled.Load() != 4 {
					t.Fatalf("scan call %d time(s), want 4", onScanCalled.Load())
				}
			},
		},
		{
			name: "ok archive with all empty files",
			fields: fields{
				config: Config{
					MaxFileSize:         200,
					ExtractMinThreshold: 1,
					Extract:             true,
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
					},
					QuarantineFolder: t.TempDir(),
				},
			},
			assert: func(t *testing.T, c *Connector, buff *bytes.Buffer) {
				archive, _ := createArchive(t, []string{"", "", ""})
				if e := c.ScanFile(t.Context(), archive); e != nil {
					t.Errorf("unwanted error: %v", e)
				}
				c.Close(t.Context())
				assertNoOutput(t, buff)
			},
		},
		{
			name: "skip previously restored file",
			fields: fields{
				config: Config{
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
					},
					QuarantineFolder: t.TempDir(),
				},
				isRestoredResps: map[string]struct {
					restored bool
					err      error
				}{
					badFileSHA256: {
						restored: true,
					},
				},
			},
			assert: func(t *testing.T, c *Connector, buff *bytes.Buffer) {
				testFile, _ := createTestFile(t, t.TempDir(), badFileContent)
				if err := c.ScanFile(t.Context(), testFile); err != nil {
					t.Errorf("unwanted error: %v", err)
				}
				c.Close(t.Context())
				// File should not be acted upon (no output)
				assertNoOutput(t, buff)
				// File should still exist (not deleted)
				if _, err := os.Stat(testFile); err != nil {
					t.Fatalf("file %s should still exist but got error: %v", testFile, err)
				}
			},
		},
		{
			name: "error cache set fails",
			fields: fields{
				config: Config{
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
					},
					QuarantineFolder: t.TempDir(),
				},
				errQuarantine: true,
				isRestoredResps: map[string]struct {
					restored bool
					err      error
				}{
					badFileSHA256: {
						restored: true,
					},
				},
			},
			assert: func(t *testing.T, c *Connector, buff *bytes.Buffer) {
				testFile, _ := createTestFile(t, t.TempDir(), badFileContent)
				if err := c.ScanFile(t.Context(), testFile); err != nil {
					t.Errorf("unwanted error: %v", err)
				}
				c.Close(t.Context())
				// Even if cache set fails, file should still be marked as restored
				assertNoOutput(t, buff)
			},
		},
		{
			name: "error cache get fails",
			fields: fields{
				config: Config{
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
					},
					QuarantineFolder: t.TempDir(),
				},
				isRestoredResps: map[string]struct {
					restored bool
					err      error
				}{
					badFileSHA256: {
						err: errors.New("error isRestored"),
					},
				},
			},
			assert: func(t *testing.T, c *Connector, buff *bytes.Buffer) {
				testFile, _ := createTestFile(t, t.TempDir(), badFileContent)
				err := c.ScanFile(t.Context(), testFile)
				// Should return error from cache
				if err == nil {
					t.Errorf("expected error from cache, got nil")
				}
				c.Close(t.Context())
			},
		},
		{
			name: "ok large file without extraction",
			fields: fields{
				config: Config{
					MaxFileSize: 10,
					Extract:     false,
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
					},
					QuarantineFolder: t.TempDir(),
				},
			},
			assert: func(t *testing.T, c *Connector, buff *bytes.Buffer) {
				testFile, _ := createTestFile(t, t.TempDir(), badFileContent)
				if err := c.ScanFile(t.Context(), testFile); err != nil {
					t.Errorf("unwanted error: %v", err)
				}
				c.Close(t.Context())
				// File is too large, error result doesn't trigger actions (no malware detected)
				assertNoOutput(t, buff)
			},
		},
		{
			name: "error submitter wait for file",
			fields: fields{
				config: Config{
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
					},
					QuarantineFolder: t.TempDir(),
				},
				submitterWaitForResps: map[string]waitForResp{
					badFileSHA256: {
						result: gdetect.Result{},
						err:    errors.New("submitter error"),
					},
				},
			},
			assert: func(t *testing.T, c *Connector, buff *bytes.Buffer) {
				testFile, _ := createTestFile(t, t.TempDir(), badFileContent)
				if err := c.ScanFile(t.Context(), testFile); err != nil {
					t.Errorf("unwanted error: %v", err)
				}
				c.Close(t.Context())
				// Error from submitter doesn't trigger actions (no malware detected)
				assertNoOutput(t, buff)
			},
		},
		{
			name: "error extract expert view url",
			fields: fields{
				config: Config{
					Actions: Actions{
						Deleted:    true,
						Quarantine: true,
						Log:        true,
						Inform:     true,
					},
					QuarantineFolder: t.TempDir(),
				},
				errExtractExpertViewURL: true,
			},
			assert: func(t *testing.T, c *Connector, buff *bytes.Buffer) {
				testFile, fileSHA256 := createTestFile(t, t.TempDir(), badFileContent)
				if err := c.ScanFile(t.Context(), testFile); err != nil {
					t.Errorf("unwanted error: %v", err)
				}
				// Wait for workers to finish processing
				c.Close(t.Context())
				// Should handle error from ExtractExpertViewURL gracefully
				cacheID := quarantine.ComputeCacheID(testFile, fileSHA256)
				assertFileDeleted(t, buff, testFile, cacheID)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			submitter := &mockSubmitter{
				ExtractExpertViewURLMock: func(result *gdetect.Result) (urlExpertView string, err error) {
					if tt.fields.errExtractExpertViewURL {
						err = errors.New("error extracting expert view url")
						return
					}
					return
				},
				WaitForFileMock: func(ctx context.Context, file string, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
					f, err := os.Open(filepath.Clean(file))
					if err != nil {
						t.Fatalf("could not open file, err: %v", err)
					}
					defer func() {
						if e := f.Close(); e != nil {
							t.Fatalf("could not close file, err: %v", e)
						}
					}()
					hash := sha256.New()
					if _, err = io.Copy(hash, f); err != nil {
						return
					}
					sha256Sum := hex.EncodeToString(hash.Sum(nil))
					if resp, ok := tt.fields.submitterWaitForResps[sha256Sum]; ok {
						return resp.result, resp.err
					}
					if sha256Sum == badFileSHA256 {
						result = gdetect.Result{
							Malware:  true,
							Malwares: []string{"MALWARE"},
						}
						return
					}
					return
				},
			}
			quarantiner := quarantinemock.QuarantineMock{
				QuarantineMock: func(ctx context.Context, file, fileSHA256 string, malwares []string) (quarantineLocation string, entryID string, err error) {
					if tt.fields.errQuarantine {
						err = errors.New("error quarantine")
						return
					}
					entryID = quarantine.ComputeCacheID(file, fileSHA256)
					quarantineLocation = filepath.Join(t.TempDir(), entryID+".lock")
					return
				},
				IsRestoredMock: func(ctx context.Context, sha256 string) (restored bool, err error) {
					if resp, ok := tt.fields.isRestoredResps[sha256]; ok {
						restored = resp.restored
						err = resp.err
						return
					}
					return
				},
			}
			buff := bytes.NewBuffer(nil)
			tt.fields.config.Actions.InformDest = buff
			con := NewConnector(tt.fields.config, &quarantiner, submitter)
			if e := con.Start(); e != nil {
				t.Fatalf("could not start connector, error: %v", e.Error())
			}
			tt.assert(t, con, buff)
		})
	}
}

func TestConnector_handleFile(t *testing.T) {
	type fields struct {
		config                   Config
		onScanFileResp           *datamodel.Result
		submitterWaitForFileResp struct {
			result gdetect.Result
			err    error
		}
		submitterExtractURLResp struct {
			url string
			err error
		}
	}
	type args struct {
		input fileToAnalyze
	}
	tests := []struct {
		name              string
		fields            fields
		args              args
		wantResult        datamodel.Result
		wantAnalysisError []string
	}{
		{
			name: "ok onScanFile returns result",
			fields: fields{
				config: Config{
					Timeout:     sdk.Duration(1 * time.Second),
					MaxFileSize: 1000,
				},
				onScanFileResp: &datamodel.Result{
					Filename: "test.txt",
					Location: "/path/test.txt",
					SHA256:   "abc123",
				},
			},
			args: args{
				input: fileToAnalyze{
					filename: "test.txt",
					location: "/path/test.txt",
					sha256:   "abc123",
					size:     100,
				},
			},
			wantResult: datamodel.Result{
				Filename: "test.txt",
				Location: "/path/test.txt",
				SHA256:   "abc123",
			},
		},
		{
			name: "ok file too big",
			fields: fields{
				config: Config{
					Timeout:     sdk.Duration(1 * time.Second),
					MaxFileSize: 100,
				},
			},
			args: args{
				input: fileToAnalyze{
					filename: "large.txt",
					location: "/path/large.txt",
					sha256:   "def456",
					size:     200,
				},
			},
			wantResult: datamodel.Result{
				Filename: "large.txt",
				Location: "/path/large.txt",
				SHA256:   "def456",
				FileSize: 200,
				Error:    errors.New("file is too big to be analyzed"),
			},
		},
		{
			name: "ok malware detected",
			fields: fields{
				config: Config{
					Timeout:     sdk.Duration(1 * time.Second),
					MaxFileSize: 1000,
				},
				submitterWaitForFileResp: struct {
					result gdetect.Result
					err    error
				}{
					result: gdetect.Result{
						Malware:  true,
						Malwares: []string{"Trojan.Generic"},
						FileType: "PE32",
						FileSize: 500,
						Files:    []gdetect.FileResult{{Size: 500}},
					},
					err: nil,
				},
				submitterExtractURLResp: struct {
					url string
					err error
				}{
					url: "https://example.com/analysis/123",
					err: nil,
				},
			},
			args: args{
				input: fileToAnalyze{
					filename: "malware.exe",
					location: "/path/malware.exe",
					sha256:   "bad123",
					size:     500,
				},
			},
			wantResult: datamodel.Result{
				Filename:       "malware.exe",
				Location:       "/path/malware.exe",
				SHA256:         "bad123",
				Malware:        true,
				Malwares:       []string{"Trojan.Generic"},
				FileType:       "PE32",
				FileSize:       500,
				AnalyzedVolume: 500,
				GMalwareURL:    "https://example.com/analysis/123",
				MalwareReason:  datamodel.MalwareDetected,
			},
		},
		{
			name: "ok clean file",
			fields: fields{
				config: Config{
					Timeout:     sdk.Duration(1 * time.Second),
					MaxFileSize: 1000,
				},
				submitterWaitForFileResp: struct {
					result gdetect.Result
					err    error
				}{
					result: gdetect.Result{
						Malware:  false,
						Malwares: []string{},
						FileType: "text/plain",
						FileSize: 100,
					},
					err: nil,
				},
				submitterExtractURLResp: struct {
					url string
					err error
				}{
					url: "https://example.com/analysis/456",
					err: nil,
				},
			},
			args: args{
				input: fileToAnalyze{
					filename: "clean.txt",
					location: "/path/clean.txt",
					sha256:   "clean123",
					size:     100,
				},
			},
			wantResult: datamodel.Result{
				Filename:    "clean.txt",
				Location:    "/path/clean.txt",
				SHA256:      "clean123",
				Malware:     false,
				Malwares:    []string{},
				FileType:    "text/plain",
				FileSize:    100,
				GMalwareURL: "https://example.com/analysis/456",
			},
		},
		{
			name: "ok with analyzed volume",
			fields: fields{
				config: Config{
					Timeout:     sdk.Duration(1 * time.Second),
					MaxFileSize: 1000,
				},
				submitterWaitForFileResp: struct {
					result gdetect.Result
					err    error
				}{
					result: gdetect.Result{
						Malware:  false,
						FileType: "application/zip",
						FileSize: 500,
						Files: []gdetect.FileResult{
							{Size: 100},
							{Size: 200},
							{Size: 150},
						},
					},
					err: nil,
				},
				submitterExtractURLResp: struct {
					url string
					err error
				}{
					url: "https://example.com/analysis/789",
					err: nil,
				},
			},
			args: args{
				input: fileToAnalyze{
					filename: "archive.zip",
					location: "/path/archive.zip",
					sha256:   "zip123",
					size:     500,
				},
			},
			wantResult: datamodel.Result{
				Filename:       "archive.zip",
				Location:       "/path/archive.zip",
				SHA256:         "zip123",
				Malware:        false,
				Malwares:       nil,
				FileType:       "application/zip",
				FileSize:       500,
				AnalyzedVolume: 450,
				GMalwareURL:    "https://example.com/analysis/789",
			},
		},
		{
			name: "error timeout",
			fields: fields{
				config: Config{
					Timeout:     sdk.Duration(1 * time.Second),
					MaxFileSize: 1000,
				},
				submitterWaitForFileResp: struct {
					result gdetect.Result
					err    error
				}{
					result: gdetect.Result{},
					err:    context.DeadlineExceeded,
				},
			},
			args: args{
				input: fileToAnalyze{
					filename: "timeout.txt",
					location: "/path/timeout.txt",
					sha256:   "timeout123",
					size:     100,
				},
			},
			wantResult: datamodel.Result{
				Filename: "timeout.txt",
				Location: "/path/timeout.txt",
				SHA256:   "timeout123",
				FileSize: 100,
				Error:    context.DeadlineExceeded,
			},
		},
		{
			name: "error http error",
			fields: fields{
				config: Config{
					Timeout:     sdk.Duration(1 * time.Second),
					MaxFileSize: 1000,
				},
				submitterWaitForFileResp: struct {
					result gdetect.Result
					err    error
				}{
					result: gdetect.Result{},
					err:    gdetect.HTTPError{Code: 500, Status: "Internal Server Error", Body: "server error"},
				},
			},
			args: args{
				input: fileToAnalyze{
					filename: "error.txt",
					location: "/path/error.txt",
					sha256:   "error123",
					size:     100,
				},
			},
			wantResult: datamodel.Result{
				Filename: "error.txt",
				Location: "/path/error.txt",
				SHA256:   "error123",
				FileSize: 100,
				Error:    &gdetect.HTTPError{Code: 500, Status: "Internal Server Error", Body: "server error"},
			},
		},
		{
			name: "error http error unauthorized",
			fields: fields{
				config: Config{
					Timeout:     sdk.Duration(1 * time.Second),
					MaxFileSize: 1000,
				},
				submitterWaitForFileResp: struct {
					result gdetect.Result
					err    error
				}{
					result: gdetect.Result{},
					err:    gdetect.HTTPError{Code: 401, Status: "Unauthorized", Body: "authentication required"},
				},
			},
			args: args{
				input: fileToAnalyze{
					filename: "unauthorized.txt",
					location: "/path/unauthorized.txt",
					sha256:   "unauth123",
					size:     100,
				},
			},
			wantResult: datamodel.Result{
				Filename: "unauthorized.txt",
				Location: "/path/unauthorized.txt",
				SHA256:   "unauth123",
				FileSize: 100,
				Error:    &gdetect.HTTPError{Code: 401, Status: "Unauthorized", Body: "authentication required"},
			},
		},
		{
			name: "error other error",
			fields: fields{
				config: Config{
					Timeout:     sdk.Duration(1 * time.Second),
					MaxFileSize: 1000,
				},
				submitterWaitForFileResp: struct {
					result gdetect.Result
					err    error
				}{
					result: gdetect.Result{},
					err:    errors.New("generic error"),
				},
			},
			args: args{
				input: fileToAnalyze{
					filename: "fail.txt",
					location: "/path/fail.txt",
					sha256:   "fail123",
					size:     100,
				},
			},
			wantResult: datamodel.Result{
				Filename: "fail.txt",
				Location: "/path/fail.txt",
				SHA256:   "fail123",
				FileSize: 100,
				Error:    errors.New("generic error"),
			},
		},
		{
			name: "error ExtractExpertViewURL fails",
			fields: fields{
				config: Config{
					Timeout:     sdk.Duration(1 * time.Second),
					MaxFileSize: 1000,
				},
				submitterWaitForFileResp: struct {
					result gdetect.Result
					err    error
				}{
					result: gdetect.Result{
						Malware:  false,
						FileType: "text/plain",
						FileSize: 100,
					},
					err: nil,
				},
				submitterExtractURLResp: struct {
					url string
					err error
				}{
					url: "",
					err: errors.New("url extraction error"),
				},
			},
			args: args{
				input: fileToAnalyze{
					filename: "nourl.txt",
					location: "/path/nourl.txt",
					sha256:   "nourl123",
					size:     100,
				},
			},
			wantResult: datamodel.Result{
				Filename:    "nourl.txt",
				Location:    "/path/nourl.txt",
				SHA256:      "nourl123",
				Malware:     false,
				Malwares:    nil,
				FileType:    "text/plain",
				FileSize:    100,
				GMalwareURL: "",
			},
		},
		{
			name: "ok gdetectResult with Error field",
			fields: fields{
				config: Config{
					Timeout:     sdk.Duration(1 * time.Second),
					MaxFileSize: 1000,
				},
				submitterWaitForFileResp: struct {
					result gdetect.Result
					err    error
				}{
					result: gdetect.Result{
						Malware:  false,
						FileType: "text/plain",
						FileSize: 100,
						Error:    "analysis error occurred",
					},
					err: nil,
				},
				submitterExtractURLResp: struct {
					url string
					err error
				}{
					url: "https://example.com/analysis/999",
					err: nil,
				},
			},
			args: args{
				input: fileToAnalyze{
					filename: "analyzerror.txt",
					location: "/path/analyzerror.txt",
					sha256:   "analyzerror123",
					size:     100,
				},
			},
			wantResult: datamodel.Result{
				Filename:    "analyzerror.txt",
				Location:    "/path/analyzerror.txt",
				SHA256:      "analyzerror123",
				Malware:     false,
				FileType:    "text/plain",
				FileSize:    100,
				GMalwareURL: "https://example.com/analysis/999",
			},
			wantAnalysisError: []string{"analysis error occurred"},
		},
		{
			name: "ok gdetectResult with errors",
			fields: fields{
				config: Config{
					Timeout:     sdk.Duration(1 * time.Second),
					MaxFileSize: 1000,
				},
				submitterWaitForFileResp: struct {
					result gdetect.Result
					err    error
				}{
					result: gdetect.Result{
						Malware:  false,
						FileType: "text/plain",
						FileSize: 100,
						Errors: map[string]string{
							"extract":    "error",
							"deepengine": "error",
						},
						Error: "error with 2 service",
					},
					err: nil,
				},
				submitterExtractURLResp: struct {
					url string
					err error
				}{
					url: "https://example.com/analysis/888",
					err: nil,
				},
			},
			args: args{
				input: fileToAnalyze{
					filename: "multiperror.txt",
					location: "/path/multiperror.txt",
					sha256:   "multiperror123",
					size:     100,
				},
			},
			wantResult: datamodel.Result{
				Filename:    "multiperror.txt",
				Location:    "/path/multiperror.txt",
				SHA256:      "multiperror123",
				Malware:     false,
				FileType:    "text/plain",
				FileSize:    100,
				GMalwareURL: "https://example.com/analysis/888",
			},
			wantAnalysisError: []string{"extract: error", "deepengine: error"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			submitter := &mockSubmitter{
				WaitForFileMock: func(ctx context.Context, filepath string, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
					return tt.fields.submitterWaitForFileResp.result, tt.fields.submitterWaitForFileResp.err
				},
				ExtractExpertViewURLMock: func(result *gdetect.Result) (urlExpertView string, err error) {
					return tt.fields.submitterExtractURLResp.url, tt.fields.submitterExtractURLResp.err
				},
			}

			c := &Connector{
				submitter: submitter,
				config:    tt.fields.config,
			}

			if tt.fields.onScanFileResp != nil {
				c.onScanFileCbs = append(c.onScanFileCbs, func(filename string, location string, sha256 string, isArchive bool) (res *datamodel.Result) {
					return tt.fields.onScanFileResp
				})
			}

			gotResult := c.handleFile(tt.args.input)

			// Compare all fields except Error and AnalysisError using cmp.Diff
			if diff := cmp.Diff(gotResult, tt.wantResult, cmpopts.IgnoreFields(datamodel.Result{}, "Error", "AnalysisError")); diff != "" {
				t.Errorf("handleFile() diff(-got +want):\n%s", diff)
			}

			// Check AnalysisError contains expected strings
			for _, want := range tt.wantAnalysisError {
				if !strings.Contains(gotResult.AnalysisError, want) {
					t.Errorf("handleFile() AnalysisError = %v, want to contain %v", gotResult.AnalysisError, want)
				}
			}

			if tt.wantResult.Error != nil {
				if gotResult.Error == nil {
					t.Errorf("handleFile() result Error = %v, want %v", gotResult.Error, tt.wantResult.Error)
					return
				}
				if !errors.Is(tt.wantResult.Error, gotResult.Error) {
					if tt.wantResult.Error.Error() != gotResult.Error.Error() {
						t.Errorf("handleFile() result Error = %v, want %v", gotResult.Error, tt.wantResult.Error)
					}
				}
				return
			}
			if gotResult.Error != nil {
				t.Errorf("handleFile() result Error = %v, want %v", gotResult.Error, tt.wantResult.Error)
			}
		})
	}
}

func Test_getFileSHA256(t *testing.T) {
	type fields struct {
		fileContent    string
		fileNotExist   bool
		usePathWithDot bool
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "ok valid file with content",
			fields: fields{
				fileContent: "test content",
			},
			wantErr: false,
		},
		{
			name: "ok empty file",
			fields: fields{
				fileContent: "",
			},
			wantErr: false,
		},
		{
			name: "ok large file",
			fields: fields{
				fileContent: strings.Repeat("a", 256*1024),
			},
			wantErr: false,
		},
		{
			name: "error file does not exist",
			fields: fields{
				fileNotExist: true,
			},
			wantErr: true,
		},
		{
			name: "ok path with dots",
			fields: fields{
				fileContent:    "test content",
				usePathWithDot: true,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var expectedSHA256 string
			location := filepath.Join(t.TempDir(), "nonexistent.txt")

			if !tt.fields.fileNotExist {
				// Create file and compute expected SHA256 simultaneously
				testFile, err := os.CreateTemp(t.TempDir(), "test*")
				if err != nil {
					t.Fatalf("could not create test file: %v", err)
				}

				hash := sha256.New()
				mw := io.MultiWriter(testFile, hash)
				if _, err := mw.Write([]byte(tt.fields.fileContent)); err != nil {
					t.Fatalf("could not write test file: %v", err)
				}
				if err := testFile.Close(); err != nil {
					t.Fatalf("could not close test file: %v", err)
				}

				location = testFile.Name()
				expectedSHA256 = hex.EncodeToString(hash.Sum(nil))

				if tt.fields.usePathWithDot {
					location = location + string(filepath.Separator) + ".." + string(filepath.Separator) + filepath.Base(location)
				}
			}

			gotFileSHA256, err := getFileSHA256(location)
			if (err != nil) != tt.wantErr {
				t.Errorf("getFileSHA256() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if gotFileSHA256 != expectedSHA256 {
				t.Errorf("getFileSHA256() = %v, want %v", gotFileSHA256, expectedSHA256)
			}
		})
	}
}

func Test_Connector_checkBeforeExtract(t *testing.T) {
	type fields struct {
		recursiveExtractMaxDepth int
		extractMinThreshold      int64
		recursiveExtractMaxSize  int64
		recursiveExtractMaxFiles int
		fileContent              string
		fileNotExist             bool
		createZipArchive         bool
	}
	type args struct {
		size                int64
		totalExtractedSize  *int64
		totalExtractedFiles *int
		depth               int
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "ko max depth reached",
			fields: fields{
				recursiveExtractMaxDepth: 5,
				extractMinThreshold:      100,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				fileContent:              strings.Repeat("a", 200),
			},
			args: args{
				size:                200,
				totalExtractedSize:  ptrInt64(0),
				totalExtractedFiles: ptrInt(0),
				depth:               5,
			},
			wantErr: true,
		},
		{
			name: "ko size below threshold",
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      1000,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				fileContent:              strings.Repeat("a", 500),
			},
			args: args{
				size:                500,
				totalExtractedSize:  ptrInt64(0),
				totalExtractedFiles: ptrInt(0),
				depth:               0,
			},
			wantErr: true,
		},
		{
			name: "ko totalExtractedSize nil",
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      100,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				fileContent:              strings.Repeat("a", 200),
			},
			args: args{
				size:                200,
				totalExtractedSize:  nil,
				totalExtractedFiles: ptrInt(0),
				depth:               0,
			},
			wantErr: true,
		},
		{
			name: "ko total extracted size limit reached",
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      100,
				recursiveExtractMaxSize:  1000,
				recursiveExtractMaxFiles: 100,
				fileContent:              strings.Repeat("a", 200),
			},
			args: args{
				size:                200,
				totalExtractedSize:  ptrInt64(1001),
				totalExtractedFiles: ptrInt(0),
				depth:               0,
			},
			wantErr: true,
		},
		{
			name: "ko totalExtractedFiles nil",
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      100,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				fileContent:              strings.Repeat("a", 200),
			},
			args: args{
				size:                200,
				totalExtractedSize:  ptrInt64(0),
				totalExtractedFiles: nil,
				depth:               0,
			},
			wantErr: true,
		},
		{
			name: "ko total extracted files limit reached",
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      100,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 50,
				fileContent:              strings.Repeat("a", 200),
			},
			args: args{
				size:                200,
				totalExtractedSize:  ptrInt64(0),
				totalExtractedFiles: ptrInt(51),
				depth:               0,
			},
			wantErr: true,
		},
		{
			name: "ko file does not exist",
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      100,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				fileNotExist:             true,
			},
			args: args{
				size:                200,
				totalExtractedSize:  ptrInt64(0),
				totalExtractedFiles: ptrInt(0),
				depth:               0,
			},
			wantErr: true,
		},
		{
			name: "ko type not in extractable list",
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      100,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				fileContent:              "plain text content",
			},
			args: args{
				size:                200,
				totalExtractedSize:  ptrInt64(0),
				totalExtractedFiles: ptrInt(0),
				depth:               0,
			},
			wantErr: true,
		},
		{
			name: "ok zip file",
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      1,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				createZipArchive:         true,
			},
			args: args{
				size:                200,
				totalExtractedSize:  ptrInt64(0),
				totalExtractedFiles: ptrInt(0),
				depth:               0,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Connector{
				config: Config{
					RecursiveExtractMaxDepth: tt.fields.recursiveExtractMaxDepth,
					ExtractMinThreshold:      tt.fields.extractMinThreshold,
					RecursiveExtractMaxSize:  tt.fields.recursiveExtractMaxSize,
					RecursiveExtractMaxFiles: tt.fields.recursiveExtractMaxFiles,
				},
				typesToExtract: extractableTypes(),
			}

			var location string
			switch {
			case tt.fields.fileNotExist:
				location = filepath.Join(t.TempDir(), "nonexistent.zip")
			case tt.fields.createZipArchive:
				archive, _ := createArchive(t, []string{"content1", "content2"})
				location = archive
			default:
				testFile, err := os.CreateTemp(t.TempDir(), "test*")
				if err != nil {
					t.Fatalf("could not create test file: %v", err)
				}
				if _, err := testFile.WriteString(tt.fields.fileContent); err != nil {
					t.Fatalf("could not write test file: %v", err)
				}
				if err := testFile.Close(); err != nil {
					t.Fatalf("could not close test file: %v", err)
				}
				location = testFile.Name()
			}

			err := c.checkBeforeExtract(location, tt.args.size, tt.args.totalExtractedSize, tt.args.totalExtractedFiles, tt.args.depth, logger)

			if (err != nil) != tt.wantErr {
				t.Errorf("checkBeforeExtract() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func ptrInt64(v int64) *int64 {
	return &v
}

func ptrInt(v int) *int {
	return &v
}

func Test_Connector_sendForAnalyze(t *testing.T) {
	type fields struct {
		stopWorker bool
	}
	tests := []struct {
		name            string
		fields          fields
		wantErr         bool
		wantSpecificErr error
	}{
		{
			name: "ko worker stopped",
			fields: fields{
				stopWorker: true,
			},
			wantErr:         true,
			wantSpecificErr: context.Canceled,
		},
		{
			name: "ok",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopWorker := make(chan struct{})
			var fileChan chan fileToAnalyze
			if tt.fields.stopWorker {
				fileChan = make(chan fileToAnalyze) // unbuffered to force select choice
			} else {
				fileChan = make(chan fileToAnalyze, 1)
			}

			if tt.fields.stopWorker {
				close(stopWorker)
			}

			c := &Connector{
				stopWorker: stopWorker,
				fileChan:   fileChan,
			}

			file := fileToAnalyze{
				sha256:   "abc123",
				location: "/path/to/file",
				filename: "file.txt",
				size:     100,
			}

			err := c.sendForAnalyze(file, logger)

			if (err != nil) != tt.wantErr {
				t.Errorf("sendForAnalyze() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantSpecificErr != nil && !errors.Is(err, tt.wantSpecificErr) {
				t.Errorf("sendForAnalyze() want specific error %v, got %v", tt.wantSpecificErr, err)
				return
			}
			if err != nil {
				return
			}

			select {
			case <-fileChan:
			default:
				t.Errorf("sendForAnalyze() file not sent to channel")
			}
		})
	}
}

func Test_Connector_finishArchiveAnalysis(t *testing.T) {
	actionErr := errors.New("action error (test)")

	type fields struct {
		archiveNotFound        bool
		archiveFileDeleted     bool
		sha256Mismatch         bool
		actionError            bool
		isSubArchive           bool
		parentFinishesAfterSub bool
	}
	tests := []struct {
		name            string
		fields          fields
		wantErr         bool
		wantSpecificErr error
		wantActions     bool
		wantStatusKept  bool
	}{
		{
			name: "ko archive not found",
			fields: fields{
				archiveNotFound: true,
			},
		},
		{
			name: "ko getFileSHA256 error",
			fields: fields{
				archiveFileDeleted: true,
			},
			wantErr:        true,
			wantStatusKept: true,
		},
		{
			name: "ko SHA256 mismatch",
			fields: fields{
				sha256Mismatch: true,
			},
			wantStatusKept: true,
		},
		{
			name: "ko error handling action",
			fields: fields{
				actionError: true,
			},
			wantErr:         true,
			wantSpecificErr: actionErr,
			wantActions:     true,
		},
		{
			name:        "ok top-level archive",
			wantActions: true,
		},
		{
			name: "ok sub-archive",
			fields: fields{
				isSubArchive: true,
			},
		},
		{
			name: "ok sub-archive triggers parent archive completion",
			fields: fields{
				isSubArchive:           true,
				parentFinishesAfterSub: true,
			},
			wantActions: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var actionCalled bool
			var actionPath string
			action := &MockAction{
				HandleMock: func(ctx context.Context, path string, result datamodel.Result, analysisReport *datamodel.Report) (err error) {
					actionCalled = true
					actionPath = path
					if tt.fields.actionError {
						err = actionErr
						return
					}
					return
				},
			}

			c := &Connector{
				action:          action,
				archiveStatus:   newArchiveStatusHandler(),
				ongoingAnalysis: new(sync.Map),
			}

			var archiveID string
			var archiveLocation string
			var tmpFolder string
			var parentID string
			var parentLocation string
			var err error

			switch {
			case tt.fields.archiveNotFound:
				archiveID = "nonexistent-id"
				archiveLocation = filepath.Join(t.TempDir(), "nonexistent.zip")
				tmpFolder = t.TempDir()
			case tt.fields.isSubArchive:
				// Create parent archive for sub-archive tests
				var parentSHA256 string
				parentLocation, parentSHA256 = createTestFile(t, t.TempDir(), "parent archive content")
				parentInfo, e := os.Stat(parentLocation)
				if e != nil {
					t.Fatalf("could not stat parent archive: %v", e)
				}
				parentTmpFolder := t.TempDir()

				parentTotal := 2
				if tt.fields.parentFinishesAfterSub {
					parentTotal = 1
				}
				parentID = c.archiveStatus.addStatus(archiveStatus{
					started:         true,
					finished:        false,
					archiveLocation: parentLocation,
					result: datamodel.Result{
						SHA256:   parentSHA256,
						FileSize: parentInfo.Size(),
					},
					analyzed:  0,
					total:     parentTotal,
					tmpFolder: parentTmpFolder,
				})

				subArchiveLocation := filepath.Join(t.TempDir(), "sub-archive.zip")
				subTmpFolder := t.TempDir()
				archiveID = c.archiveStatus.addStatus(archiveStatus{
					started:         true,
					finished:        true,
					archiveLocation: subArchiveLocation,
					result: datamodel.Result{
						SHA256:   "sub-archive-sha256",
						Malware:  true,
						Malwares: []string{"TestMalware"},
					},
					analyzed:  1,
					total:     1,
					tmpFolder: subTmpFolder,
					parentArchive: parentArchive{
						statusID: parentID,
						relPath:  "sub-archive.zip",
					},
				})
				archiveLocation = subArchiveLocation
				tmpFolder = subTmpFolder
			default:
				// Top-level archive tests
				location, fileSHA256 := createTestFile(t, t.TempDir(), "archive content")
				info, e := os.Stat(location)
				if e != nil {
					t.Fatalf("could not stat archive: %v", e)
				}
				tmpFolder = t.TempDir()

				storedSHA256 := fileSHA256
				if tt.fields.sha256Mismatch {
					storedSHA256 = "different-sha256"
				}
				archiveID = c.archiveStatus.addStatus(archiveStatus{
					started:         true,
					finished:        true,
					archiveLocation: location,
					result: datamodel.Result{
						SHA256:   storedSHA256,
						FileSize: info.Size(),
					},
					analyzed:  1,
					total:     1,
					tmpFolder: tmpFolder,
				})
				archiveLocation = location
			}

			if tt.fields.archiveFileDeleted {
				if e := os.Remove(archiveLocation); e != nil {
					t.Fatalf("could not delete archive file: %v", e)
				}
			}

			err = c.finishArchiveAnalysis(archiveID)

			if (err != nil) != tt.wantErr {
				t.Errorf("finishArchiveAnalysis() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantSpecificErr != nil && !errors.Is(err, tt.wantSpecificErr) {
				t.Errorf("finishArchiveAnalysis() want specific error %v, got %v", tt.wantSpecificErr, err)
				return
			}
			if actionCalled != tt.wantActions {
				t.Errorf("action.Handle() called = %v, want %v", actionCalled, tt.wantActions)
			}

			if !tt.fields.archiveNotFound {
				_, _, ok := c.archiveStatus.getArchiveStatus(archiveID, false)
				if ok != tt.wantStatusKept {
					t.Errorf("archive status kept = %v, want %v", ok, tt.wantStatusKept)
				}
			}

			if tt.fields.isSubArchive && tt.fields.parentFinishesAfterSub {
				if actionPath != parentLocation {
					// check action has been called on parent
					t.Errorf("action.Handle() path = %v, want parent %v", actionPath, parentLocation)
				}
				// check parent status is deleted
				_, _, ok := c.archiveStatus.getArchiveStatus(parentID, false)
				if ok {
					t.Errorf("parent status should have been deleted after completion")
					return
				}
			}

			// check tmpFolder was cleaned up
			if !tt.fields.archiveNotFound && !tt.wantStatusKept {
				if _, err := os.Stat(tmpFolder); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("tmpFolder should have been removed, but still exists or error: %v", err)
				}
			}
		})
	}
}

func Test_Connector_handleArchive(t *testing.T) {
	type fields struct {
		archiveNotFound bool
		archiveFinished bool
		archiveTotal    int
		archiveAnalyzed int
	}
	tests := []struct {
		name              string
		fields            fields
		wantErr           bool
		wantActionsCalled bool
	}{
		{
			name:   "ko archive not found",
			fields: fields{archiveNotFound: true},
		},
		{
			name:   "ko archive already finished",
			fields: fields{archiveFinished: true},
		},
		{
			name: "ok file analyzed, archive not finished",
			fields: fields{
				archiveTotal:    3,
				archiveAnalyzed: 0,
			},
		},
		{
			name: "ok file analyzed, archive finished",
			fields: fields{
				archiveTotal:    1,
				archiveAnalyzed: 0,
			},
			wantActionsCalled: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var actionCalled bool
			action := &MockAction{
				HandleMock: func(ctx context.Context, path string, result datamodel.Result, analysisReport *datamodel.Report) (err error) {
					actionCalled = true
					return
				},
			}

			c := &Connector{
				action:          action,
				archiveStatus:   newArchiveStatusHandler(),
				ongoingAnalysis: new(sync.Map),
				config: Config{
					MaxFileSize: 100,
				},
			}

			var archiveID string
			var archiveLocation string
			var tmpFolder string

			switch {
			case tt.fields.archiveNotFound:
				archiveID = "nonexistent-id"
				archiveLocation = "/path/to/archive.zip"
			case tt.fields.archiveFinished:
				archiveID = c.archiveStatus.addStatus(archiveStatus{
					started:         true,
					finished:        true,
					archiveLocation: "/path/to/archive.zip",
					result:          datamodel.Result{SHA256: "archive-sha256"},
					analyzed:        1,
					total:           1,
				})
				archiveLocation = "/path/to/archive.zip"
			default:
				location, fileSHA256 := createTestFile(t, t.TempDir(), "archive content")
				tmpFolder = t.TempDir()
				archiveID = c.archiveStatus.addStatus(archiveStatus{
					started:         true,
					finished:        false,
					archiveLocation: location,
					result: datamodel.Result{
						SHA256:   fileSHA256,
						Location: location,
					},
					analyzed:  tt.fields.archiveAnalyzed,
					total:     tt.fields.archiveTotal,
					tmpFolder: tmpFolder,
				})
				archiveLocation = location
			}

			input := fileToAnalyze{
				archiveID:       archiveID,
				archiveLocation: archiveLocation,
				filename:        "file.txt",
				location:        "/tmp/file.txt",
				size:            1000,
			}

			err := c.handleArchive(input)

			if (err != nil) != tt.wantErr {
				t.Errorf("handleArchive() error = %v, wantErr %v", err, tt.wantErr)
			}
			if actionCalled != tt.wantActionsCalled {
				t.Errorf("action.Handle() called = %v, want %v", actionCalled, tt.wantActionsCalled)
			}
		})
	}
}

// test_recursive_depth_8.zip
// └── test_recursive/
//
//	├── file_1-1.txt
//	├── file_1-2.txt
//	└── level1.zip
//	    └── level1/
//	        ├── file_2-1.txt
//	        ├── file_2-2.txt
//	        └── level2.zip
//	            └── ... (to level7.zip with file_8-1.txt and file_8-2.txt inside)
//
//go:embed testdata/test_recursive_depth_8.zip
var testRecursive []byte

func Test_Connector_recursiveExtract(t *testing.T) {
	inputArchiveSHA256 := "INPUT_ARCHIVE_SHA256"
	innermostArchiveSHA256 := "INNERMOST_ARCHIVE_SHA256"
	type fields struct {
		recursiveExtractMaxDepth int
		extractMinThreshold      int64
		recursiveExtractMaxSize  int64
		recursiveExtractMaxFiles int
		inputFile                []byte
		createTestFile           bool
		createZipArchive         []string // with contents
		createEmptyZipArchive    bool
		createInvalidArchive     bool
		createArchiveWithDepth   int // ex: 1 means archive -> archive -> txtFile
	}
	type args struct {
		totalExtractedSizeNil  bool
		totalExtractedFilesNil bool
		depth                  int
	}
	tests := []struct {
		name          string
		fields        fields
		args          args
		wantErr       bool
		wantFilesSent []fileToAnalyze
	}{
		{
			name: "ko totalExtractedSize nil",
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      1,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				createZipArchive:         []string{"content1"},
			},
			args: args{
				totalExtractedSizeNil: true,
			},
			wantErr: true,
		},
		{
			name: "ko totalExtractedFiles nil",
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      1,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				createZipArchive:         []string{"content1"},
			},
			args: args{
				totalExtractedFilesNil: true,
			},
			wantErr: true,
		},
		{
			name: "ok input is not an archive", // (= MIME type not in whitelist)
			fields: fields{
				recursiveExtractMaxDepth: 1,
				extractMinThreshold:      100,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				createTestFile:           true,
			},
			args: args{
				depth: 0,
			},
			wantFilesSent: []fileToAnalyze{
				{filename: "test*"},
			},
		},
		{
			name: "ok with checkBeforeExtract error for input archive",
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      100000, // so file size < extractMinThreshold, to provoke error checking before extract
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				createZipArchive:         []string{"content1"},
			},
			args: args{
				depth: 0,
			},
			wantFilesSent: []fileToAnalyze{
				{filename: "archive_*.zip"},
			},
		},
		{
			name: "ok with ExtractFile error for input archive",
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      1,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				createInvalidArchive:     true,
			},
			args: args{
				depth: 0,
			},
			wantFilesSent: []fileToAnalyze{
				{filename: "invalid*.zip"},
			},
		},
		{
			name: "ok empty archive", // (0 files to extract)
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      1,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				createEmptyZipArchive:    true,
			},
			args: args{
				depth: 0,
			},
			wantFilesSent: []fileToAnalyze{
				{filename: "archive_*.zip"}, // 0 extracted files => input archive sent for analyze
			},
		},
		{
			name: "ok archive with 1 non-archive file inside",
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      1,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				createZipArchive:         []string{"content1"},
			},
			args: args{
				depth: 0,
			},
			wantFilesSent: []fileToAnalyze{
				{filename: "file-0", archiveSHA256: inputArchiveSHA256},
			},
		},
		{
			name: "ok archive with 3 non-archive files inside",
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      1,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				createZipArchive:         []string{"content1", "content2", "content3"},
			},
			args: args{
				depth: 0,
			},
			wantFilesSent: []fileToAnalyze{
				{filename: "file-0", archiveSHA256: inputArchiveSHA256},
				{filename: "file-1", archiveSHA256: inputArchiveSHA256},
				{filename: "file-2", archiveSHA256: inputArchiveSHA256},
			},
		},
		{
			name: "ok starting at depth 1",
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      1,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				createZipArchive:         []string{"content1"},
			},
			args: args{
				depth: 1,
			},
			wantFilesSent: []fileToAnalyze{
				{filename: "file-0", archiveSHA256: inputArchiveSHA256},
			},
		},
		{
			name: "ok max recursive extracted files reached",
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      1,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 2,
				createArchiveWithDepth:   3, // archive_*.zip -> archive_level_0.zip -> archive_level_1.zip -> archive_level_2.zip -> file-0
			},
			args: args{
				depth: 0,
			},
			wantFilesSent: []fileToAnalyze{
				{filename: "archive_level_2.zip"},
			},
		},
		{
			name: "ok max depth reached",
			fields: fields{
				recursiveExtractMaxDepth: 1, // can only extract at depth 0
				extractMinThreshold:      1,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				createArchiveWithDepth:   1, // archive_*.zip -> archive_level_0.zip -> file-0
			},
			args: args{
				depth: 0,
			},
			wantFilesSent: []fileToAnalyze{
				{filename: "archive_level_0.zip"},
			},
		},
		{
			name: "ok max recursive extracted size reached",
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      1,
				recursiveExtractMaxSize:  1,
				recursiveExtractMaxFiles: 100,
				createArchiveWithDepth:   2, // archive_*.zip -> archive_level_0.zip -> archive_level_1.zip -> file-0
			},
			args: args{
				depth: 0,
			},
			wantFilesSent: []fileToAnalyze{
				{filename: "archive_level_0.zip"},
			},
		},
		{
			name: "ok nested archive till depth 1",
			fields: fields{
				recursiveExtractMaxDepth: 2, // need depth 2 to extract inner archive at depth 1
				extractMinThreshold:      1,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				createArchiveWithDepth:   1,
			},
			args: args{
				depth: 0,
			},
			wantFilesSent: []fileToAnalyze{
				{filename: "file-0", archiveSHA256: innermostArchiveSHA256},
			},
		},
		{
			name: "ok nested archive till depth 2",
			fields: fields{
				recursiveExtractMaxDepth: 3,
				extractMinThreshold:      1,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				createArchiveWithDepth:   2,
			},
			args: args{
				depth: 0,
			},
			wantFilesSent: []fileToAnalyze{
				{filename: "file-0", archiveSHA256: innermostArchiveSHA256},
			},
		},
		{
			name: "ok nested archive till max depth",
			fields: fields{
				recursiveExtractMaxDepth: defaultRecursiveExtractMaxDepth,
				extractMinThreshold:      1,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				createArchiveWithDepth:   defaultRecursiveExtractMaxDepth - 1,
			},
			args: args{
				depth: 0,
			},
			wantFilesSent: []fileToAnalyze{
				{filename: "file-0", archiveSHA256: innermostArchiveSHA256},
			},
		},
		{
			name: "ok archive with mixed content", // archive containing both archives and regular files on each level
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      1,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				inputFile:                testRecursive,
			},
			args: args{
				depth: 0,
			},
			wantFilesSent: []fileToAnalyze{
				{filename: "test_recursive/file_1-1.txt", archiveSHA256: inputArchiveSHA256},
				{filename: "test_recursive/file_1-2.txt", archiveSHA256: inputArchiveSHA256},
				{filename: "level1/file_2-1.txt", archiveSHA256: ""},
				{filename: "level1/file_2-2.txt", archiveSHA256: ""},
				{filename: "level2/file_3-1.txt", archiveSHA256: ""},
				{filename: "level2/file_3-2.txt", archiveSHA256: ""},
				{filename: "level3/file_4-1.txt", archiveSHA256: ""},
				{filename: "level3/file_4-2.txt", archiveSHA256: ""},
				{filename: "level4/file_5-1.txt", archiveSHA256: ""},
				{filename: "level4/file_5-2.txt", archiveSHA256: ""},
				{filename: "level5/file_6-1.txt", archiveSHA256: ""},
				{filename: "level5/file_6-2.txt", archiveSHA256: ""},
				{filename: "level6/file_7-1.txt", archiveSHA256: ""},
				{filename: "level6/file_7-2.txt", archiveSHA256: ""},
				{filename: "level7/file_8-1.txt", archiveSHA256: ""},
				{filename: "level7/file_8-2.txt", archiveSHA256: ""},
			},
		},
		{
			name: "ok archive with mixed content blocked by recursive depth",
			fields: fields{
				recursiveExtractMaxDepth: 6,
				extractMinThreshold:      1,
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				inputFile:                testRecursive,
			},
			args: args{
				depth: 0,
			},
			wantFilesSent: []fileToAnalyze{
				{filename: "test_recursive/file_1-1.txt", archiveSHA256: inputArchiveSHA256},
				{filename: "test_recursive/file_1-2.txt", archiveSHA256: inputArchiveSHA256},
				{filename: "level1/file_2-1.txt", archiveSHA256: ""},
				{filename: "level1/file_2-2.txt", archiveSHA256: ""},
				{filename: "level2/file_3-1.txt", archiveSHA256: ""},
				{filename: "level2/file_3-2.txt", archiveSHA256: ""},
				{filename: "level3/file_4-1.txt", archiveSHA256: ""},
				{filename: "level3/file_4-2.txt", archiveSHA256: ""},
				{filename: "level4/file_5-1.txt", archiveSHA256: ""},
				{filename: "level4/file_5-2.txt", archiveSHA256: ""},
				{filename: "level5/file_6-1.txt", archiveSHA256: ""},
				{filename: "level5/file_6-2.txt", archiveSHA256: ""},
				{filename: "level5/level6.zip", archiveSHA256: ""},
			},
		},
		{
			name: "ok inner archive below threshold",
			fields: fields{
				recursiveExtractMaxDepth: 10,
				extractMinThreshold:      200, // threshold between outer (~257B) and inner (~170B) archive sizes
				recursiveExtractMaxSize:  1000000,
				recursiveExtractMaxFiles: 100,
				createArchiveWithDepth:   1, // outer_archive_*.zip -> inner_archive_level_0.zip -> file-0
			},
			args: args{
				depth: 0,
			},
			wantFilesSent: []fileToAnalyze{
				{filename: "archive_level_0.zip", archiveSHA256: inputArchiveSHA256},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			LogLevel.Set(slog.LevelDebug.Level())
			stopWorker := make(chan struct{})
			fileChan := make(chan fileToAnalyze, 20) // large enough to be able to send all extracted files

			c := &Connector{
				config: Config{
					RecursiveExtractMaxDepth: tt.fields.recursiveExtractMaxDepth,
					ExtractMinThreshold:      tt.fields.extractMinThreshold,
					RecursiveExtractMaxSize:  tt.fields.recursiveExtractMaxSize,
					RecursiveExtractMaxFiles: tt.fields.recursiveExtractMaxFiles,
				},
				typesToExtract: extractableTypes(),
				stopWorker:     stopWorker,
				fileChan:       fileChan,
				archiveStatus:  newArchiveStatusHandler(),
			}

			var archiveLocation string
			var archiveSHA256 string
			var innerArchiveSHA256 string
			var archiveSize int64
			switch {
			case len(tt.fields.inputFile) > 0:
				testFile, err := os.CreateTemp(t.TempDir(), "test_recursive*.zip")
				if err != nil {
					t.Fatalf("could not create test file, error: %s", err)
				}
				defer func() {
					if e := testFile.Close(); e != nil {
						t.Fatalf("could not close test file: %v", e)
					}
				}()
				h := sha256.New()
				mw := io.MultiWriter(testFile, h)
				if _, e := mw.Write(tt.fields.inputFile); e != nil {
					t.Fatalf("could not write test file: %v", e)
				}
				archiveLocation = testFile.Name()
				archiveSHA256 = hex.EncodeToString(h.Sum(nil))
				info, _ := os.Stat(archiveLocation)
				archiveSize = info.Size()
			case len(tt.fields.createZipArchive) > 0:
				archiveLocation, archiveSHA256 = createArchive(t, tt.fields.createZipArchive)
				info, _ := os.Stat(archiveLocation)
				archiveSize = info.Size()
			case tt.fields.createEmptyZipArchive:
				archiveLocation, archiveSHA256 = createArchive(t, []string{})
				info, _ := os.Stat(archiveLocation)
				archiveSize = info.Size()
			case tt.fields.createTestFile:
				folder := t.TempDir()
				archiveLocation, archiveSHA256 = createTestFile(t, folder, "plain text")
				info, _ := os.Stat(archiveLocation)
				archiveSize = info.Size()
			case tt.fields.createInvalidArchive:
				testFile, err := os.CreateTemp(t.TempDir(), "invalid*.zip")
				if err != nil {
					t.Fatalf("could not create test file: %v", err)
				}
				// Write valid ZIP magic bytes followed by garbage to pass type detection but fail extraction
				invalidZipContent := []byte{0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF}
				if _, err := testFile.Write(invalidZipContent); err != nil {
					t.Fatalf("could not write test file: %v", err)
				}
				if err := testFile.Close(); err != nil {
					t.Fatalf("could not close test file: %v", err)
				}
				archiveLocation = testFile.Name()
				archiveSHA256 = "fakehash"
				info, _ := os.Stat(archiveLocation)
				archiveSize = info.Size()
			case tt.fields.createArchiveWithDepth >= 1:
				// Start with the innermost archive containing a file at the deepest level
				fileContent := fmt.Sprintf("file content at depth %d", tt.fields.createArchiveWithDepth)
				var nestedArchive string
				nestedArchive, innerArchiveSHA256 = createArchive(t, []string{fileContent})

				// Create nested archives up to the requested depth
				for d := 0; d < tt.fields.createArchiveWithDepth; d++ {
					innerContent, err := os.ReadFile(nestedArchive) // #nosec G304 // path is controlled by test
					if err != nil {
						t.Fatalf("could not read inner archive: %v", err)
					}
					level := tt.fields.createArchiveWithDepth - 1 - d
					nestedArchive, archiveSHA256 = createArchiveWithRawFiles(t, map[string][]byte{fmt.Sprintf("archive_level_%d.zip", level): innerContent})
				}

				archiveLocation = nestedArchive
				info, _ := os.Stat(archiveLocation)
				archiveSize = info.Size()
			}

			archive := fileToAnalyze{
				sha256:   archiveSHA256,
				location: archiveLocation,
				filename: filepath.Base(archiveLocation),
				size:     archiveSize,
			}

			var totalExtractedSize *int64
			var totalExtractedFiles *int
			if !tt.args.totalExtractedSizeNil {
				totalExtractedSize = ptrInt64(0)
			}
			if !tt.args.totalExtractedFilesNil {
				totalExtractedFiles = ptrInt(0)
			}

			archiveLogger := logger.With(slog.String("input file", archive.location))
			err := c.recursiveExtract(archive, tt.args.depth, totalExtractedSize, totalExtractedFiles, archiveLogger)

			if (err != nil) != tt.wantErr {
				t.Errorf("recursiveExtract() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			close(fileChan)
			var filesSent []fileToAnalyze
			for f := range fileChan {
				filesSent = append(filesSent, f)
			}

			if len(filesSent) != len(tt.wantFilesSent) {
				t.Errorf("recursiveExtract() files sent = %d, want %d", len(filesSent), len(tt.wantFilesSent))
				return
			}

			if len(tt.wantFilesSent) == 0 {
				return
			}

			slices.SortFunc(filesSent, func(a, b fileToAnalyze) int {
				return strings.Compare(a.filename, b.filename)
			})
			fmt.Printf("\n\nfileSent:%+v\n", filesSent)
			slices.SortFunc(tt.wantFilesSent, func(a, b fileToAnalyze) int {
				return strings.Compare(a.filename, b.filename)
			})

			for i, want := range tt.wantFilesSent {
				// use pattern because file names generated in test can contain random strings
				matched, err := filepath.Match(want.filename, filesSent[i].filename)
				if err != nil {
					t.Fatalf("invalid pattern %q: %v", want.filename, err)
				}
				if !matched {
					t.Errorf("filesSent[%d].filename = %q, want match %q", i, filesSent[i].filename, want.filename)
					return
				}
				tt.wantFilesSent[i].filename = filesSent[i].filename

				switch want.archiveSHA256 {
				case inputArchiveSHA256:
					tt.wantFilesSent[i].archiveSHA256 = archiveSHA256
				case innermostArchiveSHA256:
					tt.wantFilesSent[i].archiveSHA256 = innerArchiveSHA256
				case "":
					// Don't check archiveSHA256 - copy from got to skip comparison
					tt.wantFilesSent[i].archiveSHA256 = filesSent[i].archiveSHA256
				}
			}

			if diff := cmp.Diff(filesSent, tt.wantFilesSent,
				cmp.AllowUnexported(fileToAnalyze{}),
				cmpopts.IgnoreFields(fileToAnalyze{}, "sha256", "location", "size", "archiveID", "archiveLocation", "archiveSize"),
			); diff != "" {
				t.Errorf("recursiveExtract() files sent mismatch (want-got):\n%s", diff)
			}
		})
	}
}
