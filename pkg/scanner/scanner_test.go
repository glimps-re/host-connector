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
	"os"
	"path/filepath"
	"strings"
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
					MaxFileSize: 200,
					Extract:     true,
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
					MaxFileSize: 200,
					Extract:     true,
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
					MaxFileSize: 200,
					Extract:     true,
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

				onStartCalled := 0
				onScanCalled := 0

				c.onStartScanFileCbs = append(c.onStartScanFileCbs, func(file string, sha256 string) {
					onStartCalled++
				})
				c.onScanFileCbs = append(c.onScanFileCbs, func(filename string, location string, sha256 string, isArchive bool) (res *datamodel.Result) {
					onScanCalled++
					return
				})

				if e := c.ScanFile(t.Context(), archive); e != nil {
					t.Errorf("unwanted error: %v", e)
				}
				// Wait for workers to finish processing
				c.Close(t.Context())
				cacheID := quarantine.ComputeCacheID(archive, archiveSHA256)
				assertFileDeleted(t, buff, archive, cacheID)

				if onStartCalled != 1 {
					t.Fatalf("start scan call %d time(s), want 1", onStartCalled)
				}
				if onScanCalled != 4 {
					t.Fatalf("scan call %d time(s), want 4", onScanCalled)
				}
			},
		},
		{
			name: "ok archive with all empty files",
			fields: fields{
				config: Config{
					MaxFileSize: 200,
					Extract:     true,
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
