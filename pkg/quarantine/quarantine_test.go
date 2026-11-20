package quarantine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

type lockerMock struct {
	LockFileMock   func(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error
	UnlockFileMock func(src io.ReaderAt, size int64, out io.Writer) (locked LockedFile, err error)
	GetHeaderMock  func(src io.ReaderAt, size int64) (entry LockEntry, err error)
}

func (l *lockerMock) LockFile(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error {
	if l.LockFileMock != nil {
		return l.LockFileMock(file, in, info, reason, out)
	}
	panic("LockFileMock not implemented")
}

func (l *lockerMock) UnlockFile(src io.ReaderAt, size int64, out io.Writer) (LockedFile, error) {
	if l.UnlockFileMock != nil {
		return l.UnlockFileMock(src, size, out)
	}
	panic("UnlockFileMock not implemented")
}

func (l *lockerMock) GetHeader(src io.ReaderAt, size int64) (entry LockEntry, err error) {
	if l.GetHeaderMock != nil {
		return l.GetHeaderMock(src, size)
	}
	panic("GetHeaderMock not implemented")
}

type registryMock struct {
	GetLocationMock func() (location string)
	SetMock         func(ctx context.Context, entry *Entry) error
	GetMock         func(ctx context.Context, id string) (entry *Entry, err error)
	CloneMock       func(ctx context.Context, newLocation string, mergeExisting bool) (quarantineRegistry, error)
	DiscardMock     func() error
	CloseMock       func() error
	GetBySHA256Mock func(ctx context.Context, id string) (*Entry, error)
}

func (m *registryMock) GetLocation() (location string) {
	if m.GetLocationMock != nil {
		return m.GetLocationMock()
	}
	panic("GetLocation not implemented")
}

func (m *registryMock) Set(ctx context.Context, entry *Entry) error {
	if m.SetMock != nil {
		return m.SetMock(ctx, entry)
	}
	panic("Set not implemented")
}

func (m *registryMock) Get(ctx context.Context, id string) (*Entry, error) {
	if m.GetMock != nil {
		return m.GetMock(ctx, id)
	}
	panic("Get not implemented")
}

func (m *registryMock) GetBySHA256(ctx context.Context, id string) (*Entry, error) {
	if m.GetBySHA256Mock != nil {
		return m.GetBySHA256Mock(ctx, id)
	}
	panic("GetBySha256 not implemented")
}

func (m *registryMock) Clone(ctx context.Context, newLocation string, _ bool) (quarantineRegistry, error) {
	if m.CloneMock != nil {
		return m.CloneMock(ctx, newLocation, false)
	}
	panic("Clone not implemented")
}

func (m *registryMock) Discard() error {
	if m.DiscardMock != nil {
		return m.DiscardMock()
	}
	panic("Discard not implemented")
}

func (m *registryMock) Close() error {
	if m.CloseMock != nil {
		return m.CloseMock()
	}
	panic("CloseMock not implemented")
}

func TestQuarantineHandler_Quarantine(t *testing.T) {
	type fields struct {
		lockFileMock func(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error
		registrySet  func(ctx context.Context, entry *Entry) error
		fileContent  string
		fileExists   bool
	}
	type args struct {
		fileName   string
		fileSHA256 string
		malwares   []string
	}
	tests := []struct {
		name            string
		fields          fields
		args            args
		wantLocation    func(quarantineDir string, id string) string
		wantID          func(filePath string, sha256 string) string
		wantErr         error
		wantLockCleaned bool // expect .lock file to be removed on failure
	}{
		{
			name: "ok quarantine with single malware",
			fields: fields{
				lockFileMock: func(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error {
					return nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return nil
				},
				fileContent: "test content",
				fileExists:  true,
			},
			args: args{
				fileName:   "test.txt",
				fileSHA256: "abc123",
				malwares:   []string{"trojan.win32.agent"},
			},
			wantLocation: func(quarantineDir string, id string) string {
				return filepath.Join(quarantineDir, id+".lock")
			},
			wantID:  ComputeCacheID,
			wantErr: nil,
		},
		{
			name: "ok quarantine with multiple malwares (uses first)",
			fields: fields{
				lockFileMock: func(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error {
					if reason != "malware: trojan.win32.agent" {
						t.Errorf("expected reason to be 'malware: trojan.win32.agent', got %s", reason)
					}
					return nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return nil
				},
				fileContent: "malicious content",
				fileExists:  true,
			},
			args: args{
				fileName:   "test.txt",
				fileSHA256: "def456",
				malwares:   []string{"trojan.win32.agent", "backdoor.linux.gafgyt"},
			},
			wantLocation: func(quarantineDir string, id string) string {
				return filepath.Join(quarantineDir, id+".lock")
			},
			wantID:  ComputeCacheID,
			wantErr: nil,
		},
		{
			name: "ok quarantine with no malware name (uses unknown)",
			fields: fields{
				lockFileMock: func(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error {
					if reason != "malware: unknown" {
						t.Errorf("expected reason to be 'malware: unknown', got %s", reason)
					}
					return nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return nil
				},
				fileContent: "suspicious content",
				fileExists:  true,
			},
			args: args{
				fileName:   "test.txt",
				fileSHA256: "ghi789",
				malwares:   []string{},
			},
			wantLocation: func(quarantineDir string, id string) string {
				return filepath.Join(quarantineDir, id+".lock")
			},
			wantID:  ComputeCacheID,
			wantErr: nil,
		},
		{
			name: "error when file does not exist",
			fields: fields{
				lockFileMock: func(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error {
					return nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return nil
				},
				fileExists: false,
			},
			args: args{
				fileName:   "nonexistent.txt",
				fileSHA256: "xyz000",
				malwares:   []string{},
			},
			wantLocation: func(quarantineDir string, id string) string {
				return ""
			},
			wantID: func(filePath string, sha256 string) string {
				return ""
			},
			wantErr: os.ErrNotExist,
		},
		{
			name: "error when locker fails",
			fields: fields{
				lockFileMock: func(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error {
					return errors.New("locker failed")
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return nil
				},
				fileContent: "content",
				fileExists:  true,
			},
			args: args{
				fileName:   "test.txt",
				fileSHA256: "lock_fail",
				malwares:   []string{"malware"},
			},
			wantLocation: func(quarantineDir string, id string) string {
				return ""
			},
			wantID: func(filePath string, sha256 string) string {
				return ""
			},
			wantErr:         errors.New("locker failed"),
			wantLockCleaned: true,
		},
		{
			name: "error when registry set",
			fields: fields{
				lockFileMock: func(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error {
					return nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return errors.New("registry set failed")
				},
				fileContent: "content",
				fileExists:  true,
			},
			args: args{
				fileName:   "test.txt",
				fileSHA256: "registry_fail",
				malwares:   []string{},
			},
			wantLocation: func(quarantineDir string, id string) string {
				return ""
			},
			wantID: func(filePath string, sha256 string) string {
				return ""
			},
			wantErr:         errors.New("registry set failed"),
			wantLockCleaned: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			// Setup test file
			tmpDir := t.TempDir()
			testFilePath := filepath.Join(tmpDir, tt.args.fileName)
			if tt.fields.fileExists {
				err := os.WriteFile(testFilePath, []byte(tt.fields.fileContent), 0o600)
				if err != nil {
					t.Fatalf("failed to create test file: %v", err)
				}
			}

			// Setup quarantine directory
			quarantineDir := t.TempDir()

			// Create mocks
			locker := &lockerMock{
				LockFileMock: func(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error {
					if err := tt.fields.lockFileMock(file, in, info, reason, out); err != nil {
						return err
					}
					_, err := io.Copy(io.Discard, in)
					return err
				},
			}
			registry := &registryMock{
				SetMock: tt.fields.registrySet,
			}

			// Create handler
			q := &QuarantineHandler{
				location: quarantineDir,
				locker:   locker,
				registry: registry,
			}

			// Quarantine only accepts the real SHA256 of the file content.
			tt.args.fileSHA256 = sha256Hex([]byte(tt.fields.fileContent))

			// Execute
			gotLocation, gotID, err := q.Quarantine(ctx, testFilePath, tt.args.fileSHA256, tt.args.malwares)

			// Check error
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("Quarantine() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) && err.Error() != tt.wantErr.Error() {
					t.Errorf("Quarantine() error = %v, wantErr %v", err, tt.wantErr)
				}
				// Verify .lock file cleanup on failure
				if tt.wantLockCleaned {
					entries, readErr := os.ReadDir(quarantineDir)
					if readErr != nil {
						t.Fatalf("failed to read quarantine dir: %v", readErr)
					}
					for _, entry := range entries {
						if filepath.Ext(entry.Name()) == ".lock" {
							t.Errorf("Quarantine() left orphaned .lock file %s after failure", entry.Name())
						}
					}
				}
				return
			}

			if err != nil {
				t.Errorf("Quarantine() unexpected error = %v", err)
				return
			}

			// Check ID
			expectedID := tt.wantID(testFilePath, tt.args.fileSHA256)
			if diff := cmp.Diff(gotID, expectedID); diff != "" {
				t.Errorf("Quarantine() id diff(-got+want)=%s", diff)
			}

			// Check location
			expectedLocation := tt.wantLocation(quarantineDir, expectedID)
			if diff := cmp.Diff(gotLocation, expectedLocation); diff != "" {
				t.Errorf("Quarantine() location diff(-got+want)=%s", diff)
			}
		})
	}
}

// unlockWriteContent is a small helper building an UnlockFileMock that
// writes content to out and reports it as the plaintext size.
func unlockWriteContent(content string, reason string) func(src io.ReaderAt, size int64, out io.Writer) (LockedFile, error) {
	return func(src io.ReaderAt, size int64, out io.Writer) (locked LockedFile, err error) {
		if _, err = out.Write([]byte(content)); err != nil {
			return
		}
		locked.Reason = reason
		locked.Size = int64(len(content))
		locked.Mode = 0o600
		return
	}
}

func TestQuarantineHandler_Restore(t *testing.T) {
	existingRestorePath := filepath.Join(t.TempDir(), "restored.txt")
	recreatedRestorePath := filepath.Join(t.TempDir(), "missing", "sub", "restored.txt")

	regularFile := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(regularFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("failed to create regular file: %v", err)
	}
	notADirRestorePath := filepath.Join(regularFile, "sub", "file.txt")

	mismatchPath := filepath.Join(t.TempDir(), "mismatch.txt")
	tooLargePath := filepath.Join(t.TempDir(), "too_large.txt")
	registrySetFailPath := filepath.Join(t.TempDir(), "restored.txt")
	unlockFailPath := filepath.Join(t.TempDir(), "restored.txt")
	registryGetFailPath := filepath.Join(t.TempDir(), "restored.txt")
	sizeMismatchPath := filepath.Join(t.TempDir(), "restored.txt")
	noRegistryEntryPath := filepath.Join(t.TempDir(), "restored.txt")

	type fields struct {
		getHeaderMock  func(src io.ReaderAt, size int64) (entry LockEntry, err error)
		unlockFileMock func(src io.ReaderAt, size int64, out io.Writer) (locked LockedFile, err error)
		registryGet    func(ctx context.Context, id string) (entry *Entry, err error)
		registrySet    func(ctx context.Context, entry *Entry) error
		lockFileExists bool
	}
	type args struct {
		entryID string
	}
	tests := []struct {
		name              string
		fields            fields
		args              args
		wantRestoredFile  string // path where the restored file must exist on success
		wantErr           error
		wantDestUntouched string // path that must NOT exist after a failed Restore
	}{
		{
			name: "ok restore",
			fields: fields{
				getHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
					return LockEntry{Filepath: existingRestorePath}, nil
				},
				unlockFileMock: unlockWriteContent("test content", "malware: test"),
				registryGet: func(ctx context.Context, id string) (entry *Entry, err error) {
					return &Entry{
						ID:                 id,
						SHA256:             sha256Hex([]byte("test content")),
						InitialLocation:    existingRestorePath,
						QuarantineLocation: "some/path.lock",
					}, nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return nil
				},
				lockFileExists: true,
			},
			args:             args{entryID: testRestoreID},
			wantRestoredFile: existingRestorePath,
			wantErr:          nil,
		},
		{
			name: "error when lock file does not exist",
			fields: fields{
				getHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
					return LockEntry{}, nil
				},
				unlockFileMock: unlockWriteContent("", ""),
				registryGet: func(ctx context.Context, id string) (entry *Entry, err error) {
					return &Entry{}, nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return nil
				},
				lockFileExists: false,
			},
			args:    args{entryID: testRestoreID},
			wantErr: os.ErrNotExist,
		},
		{
			name: "error when GetHeader fails",
			fields: fields{
				getHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
					return LockEntry{}, errors.New("get header failed")
				},
				unlockFileMock: unlockWriteContent("", ""),
				registryGet: func(ctx context.Context, id string) (entry *Entry, err error) {
					return &Entry{}, nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return nil
				},
				lockFileExists: true,
			},
			args:    args{entryID: testRestoreID},
			wantErr: errors.New("get header failed"),
		},
		{
			name: "error when no registry entry exists (checked before any write)",
			fields: fields{
				getHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
					return LockEntry{Filepath: noRegistryEntryPath}, nil
				},
				unlockFileMock: unlockWriteContent("should never be written", "malware: test"),
				registryGet: func(ctx context.Context, id string) (entry *Entry, err error) {
					return nil, errEntryNotFound
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					t.Fatalf("registry.Set must not be called when the registry entry is missing")
					return nil
				},
				lockFileExists: true,
			},
			args:              args{entryID: testRestoreID},
			wantErr:           ErrNoRegistryEntry,
			wantDestUntouched: noRegistryEntryPath,
		},
		{
			name: "error when container path does not match registry entry",
			fields: fields{
				getHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
					return LockEntry{Filepath: mismatchPath}, nil
				},
				unlockFileMock: unlockWriteContent("should never be written", "malware: test"),
				registryGet: func(ctx context.Context, id string) (entry *Entry, err error) {
					return &Entry{ID: id, SHA256: "abc123", InitialLocation: existingRestorePath}, nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					t.Fatalf("registry.Set must not be called on a path mismatch")
					return nil
				},
				lockFileExists: true,
			},
			args:              args{entryID: testRestoreID},
			wantErr:           ErrRestorePathMismatch,
			wantDestUntouched: mismatchPath,
		},
		{
			name: "error when restored payload is larger than its container",
			fields: fields{
				getHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
					return LockEntry{Filepath: tooLargePath}, nil
				},
				unlockFileMock: unlockWriteContent("this content is longer than the configured limit", "malware: test"),
				registryGet: func(ctx context.Context, id string) (entry *Entry, err error) {
					return &Entry{ID: id, SHA256: "abc123", InitialLocation: tooLargePath}, nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					t.Fatalf("registry.Set must not be called when the restore size limit is exceeded")
					return nil
				},
				lockFileExists: true,
			},
			args:              args{entryID: testRestoreID},
			wantErr:           ErrRestoreTooLarge,
			wantDestUntouched: tooLargePath,
		},
		{
			name: "error when the size recorded in the container differs from the restored size",
			fields: fields{
				getHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
					return LockEntry{Filepath: sizeMismatchPath}, nil
				},
				unlockFileMock: func(src io.ReaderAt, size int64, out io.Writer) (locked LockedFile, err error) {
					if _, err = out.Write([]byte("abc")); err != nil {
						return
					}
					locked.Size = 4
					return
				},
				registryGet: func(ctx context.Context, id string) (entry *Entry, err error) {
					return &Entry{ID: id, SHA256: "abc123", InitialLocation: sizeMismatchPath}, nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					t.Fatalf("registry.Set must not be called on a size mismatch")
					return nil
				},
				lockFileExists: true,
			},
			args:              args{entryID: testRestoreID},
			wantErr:           ErrRestoreSizeMismatch,
			wantDestUntouched: sizeMismatchPath,
		},
		{
			name: "error recreating directory tree",
			fields: fields{
				getHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
					return LockEntry{Filepath: notADirRestorePath}, nil // to force failure
				},
				unlockFileMock: unlockWriteContent("", ""),
				registryGet: func(ctx context.Context, id string) (entry *Entry, err error) {
					return &Entry{InitialLocation: notADirRestorePath}, nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return nil
				},
				lockFileExists: true,
			},
			args:    args{entryID: testRestoreID},
			wantErr: syscall.ENOTDIR,
		},
		{
			name: "error when UnlockFile fails",
			fields: fields{
				getHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
					return LockEntry{Filepath: unlockFailPath}, nil
				},
				unlockFileMock: func(src io.ReaderAt, size int64, out io.Writer) (locked LockedFile, err error) {
					err = errors.New("unlock failed")
					return
				},
				registryGet: func(ctx context.Context, id string) (entry *Entry, err error) {
					return &Entry{InitialLocation: unlockFailPath}, nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return nil
				},
				lockFileExists: true,
			},
			args:    args{entryID: testRestoreID},
			wantErr: errors.New("unlock failed"),
		},
		{
			name: "error registry get fails",
			fields: fields{
				getHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
					return LockEntry{Filepath: registryGetFailPath}, nil
				},
				unlockFileMock: unlockWriteContent("test content", "malware: test"),
				registryGet: func(ctx context.Context, id string) (entry *Entry, err error) {
					return nil, errors.New("registry get failed")
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return nil
				},
				lockFileExists: true,
			},
			args:    args{entryID: testRestoreID},
			wantErr: errors.New("registry get failed"),
		},
		{
			name: "error registry set fails",
			fields: fields{
				getHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
					return LockEntry{Filepath: registrySetFailPath}, nil
				},
				unlockFileMock: unlockWriteContent("test content", "malware: test"),
				registryGet: func(ctx context.Context, id string) (entry *Entry, err error) {
					return &Entry{
						ID:                 id,
						SHA256:             sha256Hex([]byte("test content")),
						InitialLocation:    registrySetFailPath,
						QuarantineLocation: "some/path.lock",
					}, nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return errors.New("registry set failed")
				},
				lockFileExists: true,
			},
			args:    args{entryID: testRestoreID},
			wantErr: fmt.Errorf("error set cache for sha256 %s, registry set failed", sha256Hex([]byte("test content"))),
		},
		{
			name: "ok restore recreates missing directory tree",
			fields: fields{
				getHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
					return LockEntry{Filepath: recreatedRestorePath}, nil
				},
				unlockFileMock: unlockWriteContent("test content", "malware: test"),
				registryGet: func(ctx context.Context, id string) (entry *Entry, err error) {
					return &Entry{
						ID:                 id,
						SHA256:             sha256Hex([]byte("test content")),
						InitialLocation:    recreatedRestorePath,
						QuarantineLocation: "some/path.lock",
					}, nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return nil
				},
				lockFileExists: true,
			},
			args:             args{entryID: testRestoreID},
			wantRestoredFile: recreatedRestorePath,
			wantErr:          nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			// Setup quarantine directory and lock file
			quarantineDir := t.TempDir()
			lockFilePath := filepath.Join(quarantineDir, tt.args.entryID+".lock")
			if tt.fields.lockFileExists {
				err := os.WriteFile(lockFilePath, []byte("dummy lock file"), 0o600)
				if err != nil {
					t.Fatalf("failed to create lock file: %v", err)
				}
			}

			// Create mocks
			locker := &lockerMock{
				GetHeaderMock:  tt.fields.getHeaderMock,
				UnlockFileMock: tt.fields.unlockFileMock,
			}
			registry := &registryMock{
				GetMock: tt.fields.registryGet,
				SetMock: tt.fields.registrySet,
			}

			// Create handler
			q := &QuarantineHandler{
				location: quarantineDir,
				locker:   locker,
				registry: registry,
				watched:  []string{filepath.Dir(filepath.Dir(filepath.Dir(recreatedRestorePath)))},
			}

			// Execute
			err := q.Restore(ctx, tt.args.entryID)

			// Check error
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("Restore() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) && err.Error() != tt.wantErr.Error() {
					t.Errorf("Restore() error = %v, wantErr %v", err, tt.wantErr)
				}
				if tt.wantDestUntouched != "" {
					if _, statErr := os.Stat(tt.wantDestUntouched); !errors.Is(statErr, os.ErrNotExist) {
						t.Errorf("Restore() must not create %s on failure, stat error: %v", tt.wantDestUntouched, statErr)
					}
				}
				if tt.fields.lockFileExists {
					if _, statErr := os.Stat(lockFilePath); statErr != nil {
						t.Errorf("Restore() must keep the .lock file on failure: %v", statErr)
					}
				}
				return
			}

			if err != nil {
				t.Errorf("Restore() unexpected error = %v", err)
				return
			}

			// Verify lock file was deleted on success
			if _, statErr := os.Stat(lockFilePath); !errors.Is(statErr, os.ErrNotExist) {
				t.Errorf("Restore() lock file should be deleted, but still exists or stat error: %v", statErr)
			}

			// Verify restored file exists at its original path
			if tt.wantRestoredFile != "" {
				if _, statErr := os.Stat(tt.wantRestoredFile); statErr != nil {
					t.Errorf("Restore() restored file not found at %s: %v", tt.wantRestoredFile, statErr)
				}
			}
		})
	}
}

// TestQuarantineHandler_Restore_SymlinkedDestinationDir is an end-to-end
// (real tarLocker, real registry, real filesystem) regression test for the
// restore-path contract's directory-safety guarantee: os.OpenRoot follows a
// symlink given as its argument, so Restore must independently refuse to
// use a destination directory that is a symlink (or whose identity changed
// between inspection and open) rather than silently writing through it.
func TestQuarantineHandler_Restore_SymlinkedDestinationDir(t *testing.T) {
	ctx := t.Context()

	quarantineDir := t.TempDir()
	q, err := NewQuarantineHandler(ctx, Config{Location: quarantineDir, LockPassword: "pw"})
	if err != nil {
		t.Fatalf("NewQuarantineHandler() error = %v", err)
	}
	defer func() {
		if err := q.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	realDir := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(realDir, 0o750); err != nil {
		t.Fatalf("failed to create real dir: %v", err)
	}
	samplePath := filepath.Join(realDir, "sample.txt")
	if err := os.WriteFile(samplePath, []byte("malicious content"), 0o600); err != nil {
		t.Fatalf("failed to create sample file: %v", err)
	}

	_, id, err := q.Quarantine(ctx, samplePath, sha256Hex([]byte("malicious content")), []string{"test"})
	if err != nil {
		t.Fatalf("Quarantine() error = %v", err)
	}

	// The attacker deletes the original directory and replaces it with a
	// symlink to a directory they want the privileged Restore to write
	// into instead.
	decoyDir := filepath.Join(t.TempDir(), "decoy")
	if err := os.Mkdir(decoyDir, 0o750); err != nil {
		t.Fatalf("failed to create decoy dir: %v", err)
	}
	if err := os.RemoveAll(realDir); err != nil {
		t.Fatalf("failed to remove real dir: %v", err)
	}
	if err := os.Symlink(decoyDir, realDir); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	err = q.Restore(ctx, id)
	if !errors.Is(err, ErrRestoreDestinationUnsafe) {
		t.Errorf("Restore() error = %v, want ErrRestoreDestinationUnsafe", err)
	}

	// The decoy directory must remain empty: nothing was written through
	// the symlink.
	entries, readErr := os.ReadDir(decoyDir)
	if readErr != nil {
		t.Fatalf("failed to read decoy dir: %v", readErr)
	}
	if len(entries) != 0 {
		t.Errorf("Restore() wrote into the symlinked decoy directory: %v", entries)
	}

	// The .lock file must still be present (kept on failure).
	if _, statErr := os.Stat(filepath.Join(quarantineDir, id+".lock")); statErr != nil {
		t.Errorf("Restore() must keep the .lock file on failure: %v", statErr)
	}
}

// TestQuarantineHandler_Restore_ConcurrentSameID exercises two
// concurrent Restore calls for the same id must be serialised, never
// interleaved on the same temp file / rename / registry update.
func TestQuarantineHandler_Restore_ConcurrentSameID(t *testing.T) {
	quarantineDir := t.TempDir()
	destPath := filepath.Join(t.TempDir(), "restored.txt")
	const id = testRestoreID
	lockFilePath := filepath.Join(quarantineDir, id+".lock")
	if err := os.WriteFile(lockFilePath, []byte("dummy lock file"), 0o600); err != nil {
		t.Fatalf("failed to create lock file: %v", err)
	}

	var running atomic.Int32
	var overlapped atomic.Bool

	locker := &lockerMock{
		GetHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
			return LockEntry{Filepath: destPath}, nil
		},
		UnlockFileMock: func(src io.ReaderAt, size int64, out io.Writer) (locked LockedFile, err error) {
			if running.Add(1) > 1 {
				overlapped.Store(true)
			}
			defer running.Add(-1)
			time.Sleep(20 * time.Millisecond)
			if _, err = out.Write([]byte("content")); err != nil {
				return
			}
			locked.Reason = "malware: test"
			locked.Size = 7
			return
		},
	}
	registry := &registryMock{
		GetMock: func(ctx context.Context, gotID string) (entry *Entry, err error) {
			return &Entry{ID: gotID, SHA256: sha256Hex([]byte("content")), InitialLocation: destPath}, nil
		},
		SetMock: func(ctx context.Context, entry *Entry) error {
			return nil
		},
	}
	q := &QuarantineHandler{
		location: quarantineDir,
		locker:   locker,
		registry: registry,
	}

	// The lock file only exists once: the second call is expected to fail
	// with "file does not exist" after the first has already removed it,
	// but must never observe a torn/partial temp file from the first call.
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = q.Restore(t.Context(), id)
		}(i)
	}
	wg.Wait()

	if overlapped.Load() {
		t.Errorf("Restore() calls for the same id overlapped; expected serialisation via the per-ID lock")
	}
	okCount := 0
	for _, e := range errs {
		if e == nil {
			okCount++
		}
	}
	if okCount != 1 {
		t.Errorf("expected exactly one of the two concurrent Restore() calls to succeed, got %d successes: %v", okCount, errs)
	}
}

func TestQuarantineHandler_IsRestored(t *testing.T) {
	type fields struct {
		registryGetBySHA256 func(ctx context.Context, sha256 string) (*Entry, error)
	}
	type args struct {
		sha256 string
	}
	tests := []struct {
		name         string
		fields       fields
		args         args
		wantRestored bool
		wantErr      error
	}{
		{
			name: "file is restored",
			fields: fields{
				registryGetBySHA256: func(ctx context.Context, sha256 string) (*Entry, error) {
					return &Entry{
						ID:                 "entry-1",
						SHA256:             sha256,
						InitialLocation:    "/path/to/file.txt",
						QuarantineLocation: "",
						RestoredAt:         now(),
					}, nil
				},
			},
			args: args{
				sha256: "abc123",
			},
			wantRestored: true,
			wantErr:      nil,
		},
		{
			name: "file is not restored (RestoredAt is zero)",
			fields: fields{
				registryGetBySHA256: func(ctx context.Context, sha256 string) (*Entry, error) {
					return &Entry{
						ID:                 "entry-2",
						SHA256:             sha256,
						InitialLocation:    "/path/to/file.txt",
						QuarantineLocation: "/quarantine/entry-2.lock",
						RestoredAt:         time.Time{},
					}, nil
				},
			},
			args: args{
				sha256: "def456",
			},
			wantRestored: false,
			wantErr:      nil,
		},
		{
			name: "entry not found",
			fields: fields{
				registryGetBySHA256: func(ctx context.Context, sha256 string) (*Entry, error) {
					return nil, errEntryNotFound
				},
			},
			args: args{
				sha256: "notfound",
			},
			wantRestored: false,
			wantErr:      nil,
		},
		{
			name: "error when registry GetBySHA256 fails",
			fields: fields{
				registryGetBySHA256: func(ctx context.Context, sha256 string) (*Entry, error) {
					return nil, errors.New("database error")
				},
			},
			args: args{
				sha256: "error123",
			},
			wantRestored: false,
			wantErr:      errors.New("database error"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			// Create mocks
			registry := &registryMock{
				GetBySHA256Mock: tt.fields.registryGetBySHA256,
			}

			// Create handler
			q := &QuarantineHandler{
				registry: registry,
			}

			// Execute
			gotRestored, err := q.IsRestored(ctx, tt.args.sha256)

			// Check error
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("IsRestored() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) && err.Error() != tt.wantErr.Error() {
					t.Errorf("IsRestored() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("IsRestored() unexpected error = %v", err)
				return
			}

			// Check restored status
			if diff := cmp.Diff(gotRestored, tt.wantRestored); diff != "" {
				t.Errorf("IsRestored() restored diff(-got+want)=%s", diff)
			}
		})
	}
}

func TestQuarantineHandler_ListQuarantinedFiles(t *testing.T) {
	type fields struct {
		getHeaderMock func(src io.ReaderAt, size int64) (entry LockEntry, err error)
		lockFiles     []string
		otherFiles    []string
		createSubdir  bool
	}
	tests := []struct {
		name                 string
		fields               fields
		wantQuarantinedFiles []string
		wantErr              bool
		contextCancelled     bool
	}{
		{
			name: "empty directory",
			fields: fields{
				getHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
					return LockEntry{}, nil
				},
				lockFiles:  []string{},
				otherFiles: []string{},
			},
			wantQuarantinedFiles: []string{},
			wantErr:              false,
		},
		{
			name: "single lock file",
			fields: fields{
				getHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
					return LockEntry{
						Filepath: "/original/file.txt",
					}, nil
				},
				lockFiles: []string{"entry-1.lock"},
			},
			wantQuarantinedFiles: []string{"entry-1"},
			wantErr:              false,
		},
		{
			name: "multiple lock files",
			fields: fields{
				getHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
					return LockEntry{
						Filepath: "/original/file.txt",
					}, nil
				},
				lockFiles: []string{"entry-1.lock", "entry-2.lock", "entry-3.lock"},
			},
			wantQuarantinedFiles: []string{"entry-1", "entry-2", "entry-3"},
			wantErr:              false,
		},
		{
			name: "mixed files (only .lock files should be listed)",
			fields: fields{
				getHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
					return LockEntry{
						Filepath: "/original/file.txt",
					}, nil
				},
				lockFiles:  []string{"entry-1.lock", "entry-2.lock"},
				otherFiles: []string{"readme.txt", "data.json", "config.yaml"},
			},
			wantQuarantinedFiles: []string{"entry-1", "entry-2"},
			wantErr:              false,
		},
		{
			name: "subdirectories should be skipped",
			fields: fields{
				getHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
					return LockEntry{
						Filepath: "/original/file.txt",
					}, nil
				},
				lockFiles:    []string{"entry-1.lock"},
				createSubdir: true,
			},
			wantQuarantinedFiles: []string{"entry-1"},
			wantErr:              false,
		},
		{
			// An unreadable or malformed container is logged and
			// skipped, it no longer aborts the whole listing.
			name: "GetHeader failure on one file is skipped, not surfaced",
			fields: fields{
				getHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
					return LockEntry{}, errors.New("failed to read header")
				},
				lockFiles: []string{"entry-1.lock"},
			},
			wantQuarantinedFiles: []string{},
			wantErr:              false,
		},
		{
			name: "context cancellation",
			fields: fields{
				getHeaderMock: func(src io.ReaderAt, size int64) (entry LockEntry, err error) {
					return LockEntry{
						Filepath: "/original/file.txt",
					}, nil
				},
				lockFiles: []string{"entry-1.lock", "entry-2.lock"},
			},
			wantQuarantinedFiles: []string{},
			wantErr:              false,
			contextCancelled:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup context
			ctx := t.Context()
			if tt.contextCancelled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel() // Cancel immediately
			}

			// Setup quarantine directory
			quarantineDir := t.TempDir()

			// Create lock files
			for _, filename := range tt.fields.lockFiles {
				filePath := filepath.Join(quarantineDir, filename)
				err := os.WriteFile(filePath, []byte("dummy lock file content"), 0o600)
				if err != nil {
					t.Fatalf("failed to create lock file: %v", err)
				}
			}

			// Create other files
			for _, filename := range tt.fields.otherFiles {
				filePath := filepath.Join(quarantineDir, filename)
				err := os.WriteFile(filePath, []byte("other file content"), 0o600)
				if err != nil {
					t.Fatalf("failed to create other file: %v", err)
				}
			}

			// Create subdirectory if needed
			if tt.fields.createSubdir {
				subdirPath := filepath.Join(quarantineDir, "subdir")
				err := os.Mkdir(subdirPath, 0o750)
				if err != nil {
					t.Fatalf("failed to create subdirectory: %v", err)
				}
			}

			// Create mocks
			locker := &lockerMock{
				GetHeaderMock: tt.fields.getHeaderMock,
			}

			// Create handler
			q := &QuarantineHandler{
				location: quarantineDir,
				locker:   locker,
			}

			// Execute
			var gotFiles []*QuarantinedFile
			var gotErr error
			for file, err := range q.ListQuarantinedFiles(ctx) {
				if err != nil {
					gotErr = err
					break
				}
				if file != nil {
					gotFiles = append(gotFiles, file)
				}
			}

			// Check error
			if tt.wantErr {
				if gotErr == nil {
					t.Errorf("ListQuarantinedFiles() error = nil, wantErr = true")
				}
				return
			}

			if gotErr != nil {
				t.Errorf("ListQuarantinedFiles() unexpected error = %v", gotErr)
				return
			}

			// Check files count
			if len(gotFiles) != len(tt.wantQuarantinedFiles) {
				t.Errorf("ListQuarantinedFiles() got %d files, want %d files", len(gotFiles), len(tt.wantQuarantinedFiles))
			}

			// Check file IDs
			gotIDs := make([]string, len(gotFiles))
			for i, f := range gotFiles {
				gotIDs[i] = f.ID
			}

			if diff := cmp.Diff(gotIDs, tt.wantQuarantinedFiles); diff != "" {
				t.Errorf("ListQuarantinedFiles() IDs diff(-got+want)=%s", diff)
			}

			// Verify all files have proper LockEntry (unless context was cancelled)
			if !tt.contextCancelled {
				for _, f := range gotFiles {
					if f.Filepath == "" && len(tt.wantQuarantinedFiles) > 0 {
						t.Errorf("ListQuarantinedFiles() file %s has empty Filepath", f.ID)
					}
				}
			}
		})
	}
}

func checkQuarantineLocation(t *testing.T, quarantiner *QuarantineHandler, location string, nbEntries int) {
	t.Helper()
	if quarantiner.location != location {
		t.Errorf("location not updated, got %s, want %s", quarantiner.location, location)
	}
	entries, err := os.ReadDir(location)
	if err != nil {
		t.Errorf("failed to read new location: %v", err)
	}
	lockFileCount := 0
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".lock" {
			lockFileCount++
		}
	}
	if lockFileCount != nbEntries {
		t.Errorf("expected %d lock files in new location, got %d", nbEntries, lockFileCount)
	}
}

func TestQuarantineHandler_Reconfigure(t *testing.T) {
	type fields struct {
		initialPassword    string
		registryMigrateErr bool
		registrGetErrs     map[string]error
		registrySetErrs    map[string]bool
		createLockFiles    []string
	}
	type args struct {
		newPassword     string
		useSameLocation bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "ok reconfigure with password change only",
			fields: fields{
				initialPassword: "oldpassword",
			},
			args: args{
				newPassword:     "newpassword",
				useSameLocation: true,
			},
		},
		{
			name: "ok reconfigure with location change",
			fields: fields{
				initialPassword: "password",
				createLockFiles: []string{"entry-1.lock", "entry-2.lock"},
			},
			args: args{
				newPassword: "newpassword",
			},
		},
		{
			name: "ok reconfigure with same location (no move)",
			fields: fields{
				initialPassword: "password",
				createLockFiles: []string{"entry-1.lock"},
			},
			args: args{
				newPassword:     "newpassword",
				useSameLocation: true,
			},
		},
		{
			name: "error when registry migration fails",
			fields: fields{
				initialPassword:    "password",
				registryMigrateErr: true,
			},
			args: args{
				useSameLocation: true,
			},
			wantErr: true,
		},
		{
			name: "error get entry reconfigure with location change",
			fields: fields{
				initialPassword: "password",
				createLockFiles: []string{"entry-1.lock", "entry-2.lock"},
				registrGetErrs: map[string]error{
					"entry-1": errors.New("error"),
				},
			},
			args: args{
				newPassword: "newpassword",
			},
			wantErr: true,
		},
		{
			name: "error set entry reconfigure with location change",
			fields: fields{
				initialPassword: "password",
				createLockFiles: []string{"entry-1.lock", "entry-2.lock"},
				registrySetErrs: map[string]bool{"entry-1": true},
			},
			args: args{
				newPassword: "newpassword",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			initialDir := t.TempDir()
			for _, filename := range tt.fields.createLockFiles {
				filePath := filepath.Join(initialDir, filename)
				err := os.WriteFile(filePath, []byte("dummy lock content"), 0o600)
				if err != nil {
					t.Fatalf("failed to create lock file: %v", err)
				}
			}

			registry := &registryMock{
				GetMock: func(ctx context.Context, id string) (entry *Entry, err error) {
					if getErr, ok := tt.fields.registrGetErrs[id]; ok {
						err = getErr
					}
					entry = &Entry{
						ID: id,
					}
					return
				},
				SetMock: func(ctx context.Context, entry *Entry) error {
					if setErr, ok := tt.fields.registrySetErrs[entry.ID]; ok && setErr {
						return errors.New("error set")
					}
					return nil
				},
				GetLocationMock: func() string { return "file::memory:" },
				CloneMock: func(ctx context.Context, newLocation string, _ bool) (quarantineRegistry, error) {
					return nil, errors.New("error clone registry")
				},
			}

			locker := &tarLocker{Password: tt.fields.initialPassword}
			q := &QuarantineHandler{
				location: initialDir,
				locker:   locker,
				registry: registry,
			}

			var newLocation string
			switch {
			case tt.args.useSameLocation:
				newLocation = initialDir
			default:
				newLocation = t.TempDir()
			}

			newConfig := Config{
				Location: newLocation,
			}
			if tt.fields.registryMigrateErr {
				newConfig.RegistryLocation = filepath.Join(t.TempDir(), "other.db")
			}
			err := q.Reconfigure(ctx, newConfig)

			if tt.wantErr != (err != nil) {
				t.Errorf("Reconfigure() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				for _, name := range tt.fields.createLockFiles {
					if _, statErr := os.Stat(filepath.Join(initialDir, name)); statErr != nil {
						t.Errorf("%s must be back in the original location after a failed Reconfigure: %v", name, statErr)
					}
					if !tt.args.useSameLocation {
						if _, statErr := os.Stat(filepath.Join(newLocation, name)); statErr == nil {
							t.Errorf("%s must not stay in the new location after a failed Reconfigure", name)
						}
					}
				}
				if q.location != initialDir || q.locker != locker {
					t.Error("a failed Reconfigure must leave the location and the locker (password) unchanged")
				}
				return
			}
			checkQuarantineLocation(t, q, newLocation, len(tt.fields.createLockFiles))
		})
	}
}

func TestMoveFile(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) (src, dst string)
		wantErr bool
		check   func(t *testing.T, src, dst string)
	}{
		{
			name: "successful move within same filesystem",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				tmpDir := t.TempDir()
				src := filepath.Join(tmpDir, "source.txt")
				dst := filepath.Join(tmpDir, "dest.txt")
				if err := os.WriteFile(src, []byte("test content"), 0o600); err != nil {
					t.Fatalf("failed to create source file: %v", err)
				}
				return src, dst
			},
			check: func(t *testing.T, src, dst string) {
				t.Helper()
				content, err := os.ReadFile(filepath.Clean(dst))
				if err != nil {
					t.Fatalf("failed to read destination file: %v", err)
				}
				if string(content) != "test content" {
					t.Errorf("content mismatch: got %s, want 'test content'", string(content))
				}
				if _, err := os.Stat(src); !os.IsNotExist(err) {
					t.Errorf("source file should not exist after move")
				}
			},
		},
		{
			name: "preserves file permissions",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				tmpDir := t.TempDir()
				src := filepath.Join(tmpDir, "source.txt")
				dst := filepath.Join(tmpDir, "dest.txt")
				if err := os.WriteFile(src, []byte("test file content"), 0o600); err != nil {
					t.Fatalf("failed to create source file: %v", err)
				}
				return src, dst
			},
			check: func(t *testing.T, src, dst string) {
				t.Helper()
				if _, err := os.Stat(src); !os.IsNotExist(err) {
					t.Errorf("source file should not exist after move")
				}
				info, err := os.Stat(dst)
				if err != nil {
					t.Fatalf("failed to stat destination: %v", err)
				}
				if info.Mode().Perm() != 0o600 {
					t.Errorf("permissions not preserved: got %o, want 0600", info.Mode().Perm())
				}
			},
		},
		{
			name: "source file does not exist",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				tmpDir := t.TempDir()
				return filepath.Join(tmpDir, "nonexistent.txt"), filepath.Join(tmpDir, "dest.txt")
			},
			wantErr: true,
		},
		{
			name: "destination directory does not exist",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
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
			err := MoveFile(src, dst)

			if (err != nil) != tt.wantErr {
				t.Errorf("MoveFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.check != nil {
				tt.check(t, src, dst)
			}
		})
	}
}
