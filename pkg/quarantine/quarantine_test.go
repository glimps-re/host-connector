package quarantine

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

type lockerMock struct {
	LockFileMock   func(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error
	UnlockFileMock func(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error)
	GetHeaderMock  func(in io.Reader) (entry LockEntry, err error)
}

func (l *lockerMock) LockFile(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error {
	if l.LockFileMock != nil {
		return l.LockFileMock(file, in, info, reason, out)
	}
	panic("LockFileMock not implemented")
}

func (l *lockerMock) UnlockFile(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error) {
	if l.UnlockFileMock != nil {
		return l.UnlockFileMock(in, out)
	}
	panic("UnlockFileMock not implemented")
}

func (l *lockerMock) GetHeader(in io.Reader) (entry LockEntry, err error) {
	if l.GetHeaderMock != nil {
		return l.GetHeaderMock(in)
	}
	panic("GetHeaderMock not implemented")
}

type registryMock struct {
	GetLocationMock func() (location string)
	SetMock         func(ctx context.Context, entry *Entry) error
	GetMock         func(ctx context.Context, id string) (entry *Entry, err error)
	MigrateMock     func(ctx context.Context, newLocation string) error
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

func (m *registryMock) Migrate(ctx context.Context, newLocation string) error {
	if m.MigrateMock != nil {
		return m.MigrateMock(ctx, newLocation)
	}
	panic("Migrate not implemented")
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
		name         string
		fields       fields
		args         args
		wantLocation func(quarantineDir string, id string) string
		wantID       func(filePath string, sha256 string) string
		wantErr      error
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
			wantErr: errors.New("locker failed"),
		},
		{
			name: "error when registry set fails",
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
			wantErr: errors.New("registry set failed"),
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
				LockFileMock: tt.fields.lockFileMock,
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

func TestQuarantineHandler_Restore(t *testing.T) {
	type fields struct {
		getHeaderMock  func(in io.Reader) (entry LockEntry, err error)
		unlockFileMock func(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error)
		registryGet    func(ctx context.Context, id string) (entry *Entry, err error)
		registrySet    func(ctx context.Context, entry *Entry) error
		lockFileExists bool
	}
	type args struct {
		entryID string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr error
	}{
		{
			name: "ok restore",
			fields: fields{
				getHeaderMock: func(in io.Reader) (entry LockEntry, err error) {
					return LockEntry{
						Filepath: filepath.Join(t.TempDir(), "restored.txt"),
					}, nil
				},
				unlockFileMock: func(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error) {
					tmpFile := filepath.Join(t.TempDir(), "temp.txt")
					if err = os.WriteFile(tmpFile, []byte("test content"), 0o600); err != nil {
						return
					}
					fInfo, err := os.Stat(tmpFile)
					if err != nil {
						return
					}
					_, err = out.Write([]byte("test content"))
					file = tmpFile
					info = fInfo
					return
				},
				registryGet: func(ctx context.Context, id string) (entry *Entry, err error) {
					return &Entry{
						ID:                 id,
						SHA256:             "abc123",
						QuarantineLocation: "some/path.lock",
					}, nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return nil
				},
				lockFileExists: true,
			},
			args: args{
				entryID: "test-entry",
			},
			wantErr: nil,
		},
		{
			name: "error when lock file does not exist",
			fields: fields{
				getHeaderMock: func(in io.Reader) (entry LockEntry, err error) {
					return LockEntry{}, nil
				},
				unlockFileMock: func(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error) {
					return
				},
				registryGet: func(ctx context.Context, id string) (entry *Entry, err error) {
					return &Entry{}, nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return nil
				},
				lockFileExists: false,
			},
			args: args{
				entryID: "nonexistent",
			},
			wantErr: os.ErrNotExist,
		},
		{
			name: "error when GetHeader fails",
			fields: fields{
				getHeaderMock: func(in io.Reader) (entry LockEntry, err error) {
					return LockEntry{}, errors.New("get header failed")
				},
				unlockFileMock: func(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error) {
					return
				},
				registryGet: func(ctx context.Context, id string) (entry *Entry, err error) {
					return &Entry{}, nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return nil
				},
				lockFileExists: true,
			},
			args: args{
				entryID: "test-entry",
			},
			wantErr: errors.New("get header failed"),
		},
		{
			name: "error when creating output file fails",
			fields: fields{
				getHeaderMock: func(in io.Reader) (entry LockEntry, err error) {
					return LockEntry{
						Filepath: "/nonexistent/dir/file.txt",
					}, nil
				},
				unlockFileMock: func(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error) {
					return
				},
				registryGet: func(ctx context.Context, id string) (entry *Entry, err error) {
					return &Entry{}, nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return nil
				},
				lockFileExists: true,
			},
			args: args{
				entryID: "test-entry",
			},
			wantErr: os.ErrNotExist,
		},
		{
			name: "error when UnlockFile fails",
			fields: fields{
				getHeaderMock: func(in io.Reader) (entry LockEntry, err error) {
					return LockEntry{
						Filepath: filepath.Join(t.TempDir(), "restored.txt"),
					}, nil
				},
				unlockFileMock: func(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error) {
					err = errors.New("unlock failed")
					return
				},
				registryGet: func(ctx context.Context, id string) (entry *Entry, err error) {
					return &Entry{}, nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return nil
				},
				lockFileExists: true,
			},
			args: args{
				entryID: "test-entry",
			},
			wantErr: errors.New("unlock failed"),
		},
		{
			name: "error when registry Get fails",
			fields: fields{
				getHeaderMock: func(in io.Reader) (entry LockEntry, err error) {
					return LockEntry{
						Filepath: filepath.Join(t.TempDir(), "restored.txt"),
					}, nil
				},
				unlockFileMock: func(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error) {
					tmpFile := filepath.Join(t.TempDir(), "temp.txt")
					if err = os.WriteFile(tmpFile, []byte("test content"), 0o600); err != nil {
						return
					}
					fInfo, err := os.Stat(tmpFile)
					if err != nil {
						return
					}
					_, err = out.Write([]byte("test content"))
					file = tmpFile
					info = fInfo
					reason = "malware: test"
					return
				},
				registryGet: func(ctx context.Context, id string) (entry *Entry, err error) {
					return nil, errors.New("registry get failed")
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return nil
				},
				lockFileExists: true,
			},
			args: args{
				entryID: "test-entry",
			},
			wantErr: errors.New("registry get failed"),
		},
		{
			name: "error when registry Set fails",
			fields: fields{
				getHeaderMock: func(in io.Reader) (entry LockEntry, err error) {
					return LockEntry{
						Filepath: filepath.Join(t.TempDir(), "restored.txt"),
					}, nil
				},
				unlockFileMock: func(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error) {
					tmpFile := filepath.Join(t.TempDir(), "temp.txt")
					if err = os.WriteFile(tmpFile, []byte("test content"), 0o600); err != nil {
						return
					}
					fInfo, err := os.Stat(tmpFile)
					if err != nil {
						return
					}
					_, err = out.Write([]byte("test content"))
					file = tmpFile
					info = fInfo
					reason = "malware: test"
					return
				},
				registryGet: func(ctx context.Context, id string) (entry *Entry, err error) {
					return &Entry{
						ID:                 id,
						SHA256:             "abc123",
						QuarantineLocation: "some/path.lock",
					}, nil
				},
				registrySet: func(ctx context.Context, entry *Entry) error {
					return errors.New("registry set failed")
				},
				lockFileExists: true,
			},
			args: args{
				entryID: "test-entry",
			},
			wantErr: errors.New("registry set failed"),
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
		})
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
						RestoredAt:         Now(),
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
					return nil, ErrEntryNotFound
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
		getHeaderMock func(in io.Reader) (entry LockEntry, err error)
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
				getHeaderMock: func(in io.Reader) (entry LockEntry, err error) {
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
				getHeaderMock: func(in io.Reader) (entry LockEntry, err error) {
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
				getHeaderMock: func(in io.Reader) (entry LockEntry, err error) {
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
				getHeaderMock: func(in io.Reader) (entry LockEntry, err error) {
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
				getHeaderMock: func(in io.Reader) (entry LockEntry, err error) {
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
			name: "error when GetHeader fails",
			fields: fields{
				getHeaderMock: func(in io.Reader) (entry LockEntry, err error) {
					return LockEntry{}, errors.New("failed to read header")
				},
				lockFiles: []string{"entry-1.lock"},
			},
			wantQuarantinedFiles: []string{},
			wantErr:              true,
		},
		{
			name: "context cancellation",
			fields: fields{
				getHeaderMock: func(in io.Reader) (entry LockEntry, err error) {
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

func checkQuarantineLocation(t *testing.T, quarantiner QuarantineHandler, location string, nbEntries int) {
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
				MigrateMock: func(ctx context.Context, newLocation string) error {
					if tt.fields.registryMigrateErr {
						return errors.New("error migrate registry")
					}
					return nil
				},
			}

			locker := &fileLock{Password: tt.fields.initialPassword}
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
			err := q.Reconfigure(ctx, newConfig)

			if tt.wantErr != (err != nil) {
				t.Errorf("Reconfigure() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			checkQuarantineLocation(t, *q, newLocation, len(tt.fields.createLockFiles))
		})
	}
}
