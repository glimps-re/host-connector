package filesystem

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestLocalFileSystem_Open(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name         string
		setupFile    func(t *testing.T) string
		args         args
		wantData     []byte
		wantErr      bool
		useSetupFile bool
	}{
		{
			name: "successful file read",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp(t.TempDir(), "test_*.txt")
				if err != nil {
					t.Fatalf("failed to create temp file: %v", err)
				}
				defer func() {
					if e := f.Close(); e != nil {
						t.Fatalf("failed to close temp file: %v", e)
					}
				}()
				content := []byte("test file content")
				if _, err := f.Write(content); err != nil {
					t.Fatalf("failed to write test content: %v", err)
				}
				return f.Name()
			},
			useSetupFile: true,
			wantData:     []byte("test file content"),
			wantErr:      false,
		},
		{
			name: "file not found",
			args: args{
				name: "/nonexistent/file.txt",
			},
			wantData: nil,
			wantErr:  true,
		},
		{
			name: "empty file",
			setupFile: func(t *testing.T) string {
				f, err := os.CreateTemp(t.TempDir(), "empty_*.txt")
				if err != nil {
					t.Fatalf("failed to create temp file: %v", err)
				}
				defer func() {
					if e := f.Close(); e != nil {
						t.Fatalf("failed to close temp file: %v", e)
					}
				}()
				return f.Name()
			},
			useSetupFile: true,
			wantData:     []byte{},
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewLocalFileSystem()

			filename := tt.args.name
			if tt.useSetupFile {
				filename = tt.setupFile(t)
			}

			reader, err := l.Open(t.Context(), filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("LocalFileSystem.Open() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			defer func() {
				if e := reader.Close(); e != nil {
					t.Errorf("failed to close reader: %v", e)
				}
			}()
			data, err := io.ReadAll(reader)
			if err != nil {
				t.Errorf("failed to read from opened file: %v", err)
				return
			}

			if diff := cmp.Diff(tt.wantData, data); diff != "" {
				t.Errorf("LocalFileSystem.Open() data mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLocalFileSystem_Stat(t *testing.T) {
	tests := []struct {
		name      string
		setupPath func(t *testing.T) string
		wantIsDir bool
		wantSize  int64
		wantErr   bool
	}{
		{
			name: "file stat",
			setupPath: func(t *testing.T) string {
				f, err := os.CreateTemp(t.TempDir(), "test_*.txt")
				if err != nil {
					t.Fatalf("failed to create temp file: %v", err)
				}
				defer func() {
					if e := f.Close(); e != nil {
						t.Errorf("failed to close file: %v", e)
					}
				}()
				content := []byte("test content")
				if _, err := f.Write(content); err != nil {
					t.Fatalf("failed to write test content: %v", err)
				}
				return f.Name()
			},
			wantIsDir: false,
			wantSize:  12, // len("test content")
			wantErr:   false,
		},
		{
			name: "directory stat",
			setupPath: func(t *testing.T) string {
				return t.TempDir()
			},
			wantIsDir: true,
			wantSize:  0, // Directory size varies by OS
			wantErr:   false,
		},
		{
			name: "nonexistent path",
			setupPath: func(t *testing.T) string {
				return "/nonexistent/path"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewLocalFileSystem()
			path := tt.setupPath(t)

			info, err := l.Stat(t.Context(), path)
			if (err != nil) != tt.wantErr {
				t.Errorf("LocalFileSystem.Stat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if info.IsDir() != tt.wantIsDir {
				t.Errorf("LocalFileSystem.Stat() IsDir = %v, want %v", info.IsDir(), tt.wantIsDir)
			}

			if !tt.wantIsDir && info.Size() != tt.wantSize {
				t.Errorf("LocalFileSystem.Stat() Size = %v, want %v", info.Size(), tt.wantSize)
			}
		})
	}
}

func TestLocalFileSystem_Lstat(t *testing.T) {
	tests := []struct {
		name      string
		setupPath func(t *testing.T) string
		wantIsDir bool
		wantErr   bool
	}{
		{
			name: "regular file",
			setupPath: func(t *testing.T) string {
				f, err := os.CreateTemp(t.TempDir(), "test_*.txt")
				if err != nil {
					t.Fatalf("failed to create temp file: %v", err)
				}
				defer func() {
					if e := f.Close(); e != nil {
						t.Fatalf("failed to close temp file: %v", e)
					}
				}()
				return f.Name()
			},
			wantIsDir: false,
			wantErr:   false,
		},
		{
			name: "directory",
			setupPath: func(t *testing.T) string {
				return t.TempDir()
			},
			wantIsDir: true,
			wantErr:   false,
		},
		{
			name: "nonexistent path",
			setupPath: func(t *testing.T) string {
				return "/nonexistent/path"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewLocalFileSystem()
			path := tt.setupPath(t)

			info, err := l.Lstat(t.Context(), path)
			if (err != nil) != tt.wantErr {
				t.Errorf("LocalFileSystem.Lstat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if info.IsDir() != tt.wantIsDir {
				t.Errorf("LocalFileSystem.Lstat() IsDir = %v, want %v", info.IsDir(), tt.wantIsDir)
			}
		})
	}
}

func TestLocalFileSystem_WalkDir(t *testing.T) {
	type walkResult struct {
		path  string
		isDir bool
	}
	type fields struct {
		setupDir             func(tempDir string)
		nonExistentDirectory bool
	}
	tests := []struct {
		name        string
		fields      fields
		wantResults []walkResult
		wantErr     bool
	}{
		{
			name: "simple directory structure",
			fields: fields{
				setupDir: func(tempDir string) {
					// Create files and subdirectories
					file1 := filepath.Join(tempDir, "file1.txt")
					if err := os.WriteFile(file1, []byte("content1"), 0o600); err != nil {
						t.Fatalf("failed to create file1: %v", err)
					}

					subdir := filepath.Join(tempDir, "subdir")
					if err := os.Mkdir(subdir, 0o750); err != nil {
						t.Fatalf("failed to create subdir: %v", err)
					}

					file2 := filepath.Join(subdir, "file2.txt")
					if err := os.WriteFile(file2, []byte("content2"), 0o600); err != nil {
						t.Fatalf("failed to create file2: %v", err)
					}
				},
			},
			wantResults: []walkResult{
				{".", true},
				{"file1.txt", false},
				{"subdir", true},
				{"subdir/file2.txt", false},
			},
			wantErr: false,
		},
		{
			name: "empty directory",
			fields: fields{
				setupDir: func(tempDir string) {},
			},
			wantResults: []walkResult{
				{".", true}, // root directory only
			},
			wantErr: false,
		},
		{
			name: "nonexistent directory",
			fields: fields{
				nonExistentDirectory: true,
				setupDir:             func(tempDir string) {},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewLocalFileSystem()
			tempDir := t.TempDir()
			if tt.fields.nonExistentDirectory {
				err := os.Remove(tempDir)
				if err != nil {
					panic(err)
				}
			}

			tt.fields.setupDir(tempDir)

			var results []walkResult
			walkFunc := func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				// Calculate relative path
				relPath, relErr := filepath.Rel(tempDir, path)
				if relErr != nil {
					t.Errorf("could not compute relative path: %v", relErr)
					return nil
				}

				results = append(results, walkResult{
					path:  relPath,
					isDir: d.IsDir(),
				})

				return nil
			}

			err := l.WalkDir(t.Context(), tempDir, walkFunc)
			if (err != nil) != tt.wantErr {
				t.Errorf("LocalFileSystem.WalkDir() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Sort results for consistent comparison
			sort.Slice(results, func(i, j int) bool {
				return results[i].path < results[j].path
			})
			sort.Slice(tt.wantResults, func(i, j int) bool {
				return tt.wantResults[i].path < tt.wantResults[j].path
			})

			if diff := cmp.Diff(tt.wantResults, results, cmp.AllowUnexported(walkResult{})); diff != "" {
				t.Errorf("LocalFileSystem.WalkDir() results mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLocalFileSystem_Remove(t *testing.T) {
	tests := []struct {
		name      string
		setupPath func(t *testing.T) string
		wantErr   bool
	}{
		{
			name: "remove existing file",
			setupPath: func(t *testing.T) string {
				f, err := os.CreateTemp(t.TempDir(), "test_*.txt")
				if err != nil {
					t.Fatalf("failed to create temp file: %v", err)
				}
				defer func() {
					if e := f.Close(); e != nil {
						t.Fatalf("failed to close temp file: %v", e)
					}
				}()
				return f.Name()
			},
			wantErr: false,
		},
		{
			name: "remove nonexistent file",
			setupPath: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "nonexistent.txt")
			},
			wantErr: true,
		},
		{
			name: "remove empty directory",
			setupPath: func(t *testing.T) string {
				dir := filepath.Join(t.TempDir(), "empty_dir")
				if err := os.Mkdir(dir, 0o750); err != nil {
					t.Fatalf("failed to create directory: %v", err)
				}
				return dir
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewLocalFileSystem()
			path := tt.setupPath(t)

			err := l.Remove(t.Context(), path)
			if (err != nil) != tt.wantErr {
				t.Errorf("LocalFileSystem.Remove() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify file was actually removed
				if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
					t.Errorf("LocalFileSystem.Remove() file still exists after removal")
				}
			}
		})
	}
}

func TestLocalFileSystem_Create(t *testing.T) {
	tests := []struct {
		name        string
		setupDir    func(t *testing.T) string
		filename    string
		writeData   []byte
		wantErr     bool
		wantContent []byte
	}{
		{
			name: "create new file",
			setupDir: func(t *testing.T) string {
				return t.TempDir()
			},
			filename:    "newfile.txt",
			writeData:   []byte("test content"),
			wantErr:     false,
			wantContent: []byte("test content"),
		},
		{
			name: "create file in nonexistent directory",
			setupDir: func(t *testing.T) string {
				return t.TempDir()
			},
			filename: "nonexistent/dir/file.txt",
			wantErr:  true,
		},
		{
			name: "overwrite existing file",
			setupDir: func(t *testing.T) string {
				dir := t.TempDir()
				existingFile := filepath.Join(dir, "existing.txt")
				if err := os.WriteFile(existingFile, []byte("old content"), 0o600); err != nil {
					t.Fatalf("failed to create existing file: %v", err)
				}
				return dir
			},
			filename:    "existing.txt",
			writeData:   []byte("new content"),
			wantErr:     false,
			wantContent: []byte("new content"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewLocalFileSystem()
			dir := tt.setupDir(t)
			fullPath := filepath.Join(dir, tt.filename)

			writer, err := l.Create(t.Context(), fullPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("LocalFileSystem.Create() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if tt.writeData != nil {
				if _, err := writer.Write(tt.writeData); err != nil {
					t.Errorf("failed to write to created file: %v", err)
					if e := writer.Close(); e != nil {
						t.Errorf("could not close writer, error: %v", e)
					}
					return
				}
			}

			if err := writer.Close(); err != nil {
				t.Errorf("failed to close created file: %v", err)
				return
			}

			// Verify file contents
			if tt.wantContent != nil {
				content, err := os.ReadFile(fullPath) //nolint:gosec // read test file
				if err != nil {
					t.Errorf("failed to read created file: %v", err)
					return
				}

				if diff := cmp.Diff(tt.wantContent, content); diff != "" {
					t.Errorf("LocalFileSystem.Create() content mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestLocalFileSystem_MkdirAll(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		perm    fs.FileMode
		wantErr bool
	}{
		{
			name:    "create single directory",
			path:    "testdir",
			perm:    0o750,
			wantErr: false,
		},
		{
			name:    "create nested directories",
			path:    "parent/child/grandchild",
			perm:    0o750,
			wantErr: false,
		},
		{
			name:    "create directory that already exists",
			path:    "existing",
			perm:    0o750,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewLocalFileSystem()
			baseDir := t.TempDir()
			fullPath := filepath.Join(baseDir, tt.path)

			// For "existing directory" test, create the directory first
			if strings.Contains(tt.name, "already exists") {
				if err := os.MkdirAll(fullPath, tt.perm); err != nil {
					t.Fatalf("failed to setup existing directory: %v", err)
				}
			}

			err := l.MkdirAll(t.Context(), fullPath, tt.perm)
			if (err != nil) != tt.wantErr {
				t.Errorf("LocalFileSystem.MkdirAll() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify directory was created
				info, err := os.Stat(fullPath)
				if err != nil {
					t.Errorf("created directory does not exist: %v", err)
					return
				}

				if !info.IsDir() {
					t.Errorf("created path is not a directory")
				}
			}
		})
	}
}

func TestLocalFileSystem_Rename(t *testing.T) {
	tests := []struct {
		name       string
		setupPaths func(t *testing.T) (string, string)
		wantErr    bool
	}{
		{
			name: "rename existing file",
			setupPaths: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				oldPath := filepath.Join(dir, "oldfile.txt")
				newPath := filepath.Join(dir, "newfile.txt")

				if err := os.WriteFile(oldPath, []byte("content"), 0o600); err != nil {
					t.Fatalf("failed to create source file: %v", err)
				}

				return oldPath, newPath
			},
			wantErr: false,
		},
		{
			name: "rename nonexistent file",
			setupPaths: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				return filepath.Join(dir, "nonexistent.txt"), filepath.Join(dir, "target.txt")
			},
			wantErr: true,
		},
		{
			name: "rename to existing file",
			setupPaths: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				oldPath := filepath.Join(dir, "oldfile.txt")
				newPath := filepath.Join(dir, "newfile.txt")

				if err := os.WriteFile(oldPath, []byte("old content"), 0o600); err != nil {
					t.Fatalf("failed to create source file: %v", err)
				}
				if err := os.WriteFile(newPath, []byte("new content"), 0o600); err != nil {
					t.Fatalf("failed to create target file: %v", err)
				}

				return oldPath, newPath
			},
			wantErr: false, // Should overwrite
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewLocalFileSystem()
			oldPath, newPath := tt.setupPaths(t)

			err := l.Rename(t.Context(), oldPath, newPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("LocalFileSystem.Rename() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify old file no longer exists
				if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
					t.Errorf("source file still exists after rename")
				}

				// Verify new file exists
				if _, err := os.Stat(newPath); err != nil {
					t.Errorf("target file does not exist after rename: %v", err)
				}
			}
		})
	}
}

func TestLocalFileSystem_IsLocal(t *testing.T) {
	l := NewLocalFileSystem()
	if !l.IsLocal() {
		t.Errorf("LocalFileSystem.IsLocal() = false, want true")
	}
}

type waitedEvent struct {
	eventType WatchEventType
	filename  string
}

func waitForEvents(t *testing.T, events <-chan WatchEvent, waitedEvents []waitedEvent, timeout time.Duration) (err error) {
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(timeout))
	defer cancel()
	i := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e, ok := <-events:
			if !ok {
				err = errors.New("events chan canceled")
				return
			}
			wantEventType := waitedEvents[i].eventType
			wantFileNames := waitedEvents[i].filename
			if e.Type != wantEventType {
				err = fmt.Errorf("bad event type, want %s got %s", wantEventType, e.Type)
				return
			}
			if e.Path != wantFileNames {
				err = fmt.Errorf("bad event filename, want %s got %s", wantFileNames, e.Path)
				return
			}
			i++
			if i >= len(waitedEvents) {
				return
			}
		}
	}
}

func TestLocalFileSystem_Watch(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "error nonexistent directory",
			test: func(t *testing.T) {
				l := NewLocalFileSystem()
				_, err := l.Watch(t.Context(), "/nonexistent/path")
				if err == nil {
					t.Error("expected error when watching nonexistent directory")
				}
				if !strings.Contains(err.Error(), "no such file or directory") {
					t.Errorf("expected error to contain 'no such file or directory', got %v", err)
				}
			},
		},
		{
			name: "ok file creation",
			test: func(t *testing.T) {
				l := NewLocalFileSystem()
				watchPath := t.TempDir()

				watcher, err := l.Watch(t.Context(), watchPath)
				if err != nil {
					t.Errorf("failed to create watcher: %v", err)
				}
				defer func() {
					if e := watcher.Close(); e != nil {
						t.Errorf("failed to close watcher: %v", e)
					}
				}()

				// Create a file
				testFile := filepath.Join(watchPath, "test_create.txt")
				if err := os.WriteFile(testFile, []byte("content"), 0o600); err != nil {
					t.Errorf("failed to create test file: %v", err)
				}

				waitedEvents := []waitedEvent{
					{
						eventType: WatchEventCreate,
						filename:  testFile,
					},
					{
						eventType: WatchEventWrite,
						filename:  testFile,
					},
				}

				if e := waitForEvents(t, watcher.Events(), waitedEvents, time.Millisecond*10); e != nil {
					t.Error(e)
				}
			},
		},
		{
			name: "ok modification",
			test: func(t *testing.T) {
				l := NewLocalFileSystem()
				watchPath := t.TempDir()

				watcher, err := l.Watch(t.Context(), watchPath)
				if err != nil {
					t.Errorf("failed to create watcher: %v", err)
				}
				defer func() {
					if e := watcher.Close(); e != nil {
						t.Errorf("failed to close watcher: %v", e)
					}
				}()

				// Create file first
				testFile := filepath.Join(watchPath, "test_modify.txt")
				if err := os.WriteFile(testFile, []byte("initial"), 0o600); err != nil {
					t.Errorf("failed to create initial file: %v", err)
				}

				waitedEvents := []waitedEvent{
					{
						eventType: WatchEventCreate,
						filename:  testFile,
					},
					{
						eventType: WatchEventWrite,
						filename:  testFile,
					},
				}
				if e := waitForEvents(t, watcher.Events(), waitedEvents, time.Millisecond*10); e != nil {
					t.Error(e)
				}

				// Now modify it
				if err := os.WriteFile(testFile, []byte("modified"), 0o600); err != nil {
					t.Errorf("failed to modify test file: %v", err)
				}

				waitedEvents = []waitedEvent{
					{
						eventType: WatchEventWrite,
						filename:  testFile,
					},
				}
				if e := waitForEvents(t, watcher.Events(), waitedEvents, time.Millisecond*10); e != nil {
					t.Error(e)
				}
			},
		},
		{
			name: "ok remove",
			test: func(t *testing.T) {
				l := NewLocalFileSystem()
				watchPath := t.TempDir()

				watcher, err := l.Watch(t.Context(), watchPath)
				if err != nil {
					t.Errorf("failed to create watcher: %v", err)
				}
				defer func() {
					if e := watcher.Close(); e != nil {
						t.Errorf("failed to close watcher: %v", e)
					}
				}()

				testFile := filepath.Join(watchPath, "test_remove.txt")
				if err := os.WriteFile(testFile, []byte("content"), 0o600); err != nil {
					t.Errorf("failed to create file for removal: %v", err)
				}

				waitedEvents := []waitedEvent{
					{
						eventType: WatchEventCreate,
						filename:  testFile,
					},
					{
						eventType: WatchEventWrite,
						filename:  testFile,
					},
				}
				if e := waitForEvents(t, watcher.Events(), waitedEvents, time.Millisecond*10); e != nil {
					t.Error(e)
				}
			},
		},
		{
			name: "watch nested directories",
			test: func(t *testing.T) {
				l := NewLocalFileSystem()
				baseDir := t.TempDir()

				// Setup directory structure
				subDir := filepath.Join(baseDir, "subdir")
				if err := os.Mkdir(subDir, 0o750); err != nil {
					t.Fatalf("failed to create subdirectory: %v", err)
				}

				watcher, err := l.Watch(t.Context(), baseDir)
				if err != nil {
					t.Fatalf("failed to create watcher: %v", err)
				}
				defer func() {
					if e := watcher.Close(); e != nil {
						t.Errorf("failed to close watcher: %v", e)
					}
				}()

				// Create file in existing subdirectory
				nestedFile := filepath.Join(subDir, "nested_file.txt")
				if err := os.WriteFile(nestedFile, []byte("content"), 0o600); err != nil {
					t.Fatalf("failed to create nested file: %v", err)
				}

				waitedEvents := []waitedEvent{
					{
						eventType: WatchEventCreate,
						filename:  nestedFile,
					},
					{
						eventType: WatchEventWrite,
						filename:  nestedFile,
					},
				}
				if e := waitForEvents(t, watcher.Events(), waitedEvents, time.Millisecond*10); e != nil {
					t.Error(e)
				}

				// Create another nested directory
				nestedDir := filepath.Join(subDir, "nested")
				if err := os.Mkdir(nestedDir, 0o750); err != nil {
					t.Fatalf("failed to create nested directory: %v", err)
				}

				waitedEvents = []waitedEvent{
					{
						eventType: WatchEventCreate,
						filename:  nestedDir,
					},
				}
				if e := waitForEvents(t, watcher.Events(), waitedEvents, time.Millisecond*100); e != nil {
					t.Error(e)
				}

				// Create file in the new nested directory
				deepFile := filepath.Join(nestedDir, "deep_file.txt")
				if err := os.WriteFile(deepFile, []byte("deep content"), 0o600); err != nil {
					t.Fatalf("failed to create deep file: %v", err)
				}

				waitedEvents = []waitedEvent{
					{
						eventType: WatchEventCreate,
						filename:  deepFile,
					},
					{
						eventType: WatchEventWrite,
						filename:  deepFile,
					},
				}
				if e := waitForEvents(t, watcher.Events(), waitedEvents, time.Millisecond*100); e != nil {
					t.Error(e)
				}
			},
		},
		{
			name: "watch nested directories",
			test: func(t *testing.T) {
				l := NewLocalFileSystem()
				baseDir := t.TempDir()

				// Setup directory structure
				subDir := filepath.Join(baseDir, "subdir")
				if err := os.Mkdir(subDir, 0o750); err != nil {
					t.Fatalf("failed to create subdirectory: %v", err)
				}

				watcher, err := l.Watch(t.Context(), baseDir)
				if err != nil {
					t.Fatalf("failed to create watcher: %v", err)
				}
				defer func() {
					if e := watcher.Close(); e != nil {
						t.Errorf("failed to close watcher: %v", e)
					}
				}()

				// Create file in existing subdirectory
				nestedFile := filepath.Join(subDir, "nested_file.txt")
				if err := os.WriteFile(nestedFile, []byte("content"), 0o600); err != nil {
					t.Fatalf("failed to create nested file: %v", err)
				}

				waitedEvents := []waitedEvent{
					{
						eventType: WatchEventCreate,
						filename:  nestedFile,
					},
					{
						eventType: WatchEventWrite,
						filename:  nestedFile,
					},
				}
				if e := waitForEvents(t, watcher.Events(), waitedEvents, time.Millisecond*10); e != nil {
					t.Error(e)
				}

				// Create another nested directory
				nestedDir := filepath.Join(subDir, "nested")
				if err := os.Mkdir(nestedDir, 0o750); err != nil {
					t.Fatalf("failed to create nested directory: %v", err)
				}

				waitedEvents = []waitedEvent{
					{
						eventType: WatchEventCreate,
						filename:  nestedDir,
					},
				}
				if e := waitForEvents(t, watcher.Events(), waitedEvents, time.Millisecond*100); e != nil {
					t.Error(e)
				}

				// Create file in the new nested directory
				deepFile := filepath.Join(nestedDir, "deep_file.txt")
				if err := os.WriteFile(deepFile, []byte("deep content"), 0o600); err != nil {
					t.Fatalf("failed to create deep file: %v", err)
				}

				waitedEvents = []waitedEvent{
					{
						eventType: WatchEventCreate,
						filename:  deepFile,
					},
					{
						eventType: WatchEventWrite,
						filename:  deepFile,
					},
				}
				if e := waitForEvents(t, watcher.Events(), waitedEvents, time.Millisecond*100); e != nil {
					t.Error(e)
				}
			},
		},
	}

	for _, tt := range tests {
		// Run each test in its own temp directory
		t.Run(tt.name, tt.test)
	}
}
