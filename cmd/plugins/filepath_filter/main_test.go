package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func Test_checkPatternsConflicts(t *testing.T) {
	type args struct {
		forbidden []string
		skipped   []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ko same pattern in both lists",
			args: args{
				forbidden: []string{"^/tmp/"},
				skipped:   []string{"^/tmp/"},
			},
			wantErr: true,
		},
		{
			name: "ko conflict with multiple patterns",
			args: args{
				forbidden: []string{"^/var/", "^/tmp/"},
				skipped:   []string{"^/home/", "^/tmp/"},
			},
			wantErr: true,
		},
		{
			name: "ok no conflict",
			args: args{
				forbidden: []string{"^/tmp/"},
				skipped:   []string{"^/var/log/"},
			},
		},
		{
			name: "ok empty lists",
			args: args{
				forbidden: []string{},
				skipped:   []string{},
			},
		},
		{
			name: "ok similar but different patterns",
			args: args{
				forbidden: []string{"^/tmp/"},
				skipped:   []string{"^/tmp/logs/"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkPatternsConflicts(tt.args.forbidden, tt.args.skipped)

			if (err != nil) != tt.wantErr {
				t.Errorf("checkPatternsConflicts() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_compileRegexps(t *testing.T) {
	type args struct {
		pathPatterns []string
	}
	tests := []struct {
		name    string
		args    args
		wantLen int
		wantErr bool
	}{
		{
			name: "ko invalid regexp",
			args: args{
				pathPatterns: []string{"[invalid"},
			},
			wantErr: true,
		},
		{
			name: "ko invalid regexp among valid ones",
			args: args{
				pathPatterns: []string{"^/tmp/", "[invalid", "\\.log$"},
			},
			wantErr: true,
		},
		{
			name: "ok single pattern",
			args: args{
				pathPatterns: []string{"^/tmp/"},
			},
			wantLen: 1,
		},
		{
			name: "ok multiple patterns",
			args: args{
				pathPatterns: []string{"^/tmp/", "\\.log$", "(?i)readme"},
			},
			wantLen: 3,
		},
		{
			name: "ok with duplicated patterns",
			args: args{
				pathPatterns: []string{"^/tmp/", "\\.log$", "^/tmp/", "(?i)readme", "^/tmp/"},
			},
			wantLen: 3,
		},
		{
			name: "ok empty list",
			args: args{
				pathPatterns: []string{},
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := compileRegexps(tt.args.pathPatterns)

			if (err != nil) != tt.wantErr {
				t.Errorf("compileRegexps() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			if len(got) != tt.wantLen {
				t.Errorf("compileRegexps() len = %v, want %v", len(got), tt.wantLen)
			}
		})
	}
}

func Test_FilePathFilterPlugin_GetDefaultConfig(t *testing.T) {
	pfp := &FilePathFilterPlugin{}

	got := pfp.GetDefaultConfig()

	config, ok := got.(*Config)
	if !ok {
		t.Errorf("GetDefaultConfig() returned %T, want *Config", got)
		return
	}

	if config.ForbiddenPaths != nil {
		t.Errorf("GetDefaultConfig() ForbiddenPaths = %v, want nil", config.ForbiddenPaths)
	}

	if config.SkippedPaths != nil {
		t.Errorf("GetDefaultConfig() SkippedPaths = %v, want nil", config.SkippedPaths)
	}
}

func Test_FilePathFilterPlugin_Init(t *testing.T) {
	type args struct {
		config any
	}
	type want struct {
		forbiddenPaths []string
		skippedPaths   []string
	}
	tests := []struct {
		name    string
		args    args
		want    want
		wantErr bool
	}{
		{
			name: "ko invalid config type",
			args: args{
				config: struct{}{},
			},
			wantErr: true,
		},
		{
			name: "ko pattern conflict",
			args: args{
				config: &Config{
					ForbiddenPaths: []string{"^/tmp/"},
					SkippedPaths:   []string{"^/tmp/"},
				},
			},
			wantErr: true,
		},
		{
			name: "ko invalid forbidden regexp",
			args: args{
				config: &Config{
					ForbiddenPaths: []string{"[invalid"},
				},
			},
			wantErr: true,
		},
		{
			name: "ko invalid skipped regexp",
			args: args{
				config: &Config{
					SkippedPaths: []string{"[invalid"},
				},
			},
			wantErr: true,
		},
		{
			name: "ok empty config",
			args: args{
				config: &Config{},
			},
			want: want{
				forbiddenPaths: []string{},
				skippedPaths:   []string{},
			},
		},
		{
			name: "ok with valid patterns",
			args: args{
				config: &Config{
					ForbiddenPaths: []string{"^/tmp/", "\\.exe$"},
					SkippedPaths:   []string{"\\.log$", "(?i)readme"},
				},
			},
			want: want{
				forbiddenPaths: []string{"^/tmp/", "\\.exe$"},
				skippedPaths:   []string{"\\.log$", "(?i)readme"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &FilePathFilterPlugin{}
			mockContext := mock.NewMockHCContext()

			err := plugin.Init(tt.args.config, mockContext)

			if (err != nil) != tt.wantErr {
				t.Errorf("Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			if mockContext.OnScanFile == nil {
				t.Error("Init() OnScanFile should be registered but got nil")
			}

			gotForbidden := make([]string, 0, len(plugin.ForbiddenPaths))
			for k := range plugin.ForbiddenPaths {
				gotForbidden = append(gotForbidden, k)
			}
			slices.Sort(gotForbidden)

			wantForbidden := tt.want.forbiddenPaths
			slices.Sort(wantForbidden)

			if diff := cmp.Diff(gotForbidden, wantForbidden); diff != "" {
				t.Errorf("Init() ForbiddenPaths don't match expected, diff = %v", diff)
			}

			gotSkipped := make([]string, 0, len(plugin.SkippedPaths))
			for k := range plugin.SkippedPaths {
				gotSkipped = append(gotSkipped, k)
			}
			slices.Sort(gotSkipped)

			wantSkipped := tt.want.skippedPaths
			slices.Sort(wantSkipped)

			if diff := cmp.Diff(gotSkipped, wantSkipped); diff != "" {
				t.Errorf("Init() SkippedPaths don't match expected, diff = %v", diff)
			}
		})
	}
}

func Test_FilePathFilterPlugin_Close(t *testing.T) {
	plugin := &FilePathFilterPlugin{}

	err := plugin.Close(t.Context())
	if err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

func Test_FilePathFilterPlugin_OnScanFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	testFile1 := "test.txt"
	tmpFile := filepath.Join(tmpDir, testFile1)
	err := os.WriteFile(tmpFile, []byte("test content"), 0o600)
	if err != nil {
		t.Fatalf("could not create test file %q: %v", testFile1, err)
		return
	}

	testFile2 := "app.log"
	logFile := filepath.Join(tmpDir, testFile2)
	err = os.WriteFile(logFile, []byte("test content"), 0o600)
	if err != nil {
		t.Fatalf("could not create test file %q: %v", testFile2, err)
		return
	}

	type fields struct {
		forbiddenPaths map[string]*regexp.Regexp
		skippedPaths   map[string]*regexp.Regexp
	}
	type args struct {
		fileName string
		location string
		sha256   string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *datamodel.Result
	}{
		{
			name: "ko file does not exist",
			args: args{
				fileName: "nonexistent.txt",
				location: "/nonexistent/path/file.txt",
				sha256:   "abc123",
			},
			want: nil,
		},
		{
			name: "ok file matches forbidden path",
			fields: fields{
				forbiddenPaths: map[string]*regexp.Regexp{
					tmpDir: regexp.MustCompile(regexp.QuoteMeta(tmpDir)),
				},
			},
			args: args{
				fileName: "test.txt",
				location: tmpFile,
				sha256:   "abc123",
			},
			want: &datamodel.Result{
				Filename:      "test.txt",
				Location:      tmpFile,
				Malware:       true,
				SHA256:        "abc123",
				Score:         1000,
				Malwares:      []string{"forbidden_file_path"},
				MalwareReason: datamodel.FilteredFilePath,
			},
		},
		{
			name: "ok file matches skipped path",
			fields: fields{
				skippedPaths: map[string]*regexp.Regexp{
					`\.log$`: regexp.MustCompile(`\.log$`),
				},
			},
			args: args{
				fileName: "app.log",
				location: logFile,
				sha256:   "def456",
			},
			want: &datamodel.Result{
				Filename: "app.log",
				Location: logFile,
				Malware:  false,
				SHA256:   "def456",
				Score:    -500,
			},
		},
		{
			name: "ok file matches no pattern",
			fields: fields{
				forbiddenPaths: map[string]*regexp.Regexp{
					"^/forbidden/": regexp.MustCompile("^/forbidden/"),
				},
				skippedPaths: map[string]*regexp.Regexp{
					`\.bak$`: regexp.MustCompile(`\.bak$`),
				},
			},
			args: args{
				fileName: "test.txt",
				location: tmpFile,
				sha256:   "ghi789",
			},
			want: nil,
		},
		{
			name: "ok file matches both forbidden and skipped", // to test forbidden takes priority over skipped
			fields: fields{
				forbiddenPaths: map[string]*regexp.Regexp{
					tmpDir: regexp.MustCompile(regexp.QuoteMeta(tmpDir)),
				},
				skippedPaths: map[string]*regexp.Regexp{
					`\.log$`: regexp.MustCompile(`\.log$`),
				},
			},
			args: args{
				fileName: "app.log",
				location: logFile,
				sha256:   "jkl012",
			},
			want: &datamodel.Result{
				Filename:      "app.log",
				Location:      logFile,
				Malware:       true,
				SHA256:        "jkl012",
				Score:         1000,
				Malwares:      []string{"forbidden_file_path"},
				MalwareReason: datamodel.FilteredFilePath,
			},
		},
		{
			name: "ok with file path not cleaned 1",
			fields: fields{
				forbiddenPaths: map[string]*regexp.Regexp{
					tmpDir: regexp.MustCompile(regexp.QuoteMeta(tmpDir)),
				},
			},
			args: args{
				fileName: "test.txt",
				location: tmpDir + "/../" + filepath.Base(tmpDir) + "/" + testFile1, // e.g., /tmp/abc/../abc/test.txt
				sha256:   "mno345",
			},
			want: &datamodel.Result{
				Filename:      "test.txt",
				Location:      tmpFile,
				Malware:       true,
				SHA256:        "mno345",
				Score:         1000,
				Malwares:      []string{"forbidden_file_path"},
				MalwareReason: datamodel.FilteredFilePath,
			},
		},
		{
			name: "ok with file path not cleaned 2",
			fields: fields{
				forbiddenPaths: map[string]*regexp.Regexp{
					tmpDir: regexp.MustCompile(regexp.QuoteMeta(tmpDir)),
				},
			},
			args: args{
				fileName: "test.txt",
				location: tmpDir + "//" + testFile1, // e.g., /tmp/abc//test.txt
				sha256:   "pqr678",
			},
			want: &datamodel.Result{
				Filename:      "test.txt",
				Location:      tmpFile,
				Malware:       true,
				SHA256:        "pqr678",
				Score:         1000,
				Malwares:      []string{"forbidden_file_path"},
				MalwareReason: datamodel.FilteredFilePath,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &FilePathFilterPlugin{
				ForbiddenPaths: tt.fields.forbiddenPaths,
				SkippedPaths:   tt.fields.skippedPaths,
			}

			got := plugin.OnScanFile(tt.args.fileName, tt.args.location, tt.args.sha256, false)

			if got != nil {
				slices.Sort(got.Malwares)
			}
			if tt.want != nil {
				slices.Sort(tt.want.Malwares)
			}

			if diff := cmp.Diff(got, tt.want, cmpopts.IgnoreFields(datamodel.Result{}, "MaliciousSubfiles", "FilteredVolume", "FileSize")); diff != "" {
				t.Errorf("OnScanFile() result don't match expected, diff = %v", diff)
				return
			}
		})
	}
}
