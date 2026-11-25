//go:build linux

package main

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func writeAt(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveRun_leavesNothingNewAndNothingOutsideTheFolder(t *testing.T) {
	tests := []struct {
		name    string
		before  map[string]string
		outside map[string]string
		run     []string
		want    []string
	}{
		{
			name:    "files of the run, a link to a file and a link to a folder outside",
			before:  map[string]string{"kept.txt": "written before the run", filepath.Join("sub", "kept-too.txt"): "also before"},
			outside: map[string]string{"precious.txt": "must survive"},
			run:     []string{"partial.bin", filepath.Join("deep", "er", "partial2.bin"), filepath.Join("sub", "partial3.bin")},
			want:    []string{"kept.txt", filepath.Join("sub", "kept-too.txt")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "out")
			outside := filepath.Join(root, "outside")
			for name, content := range tt.before {
				writeAt(t, filepath.Join(dir, name), content)
			}
			for name, content := range tt.outside {
				writeAt(t, filepath.Join(outside, name), content)
			}
			before, err := snapshot(dir)
			if err != nil {
				t.Fatal(err)
			}

			for _, name := range tt.run {
				writeAt(t, filepath.Join(dir, name), "written by the stopped run")
			}
			linksOK := true
			if err := os.Symlink(filepath.Join(outside, "precious.txt"), filepath.Join(dir, "link-to-file")); err != nil {
				linksOK = false
			}
			if linksOK {
				if err := os.Symlink(outside, filepath.Join(dir, "link-to-dir")); err != nil {
					t.Fatal(err)
				}
			}

			sze := &sevenZipExtract{logger: discardLogger()}
			if err := sze.removeRun(dir, before); err != nil {
				t.Fatalf("removeRun() error = %v", err)
			}

			after, err := snapshot(dir)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]string, 0, len(after))
			for name := range after {
				got = append(got, name)
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Errorf("files left after removeRun = %v, want only what was there before: %v", got, tt.want)
			}
			for name, content := range tt.before {
				if b, err := os.ReadFile(filepath.Clean(filepath.Join(dir, name))); err != nil || string(b) != content {
					t.Errorf("a file written before the run was touched: %q, %v", b, err)
				}
			}
			for name, content := range tt.outside {
				if b, err := os.ReadFile(filepath.Clean(filepath.Join(outside, name))); err != nil || string(b) != content {
					t.Errorf("a file outside the output folder was touched through a link: %q, %v", b, err)
				}
			}
			if entries, _ := os.ReadDir(outside); len(entries) != len(tt.outside) {
				t.Errorf("the folder behind a link holds %d entries, want its %d original file(s)", len(entries), len(tt.outside))
			}
		})
	}
}

func TestRemoveRun_toleratesAMissingOrEmptyFolder(t *testing.T) {
	tests := []struct {
		name string
		dir  func(t *testing.T) string
		// hostFailure: the error of a host that cannot read the folder is tolerated.
		hostFailure bool
	}{
		{name: "an empty folder", dir: func(t *testing.T) string { return t.TempDir() }},
		{name: "a missing folder", dir: func(t *testing.T) string { return filepath.Join(t.TempDir(), "never-created") }, hostFailure: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sze := &sevenZipExtract{logger: discardLogger()}
			dir := tt.dir(t)
			if err := sze.removeRun(dir, map[string]struct{}{}); err != nil && (!tt.hostFailure || !errors.Is(err, errOutputFolder)) {
				t.Errorf("removeRun() error = %v, want nil or, for a missing folder, a failure of the host", err)
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Errorf("the folder now holds %v", entries)
			}
		})
	}
}

func TestSkipVanished(t *testing.T) {
	denied := &fs.PathError{Op: "open", Path: "x", Err: fs.ErrPermission}
	tests := []struct {
		name string
		err  error
		want error
	}{
		{"no error", nil, nil},
		{"file vanished", &fs.PathError{Op: "lstat", Path: "x", Err: fs.ErrNotExist}, nil},
		{"wrapped vanish", errors.Join(errors.New("walk"), fs.ErrNotExist), nil},
		{"permission denied is a real failure", denied, denied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := skipVanished(tt.err); !errors.Is(got, tt.want) {
				t.Errorf("skipVanished(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestRecoverableAnomaly_isRecordedOnceForTheArchive(t *testing.T) {
	type anomaly struct{ step, text string }
	tests := []struct {
		name      string
		anomalies []anomaly
		want      []string
	}{
		{
			name:      "two of the listing and one of the extraction",
			anomalies: []anomaly{{"list", "Headers Error"}, {"list", "Headers Error again"}, {"extract", "Data Error"}},
			want:      []string{"7z could not list the archive cleanly", "7z could not extract the archive cleanly"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sze := &sevenZipExtract{logger: discardLogger()}
			var anomalies []string
			for _, a := range tt.anomalies {
				sze.recoverableAnomaly(&anomalies, a.step, errors.New(a.text))
			}
			if !slices.Equal(anomalies, tt.want) {
				t.Errorf("anomalies = %q, want %q: the same cause is noted once, the error text is never kept", anomalies, tt.want)
			}
		})
	}
}

func TestExtractResult_updateRecordsRegularFilesAndDropsLinks(t *testing.T) {
	tests := []struct {
		name, content, archivePath string
		mod                        time.Time
		wantDate                   string
	}{
		{name: "a regular file, then a link to it", content: "hello", archivePath: "dir/a.txt", mod: time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC), wantDate: "2024-03-04T05:06:07Z"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			ec := &extractResult{logger: discardLogger()}

			regular := filepath.Join(dir, "a.txt")
			writeAt(t, regular, tt.content)
			if err := os.Chtimes(regular, tt.mod, tt.mod); err != nil {
				t.Fatal(err)
			}
			if err := ec.update(regular, tt.archivePath); err != nil {
				t.Fatalf("update(regular) error = %v", err)
			}
			if len(ec.extractedFiles) != 1 {
				t.Fatalf("extractedFiles = %+v, want one", ec.extractedFiles)
			}
			got := ec.extractedFiles[0]
			if got.Path != regular || got.ArchivePath != tt.archivePath || got.Size != len(tt.content) || got.LastModificationDate != tt.wantDate {
				t.Errorf("ExtractedFile = %+v, want path, archive path, size %d and an RFC3339 UTC date", got, len(tt.content))
			}

			link := filepath.Join(dir, "link")
			if err := os.Symlink(regular, link); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if err := ec.update(link, "dir/link"); err != nil {
				t.Fatalf("update(link) error = %v", err)
			}
			if len(ec.extractedFiles) != 1 || len(ec.symlinkFiles) != 1 || ec.symlinkFiles[0] != link {
				t.Errorf("extracted %d, links %v: a link must be noted and never handed to the analysis", len(ec.extractedFiles), ec.symlinkFiles)
			}
			if _, err := os.Lstat(link); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the extracted link must be removed from disk: %v", err)
			}
			if b, err := os.ReadFile(filepath.Clean(regular)); err != nil || string(b) != tt.content {
				t.Errorf("removing the link touched its target: %q, %v", b, err)
			}
		})
	}
}

func TestExtractResult_updateMakesAnUnreadableFileReadableAndFailsOnAMissingOne(t *testing.T) {
	tests := []struct {
		name string
		// file makes the file in dir and returns its path.
		file         func(t *testing.T, dir string) string
		nonRoot      bool
		wantErr      bool
		wantRecorded int
	}{
		{
			name: "an unreadable file is made readable",
			file: func(t *testing.T, dir string) string {
				t.Helper()
				locked := filepath.Join(dir, "locked.bin")
				writeAt(t, locked, "x")
				if err := os.Chmod(locked, 0o000); err != nil {
					t.Fatal(err)
				}
				return locked
			},
			nonRoot:      true,
			wantRecorded: 1,
		},
		{
			name:    "a missing file fails and is not recorded",
			file:    func(_ *testing.T, dir string) string { return filepath.Join(dir, "absent") },
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.nonRoot && os.Geteuid() == 0 {
				t.Skip("root reads whatever the mode")
			}
			ec := &extractResult{logger: discardLogger()}
			path := tt.file(t, t.TempDir())
			if err := ec.update(path, filepath.Base(path)); (err != nil) != tt.wantErr {
				t.Fatalf("update() error = %v, want error %v", err, tt.wantErr)
			}
			if len(ec.extractedFiles) != tt.wantRecorded {
				t.Errorf("extractedFiles = %d, want %d", len(ec.extractedFiles), tt.wantRecorded)
			}
			if tt.wantErr {
				return
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm()&0o400 == 0 {
				t.Errorf("mode = %v (err %v), want the owner read bit set", info.Mode(), err)
			}
		})
	}
}
