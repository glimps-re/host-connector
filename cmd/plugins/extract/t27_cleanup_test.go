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

func TestT27_removeRunLeavesNothingNewAndNothingOutsideTheFolder(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "out")
	outside := filepath.Join(root, "outside")
	writeAt(t, filepath.Join(dir, "kept.txt"), "written before the run")
	writeAt(t, filepath.Join(dir, "sub", "kept-too.txt"), "also before")
	writeAt(t, filepath.Join(outside, "precious.txt"), "must survive")
	before, err := snapshot(dir)
	if err != nil {
		t.Fatal(err)
	}

	writeAt(t, filepath.Join(dir, "partial.bin"), "written by the stopped run")
	writeAt(t, filepath.Join(dir, "deep", "er", "partial2.bin"), "nested")
	writeAt(t, filepath.Join(dir, "sub", "partial3.bin"), "in an existing folder")
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
	sze.removeRun(dir, before)

	after, err := snapshot(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(after))
	for name := range after {
		got = append(got, name)
	}
	slices.Sort(got)
	want := []string{"kept.txt", filepath.Join("sub", "kept-too.txt")}
	if !slices.Equal(got, want) {
		t.Errorf("files left after removeRun = %v, want only what was there before: %v", got, want)
	}
	if b, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "kept.txt"))); err != nil || string(b) != "written before the run" {
		t.Errorf("a file written before the run was touched: %q, %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Clean(filepath.Join(outside, "precious.txt"))); err != nil || string(b) != "must survive" {
		t.Errorf("a file outside the output folder was touched through a link: %q, %v", b, err)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 1 {
		t.Errorf("the folder behind a link holds %d entries, want its single original file", len(entries))
	}
}

func TestT27_removeRunToleratesAMissingOrEmptyFolder(t *testing.T) {
	sze := &sevenZipExtract{logger: discardLogger()}
	sze.removeRun(filepath.Join(t.TempDir(), "never-created"), map[string]struct{}{})
	empty := t.TempDir()
	sze.removeRun(empty, map[string]struct{}{})
	if entries, _ := os.ReadDir(empty); len(entries) != 0 {
		t.Errorf("empty folder now holds %v", entries)
	}
}

func TestT27_skipVanished(t *testing.T) {
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

func TestT27_recoverableAnomalyIsRecordedOnceForTheArchive(t *testing.T) {
	sze := &sevenZipExtract{logger: discardLogger()}
	var anomalies []string
	sze.recoverableAnomaly(&anomalies, "list", errors.New("Headers Error"))
	sze.recoverableAnomaly(&anomalies, "list", errors.New("Headers Error again"))
	sze.recoverableAnomaly(&anomalies, "extract", errors.New("Data Error"))
	want := []string{"7z could not list the archive cleanly", "7z could not extract the archive cleanly"}
	if !slices.Equal(anomalies, want) {
		t.Errorf("anomalies = %q, want %q: the same cause is noted once, the error text is never kept", anomalies, want)
	}
}

func TestT27_updateRecordsRegularFilesAndDropsLinks(t *testing.T) {
	dir := t.TempDir()
	ec := &extractResult{logger: discardLogger()}

	regular := filepath.Join(dir, "a.txt")
	writeAt(t, regular, "hello")
	mod := time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC)
	if err := os.Chtimes(regular, mod, mod); err != nil {
		t.Fatal(err)
	}
	if err := ec.update(regular, "dir/a.txt"); err != nil {
		t.Fatalf("update(regular) error = %v", err)
	}
	if len(ec.extractedFiles) != 1 {
		t.Fatalf("extractedFiles = %+v, want one", ec.extractedFiles)
	}
	got := ec.extractedFiles[0]
	if got.Path != regular || got.ArchivePath != "dir/a.txt" || got.Size != 5 || got.LastModificationDate != "2024-03-04T05:06:07Z" {
		t.Errorf("ExtractedFile = %+v, want path, archive path, size 5 and an RFC3339 UTC date", got)
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
	if b, err := os.ReadFile(filepath.Clean(regular)); err != nil || string(b) != "hello" {
		t.Errorf("removing the link touched its target: %q, %v", b, err)
	}
}

func TestT27_updateMakesAnUnreadableFileReadableAndFailsOnAMissingOne(t *testing.T) {
	dir := t.TempDir()
	ec := &extractResult{logger: discardLogger()}
	if os.Geteuid() != 0 {
		locked := filepath.Join(dir, "locked.bin")
		writeAt(t, locked, "x")
		if err := os.Chmod(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		if err := ec.update(locked, "locked.bin"); err != nil {
			t.Fatalf("update(unreadable) error = %v, want the read permission added", err)
		}
		info, err := os.Stat(locked)
		if err != nil || info.Mode().Perm()&0o400 == 0 {
			t.Errorf("mode = %v (err %v), want the owner read bit set", info.Mode(), err)
		}
		if len(ec.extractedFiles) != 1 {
			t.Errorf("extractedFiles = %d, want the file kept", len(ec.extractedFiles))
		}
	}
	before := len(ec.extractedFiles)
	if err := ec.update(filepath.Join(dir, "absent"), "absent"); err == nil {
		t.Error("update(missing) error = nil")
	}
	if len(ec.extractedFiles) != before {
		t.Error("a missing file must not be recorded")
	}
}
