package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// build7z makes a real 7z holding the given members, with the embedded 7-Zip.
func build7z(t *testing.T, plugin *SevenZipExtractPlugin, members map[string]int) string {
	t.Helper()
	src := t.TempDir()
	for name, size := range members {
		if err := os.WriteFile(filepath.Join(src, name), make([]byte, size), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archive := filepath.Join(t.TempDir(), "members.7z")
	if out, err := runCmd(t.Context(), plugin.sze.sevenZipPath, "a", "-bd", archive, filepath.Join(src, "*")); err != nil {
		t.Fatalf("cannot build the archive: %v %s", err, out)
	}
	return archive
}

func reasonsOf(ex plugins.Extraction) map[datamodel.NotAnalyzedReason]int {
	out := map[datamodel.NotAnalyzedReason]int{}
	for _, s := range ex.Skipped {
		out[s.Reason]++
	}
	return out
}

func TestT27_memberOverTheLimitIsNeverWrittenToDisk(t *testing.T) {
	plugin := realPlugin(t)
	archive := build7z(t, plugin, map[string]int{"huge.bin": 30 * mib, "small.txt": 10})
	out := t.TempDir()
	peak := peakWatcher(t, out)
	ex, err := plugin.ExtractFile(archive, out, plugins.ExtractLimits{MaxFileSize: 10 * mib, MaxFiles: 100, MaxTotalSize: 1 << 30})
	if err != nil {
		t.Fatalf("ExtractFile() error = %v", err)
	}
	if len(ex.Files) != 1 || filepath.Base(ex.Files[0]) != "small.txt" {
		t.Errorf("Files = %v, want only small.txt", ex.Files)
	}
	if len(ex.Skipped) != 1 || ex.Skipped[0].FileName != "huge.bin" || ex.Skipped[0].Reason != datamodel.NotAnalyzedTooBig {
		t.Errorf("Skipped = %+v, want huge.bin reported too-big", ex.Skipped)
	}
	if p := peak(); p > 1*mib {
		t.Errorf("%d MiB were written for a member that must never be extracted", p/mib)
	}
}

func TestT27_budgetInFilesIsExactAndTheRestIsReportedExtractLimit(t *testing.T) {
	plugin := realPlugin(t)
	members := map[string]int{}
	for i := range 40 {
		members[fmt.Sprintf("m%03d.txt", i)] = 100 + i
	}
	archive := build7z(t, plugin, members)
	tests := []struct {
		name        string
		maxFiles    int
		wantFiles   int
		wantSkipped int
	}{
		{"budget of 10", 10, 10, 30},
		{"budget of exactly the members", 40, 40, 0},
		{"budget above", 1500, 40, 0},
		{"zero budget extracts nothing", 0, 0, 40},
		{"negative budget extracts nothing", -3, 0, 40},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := t.TempDir()
			ex, err := plugin.ExtractFile(archive, out, plugins.ExtractLimits{MaxFileSize: 10 * mib, MaxFiles: tt.maxFiles, MaxTotalSize: 1 << 30})
			if err != nil {
				t.Fatalf("ExtractFile() error = %v", err)
			}
			if len(ex.Files) != tt.wantFiles || ex.SkippedCount != tt.wantSkipped {
				t.Errorf("extracted %d, skipped %d, want %d and %d", len(ex.Files), ex.SkippedCount, tt.wantFiles, tt.wantSkipped)
			}
			if got := reasonsOf(ex)[datamodel.NotAnalyzedExtractLimit]; got != len(ex.Skipped) {
				t.Errorf("%d of %d skipped entries are extract-limit, want all of them", got, len(ex.Skipped))
			}
			if entries, _ := os.ReadDir(out); len(entries) != tt.wantFiles {
				t.Errorf("the output folder holds %d entries, want %d: nothing beyond the budget may be written", len(entries), tt.wantFiles)
			}
		})
	}
}

func TestT27_budgetInBytesStopsBeforeWritingTheMembersThatDoNotFit(t *testing.T) {
	plugin := realPlugin(t)
	archive := build7z(t, plugin, map[string]int{"a.bin": 1 * mib, "b.bin": 1 * mib, "c.bin": 1 * mib, "d.bin": 1 * mib})
	out := t.TempDir()
	peak := peakWatcher(t, out)
	ex, err := plugin.ExtractFile(archive, out, plugins.ExtractLimits{MaxFileSize: 10 * mib, MaxFiles: 100, MaxTotalSize: 2*mib + 100})
	if err != nil {
		t.Fatalf("ExtractFile() error = %v", err)
	}
	if len(ex.Files) != 2 || ex.SkippedCount != 2 {
		t.Errorf("extracted %d, skipped %d, want 2 and 2", len(ex.Files), ex.SkippedCount)
	}
	if got := reasonsOf(ex)[datamodel.NotAnalyzedExtractLimit]; got != 2 {
		t.Errorf("extract-limit entries = %d, want 2 (a budget announced by the listing, before any write)", got)
	}
	if p := peak(); p > 2*mib+100+slack {
		t.Errorf("%d bytes written, over the budget of %d", p, 2*mib+100)
	}
}

func TestT27_removedKeysAreRefusedWithTheirReplacementNotAsUnknown(t *testing.T) {
	for key, replacement := range map[string]string{
		"max_file_size":            "max_file_size of the main configuration",
		"max_extracted_files":      "recursive_extract_max_files",
		"max_total_extracted_size": "recursive_extract_max_size",
	} {
		t.Run(key, func(t *testing.T) {
			raw := map[string]any{key: "1GB", "default_passwords": []any{"s3cret-password"}}
			err := plugins.DecodeConfig("extract", raw, new(Config))
			if !errors.Is(err, plugins.ErrInvalidConfig) {
				t.Fatalf("DecodeConfig() error = %v, want ErrInvalidConfig", err)
			}
			msg := err.Error()
			if !strings.Contains(msg, key) || !strings.Contains(msg, replacement) {
				t.Errorf("error %q must name the key and the global limit that replaces it (%s)", msg, replacement)
			}
			if strings.Contains(msg, "unknown") {
				t.Errorf("error %q must not be the generic unknown key refusal", msg)
			}
			if strings.Contains(msg, "s3cret-password") || strings.Contains(msg, "1GB") {
				t.Errorf("error %q quotes a configured value", msg)
			}
		})
	}
	t.Run("remaining keys are accepted", func(t *testing.T) {
		raw := map[string]any{"default_passwords": []any{"infected"}, "seven_zip_path": "/usr/bin/7zzs"}
		if err := plugins.DecodeConfig("extract", raw, new(Config)); err != nil {
			t.Errorf("DecodeConfig() error = %v", err)
		}
	})
}
