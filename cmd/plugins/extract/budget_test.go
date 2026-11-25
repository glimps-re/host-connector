//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
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

// The budgets of 10, 40 and 1500 files are in the e2e scenario
// TestE2E_theBudgetInFilesIsExactAndTheRestIsListed; a budget under 1 cannot be
// configured (the connector replaces it with its default).
func TestExtractFile_budgetInFilesIsExactAndTheRestIsReportedExtractLimit(t *testing.T) {
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
