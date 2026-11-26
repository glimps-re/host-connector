package scanner

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

func TestRecursiveExtract_remainingBudgetShrinksFromOneLevelToTheNext(t *testing.T) {
	var mu sync.Mutex
	var seen []plugins.ExtractLimits
	inner := realZip(t)
	f := newExtractorFixture(t, func(_, outputDir string, limits plugins.ExtractLimits) (plugins.Extraction, error) {
		mu.Lock()
		seen = append(seen, limits)
		level := len(seen)
		mu.Unlock()
		if level > 1 {
			return plugins.Extraction{}, nil
		}
		var files []string
		for name, content := range map[string][]byte{"inner.zip": inner, "plain.txt": []byte("plain member")} {
			p := filepath.Join(outputDir, name)
			if err := os.WriteFile(p, content, 0o600); err != nil {
				return plugins.Extraction{}, err
			}
			files = append(files, p)
		}
		return plugins.Extraction{Size: uint64(len(inner)) + 12, Files: files}, nil
	})
	f.conn.config.RecursiveExtractMaxFiles = 50
	f.conn.config.RecursiveExtractMaxSize = 1 << 20
	f.conn.config.MaxFileSize = 1 << 19
	archive := f.deposit(t, "outer.zip")
	if err := f.conn.ScanFile(t.Context(), archive); err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}
	f.conn.Close(t.Context())
	mu.Lock()
	defer mu.Unlock()
	if len(seen) < 2 {
		t.Fatalf("the extractor was called %d time(s), the nested archive was never attempted", len(seen))
	}
	first, second := seen[0], seen[1]
	if first.MaxFiles != 50 || first.MaxTotalSize != 1<<20 || first.MaxFileSize != first.MaxTotalSize {
		t.Errorf("first level limits = %+v, want 50 files and a member bounded by the 1 MiB budget", first)
	}
	if second.MaxFileSize != second.MaxTotalSize {
		t.Errorf("per-member limit = %d at the second level, want the remaining budget %d", second.MaxFileSize, second.MaxTotalSize)
	}
	if second.MaxFiles >= first.MaxFiles || second.MaxTotalSize >= first.MaxTotalSize {
		t.Errorf("nested limits = %+v, want a budget smaller than %+v: the extracted files and bytes were already spent", second, first)
	}
	if second.MaxFiles != first.MaxFiles-2 {
		t.Errorf("remaining files = %d, want %d (two files were extracted at the first level)", second.MaxFiles, first.MaxFiles-2)
	}
	if want := first.MaxTotalSize - int64(len(inner)) - 12; second.MaxTotalSize != want {
		t.Errorf("remaining bytes = %d, want %d", second.MaxTotalSize, want)
	}
}
