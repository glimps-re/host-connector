package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

func TestT77a_aMemberIsBoundedByTheRemainingBudgetNotByMaxFileSize(t *testing.T) {
	const budget, spent = int64(1000), int64(400)
	tests := []struct {
		name                 string
		call                 func(c *Connector, path string) error
		want                 int64
		wantCheck, wantNames bool
	}{
		{"extraction", func(c *Connector, path string) error {
			size, files := spent, 30
			return c.recursiveExtract(fileToAnalyze{location: path}, 1, &size, &files, logger)
		}, budget - spent, false, false},
		{"check of a zip-family document", func(c *Connector, path string) error {
			size, files := spent, 30
			return c.recursiveExtract(fileToAnalyze{location: path, zipFamily: true, typeRead: true}, 1, &size, &files, logger)
		}, budget - spent, true, false},
		{"listing of the names", func(c *Connector, path string) error {
			_, _, err := c.listedNames(fileToAnalyze{location: path}, 10, logger)
			return err
		}, budget, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got plugins.ExtractLimits
			prev := ExtractFile
			ExtractFile = func(_, _ string, limits plugins.ExtractLimits) (plugins.Extraction, error) {
				got = limits
				return plugins.Extraction{}, nil
			}
			t.Cleanup(func() { ExtractFile = prev })
			content, name := realZip(t), "archive.zip"
			if tt.wantCheck {
				content, name = docxBytes(t), "doc.docx"
			}
			path := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := NewConnector(Config{Extract: true, WorkDir: t.TempDir(), RecursiveExtractMaxDepth: 3, ExtractMinThreshold: 1, RecursiveExtractMaxFiles: 100, RecursiveExtractMaxSize: budget, MaxFileSize: 10}, nil, cleanSubmitter())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close(context.WithoutCancel(t.Context())) })
			c.analysisChan = make(chan fileToAnalyze, 1)
			if err = tt.call(c, path); err != nil {
				t.Fatalf("call error = %v", err)
			}
			if got.CheckOnly != tt.wantCheck || got.NamesOnly != tt.wantNames {
				t.Errorf("CheckOnly = %t, NamesOnly = %t, want %t and %t: another path ran", got.CheckOnly, got.NamesOnly, tt.wantCheck, tt.wantNames)
			}
			if got.MaxTotalSize != tt.want || got.MaxFileSize != got.MaxTotalSize {
				t.Errorf("limits = %+v, want MaxFileSize == MaxTotalSize == %d (max_file_size is 10)", got, tt.want)
			}
		})
	}
}
