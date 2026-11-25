//go:build linux

package main

import (
	"bytes"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

func TestRealSevenZip_aMemberLargerThanMaxFileSizeIsExtractedWithTheBudgetAsLimit(t *testing.T) {
	const memberSize = 3 << 20
	member := make([]byte, memberSize)
	if _, err := rand.NewChaCha8([32]byte{7}).Read(member); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "big.zip")
	writeZip(t, archive, "", zipMember{name: "big.bin", data: string(member)})

	tests := []struct {
		name        string
		limits      plugins.ExtractLimits
		wantFiles   int
		wantSkipped int
		wantErr     bool
	}{
		{"max file size is the budget", plugins.ExtractLimits{MaxFileSize: 1 << 30, MaxFiles: 10, MaxTotalSize: 1 << 30}, 1, 0, false},
		{"max file size is the budget, member just fits", plugins.ExtractLimits{MaxFileSize: memberSize, MaxFiles: 10, MaxTotalSize: memberSize}, 1, 0, false},
		{"budget below the member", plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 10, MaxTotalSize: 1 << 20}, 0, 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex, err := realPlugin(t).ExtractFile(archive, t.TempDir(), tt.limits)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ExtractFile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(ex.Files) != tt.wantFiles || ex.SkippedCount != tt.wantSkipped {
				t.Fatalf("Files = %v, SkippedCount = %d (%+v), want %d files, %d skipped", baseNames(ex.Files), ex.SkippedCount, ex.Skipped, tt.wantFiles, tt.wantSkipped)
			}
			for _, f := range ex.Files {
				got, err := os.ReadFile(filepath.Clean(f))
				if err != nil || !bytes.Equal(got, member) {
					t.Errorf("extracted member differs (err %v, %d bytes), want the %d bytes of the member", err, len(got), memberSize)
				}
			}
		})
	}
}
