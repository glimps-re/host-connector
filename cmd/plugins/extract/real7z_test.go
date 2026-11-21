package main

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// realPlugin runs the embedded 7-Zip, copied where it can be executed.
func realPlugin(t *testing.T) *SevenZipExtractPlugin {
	t.Helper()
	in, err := os.Open("7zzs")
	if err != nil {
		t.Skipf("embedded 7-Zip not available: %v", err)
	}
	defer func() {
		if e := in.Close(); e != nil {
			t.Error(e)
		}
	}()
	bin := filepath.Join(t.TempDir(), "7zzs")
	out, err := os.OpenFile(filepath.Clean(bin), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, modeScript); err != nil {
		t.Fatal(err)
	}
	sze := &sevenZipExtract{sevenZipPath: bin, logger: slog.New(slog.DiscardHandler)}
	bigConfig(sze)
	return &SevenZipExtractPlugin{sze: sze, logger: sze.logger, consoleLogger: sze.logger}
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join("testdata", name)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("fixture %s not available: %v", name, err)
	}
	return p
}

func baseNames(files []string) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = filepath.Base(f)
	}
	return out
}

func TestRealSevenZip_wildcardNamedMembersAreExtractedAsThemselves(t *testing.T) {
	out := t.TempDir()
	ex, err := realPlugin(t).ExtractFile(fixture(t, "wildcard.7z"), out, openLimits)
	if err != nil {
		t.Fatalf("ExtractFile() error = %v", err)
	}
	if len(ex.Files) != 3 || ex.SkippedCount != 0 {
		t.Fatalf("Extraction = %+v (%v), want the 3 members and nothing skipped", ex, baseNames(ex.Files))
	}
	for name, want := range map[string]string{"*": "wild", "?": "q", "normal.txt": "plain"} {
		got, err := os.ReadFile(filepath.Clean(filepath.Join(out, name)))
		if err != nil || string(got) != want {
			t.Errorf("member %q = %q (err %v), want %q: a name must never act as a wildcard", name, got, err, want)
		}
	}
}

func TestRealSevenZip_controlCharactersInMemberNamesAreAnExtractError(t *testing.T) {
	for _, name := range []string{"lf.7z", "cr.7z", "esc.7z"} {
		t.Run(name, func(t *testing.T) {
			out := t.TempDir()
			ex, err := realPlugin(t).ExtractFile(fixture(t, name), out, openLimits)
			if !errors.Is(err, plugins.ErrArchiveAnomaly) {
				t.Fatalf("ExtractFile() error = %v, want an anomaly: a name with a control character must put the archive in error", err)
			}
			if ex.SkippedCount != 1 || len(ex.Skipped) != 1 || ex.Skipped[0].Reason != datamodel.NotAnalyzedExtractError || ex.Skipped[0].FileName != name {
				t.Errorf("Skipped = %+v (%d), want one extract-error named %s for the report", ex.Skipped, ex.SkippedCount, name)
			}
			for _, f := range ex.Files {
				if !strings.HasPrefix(f, out) {
					t.Errorf("extracted file %q is outside the output directory", f)
				}
			}
		})
	}
}

func TestRealSevenZip_twinNamesAreAnAnomalyNotASilentLoss(t *testing.T) {
	ex, err := realPlugin(t).ExtractFile(fixture(t, "twin.7z"), t.TempDir(), openLimits)
	if !errors.Is(err, plugins.ErrArchiveAnomaly) {
		t.Fatalf("ExtractFile() error = %v, want an anomaly: one of the two members was lost", err)
	}
	if ex.SkippedCount != 1 || len(ex.Skipped) != 1 {
		t.Fatalf("Extraction = %+v, want one extract-error entry: one of the two members was lost", ex)
	}
	if got := ex.Skipped[0]; got.FileName != "twin.7z" || got.Reason != datamodel.NotAnalyzedExtractError {
		t.Errorf("Skipped[0] = %+v, want an extract-error named after the archive", got)
	}
}

func TestRealSevenZip_trailingBytesAreAnAnomaly(t *testing.T) {
	ex, err := realPlugin(t).ExtractFile(fixture(t, "trailing.7z"), t.TempDir(), openLimits)
	if !errors.Is(err, plugins.ErrArchiveAnomaly) {
		t.Fatalf("ExtractFile() error = %v, want an anomaly: data hides after the archive", err)
	}
	if !errors.Is(err, plugins.ErrEncryptionPossible) {
		t.Errorf("ExtractFile() error = %v: data after the archive can be another archive, the encryption is possible", err)
	}
	if ex.SkippedCount != 1 || len(ex.Skipped) != 1 || ex.Skipped[0].Reason != datamodel.NotAnalyzedExtractError || ex.Skipped[0].FileName != "trailing.7z" {
		t.Errorf("Extraction = %+v, want an extract-error entry named trailing.7z: data hides after the archive", ex)
	}
	if len(ex.Files) != 3 {
		t.Errorf("Files = %v, want the members still extracted", baseNames(ex.Files))
	}
}

// realSevenZipForBench is the embedded 7-Zip copied where it can run.
func realSevenZipForBench(b *testing.B) *sevenZipExtract {
	b.Helper()
	bin := filepath.Join(b.TempDir(), "7zzs")
	if err := os.WriteFile(bin, SevenZip, 0o600); err != nil {
		b.Fatal(err)
	}
	if err := os.Chmod(bin, modeScript); err != nil {
		b.Fatal(err)
	}
	return &sevenZipExtract{sevenZipPath: bin, logger: slog.New(slog.DiscardHandler)}
}
