package main

import (
	"archive/zip"
	"bytes"
	le "encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

func paddedDocx(t *testing.T, extra int) string {
	t.Helper()
	return writeTemp(t, paddedDocxBytes(t, extra))
}

func writeTemp(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "padded.docx")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func paddedDocxBytes(t *testing.T, extra int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := make([]string, 0, 3+extra)
	names = append(names, "[Content_Types].xml", "_rels/.rels", "word/document.xml")
	for i := range extra {
		names = append(names, fmt.Sprintf("pad/%05d", i))
	}
	for _, name := range names {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if name == "[Content_Types].xml" {
			if _, err = w.Write([]byte(`<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>`)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestCheckOnly_aListingOverTheBudgetGivesEveryMemberBackAsSkipped(t *testing.T) {
	plugin := realPlugin(t)
	tests := []struct {
		name      string
		extra     int
		maxFiles  int
		wantCount int
		wantListN int
		wantEmpty bool
		wantNames bool
	}{
		{"one over the budget", 7, 9, 10, 10, false, true},
		{"within the budget", 7, 10, 0, 0, true, false},
		{"a budget of zero", 0, 0, 3, 3, false, true},
		{"over the listing cap", datamodel.MaxListedSubfiles + 50, 10, datamodel.MaxListedSubfiles + 53, datamodel.MaxListedSubfiles, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archive := paddedDocx(t, tt.extra)
			got, err := plugin.ExtractFile(archive, t.TempDir(), plugins.ExtractLimits{MaxFiles: tt.maxFiles, MaxTotalSize: 1 << 30, CheckOnly: true})
			if err != nil {
				t.Fatalf("ExtractFile() error = %v", err)
			}
			if tt.wantEmpty {
				if len(got.Skipped) != 0 || got.SkippedCount != 0 {
					t.Errorf("extraction = %+v, want empty", got)
				}
				return
			}
			if got.SkippedCount != tt.wantCount || len(got.Skipped) != tt.wantListN {
				t.Errorf("SkippedCount = %d, listed = %d, want %d and %d", got.SkippedCount, len(got.Skipped), tt.wantCount, tt.wantListN)
			}
			for _, f := range got.Skipped {
				if f.Reason != datamodel.NotAnalyzedExtractLimit {
					t.Errorf("%q has reason %q, want extract-limit", f.FileName, f.Reason)
				}
			}
			if tt.wantNames {
				listed := map[string]bool{}
				for _, f := range got.Skipped {
					listed[f.FileName] = true
				}
				for _, name := range []string{"[Content_Types].xml", "word/document.xml"} {
					if !listed[name] {
						t.Errorf("%q is a member of the document and is not listed: %v", name, got.Skipped)
					}
				}
			}
		})
	}
}

func TestOverBudgetExtraction_isBoundedAndExact(t *testing.T) {
	within := make([]string, datamodel.MaxListedSubfiles-1)
	for i := range within {
		within[i] = fmt.Sprint("w", i)
	}
	within[0] = strings.Repeat("n", 2*datamodel.MaxListedNameLen)
	result := extractResult{withinBudget: within}
	result.skipped.add("s0", 12, datamodel.NotAnalyzedExtractLimit)
	result.skipped.add("s1", 12, datamodel.NotAnalyzedExtractLimit)
	got := overBudgetExtraction(result)
	if len(got.Skipped) != datamodel.MaxListedSubfiles || got.SkippedCount != datamodel.MaxListedSubfiles+1 {
		t.Fatalf("listed = %d, count = %d", len(got.Skipped), got.SkippedCount)
	}
	if name := got.Skipped[0].FileName; len(name) > datamodel.MaxListedNameLen+len("…")*3 {
		t.Errorf("a name of %d bytes within the budget is listed whole, want it cut", len(name))
	}
	if last := got.Skipped[len(got.Skipped)-1]; last.FileName != "s0" || last.Size != 12 {
		t.Errorf("last = %+v, want the first skipped member, with its size", last)
	}
	result.skipped.count = datamodel.MaxFileCount
	if got = overBudgetExtraction(result); got.SkippedCount != datamodel.MaxFileCount {
		t.Errorf("count = %d, want it saturated at %d", got.SkippedCount, datamodel.MaxFileCount)
	}
}

// The padding of T48's bypass: a document padded past the limits with one
// encrypted member is encrypted, not delivered; without that member it is.
func TestCheckOnly_aPaddedDocumentWithAnEncryptedMemberIsEncrypted(t *testing.T) {
	plugin := realPlugin(t)
	limits := plugins.ExtractLimits{MaxFiles: 10000, MaxTotalSize: 1 << 30, CheckOnly: true}
	plain := paddedDocxBytes(t, 10001)
	for _, method := range []string{"ZipCrypto", "AES256"} {
		t.Run(method, func(t *testing.T) {
			archive := writeTemp(t, withEncryptedMember(t, plain, method))
			_, err := plugin.ExtractFile(archive, t.TempDir(), limits)
			if !errors.Is(err, plugins.ErrEncrypted) {
				t.Fatalf("ExtractFile() error = %v, want ErrEncrypted", err)
			}
		})
	}
	t.Run("without the encrypted member", func(t *testing.T) {
		got, err := plugin.ExtractFile(writeTemp(t, plain), t.TempDir(), limits)
		if err != nil || got.SkippedCount != 10004 || len(got.Skipped) != datamodel.MaxListedSubfiles {
			t.Fatalf("ExtractFile() = %d skipped, %d listed, %v, want 10004, %d and no error", got.SkippedCount, len(got.Skipped), err, datamodel.MaxListedSubfiles)
		}
	})
}

// clearBothEncryptionBits clears bit 0 of the flags of every local header and of
// every central directory header: the archive then says nowhere that a member is
// encrypted.
func clearBothEncryptionBits(b []byte) []byte {
	out := bytes.Clone(b)
	for i := 0; i+12 <= len(out); i++ {
		switch {
		case bytes.Equal(out[i:i+4], []byte("PK\x03\x04")):
			le.LittleEndian.PutUint16(out[i+6:], le.LittleEndian.Uint16(out[i+6:])&^1)
		case bytes.Equal(out[i:i+4], []byte("PK\x01\x02")):
			le.LittleEndian.PutUint16(out[i+8:], le.LittleEndian.Uint16(out[i+8:])&^1)
		}
	}
	return out
}

// With the flag cleared in both headers, 7-Zip still names the AES method of the
// member, which is read as encrypted. ZipCrypto has no such mark: it is the
// documented residual risk, and it is pinned so that a change is noticed.
func TestCheckOnly_anEncryptedMemberWithItsFlagClearedInBothHeadersOverTheBudget(t *testing.T) {
	plugin := realPlugin(t)
	limits := plugins.ExtractLimits{MaxFiles: 10000, MaxTotalSize: 1 << 30, CheckOnly: true}
	plain := paddedDocxBytes(t, 10001)
	t.Run("AES256 is held as encrypted", func(t *testing.T) {
		archive := writeTemp(t, clearBothEncryptionBits(withEncryptedMember(t, plain, "AES256")))
		if _, err := plugin.ExtractFile(archive, t.TempDir(), limits); !errors.Is(err, plugins.ErrEncrypted) {
			t.Fatalf("ExtractFile() error = %v, want ErrEncrypted", err)
		}
	})
	t.Run("ZipCrypto stays an accepted risk", func(t *testing.T) {
		archive := writeTemp(t, clearBothEncryptionBits(withEncryptedMember(t, plain, "ZipCrypto")))
		got, err := plugin.ExtractFile(archive, t.TempDir(), limits)
		if err != nil || got.SkippedCount != 10005 {
			t.Fatalf("ExtractFile() = %d skipped, %v: the residual risk is documented as delivered", got.SkippedCount, err)
		}
	})
}

// The startup proof reads the technical listing of its reference archive: with the
// AES rule it must still say that every member is plain.
func TestProve_theReferenceArchiveStillReadsAsPlain(t *testing.T) {
	if err := prove(realPlugin(t).sze, t.TempDir()); err != nil {
		t.Fatalf("prove() error = %v", err)
	}
}

// A 7z archive that 7-Zip encrypts itself says Encrypted = + for its members, as
// before the AES rule: over the budget it is encrypted.
func TestCheckOnly_aSevenZipEncryptedByItselfIsEncryptedOverTheBudget(t *testing.T) {
	plugin := realPlugin(t)
	dir := t.TempDir()
	files := make([]string, 0, 3)
	for i := range 3 {
		f := filepath.Join(dir, fmt.Sprintf("f%d.txt", i))
		if err := os.WriteFile(f, []byte(fmt.Sprintf("member %d", i)), 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	archive := filepath.Join(t.TempDir(), "enc.7z")
	args := append([]string{"a", "-t7z", "-psecret-pw", archive}, files...)
	if out, err := runCmd(t.Context(), plugin.sze.sevenZipPath, args...); err != nil {
		t.Fatalf("cannot build the archive: %v %s", err, out)
	}
	_, err := plugin.ExtractFile(archive, t.TempDir(), plugins.ExtractLimits{MaxFiles: 1, MaxTotalSize: 1 << 30, CheckOnly: true})
	if !errors.Is(err, plugins.ErrEncrypted) {
		t.Fatalf("ExtractFile() error = %v, want ErrEncrypted", err)
	}
}
