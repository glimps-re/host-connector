package main

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

type zipMember struct {
	name    string
	data    string
	symlink bool
}

// writeZip writes a stored (uncompressed) zip with the members, in order. Two
// members may share a name.
func writeZip(t *testing.T, path string, comment string, members ...zipMember) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, m := range members {
		hdr := &zip.FileHeader{Name: m.name, Method: zip.Store}
		hdr.SetMode(0o644)
		if m.symlink {
			hdr.SetMode(os.ModeSymlink | 0o777)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(m.data)); err != nil {
			t.Fatal(err)
		}
	}
	if comment != "" {
		if err := zw.SetComment(comment); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// corruptPayload changes a byte of a stored member's data: its CRC fails.
func corruptPayload(t *testing.T, path, marker string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(b, []byte(marker)) != 1 {
		t.Fatalf("marker %q must appear once in the archive", marker)
	}
	b = bytes.Replace(b, []byte(marker), []byte(marker[:len(marker)-1]+"#"), 1)
	rewriteFile(t, path, b)
}

// rewriteFile replaces the content of an existing test file.
func rewriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := root.Close(); e != nil {
			t.Error(e)
		}
	}()
	if err := root.WriteFile(filepath.Base(path), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func requireAnomaly(t *testing.T, ex plugins.Extraction, err error, archive string) {
	t.Helper()
	if !errors.Is(err, plugins.ErrArchiveAnomaly) {
		t.Fatalf("ExtractFile() error = %v, want plugins.ErrArchiveAnomaly", err)
	}
	if len(ex.Skipped) == 0 || ex.Skipped[0].Reason != datamodel.NotAnalyzedExtractError || ex.Skipped[0].FileName != filepath.Base(archive) {
		t.Fatalf("Extraction = %+v, want an extract-error entry named %s for the report", ex, filepath.Base(archive))
	}
}

// requireDamaged accepts what a damaged archive gives: an anomaly, or a failure
// told from those of the extractor.
func requireDamaged(t *testing.T, ex plugins.Extraction, err error, archive string) {
	t.Helper()
	if errors.Is(err, plugins.ErrArchiveAnomaly) && len(ex.Skipped) > 0 {
		requireAnomaly(t, ex, err, archive)
		return
	}
	requireFailure(t, err)
}

func requireFailure(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("ExtractFile() error = nil, want a failure")
	}
	for _, bad := range []error{plugins.ErrUnsupportedFormat, plugins.ErrEncrypted, plugins.ErrExtractorUnavailable} {
		if errors.Is(err, bad) {
			t.Fatalf("ExtractFile() error = %v, must not be %v", err, bad)
		}
	}
	if !errors.Is(err, plugins.ErrArchiveAnomaly) {
		t.Fatalf("ExtractFile() error = %v, want plugins.ErrArchiveAnomaly: a damaged archive is told from a failure of the extractor", err)
	}
}

func TestRealSevenZip_twinWithAndWithoutADangerousLink(t *testing.T) {
	twin := []zipMember{{name: "a.txt", data: "A"}, {name: "evil_.exe", data: "E"}, {name: "evil\n.exe", data: "HIDDEN"}}
	link := zipMember{name: "link", data: "/etc/passwd", symlink: true}
	tests := map[string][]zipMember{
		"twin alone":                    twin,
		"twin with a dangerous link":    append([]zipMember{link}, twin...),
		"twin with the link after it":   append(append([]zipMember{}, twin...), link),
		"twin with two dangerous links": append([]zipMember{link, {name: "link2", data: "/etc/shadow", symlink: true}}, twin...),
	}
	for name, members := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "twin.zip")
			writeZip(t, path, "", members...)
			ex, err := realPlugin(t).ExtractFile(path, t.TempDir(), openLimits)
			requireAnomaly(t, ex, err, path)
		})
	}
}

func TestRealSevenZip_dangerousLinkAloneIsNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "link.zip")
	writeZip(t, path, "", zipMember{name: "a.txt", data: "A"}, zipMember{name: "link", data: "/etc/passwd", symlink: true}, zipMember{name: "b.txt", data: "B"})
	out := t.TempDir()
	ex, err := realPlugin(t).ExtractFile(path, out, openLimits)
	if err != nil || ex.SkippedCount != 0 {
		t.Fatalf("ExtractFile() = %+v, %v, want a clean extraction", ex, err)
	}
	if got := baseNames(ex.Files); len(got) != 2 {
		t.Errorf("files = %v, want a.txt and b.txt only: the empty placeholder of the link must be gone", got)
	}
	if _, statErr := os.Lstat(filepath.Join(out, "link")); statErr == nil {
		t.Error("the placeholder of the refused link is still there")
	}
}

func TestRealSevenZip_corruptMemberWithADangerousLinkIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crc.zip")
	writeZip(t, path, "", zipMember{name: "link", data: "/etc/passwd", symlink: true}, zipMember{name: "b.txt", data: "PAYLOADPAYLOAD"})
	corruptPayload(t, path, "PAYLOADPAYLOAD")
	ex, err := realPlugin(t).ExtractFile(path, t.TempDir(), openLimits)
	requireDamaged(t, ex, err, path)
}

func TestRealSevenZip_memberNamesLikeErrorMessagesDoNotSteerTheClassification(t *testing.T) {
	names := []string{"Dangerous link path was ignored", "Cannot open the file as archive", "Wrong password", "Is not archive", "Unexpected end of archive"}
	for _, withControl := range []bool{false, true} {
		for _, name := range names {
			t.Run(strings.ReplaceAll(name, " ", "_")+map[bool]string{true: "+ctrl", false: ""}[withControl], func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "inj.zip")
				members := []zipMember{{name: "ok.txt", data: "fine"}, {name: name, data: "PAYLOADPAYLOAD"}}
				if withControl {
					members = append(members, zipMember{name: "x\x1b[31m.txt", data: "ctl"})
				}
				writeZip(t, path, "", members...)
				corruptPayload(t, path, "PAYLOADPAYLOAD")
				ex, err := realPlugin(t).ExtractFile(path, t.TempDir(), openLimits)
				requireDamaged(t, ex, err, path)
			})
		}
	}
}

func TestRealSevenZip_memberNameWithAnInjectedErrorLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inject.zip")
	writeZip(t, path, "", zipMember{name: "x\nERROR: Wrong password : y", data: "PAYLOADPAYLOAD"}, zipMember{name: "ok.txt", data: "fine"})
	corruptPayload(t, path, "PAYLOADPAYLOAD")
	ex, err := realPlugin(t).ExtractFile(path, t.TempDir(), openLimits)
	requireDamaged(t, ex, err, path)
}

func TestRealSevenZip_archiveNamedLikeAnErrorMessage(t *testing.T) {
	for _, name := range []string{"Wrong password.zip", "Cannot open the file as archive.zip", "Dangerous link path was ignored.zip"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			writeZip(t, path, "", zipMember{name: "a.txt", data: "PAYLOADPAYLOAD"})
			corruptPayload(t, path, "PAYLOADPAYLOAD")
			ex, err := realPlugin(t).ExtractFile(path, t.TempDir(), openLimits)
			requireDamaged(t, ex, err, path)
		})
	}
}

func TestRealSevenZip_commentForgingAMemberTableIsAnAnomaly(t *testing.T) {
	fake := "x\n" + szFileListHeader1 + "\n" + szFileListHeader2 + "\n2026-11-19 14:27:56 .....           10           10  a.txt\n" + szFileListFooter + "\n"
	path := filepath.Join(t.TempDir(), "cmt.zip")
	writeZip(t, path, fake, zipMember{name: "a.txt", data: "AAAAAAAAAA"}, zipMember{name: "evil.exe", data: "MALWARE"})
	ex, err := realPlugin(t).ExtractFile(path, t.TempDir(), openLimits)
	requireAnomaly(t, ex, err, path)
}

func TestRealSevenZip_skippedMemberWithTheNameOfASelectedOne(t *testing.T) {
	big := strings.Repeat("0", 3<<20)
	orders := map[string][]zipMember{
		"small first": {{name: "a.txt", data: "A"}, {name: "big.bin", data: "small one"}, {name: "big.bin", data: big}, {name: "evil\n.exe", data: "HIDDEN"}},
		"big first":   {{name: "a.txt", data: "A"}, {name: "big.bin", data: big}, {name: "big.bin", data: "small one"}, {name: "evil\n.exe", data: "HIDDEN"}},
	}
	for name, members := range orders {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "dup.zip")
			writeZip(t, path, "", members...)
			ex, err := realPlugin(t).ExtractFile(path, t.TempDir(), openLimits)
			requireAnomaly(t, ex, err, path)
		})
	}
}

func TestRealSevenZip_everyMemberOverTheLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.zip")
	writeZip(t, path, "", zipMember{name: "a.bin", data: strings.Repeat("0", 2<<20)}, zipMember{name: "b.bin", data: strings.Repeat("1", 2<<20)})
	ex, err := realPlugin(t).ExtractFile(path, t.TempDir(), openLimits)
	if err != nil || len(ex.Files) != 0 || ex.SkippedCount != 2 {
		t.Errorf("Extraction = %+v, %v, want nothing extracted and both members skipped", ex, err)
	}
}

func TestRealSevenZip_memberNameLongerThanAnyPathIsAnAnomaly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "long.zip")
	writeZip(t, path, "", zipMember{name: "a.txt", data: "A"}, zipMember{name: strings.Repeat("n", maxMemberNameLen+10), data: "B"})
	ex, err := realPlugin(t).ExtractFile(path, t.TempDir(), openLimits)
	requireDamaged(t, ex, err, path)
}

func TestRealSevenZip_manyLongNamesAreBatched(t *testing.T) {
	members := make([]zipMember, 0, 120)
	for i := range 120 {
		members = append(members, zipMember{name: strings.Repeat(strings.Repeat("d", 200)+"/", 14) + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".txt", data: "x"})
	}
	path := filepath.Join(t.TempDir(), "names.zip")
	writeZip(t, path, "", members...)
	limits := plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 1000, MaxTotalSize: 1 << 30}
	plugin := realPlugin(t)
	ex, err := plugin.ExtractFile(path, t.TempDir(), limits)
	if err != nil || len(ex.Files) != 120 || ex.SkippedCount != 0 {
		t.Errorf("Extraction = %d files, %d skipped, %v, want the 120 members", len(ex.Files), ex.SkippedCount, err)
	}
}

func TestRealSevenZip_truncatedArchivesAreErrorsNotPlainFiles(t *testing.T) {
	plugin := realPlugin(t)
	for _, format := range []string{"7z", "zip"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			data := filepath.Join(dir, "data.bin")
			if err := os.WriteFile(data, []byte(strings.Repeat("payload-", 400)), 0o600); err != nil {
				t.Fatal(err)
			}
			full := filepath.Join(dir, "full."+format)
			if out, err := runCmd(t.Context(), plugin.sze.sevenZipPath, "a", full, data); err != nil {
				t.Fatalf("cannot build the archive: %v %s", err, out)
			}
			raw, err := os.ReadFile(filepath.Clean(full))
			if err != nil {
				t.Fatal(err)
			}
			cut := filepath.Join(dir, "cut."+format)
			rewriteFile(t, cut, raw[:len(raw)*2/3])
			ex, err := plugin.ExtractFile(cut, t.TempDir(), openLimits)
			// A cut zip still lists, 7z only says "Errors: 1" and exits with 2: either
			// an anomaly entry or a failure, both end as an extract-error in the core.
			requireDamaged(t, ex, err, cut)
		})
	}
}

// A document that declares gigabytes in a few bytes is a bomb, whatever budget is
// left: a smaller budget must not turn it into a document that is merely left out.
func TestRealSevenZip_aBombIsAnAnomalyWhateverTheBudgetLeft(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bomb.docx")
	f, err := os.Create(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("[Content_Types].xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("<x/>")); err != nil {
		t.Fatal(err)
	}
	var packed bytes.Buffer
	fw, err := flate.NewWriter(&packed, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fw.Write(make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	if err = fw.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := zw.CreateRaw(&zip.FileHeader{Name: "word/media/zeros.bin", Method: zip.Deflate, CompressedSize64: uint64(max(packed.Len(), 0)), UncompressedSize64: 4 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Write(packed.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err = errors.Join(zw.Close(), f.Close()); err != nil {
		t.Fatal(err)
	}
	for _, total := range []int64{1 << 30, 10 << 30} {
		_, err = realPlugin(t).ExtractFile(path, t.TempDir(), plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100, MaxTotalSize: total, CheckOnly: true})
		if !errors.Is(err, plugins.ErrArchiveAnomaly) {
			t.Errorf("budget %d: error = %v, want the bomb to be an anomaly", total, err)
		}
	}
}

// runCmd runs a command to build test archives with the embedded 7-Zip.
func runCmd(ctx context.Context, bin string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput() //nolint:gosec // test helper running the test binary
	return string(out), err
}

func TestRealSevenZip_aCheckOverTheBudgetLeavesMembersOutInsteadOfDamage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "five.zip")
	members := make([]zipMember, 0, 5)
	for i := range 5 {
		members = append(members, zipMember{name: strings.Repeat("m", i+1) + ".txt", data: "x"})
	}
	writeZip(t, path, "", members...)
	plugin := realPlugin(t)
	ex, err := plugin.ExtractFile(path, t.TempDir(), plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 2, MaxTotalSize: 1 << 30, CheckOnly: true})
	if err != nil || ex.SkippedCount == 0 {
		t.Errorf("Extraction = %+v, %v, want no error and members left out for the budget", ex, err)
	}
	within, err := plugin.ExtractFile(path, t.TempDir(), plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 10, MaxTotalSize: 1 << 30, CheckOnly: true})
	if err != nil || within.SkippedCount != 0 {
		t.Errorf("Extraction = %+v, %v, want a clean check within the budget", within, err)
	}
	writeZip(t, path, "", append(members, zipMember{name: strings.Repeat("n", maxMemberNameLen+10), data: "y"})...)
	if _, err = plugin.ExtractFile(path, t.TempDir(), plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 2, MaxTotalSize: 1 << 30, CheckOnly: true}); !errors.Is(err, plugins.ErrArchiveAnomaly) {
		t.Errorf("error = %v, want the anomaly to win over a budget that is exceeded too", err)
	}
}
