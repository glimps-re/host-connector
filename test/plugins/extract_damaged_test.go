//go:build linux && (e2e || e2e_plugins)

package plugins

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	le "encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// errDamagedText is the error a file held as a damaged archive is reported with.
const errDamagedText = "damaged or inconsistent"

// storedZip is a zip of members stored without compression.
func storedZip(t *testing.T, members map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range members {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func cut(raw []byte, percent int) []byte {
	return raw[:len(raw)*percent/100]
}

func concat(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

// clearLocalEncryptionBit clears bit 0 of the flags of every local header: the
// archive then says in its local headers that no member is encrypted.
func clearLocalEncryptionBit(t *testing.T, raw []byte) []byte {
	t.Helper()
	out := bytes.Clone(raw)
	cleared := 0
	for i := 0; i+8 <= len(out); i++ {
		if bytes.Equal(out[i:i+4], []byte("PK\x03\x04")) {
			le.LittleEndian.PutUint16(out[i+6:], le.LittleEndian.Uint16(out[i+6:])&^1)
			cleared++
		}
	}
	if cleared == 0 {
		t.Fatal("no local header found")
	}
	return out
}

// damagedPlainZip is a plain stored zip with a byte of a member flipped.
func damagedPlainZip(t *testing.T) []byte {
	t.Helper()
	b := storedZip(t, map[string]string{"a.txt": "PAYLOADPAYLOADPAYLOAD", "b.txt": "second member"})
	i := bytes.Index(b, []byte("PAYLOADPAYLOADPAYLOAD"))
	if i < 0 {
		t.Fatal("payload not found")
	}
	b[i+3] ^= 0xff
	return b
}

// maxMemberNameLen is the longest member name the extract plugin extracts.
const maxMemberNameLen = 4096

// maxMemberDepth is the deepest member path the extract plugin extracts.
const maxMemberDepth = 64

// folderDataZip is a zip whose second entry, evil.exe, is a folder (DOS
// attribute) that holds data.
func folderDataZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	data := []byte("0123456789")
	for _, e := range []struct {
		name  string
		attrs uint32
	}{{"a.txt", 0}, {"evil.exe", 0x10}} {
		w, err := zw.CreateRaw(&zip.FileHeader{
			Name: e.name, Method: zip.Store, ReaderVersion: 20, ExternalAttrs: e.attrs, CRC32: crc32.ChecksumIEEE(data),
			CompressedSize64: uint64(len(data)), UncompressedSize64: uint64(len(data)),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// slashFolderZip is a zip whose second entry is a file with data named with a
// trailing slash: 7-Zip lists it as a folder.
func slashFolderZip() []byte {
	return rawZip{entries: []rawEntry{{name: "a.txt", data: "0123456789"}, {name: "evil.exe/", data: "0123456789"}}}.bytes()
}

// folderDataTar is a tar whose second entry, evil.exe, is a directory that holds
// data.
func folderDataTar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range []string{"a.txt", "evil.exe"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: 10, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte("0123456789")); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	const block = 512
	header := raw[2*block : 3*block]
	header[156] = tar.TypeDir
	copy(header[148:156], "        ")
	sum := 0
	for _, b := range header {
		sum += int(b)
	}
	copy(header[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return raw
}

// sevenZipOf builds an archive of the format with the embedded 7-Zip from the
// members, written in a folder of their own.
func sevenZipOf(t *testing.T, format string, members map[string][]byte) []byte {
	t.Helper()
	bin := sevenZip(t)
	src := t.TempDir()
	names := make([]string, 0, len(members))
	for name, content := range members {
		harness.Write(t, filepath.Join(src, name), content)
		names = append(names, name)
	}
	// 7-Zip adds its extension to a name that has none.
	archive := filepath.Join(t.TempDir(), "archive."+format)
	if out, err := harness.RunCommand(src, bin, append([]string{"a", "-t" + format, archive}, names...)...); err != nil {
		t.Fatalf("cannot build the archive: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(filepath.Clean(archive))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// From TestPipeline_theDefaultPolicyKeepsEveryDamagedArchiveInInput: under extract_error error, a damaged archive is never delivered as a plain file.
func TestE2E_theDefaultPolicyKeepsEveryDamagedArchiveInInput(t *testing.T) {
	t.Parallel()
	stored := storedZip(t, map[string]string{"a.txt": "plain member"})
	zipCrypto := fixtureOf(t, "enc_zipcrypto.zip")
	headers := fixtureOf(t, "enc_headers.7z")
	content := fixtureOf(t, "enc_content.7z")
	damaged := harness.Outcome{In: harness.Input, Error: errDamagedText}
	encrypted := harness.Outcome{In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedEncrypted}
	tests := []struct {
		path    string
		content []byte
		want    harness.Outcome
	}{
		{path: "homonym_mixed.7z", content: fixtureOf(t, "homonym_mixed.7z"), want: damaged},
		{path: "zc_collision.zip", content: fixtureOf(t, "zc_collision.zip"), want: damaged},
		{path: "aes_one_corrupt.zip", content: fixtureOf(t, "aes_one_corrupt.zip"), want: damaged},
		{path: "bit0.zip", content: clearLocalEncryptionBit(t, zipCrypto), want: damaged},
		{path: "damaged.zip", content: damagedPlainZip(t), want: damaged},
		{path: "cut50-enc_headers.7z", content: cut(headers, 50), want: damaged},
		{path: "cut90-enc_headers.7z", content: cut(headers, 90), want: damaged},
		{path: "cut25-enc_content.7z", content: cut(content, 25), want: damaged},
		{path: "cut50-enc_content.7z", content: cut(content, 50), want: damaged},
		{path: "cut90-enc_content.7z", content: cut(content, 90), want: damaged},
		{path: "cut66-enc_zipcrypto.zip", content: cut(zipCrypto, 66), want: encrypted},
		{path: "plain_then_enc7.zip", content: concat(stored, content), want: damaged},
		{path: "plain_then_aes.zip", content: concat(stored, fixtureOf(t, "enc_aes.zip")), want: damaged},
		{path: "plain_then_zc.zip", content: concat(stored, zipCrypto), want: damaged},
		{path: "longname.zip", content: storedZip(t, map[string]string{"a.txt": "plain member", strings.Repeat("n", maxMemberNameLen+10): "plain too"}), want: damaged},
		{path: "longcomponent.zip", content: storedZip(t, map[string]string{"a.txt": "plain member", "d/" + strings.Repeat("x", 300) + ".exe": "left out"}), want: damaged},
		{path: "deep.zip", content: storedZip(t, map[string]string{"a.txt": "plain member", strings.Repeat("f/", maxMemberDepth) + "deep.exe": "left out"}), want: damaged},
		{path: "folderdata.zip", content: folderDataZip(t), want: damaged},
		{path: "slashfolder.zip", content: slashFolderZip(), want: damaged},
		{path: "folderdata.tar", content: folderDataTar(t), want: damaged},
		{path: "plain7_then_enc7.7z", content: concat(sevenZipOf(t, "7z", map[string][]byte{"a.txt": []byte("plain member")}), content), want: damaged},
		{path: "trailing.zip", content: concat(storedZip(t, map[string]string{"a.txt": "first member", "b.txt": "second member"}), []byte("DATA AFTER THE END OF THE ARCHIVE")), want: damaged},
	}
	s := harness.Scenario{
		Plugins: map[string]map[string]any{"extract": nil},
		Config:  map[string]any{"unanalyzable_policy": map[string]any{"encrypted": "pass"}},
		Want:    map[string]harness.Outcome{},
	}
	for _, tt := range tests {
		s.Files = append(s.Files, harness.File{Path: tt.path, Content: tt.content})
		s.Want[tt.path] = tt.want
	}
	t.Run("every damaged archive", func(t *testing.T) {
		harness.Run(t, s)
	})
}

// From TestPipeline_asFileDeliversAStructuralAnomalyMarkedExtractError: under as_file an archive whose members were all extracted despite an anomaly is delivered marked extract-error.
func TestE2E_asFileDeliversAStructuralAnomalyMarkedExtractError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		content []byte
		want    harness.Outcome
	}{
		{
			name:    "a control character in a member name",
			content: storedZip(t, map[string]string{"a\x01b.txt": "first member", "ok.txt": "second member"}),
			want:    harness.Outcome{In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedExtractError},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  map[string]any{"unanalyzable_policy": map[string]any{"extract_error": "as_file"}},
				Files:   []harness.File{{Path: "control.zip", Content: tt.content}},
				Want:    map[string]harness.Outcome{"control.zip": tt.want},
			})
		})
	}
}

// twinNamesZip is a zip of two plain members with the same name.
func twinNamesZip(t *testing.T, first, second []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, content := range [][]byte{first, second} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: "twin.txt", Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// From TestPipeline_twinNamesWithPlainMembersAreExtractedBothAndAreNoAnomaly: 7-Zip extracts both twins, so the archive is analyzed as usual.
func TestE2E_twinNamesWithPlainMembersAreExtractedBothAndAreNoAnomaly(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		first, second []byte
		want          harness.Outcome
	}{
		{name: "two members named twin.txt", first: []byte("first twin"), second: []byte("second twin"), want: harness.Outcome{In: harness.Output}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  map[string]any{"unanalyzable_policy": map[string]any{"extract_error": "as_file"}},
				Files: []harness.File{{Path: "twins.zip", Content: twinNamesZip(t, tt.first, tt.second), Members: []harness.File{
					{Path: "twin.txt", Content: tt.first},
					{Path: "twin.txt", Content: tt.second},
				}}},
				Want: map[string]harness.Outcome{"twins.zip": tt.want},
			})
			for _, twin := range [][]byte{tt.first, tt.second} {
				if names := in.NamesOf(t, twin); len(names) != 1 {
					t.Errorf("%q submitted %d times, want once", twin, len(names))
				}
			}
		})
	}
}

// From TestTruncatedZipIsNeverAPlainFile: a zip cut before its central directory is never a plain file.
func TestE2E_aTruncatedZipIsNeverAPlainFile(t *testing.T) {
	t.Parallel()
	damaged := harness.Outcome{In: harness.Input, Error: errDamagedText}
	encrypted := harness.Outcome{In: harness.Input, Error: errEncryptedText}
	passed := harness.Outcome{In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedEncrypted}
	tests := []struct {
		fixture                  string
		percent                  int
		byDefault, passAndAsFile harness.Outcome
	}{
		{fixture: "enc_aes.zip", percent: 10, byDefault: damaged, passAndAsFile: passed},
		{fixture: "enc_aes.zip", percent: 20, byDefault: encrypted, passAndAsFile: passed},
		{fixture: "enc_aes.zip", percent: 50, byDefault: encrypted, passAndAsFile: passed},
		{fixture: "enc_aes.zip", percent: 90, byDefault: encrypted, passAndAsFile: passed},
		{fixture: "enc_zipcrypto.zip", percent: 10, byDefault: damaged, passAndAsFile: passed},
		{fixture: "enc_zipcrypto.zip", percent: 20, byDefault: encrypted, passAndAsFile: passed},
		{fixture: "enc_zipcrypto.zip", percent: 50, byDefault: encrypted, passAndAsFile: passed},
		{fixture: "enc_zipcrypto.zip", percent: 90, byDefault: encrypted, passAndAsFile: passed},
		{fixture: "known_password.zip", percent: 10, byDefault: damaged, passAndAsFile: passed},
		{fixture: "known_password.zip", percent: 20, byDefault: damaged, passAndAsFile: passed},
		{fixture: "known_password.zip", percent: 50, byDefault: damaged, passAndAsFile: passed},
		{fixture: "known_password.zip", percent: 90, byDefault: damaged, passAndAsFile: passed},
		{fixture: "aes_one_corrupt.zip", percent: 10, byDefault: damaged, passAndAsFile: passed},
		{fixture: "aes_one_corrupt.zip", percent: 20, byDefault: damaged, passAndAsFile: passed},
		{fixture: "aes_one_corrupt.zip", percent: 50, byDefault: damaged, passAndAsFile: passed},
		{fixture: "aes_one_corrupt.zip", percent: 90, byDefault: damaged, passAndAsFile: passed},
	}
	for _, policy := range []string{"default", "pass and as_file"} {
		t.Run(policy, func(t *testing.T) {
			s := harness.Scenario{Plugins: map[string]map[string]any{"extract": nil}, Want: map[string]harness.Outcome{}}
			if policy != "default" {
				s.Config = map[string]any{"unanalyzable_policy": map[string]any{"encrypted": "pass", "extract_error": "as_file"}}
			}
			for _, tt := range tests {
				path := fmt.Sprintf("cut%d-%s", tt.percent, tt.fixture)
				s.Files = append(s.Files, harness.File{Path: path, Content: cut(fixtureOf(t, tt.fixture), tt.percent)})
				s.Want[path] = tt.byDefault
				if policy != "default" {
					s.Want[path] = tt.passAndAsFile
				}
			}
			harness.Run(t, s)
		})
	}
}

// From TestSevenZipWithAFlippedStartHeaderByteIsNeverAPlainFile: a 7z with a byte of its start header flipped is still a 7z.
func TestE2E_aSevenZipWithAFlippedStartHeaderByteIsNeverAPlainFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		fixture string
		want    harness.Outcome
	}{
		{fixture: "enc_headers.7z", want: harness.Outcome{In: harness.Input, Error: errDamagedText}},
		{fixture: "enc_content.7z", want: harness.Outcome{In: harness.Input, Error: errDamagedText}},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			s := harness.Scenario{Plugins: map[string]map[string]any{"extract": nil}, Want: map[string]harness.Outcome{}}
			for off := 8; off <= 31; off++ {
				b := fixtureOf(t, tt.fixture)
				b[off] ^= 0x5a
				path := fmt.Sprintf("flip%d.7z", off)
				s.Files = append(s.Files, harness.File{Path: path, Content: b})
				s.Want[path] = tt.want
			}
			harness.Run(t, s)
		})
	}
}

func truncatedTar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := bytes.Repeat([]byte("member content "), 100)
	if err := tw.WriteHeader(&tar.Header{Name: "a.txt", Mode: 0o600, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()[:900]
}

func truncatedGzip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	data := make([]byte, 0, 100000)
	for i := range 100000 {
		data = append(data, byte(i*7+i/13))
	}
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()[:buf.Len()/2]
}

// compressedAndCut is a file of the 7-Zip format holding some bytes, cut in half.
func compressedAndCut(t *testing.T, format string) []byte {
	t.Helper()
	data := make([]byte, 0, 200000)
	for i := range 200000 {
		data = append(data, byte((i*31+i/7)&0xff))
	}
	return cut(sevenZipOf(t, format, map[string][]byte{"data.bin": data}), 50)
}

// From TestOtherTruncatedArchivesAreNeverPlainFiles: a gzip, a tar, a 7z, an xz or a bzip2 cut short stays in INPUT.
func TestE2E_otherTruncatedArchivesAreNeverPlainFiles(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path    string
		content []byte
		want    harness.Outcome
	}{
		{path: "cut.gz", content: truncatedGzip(t), want: harness.Outcome{In: harness.Input, Error: "left out by the limits of the extraction"}},
		{path: "cut.tar", content: truncatedTar(t), want: harness.Outcome{In: harness.Input, Error: errDamagedText}},
		{path: "cut.7z", content: cut(fixtureOf(t, "enc_content.7z"), 50), want: harness.Outcome{In: harness.Input, Error: errDamagedText}},
		// TODO(review): likely a bug pinned here. 7-Zip says "Unexpected end of data"
		// for a cut xz or bzip2, which recoverableLabels (cmd/plugins/extract/errors.go)
		// does not list: the failure stays unclassified, so it is retried at every
		// rescan with no report instead of being reported damaged.
		{path: "cut.xz", content: compressedAndCut(t, "xz"), want: harness.Outcome{In: harness.Input, NoReport: true}},
		{path: "cut.bz2", content: compressedAndCut(t, "bzip2"), want: harness.Outcome{In: harness.Input, NoReport: true}},
	}
	s := harness.Scenario{Plugins: map[string]map[string]any{"extract": nil}, Want: map[string]harness.Outcome{}}
	for _, tt := range tests {
		s.Files = append(s.Files, harness.File{Path: tt.path, Content: tt.content})
		s.Want[tt.path] = tt.want
	}
	t.Run("five cut archives", func(t *testing.T) {
		harness.Run(t, s)
	})
}

// From TestTruncatedZipNestedInARealArchiveIsNeverAPlainFile: a cut zip inside a zip or a 7z follows the rule too.
func TestE2E_aTruncatedZipNestedInARealArchiveIsNeverAPlainFile(t *testing.T) {
	t.Parallel()
	inner := map[string][]byte{"inner.zip": cut(fixtureOf(t, "enc_aes.zip"), 50)}
	tests := []struct {
		format string
		policy map[string]any
		want   harness.Outcome
	}{
		{format: "zip", policy: map[string]any{}, want: harness.Outcome{In: harness.Input, Error: "1 extracted file(s) in error, first: inner.zip: " + errEncryptedText}},
		{format: "7z", policy: map[string]any{}, want: harness.Outcome{In: harness.Input, Error: "1 extracted file(s) in error, first: inner.zip: " + errEncryptedText}},
		{format: "zip", policy: map[string]any{"encrypted": "pass", "extract_error": "as_file"}, want: harness.Outcome{In: harness.Output, NotAnalyzedMembers: &harness.MemberList{Reason: datamodel.NotAnalyzedEncrypted, Count: 1, Includes: "inner.zip"}}},
		{format: "7z", policy: map[string]any{"encrypted": "pass", "extract_error": "as_file"}, want: harness.Outcome{In: harness.Output, NotAnalyzedMembers: &harness.MemberList{Reason: datamodel.NotAnalyzedEncrypted, Count: 1, Includes: "inner.zip"}}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%v", tt.format, tt.policy), func(t *testing.T) {
			path := "outer." + tt.format
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  map[string]any{"unanalyzable_policy": tt.policy},
				Files:   []harness.File{{Path: path, Content: sevenZipOf(t, tt.format, inner), Members: []harness.File{{Path: "inner.zip", Content: inner["inner.zip"]}}}},
				Want:    map[string]harness.Outcome{path: tt.want},
			})
		})
	}
}

// From TestWhatIsNotTypedAsAnArchiveStaysAPlainFile: what 7-Zip refuses and is not typed as an archive is a plain file.
func TestE2E_whatIsNotTypedAsAnArchiveStaysAPlainFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path    string
		content []byte
		want    harness.Outcome
	}{
		{path: "image.png", content: append([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"), bytes.Repeat([]byte{0x01}, 200)...), want: harness.Outcome{In: harness.Output}},
		{path: "blob.bin", content: append([]byte{0x00, 0x01, 0x02, 0x03}, bytes.Repeat([]byte{0x9c, 0x17}, 300)...), want: harness.Outcome{In: harness.Output}},
	}
	s := harness.Scenario{
		Plugins: map[string]map[string]any{"extract": nil},
		Config:  map[string]any{"extract_min_size": "1B"},
		Want:    map[string]harness.Outcome{},
	}
	for _, tt := range tests {
		s.Files = append(s.Files, harness.File{Path: tt.path, Content: tt.content})
		s.Want[tt.path] = tt.want
	}
	t.Run("a png and a binary", func(t *testing.T) {
		harness.Run(t, s)
	})
}

// From TestATextThatStartsLikeAnArchiveStaysInInput: a text typed as an archive by its first bytes stays in INPUT.
func TestE2E_aTextThatStartsLikeAnArchiveStaysInInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path, content string
		want          harness.Outcome
	}{
		{path: "bzh.txt", content: "BZh9 is how this text starts, and nothing else", want: harness.Outcome{In: harness.Input, Error: errDamagedText}},
		{path: "pk.txt", content: "PK\x03\x04 and then only text that is no archive", want: harness.Outcome{In: harness.Input, Error: errDamagedText}},
		{path: "cpio.txt", content: "070707 and then only text that is no archive at all", want: harness.Outcome{In: harness.Input, Error: errDamagedText}},
	}
	s := harness.Scenario{Plugins: map[string]map[string]any{"extract": nil}, Want: map[string]harness.Outcome{}}
	for _, tt := range tests {
		s.Files = append(s.Files, harness.File{Path: tt.path, Content: []byte(tt.content)})
		s.Want[tt.path] = tt.want
	}
	t.Run("three texts", func(t *testing.T) {
		harness.Run(t, s)
	})
}
