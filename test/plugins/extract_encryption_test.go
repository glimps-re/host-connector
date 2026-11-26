//go:build linux && (e2e || e2e_plugins)

package plugins

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// p3/T62b: an over-limit document with one encrypted member is not delivered: it
// follows the encrypted policy (error by default) and stays in INPUT. The same
// document without the encrypted member is delivered in the same run.
func TestE2E_anOverLimitDocumentWithAnEncryptedMemberStaysInInput(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"docx", "jar", "apk"} {
		t.Run(kind, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Files: []harness.File{
					{Path: "secret." + kind, Content: bigDocument(t, kind, "secret "+kind, overLimitEntries, true)},
					{Path: "control." + kind, Content: bigDocument(t, kind, "control "+kind, overLimitEntries, false)},
				},
				Want: map[string]harness.Outcome{
					"secret." + kind:  {In: harness.Input, Error: errEncryptedText, NotAnalyzedMembers: harness.NoMembers()},
					"control." + kind: {In: harness.Output, NotAnalyzedMembers: &harness.MemberList{Reason: datamodel.NotAnalyzedExtractLimit}},
				},
			})
		})
	}
}

func seenMembers(unique string) (files []harness.File) {
	for n, content := range nestedMembers(unique) {
		files = append(files, harness.File{Path: paddingName(n), Content: content})
	}
	return files
}

// p3/T62b (F1): the budget a document gets is what its parent left. An outer zip
// of 9,999 plain files holding a document with an encrypted member leaves the
// document no budget: the outer archive is held in INPUT, never delivered.
// The same outer archive with a plain document is delivered, and the members
// of the document are listed as not analyzed.
func TestE2E_aDocumentInAFullArchiveIsCheckedForEncryption(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		secret, plain []byte
	}{
		{
			name:   "an encrypted and a plain document in an outer zip of 9,999 files",
			secret: outerWithDocument(t, "held", bigDocument(t, "docx", "held inner", 4, true)),
			plain:  outerWithDocument(t, "delivered", bigDocument(t, "docx", "delivered inner", 5, false)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Files: []harness.File{
					{Path: "secret.zip", Content: tt.secret},
					{Path: "plain.zip", Content: tt.plain, Members: seenMembers("delivered")},
				},
				Want: map[string]harness.Outcome{
					"secret.zip": {In: harness.Input, Error: errEncryptedText, NotAnalyzedMembers: harness.NoMembers()},
					"plain.zip":  {In: harness.Output, NotAnalyzedMembers: &harness.MemberList{Reason: datamodel.NotAnalyzedExtractLimit, Includes: "word/document.xml"}},
				},
			})
			if n := len(in.ReportsOf(t, tt.plain)); n != 1 {
				t.Errorf("%d report entries for the delivered outer archive, want 1", n)
			}
		})
	}
}

// errEncryptedText is the error a file held for its encryption is reported with.
const errEncryptedText = "file is encrypted and cannot be analyzed"

// p3/T62b: the encrypted verdict is what holds the document, not its size: with
// the encrypted policy at pass the same document is delivered, marked
// encrypted. Only a real encrypted outcome does that.
func TestE2E_anOverLimitEncryptedDocumentFollowsTheEncryptedPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "encrypted pass",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  map[string]any{"unanalyzable_policy": map[string]any{"encrypted": "pass"}},
				Files: []harness.File{
					{Path: "secret.docx", Content: bigDocument(t, "docx", "pass secret", overLimitEntries, true)},
				},
				Want: map[string]harness.Outcome{
					"secret.docx": {In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedEncrypted},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// p3/T62b (F1): same as above for a document in a full archive.
func TestE2E_anEncryptedDocumentInAFullArchiveFollowsTheEncryptedPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "encrypted pass",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  map[string]any{"unanalyzable_policy": map[string]any{"encrypted": "pass"}},
				Files: []harness.File{
					{Path: "secret.zip", Content: outerWithDocument(t, "pass nested", bigDocument(t, "docx", "pass nested inner", 4, true)), Members: seenMembers("pass nested")},
				},
				Want: map[string]harness.Outcome{
					"secret.zip": {In: harness.Output, NotAnalyzedMembers: &harness.MemberList{Reason: datamodel.NotAnalyzedEncrypted}},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// T17a: an encrypted archive follows the encrypted policy, at the top level and
// nested in a plain zip: error keeps it in INPUT, pass delivers it marked
// encrypted, mitigate quarantines it as encrypted. The fixtures are under
// extract_min_size: a small archive goes through the extraction too. Mirrors
// TestPipeline_realEncryptedArchivesFollowTheEncryptedPolicy,
// TestExtract_realPluginReportsEncryptedArchives and
// TestPipeline_realEncryptedArchiveNestedInAPlainZip.
func TestE2E_anEncryptedArchiveFollowsTheEncryptedPolicy(t *testing.T) {
	t.Parallel()
	zipCrypto := harness.File{Path: "enc_zipcrypto.zip", Content: fixtureOf(t, "enc_zipcrypto.zip")}
	aes := harness.File{Path: "enc_aes.zip", Content: fixtureOf(t, "enc_aes.zip")}
	sevenZ := harness.File{Path: "enc_headers.7z", Content: fixtureOf(t, "enc_headers.7z")}
	sevenZContent := harness.File{Path: "enc_content.7z", Content: fixtureOf(t, "enc_content.7z")}
	mixed := harness.File{Path: "mixed.zip", Content: fixtureOf(t, "mixed.zip")}
	nested := archive(t, "n.zip", zipOf,
		harness.File{Path: "p.txt", Content: []byte(strings.Repeat("a plain member beside an encrypted archive ", 20))},
		harness.File{Path: "inner.zip", Content: fixtureOf(t, "enc_zipcrypto.zip")},
	)
	for _, tt := range []struct {
		file   harness.File
		policy string
		want   harness.Outcome
	}{
		{file: zipCrypto, policy: "error", want: harness.Outcome{In: harness.Input, Error: errEncryptedText}},
		{file: zipCrypto, policy: "pass", want: harness.Outcome{In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedEncrypted}},
		{file: zipCrypto, policy: "mitigate", want: harness.Outcome{In: harness.Quarantine, Malware: datamodel.Encrypted}},
		{file: aes, policy: "error", want: harness.Outcome{In: harness.Input, Error: errEncryptedText}},
		{file: aes, policy: "pass", want: harness.Outcome{In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedEncrypted}},
		{file: aes, policy: "mitigate", want: harness.Outcome{In: harness.Quarantine, Malware: datamodel.Encrypted}},
		{file: sevenZ, policy: "error", want: harness.Outcome{In: harness.Input, Error: errEncryptedText}},
		{file: sevenZ, policy: "pass", want: harness.Outcome{In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedEncrypted}},
		{file: sevenZ, policy: "mitigate", want: harness.Outcome{In: harness.Quarantine, Malware: datamodel.Encrypted}},
		{file: sevenZContent, policy: "error", want: harness.Outcome{In: harness.Input, Error: errEncryptedText}},
		{file: sevenZContent, policy: "pass", want: harness.Outcome{In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedEncrypted}},
		{file: sevenZContent, policy: "mitigate", want: harness.Outcome{In: harness.Quarantine, Malware: datamodel.Encrypted}},
		{file: mixed, policy: "error", want: harness.Outcome{In: harness.Input, Error: errEncryptedText}},
		{file: mixed, policy: "pass", want: harness.Outcome{In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedEncrypted}},
		{file: mixed, policy: "mitigate", want: harness.Outcome{In: harness.Quarantine, Malware: datamodel.Encrypted}},
		{file: nested, policy: "error", want: harness.Outcome{In: harness.Input, Error: "1 extracted file(s) in error, first: inner.zip: " + errEncryptedText}},
		{file: nested, policy: "pass", want: harness.Outcome{In: harness.Output, NotAnalyzedMembers: &harness.MemberList{Reason: datamodel.NotAnalyzedEncrypted, Count: 1, Includes: "inner.zip"}}},
		{file: nested, policy: "mitigate", want: harness.Outcome{In: harness.Quarantine, Malware: datamodel.Encrypted, MaliciousMembers: map[string]datamodel.MalwareReason{"inner.zip": datamodel.Encrypted}}},
	} {
		t.Run(tt.file.Path+"/"+tt.policy, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  map[string]any{"unanalyzable_policy": map[string]any{"encrypted": tt.policy}},
				Files:   []harness.File{tt.file},
				Want:    map[string]harness.Outcome{tt.file.Path: tt.want},
			})
		})
	}
}

// T17b: under extract_error as_file, an archive in which damage may hide an
// encryption follows the encrypted policy: with encrypted pass it is delivered
// marked encrypted, never as a plain file marked extract-error. Mirrors
// TestPipeline_asFileFollowsTheEncryptedPolicyWhenEncryptionIsPossible and
// TestTruncatedZipIsNeverAPlainFile.
func TestE2E_extractErrorAsFileWithEncryptedPass(t *testing.T) {
	t.Parallel()
	plain := zipOf(t, map[string]string{"a.txt": strings.Repeat("a plain member ", 100)})
	zipCrypto := fixtureOf(t, "enc_zipcrypto.zip")
	aes := fixtureOf(t, "enc_aes.zip")
	sevenZ := fixtureOf(t, "enc_content.7z")
	stored := storedZip(t, map[string]string{"a.txt": "plain member"})
	for _, tt := range []struct {
		name    string
		path    string
		content []byte
	}{
		{name: "a ZipCrypto zip cut at 66%", path: "a.zip", content: zipCrypto[:len(zipCrypto)*66/100]},
		{name: "an AES zip cut at 50%", path: "a.zip", content: aes[:len(aes)*50/100]},
		{name: "a 7z with encrypted content cut at 50%", path: "a.7z", content: sevenZ[:len(sevenZ)*50/100]},
		{name: "a plain zip followed by an AES zip", path: "a.zip", content: append(append([]byte(nil), plain...), aes...)},
		{name: "a member with a path component over 255 bytes", path: "a.zip", content: zipOf(t, map[string]string{"d/" + strings.Repeat("a", 300) + "/x.txt": "member"})},
		{name: "a 7z with a plain and an encrypted member of the same name", path: "a.7z", content: fixtureOf(t, "homonym_mixed.7z")},
		{name: "a ZipCrypto zip whose password check collides with a default password", path: "a.zip", content: fixtureOf(t, "zc_collision.zip")},
		{name: "an AES zip with a flipped byte", path: "aes_one_corrupt.zip", content: fixtureOf(t, "aes_one_corrupt.zip")},
		{name: "a ZipCrypto zip whose local headers say not encrypted", path: "bit0.zip", content: clearLocalEncryptionBit(t, zipCrypto)},
		{name: "a plain zip with a CRC error", path: "damaged.zip", content: damagedPlainZip(t)},
		{name: "a 7z with encrypted headers cut at 50%", path: "cut50-enc_headers.7z", content: cut(fixtureOf(t, "enc_headers.7z"), 50)},
		{name: "a 7z with encrypted headers cut at 90%", path: "cut90-enc_headers.7z", content: cut(fixtureOf(t, "enc_headers.7z"), 90)},
		{name: "a 7z with encrypted content cut at 25%", path: "cut25-enc_content.7z", content: cut(sevenZ, 25)},
		{name: "a 7z with encrypted content cut at 90%", path: "cut90-enc_content.7z", content: cut(sevenZ, 90)},
		{name: "a plain zip followed by an encrypted 7z", path: "plain_then_enc7.zip", content: concat(stored, sevenZ)},
		{name: "a plain zip followed by a ZipCrypto zip", path: "plain_then_zc.zip", content: concat(stored, zipCrypto)},
		{name: "a member name over the limit", path: "longname.zip", content: storedZip(t, map[string]string{"a.txt": "plain member", strings.Repeat("n", maxMemberNameLen+10): "plain too"})},
		{name: "a member 64 folders deep", path: "deep.zip", content: storedZip(t, map[string]string{"a.txt": "plain member", strings.Repeat("f/", maxMemberDepth) + "deep.exe": "left out"})},
		{name: "a zip folder entry that holds data", path: "folderdata.zip", content: folderDataZip(t)},
		{name: "a zip folder named with a slash that holds data", path: "slashfolder.zip", content: slashFolderZip()},
		{name: "a tar directory that holds data", path: "folderdata.tar", content: folderDataTar(t)},
		{name: "a plain 7z followed by an encrypted 7z", path: "plain7_then_enc7.7z", content: concat(sevenZipOf(t, "7z", map[string][]byte{"a.txt": []byte("plain member")}), sevenZ)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  map[string]any{"unanalyzable_policy": map[string]any{"extract_error": "as_file", "encrypted": "pass"}},
				Files:   []harness.File{{Path: tt.path, Content: tt.content}},
				Want: map[string]harness.Outcome{
					tt.path: {In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedEncrypted},
				},
			})
		})
	}
}

// aesZip builds a zip whose only member, secret.bin, is encrypted with AES-256
// by the embedded 7-Zip.
func aesZip(t *testing.T) []byte {
	t.Helper()
	bin := sevenZip(t)
	src := t.TempDir()
	harness.Write(t, filepath.Join(src, "secret.bin"), []byte(strings.Repeat("an AES encrypted member ", 40)))
	archive := filepath.Join(t.TempDir(), "aes.zip")
	if out, err := harness.RunCommand(src, bin, "a", "-tzip", "-pnobodyknows", "-mem=AES256", archive, "secret.bin"); err != nil {
		t.Fatalf("cannot build the archive: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(filepath.Clean(archive))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// localFlagsOf returns the general purpose flags of the local header of the
// entry with the name, found by its signature.
func localFlagsOf(t *testing.T, doc []byte, name string) uint16 {
	t.Helper()
	sig := []byte("PK\x03\x04")
	for off := 0; off+30 <= len(doc); off++ {
		if !bytes.HasPrefix(doc[off:], sig) {
			continue
		}
		nameLen := int(binary.LittleEndian.Uint16(doc[off+26:]))
		if off+30+nameLen <= len(doc) && string(doc[off+30:off+30+nameLen]) == name {
			return binary.LittleEndian.Uint16(doc[off+6:])
		}
	}
	t.Fatalf("no local header named %q", name)
	return 0
}

// The document the AES test builds really has what it claims: an AES member
// (method 99) whose encryption flag is clear in the local and the central header.
func TestAESDocumentHasNoEncryptionFlag(t *testing.T) {
	doc := bigDocumentWith(t, "docx", "aes", 10, aesZip(t), true)
	zr, err := zip.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != 10 {
		t.Fatalf("%d entries, want 10", len(zr.File))
	}
	f := zr.File[len(zr.File)-1]
	if f.Name != "secret.bin" || f.Method != 99 {
		t.Errorf("last entry = %q method %d, want secret.bin method 99 (AES)", f.Name, f.Method)
	}
	if f.Flags&1 != 0 {
		t.Error("the central header still says encrypted")
	}
	if got := localFlagsOf(t, doc, "secret.bin"); got&1 != 0 {
		t.Errorf("the local header still says encrypted (flags %#x)", got)
	}
	plain := bigDocumentWith(t, "docx", "aes", 10, aesZip(t), false)
	if got := localFlagsOf(t, plain, "secret.bin"); got&1 == 0 {
		t.Errorf("without clearing, the local header says not encrypted (flags %#x)", got)
	}
}

// p3/T62b: an AES member whose encryption flag is cleared in both headers does
// not slip an over-limit document through: the method says it is encrypted,
// and the document is held as encrypted.
func TestE2E_anOverLimitDocumentWithAnAESMemberWithoutFlagIsHeldAsEncrypted(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "an AES member with its flag cleared",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Files: []harness.File{
					{Path: "aes.docx", Content: bigDocumentWith(t, "docx", "aes secret", overLimitEntries, aesZip(t), true)},
				},
				Want: map[string]harness.Outcome{
					"aes.docx": {In: harness.Input, Error: errEncryptedText, NotAnalyzedMembers: harness.NoMembers()},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}
