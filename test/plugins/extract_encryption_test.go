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
					"secret." + kind:  {In: harness.Input, Error: errEncryptedText, NotAnalyzedMembers: harness.NoMembers},
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
	plain := outerWithDocument(t, "delivered", bigDocument(t, "docx", "delivered inner", 5, false))
	in := harness.Run(t, harness.Scenario{
		Plugins: map[string]map[string]any{"extract": nil},
		Files: []harness.File{
			{Path: "secret.zip", Content: outerWithDocument(t, "held", bigDocument(t, "docx", "held inner", 4, true))},
			{Path: "plain.zip", Content: plain, Members: seenMembers("delivered")},
		},
		Want: map[string]harness.Outcome{
			"secret.zip": {In: harness.Input, Error: errEncryptedText, NotAnalyzedMembers: harness.NoMembers},
			"plain.zip":  {In: harness.Output, NotAnalyzedMembers: &harness.MemberList{Reason: datamodel.NotAnalyzedExtractLimit, Includes: "word/document.xml"}},
		},
	})
	if n := len(in.ReportsOf(t, plain)); n != 1 {
		t.Errorf("%d report entries for the delivered outer archive, want 1", n)
	}
}

// errEncryptedText is the error a file held for its encryption is reported with.
const errEncryptedText = "file is encrypted and cannot be analyzed"

// p3/T62b: the encrypted verdict is what holds the document, not its size: with
// the encrypted policy at pass the same document is delivered, marked
// encrypted. Only a real encrypted outcome does that.
func TestE2E_anOverLimitEncryptedDocumentFollowsTheEncryptedPolicy(t *testing.T) {
	harness.Run(t, harness.Scenario{
		Plugins: map[string]map[string]any{"extract": nil},
		Config:  map[string]any{"unanalyzable_policy": map[string]any{"encrypted": "pass"}},
		Files: []harness.File{
			{Path: "secret.docx", Content: bigDocument(t, "docx", "pass secret", overLimitEntries, true)},
		},
		Want: map[string]harness.Outcome{
			"secret.docx": {In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedEncrypted},
		},
	})
}

// p3/T62b (F1): same as above for a document in a full archive.
func TestE2E_anEncryptedDocumentInAFullArchiveFollowsTheEncryptedPolicy(t *testing.T) {
	harness.Run(t, harness.Scenario{
		Plugins: map[string]map[string]any{"extract": nil},
		Config:  map[string]any{"unanalyzable_policy": map[string]any{"encrypted": "pass"}},
		Files: []harness.File{
			{Path: "secret.zip", Content: outerWithDocument(t, "pass nested", bigDocument(t, "docx", "pass nested inner", 4, true)), Members: seenMembers("pass nested")},
		},
		Want: map[string]harness.Outcome{
			"secret.zip": {In: harness.Output, NotAnalyzedMembers: &harness.MemberList{Reason: datamodel.NotAnalyzedEncrypted}},
		},
	})
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
	harness.Run(t, harness.Scenario{
		Plugins: map[string]map[string]any{"extract": nil},
		Files: []harness.File{
			{Path: "aes.docx", Content: bigDocumentWith(t, "docx", "aes secret", overLimitEntries, aesZip(t), true)},
		},
		Want: map[string]harness.Outcome{
			"aes.docx": {In: harness.Input, Error: errEncryptedText, NotAnalyzedMembers: harness.NoMembers},
		},
	})
}
