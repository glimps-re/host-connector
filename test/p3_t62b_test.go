//go:build linux && e2e

package test

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

// T62b: an over-limit document with one encrypted member is not delivered: it
// follows the encrypted policy (error by default) and stays in INPUT. The same
// document without the encrypted member is delivered in the same run.
func TestE2E_anOverLimitDocumentWithAnEncryptedMemberStaysInInput(t *testing.T) {
	for _, kind := range []string{"docx", "jar", "apk"} {
		t.Run(kind, func(t *testing.T) {
			gm := newGMalware(t, false)
			in := startInstance(t, gm, options{extract: true})
			in.expect.allow(datamodel.NotAnalyzedExtractLimit)
			secret := bigDocument(t, kind, "secret "+kind, overLimitEntries, true)
			control := bigDocument(t, kind, "control "+kind, overLimitEntries, false)
			path := in.drop(t, "secret."+kind, secret)
			in.drop(t, "control."+kind, control)
			in.waitFor(t, "the control document to be delivered", func() bool { return in.inOutput("control." + kind) })
			in.staysInInput(t, path, secret)
			in.heldWith(t, secret, errEncryptedText)
			if _, err := os.Stat(path); err != nil {
				t.Errorf("the document with an encrypted member is not in INPUT: %v", err)
			}
		})
	}
}

// T62b (F1): the budget a document gets is what its parent left. An outer zip
// of 9,999 plain files holding a document with an encrypted member leaves the
// document no budget: the outer archive is held in INPUT, never delivered.
// The same outer archive with a plain document is delivered, and the members
// of the document are listed as not analyzed.
func TestE2E_aDocumentInAFullArchiveIsCheckedForEncryption(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true})
	in.expect.allow(datamodel.NotAnalyzedExtractLimit)
	secret := outerWithDocument(t, "held", bigDocument(t, "docx", "held inner", 4, true))
	plain := outerWithDocument(t, "delivered", bigDocument(t, "docx", "delivered inner", 5, false))
	in.expect.archive(plain, nestedMembers("delivered")...)
	path := in.drop(t, "secret.zip", secret)
	in.drop(t, "plain.zip", plain)
	in.waitFor(t, "the plain outer archive to be delivered", func() bool { return in.inOutput("plain.zip") })
	in.staysInInput(t, path, secret)
	in.heldWith(t, secret, errEncryptedText)
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	entries := in.reportsOf(t, plain)
	if len(entries) != 1 {
		t.Fatalf("%d report entries for the delivered outer archive, want 1", len(entries))
	}
	e := entries[0]
	if e.NotAnalyzedReason != "" || e.Error != "" || e.Malicious {
		t.Errorf("the outer archive = %+v, want analyzed and delivered", e)
	}
	listed := e.NotAnalyzedExtractedFiles
	if len(listed) == 0 || e.NotAnalyzedExtractedCount < len(listed) {
		t.Fatalf("%d members listed, count %d: the members of the document are not reported", len(listed), e.NotAnalyzedExtractedCount)
	}
	found := false
	for _, m := range listed {
		if m.Reason != datamodel.NotAnalyzedExtractLimit {
			t.Errorf("member %q has the reason %q, want %q", m.FileName, m.Reason, datamodel.NotAnalyzedExtractLimit)
		}
		found = found || strings.HasSuffix(m.FileName, "word/document.xml")
	}
	if !found {
		t.Errorf("no listed member is word/document.xml of the document: %+v", listed)
	}
}

// errEncryptedText is the error a file held for its encryption is reported with.
const errEncryptedText = "file is encrypted and cannot be analyzed"

// heldWith waits for the reports of a content held in INPUT and requires that
// every entry carries the error and that one of them says why: a file held
// for another cause (too big, left out by the limits, damaged) is not the case
// under test.
func (in *instance) heldWith(t *testing.T, content []byte, want string) {
	t.Helper()
	in.waitFor(t, "the report of the held file", func() bool { return len(readReports(in)[sha256Hex(content)]) > 0 })
	for _, e := range readReports(in)[sha256Hex(content)] {
		if !strings.Contains(e.Error, want) {
			t.Errorf("the held file is reported with %q, want an error containing %q", e.Error, want)
		}
		if e.NotAnalyzedReason != "" || len(e.NotAnalyzedExtractedFiles) != 0 {
			t.Errorf("the held file lists a not-analyzed outcome: %+v", e)
		}
	}
}

// T62b: the encrypted verdict is what holds the document, not its size: with
// the encrypted policy at pass the same document is delivered, marked
// encrypted. Only a real encrypted outcome does that.
func TestE2E_anOverLimitEncryptedDocumentFollowsTheEncryptedPolicy(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true, config: map[string]any{
		"unanalyzable_policy": map[string]any{"encrypted": "pass"},
	}})
	in.expect.allow(datamodel.NotAnalyzedEncrypted, datamodel.NotAnalyzedExtractLimit)
	secret := bigDocument(t, "docx", "pass secret", overLimitEntries, true)
	in.drop(t, "secret.docx", secret)
	in.waitFor(t, "the document to be delivered", func() bool { return in.inOutput("secret.docx") })
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	entries := in.reportsOf(t, secret)
	if !slices.ContainsFunc(entries, func(e datamodel.Report) bool { return e.NotAnalyzedReason == datamodel.NotAnalyzedEncrypted }) {
		t.Errorf("no entry says the document is not analyzed for %q: %+v", datamodel.NotAnalyzedEncrypted, entries)
	}
}

// T62b (F1): same as above for a document in a full archive.
func TestE2E_anEncryptedDocumentInAFullArchiveFollowsTheEncryptedPolicy(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true, config: map[string]any{
		"unanalyzable_policy": map[string]any{"encrypted": "pass"},
	}})
	in.expect.allow(datamodel.NotAnalyzedEncrypted, datamodel.NotAnalyzedExtractLimit)
	secret := outerWithDocument(t, "pass nested", bigDocument(t, "docx", "pass nested inner", 4, true))
	in.expect.archive(secret, nestedMembers("pass nested")...)
	in.drop(t, "secret.zip", secret)
	in.waitFor(t, "the outer archive to be delivered", func() bool { return in.inOutput("secret.zip") })
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	entries := in.reportsOf(t, secret)
	marked := slices.ContainsFunc(entries, func(e datamodel.Report) bool {
		return e.NotAnalyzedReason == datamodel.NotAnalyzedEncrypted ||
			slices.ContainsFunc(e.NotAnalyzedExtractedFiles, func(m datamodel.NotAnalyzedFile) bool { return m.Reason == datamodel.NotAnalyzedEncrypted })
	})
	if !marked {
		t.Errorf("nothing says the encrypted document is not analyzed for %q: %+v", datamodel.NotAnalyzedEncrypted, entries)
	}
}

// aesZip builds a zip whose only member, secret.bin, is encrypted with AES-256
// by the embedded 7-Zip.
func aesZip(t *testing.T) []byte {
	t.Helper()
	bin := sevenZip(t)
	src := t.TempDir()
	write(t, filepath.Join(src, "secret.bin"), []byte(strings.Repeat("an AES encrypted member ", 40)))
	archive := filepath.Join(t.TempDir(), "aes.zip")
	if out, err := runCommand(src, bin, "a", "-tzip", "-pnobodyknows", "-mem=AES256", archive, "secret.bin"); err != nil {
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
	if plain := bigDocumentWith(t, "docx", "aes", 10, aesZip(t), false); bytes.Equal(plain, doc) {
		t.Error("clearing the flag changed nothing")
	}
}

// T62b: an AES member whose encryption flag is cleared in both headers does
// not slip an over-limit document through: the method says it is encrypted,
// and the document is held as encrypted.
func TestE2E_anOverLimitDocumentWithAnAESMemberWithoutFlagIsHeldAsEncrypted(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true})
	in.expect.allow(datamodel.NotAnalyzedExtractLimit)
	secret := bigDocumentWith(t, "docx", "aes secret", overLimitEntries, aesZip(t), true)
	path := in.drop(t, "aes.docx", secret)
	in.staysInInput(t, path, secret)
	in.heldWith(t, secret, errEncryptedText)
}
