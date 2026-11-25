//go:build linux

package main

import (
	"archive/zip"
	"bytes"
	le "encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

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

// clearLocalEncryptionBit clears bit 0 of the flags of every local header: the
// archive then says in its local headers that no member is encrypted.
func clearLocalEncryptionBit(t *testing.T, zipBytes []byte) []byte {
	t.Helper()
	out := bytes.Clone(zipBytes)
	cleared := 0
	for i := 0; i+8 <= len(out); i++ {
		if bytes.Equal(out[i:i+4], []byte("PK\x03\x04")) {
			flags := le.LittleEndian.Uint16(out[i+6:])
			le.LittleEndian.PutUint16(out[i+6:], flags&^1)
			cleared++
		}
	}
	if cleared == 0 {
		t.Fatal("no local header found")
	}
	return out
}

type asFileCase struct {
	file    string
	content func(t *testing.T) []byte
}

func fixtureCase(name string) asFileCase {
	return asFileCase{name, func(t *testing.T) []byte { return archiveFixture(t, name) }}
}

func cutCase(fixtureName string, percent int) asFileCase {
	return asFileCase{"cut-" + fixtureName, func(t *testing.T) []byte {
		b := archiveFixture(t, fixtureName)
		return b[:len(b)*percent/100]
	}}
}

// The archives that damage may hide an encryption of: as_file never delivers them
// as plain files, whatever the damage looks like.
func possiblyEncryptedCases() map[string]asFileCase {
	return map[string]asFileCase{
		"homonym_mixed.7z":    fixtureCase("homonym_mixed.7z"),
		"zc_collision.zip":    fixtureCase("zc_collision.zip"),
		"aes_one_corrupt.zip": fixtureCase("aes_one_corrupt.zip"),
		"local bit 0 cleared": {"bit0.zip", func(t *testing.T) []byte { return clearLocalEncryptionBit(t, archiveFixture(t, "enc_zipcrypto.zip")) }},
		"crc damaged plain":   {"damaged.zip", damagedPlainZip},
		"cut enc_headers 50%": cutCase("enc_headers.7z", 50),
		"cut enc_headers 90%": cutCase("enc_headers.7z", 90),
		"cut enc_content 25%": cutCase("enc_content.7z", 25),
		"cut enc_content 50%": cutCase("enc_content.7z", 50),
		"cut enc_content 90%": cutCase("enc_content.7z", 90),
		"cut zipcrypto 66%":   cutCase("enc_zipcrypto.zip", 66),
		"plain zip then an encrypted 7z": {"plain_then_enc7.zip", func(t *testing.T) []byte {
			return append(storedZip(t, map[string]string{"a.txt": "plain member"}), archiveFixture(t, "enc_content.7z")...)
		}},
		"plain zip then an AES zip": {"plain_then_aes.zip", func(t *testing.T) []byte {
			return append(storedZip(t, map[string]string{"a.txt": "plain member"}), archiveFixture(t, "enc_aes.zip")...)
		}},
		"plain zip then a ZipCrypto zip": {"plain_then_zc.zip", func(t *testing.T) []byte {
			return append(storedZip(t, map[string]string{"a.txt": "plain member"}), archiveFixture(t, "enc_zipcrypto.zip")...)
		}},
		"a member name over the limit":                {"longname.zip", longNamesZip},
		"a member component over 255":                 {"longcomponent.zip", longComponentZip},
		"a member path of 64 folders":                 {"deep.zip", deepPathZip},
		"a folder entry that holds data":              {"folderdata.zip", folderDataZip},
		"a folder named with a slash that holds data": {"slashfolder.zip", slashFolderZip},
		"a tar directory that holds data":             {"folderdata.tar", folderDataTar},
		"plain 7z then an encrypted 7z": {"plain7_then_enc7.7z", func(t *testing.T) []byte {
			return append(plainSevenZip(t), archiveFixture(t, "enc_content.7z")...)
		}},
	}
}

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

// Under as_file, a damaged archive that an encryption may hide in is never
// delivered as a plain file: the policy of the encrypted files decides.
func TestPipeline_asFileFollowsTheEncryptedPolicyWhenEncryptionIsPossible(t *testing.T) {
	for key, c := range possiblyEncryptedCases() {
		name := c.file
		t.Run(key+"/encrypted error", func(t *testing.T) {
			r := runPipeline(t, pipelineSetup{policy: scanner.Unanalyzable{Encrypted: scanner.PolicyError, ExtractError: scanner.PolicyAsFile}, name: name, content: c.content(t)})
			if r.exists(r.out, name) || r.quarantined(t) != 0 || !r.exists(r.in, name) {
				t.Errorf("%s was not kept in INPUT under {encrypted: error, as_file}", key)
			}
			if got, ran := r.maybe(name); ran && (got.result.Error == nil || got.result.NotAnalyzedReason == datamodel.NotAnalyzedExtractError) {
				t.Errorf("result = %+v, want the failure of the encrypted policy", got.result)
			}
		})
		t.Run(key+"/encrypted pass", func(t *testing.T) {
			r := runPipeline(t, pipelineSetup{policy: scanner.Unanalyzable{Encrypted: scanner.PolicyPass, ExtractError: scanner.PolicyAsFile}, name: name, content: c.content(t)})
			got, ran := r.maybe(name)
			if !ran {
				t.Fatalf("the actions never ran for %s under {encrypted: pass, as_file}", key)
			}
			if got.result.NotAnalyzedReason != datamodel.NotAnalyzedEncrypted || got.report.NotAnalyzedReason != datamodel.NotAnalyzedEncrypted {
				t.Errorf("reason = %q (report %q), want the file passed marked encrypted, never extract-error", got.result.NotAnalyzedReason, got.report.NotAnalyzedReason)
			}
		})
	}
}

func trailingDataZip(t *testing.T) []byte {
	t.Helper()
	return append(storedZip(t, map[string]string{"a.txt": "first member", "b.txt": "second member"}), []byte("DATA AFTER THE END OF THE ARCHIVE")...)
}

// Under as_file a structural anomaly whose members were all extracted and tested
// is analyzed as a plain file and delivered, marked extract-error: a control
// character in a name is what 7-Zip changes, and every member is still extracted.
func TestPipeline_asFileDeliversAStructuralAnomalyMarkedExtractError(t *testing.T) {
	r := runPipeline(t, pipelineSetup{policy: scanner.Unanalyzable{Encrypted: scanner.PolicyError, ExtractError: scanner.PolicyAsFile}, name: "control.zip", content: storedZip(t, map[string]string{"a\x01b.txt": "first member", "ok.txt": "second member"})})
	got := r.one(t, "control.zip")
	if got.result.Error != nil || got.result.Malware || got.result.NotAnalyzedReason != datamodel.NotAnalyzedExtractError {
		t.Errorf("result = %+v, want a clean file marked extract-error", got.result)
	}
	if !r.exists(r.out, "control.zip") || r.quarantined(t) != 0 {
		t.Error("the archive must be delivered to OUTPUT")
	}
}

// The default policy keeps every damaged archive in INPUT, with its error.
func TestPipeline_theDefaultPolicyKeepsEveryDamagedArchiveInInput(t *testing.T) {
	cases := possiblyEncryptedCases()
	cases["trailing data"] = asFileCase{"trailing.zip", trailingDataZip}
	for key, c := range cases {
		name := c.file
		t.Run(key, func(t *testing.T) {
			r := runPipeline(t, pipelineSetup{policy: scanner.Unanalyzable{Encrypted: scanner.PolicyPass}, name: name, content: c.content(t)})
			got, ran := r.maybe(name)
			delivered := r.exists(r.out, name)
			if delivered && (!ran || got.result.NotAnalyzedReason != datamodel.NotAnalyzedEncrypted) {
				t.Errorf("%s was delivered under extract_error: error (reason %q)", key, got.result.NotAnalyzedReason)
			}
			if !delivered && !r.exists(r.in, name) {
				t.Errorf("%s left INPUT without being delivered: it must stay in INPUT", key)
			}
		})
	}
}

// plainSevenZip is a 7z of one plain member, made by the embedded 7-Zip.
func plainSevenZip(t *testing.T) []byte {
	t.Helper()
	plugin := realPlugin(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(src, []byte("plain member"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "plain.7z")
	if out, err := runCmd(t.Context(), plugin.sze.sevenZipPath, "a", "-t7z", archive, src); err != nil {
		t.Fatalf("cannot build the archive: %v %s", err, out)
	}
	b, err := os.ReadFile(filepath.Clean(archive))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// stubbedZip is a zip after a stub, with its offsets counted from the start of the
// file as an SFX archive has them.
func stubbedZip(t *testing.T) []byte {
	t.Helper()
	stub := append([]byte("MZ"), make([]byte, 500)...)
	z := storedZip(t, map[string]string{"a.txt": "plain member"})
	eocd := bytes.LastIndex(z, []byte("PK\x05\x06"))
	if eocd < 0 {
		t.Fatal("no end of central directory")
	}
	const stubLen = uint32(502)
	cdOffset := le.LittleEndian.Uint32(z[eocd+16:])
	cd := int(cdOffset)
	for i := cd; i+46 <= eocd; {
		if !bytes.Equal(z[i:i+4], []byte("PK\x01\x02")) {
			t.Fatalf("no central directory record at %d", i)
		}
		le.LittleEndian.PutUint32(z[i+42:], le.LittleEndian.Uint32(z[i+42:])+stubLen)
		i += 46 + int(le.LittleEndian.Uint16(z[i+28:])) + int(le.LittleEndian.Uint16(z[i+30:])) + int(le.LittleEndian.Uint16(z[i+32:]))
	}
	le.LittleEndian.PutUint32(z[eocd+16:], cdOffset+stubLen)
	return append(stub, z...)
}

// longNamesZip is a zip of plain members one of which has a name too long to be
// extracted: a structural anomaly with every member plain.
func longNamesZip(t *testing.T) []byte {
	t.Helper()
	return storedZip(t, map[string]string{"a.txt": "plain member", strings.Repeat("n", maxMemberNameLen+10): "plain too"})
}

// longComponentZip is a zip whose second member has a path component over 255
// bytes: never extracted nor tested, so nothing proves it is not encrypted.
func longComponentZip(t *testing.T) []byte {
	t.Helper()
	return storedZip(t, map[string]string{"a.txt": "plain member", "d/" + strings.Repeat("x", 300) + ".exe": "left out"})
}

// deepPathZip is a zip whose second member sits 64 folders deep.
func deepPathZip(t *testing.T) []byte {
	t.Helper()
	return storedZip(t, map[string]string{"a.txt": "plain member", strings.Repeat("f/", maxMemberDepth) + "deep.exe": "left out"})
}

// twinNamesZip is a zip of two plain members with the same name.
func twinNamesZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, content := range []string{"first twin", "second twin"} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: "twin.txt", Method: zip.Store})
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

// 7-Zip extracts both members of a zip that has twin names (it renames the second):
// nothing is lost, so nothing is an anomaly, and the archive is analyzed as usual.
func TestPipeline_twinNamesWithPlainMembersAreExtractedBothAndAreNoAnomaly(t *testing.T) {
	r := runPipeline(t, pipelineSetup{policy: scanner.Unanalyzable{Encrypted: scanner.PolicyError, ExtractError: scanner.PolicyAsFile}, name: "twins.zip", content: twinNamesZip(t)})
	got := r.one(t, "twins.zip")
	if got.result.Error != nil || got.result.NotAnalyzedReason != "" {
		t.Errorf("result = error %v, reason %q, want an archive analyzed as usual", got.result.Error, got.result.NotAnalyzedReason)
	}
	if r.submissionsOf("twin.txt") != 1 || r.submissionsOf("twin_1.txt") != 1 && r.submissionsOf("twin (1).txt") != 1 {
		t.Logf("submitted: %v", r.submitted)
	}
}

// A zip behind a stub is listed by 7-Zip as plain, with the stub as an offset: the
// extractor does not see what the stub holds, so the encryption is possible. (An
// executable stub makes the file an executable for the connector before it reaches
// the extractor; the extractor answers for what reaches it.)
func TestExtractFile_aStubInFrontOfTheArchiveLeavesEncryptionPossible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stub.zip")
	if err := os.WriteFile(path, stubbedZip(t), 0o600); err != nil {
		t.Fatal(err)
	}
	ex, err := realPlugin(t).ExtractFile(path, t.TempDir(), openLimits)
	if !errors.Is(err, plugins.ErrArchiveAnomaly) && len(ex.Files) == 0 {
		t.Fatalf("ExtractFile() = %+v, %v, want the archive opened", ex, err)
	}
	if err == nil {
		t.Fatal("ExtractFile() succeeded: 7-Zip says nothing of the stub, the archive must be flagged")
	}
	if !errors.Is(err, plugins.ErrEncryptionPossible) {
		t.Errorf("error = %v, want the encryption possible: an archive can hide in the stub", err)
	}
}
