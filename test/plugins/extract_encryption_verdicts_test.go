//go:build linux && (e2e || e2e_plugins)

package plugins

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// plainZipMembers reads the members of a zip that is not encrypted.
func plainZipMembers(t *testing.T, raw []byte) []harness.File {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	var members []harness.File
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		if err = rc.Close(); err != nil {
			t.Fatal(err)
		}
		members = append(members, harness.File{Path: f.Name, Content: content})
	}
	return members
}

// sevenZipMembers extracts an archive with the embedded 7-Zip and the password,
// and returns its members.
func sevenZipMembers(t *testing.T, raw []byte, password string) []harness.File {
	t.Helper()
	bin := sevenZip(t)
	archive := filepath.Join(t.TempDir(), "archive")
	harness.Write(t, archive, raw)
	out := t.TempDir()
	if b, err := harness.RunCommand(out, bin, "x", "-p"+password, "-o"+out, archive); err != nil {
		t.Fatalf("cannot extract the archive: %v\n%s", err, b)
	}
	var members []harness.File
	err := filepath.WalkDir(out, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(out, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(filepath.Clean(path))
		members = append(members, harness.File{Path: rel, Content: content})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return members
}

// From TestPipeline_realEncryptedArchiveMaliciousVerdictWins: a detection of the encrypted archive wins over the encrypted policy.
func TestE2E_aDetectionOfAnEncryptedArchiveWinsOverTheEncryptedPolicy(t *testing.T) {
	t.Parallel()
	enc := harness.File{Path: "enc.zip", Content: fixtureOf(t, "enc_zipcrypto.zip"), Verdict: harness.Malicious}
	tests := []struct {
		policy string
		want   harness.Outcome
	}{
		{policy: "error", want: harness.Outcome{In: harness.Quarantine, Malware: datamodel.MalwareDetected}},
		{policy: "pass", want: harness.Outcome{In: harness.Quarantine, Malware: datamodel.MalwareDetected}},
		{policy: "mitigate", want: harness.Outcome{In: harness.Quarantine, Malware: datamodel.MalwareDetected}},
	}
	for _, tt := range tests {
		t.Run(tt.policy, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  map[string]any{"unanalyzable_policy": map[string]any{"encrypted": tt.policy}},
				Files:   []harness.File{enc},
				Want:    map[string]harness.Outcome{enc.Path: tt.want},
			})
		})
	}
}

// From TestPipeline_realEncryptedArchiveOverMaxFileSizeIsNotSubmitted and TestRecursiveExtract_anEncryptedArchiveOverMaxFileSizeIsNotSubmitted: an encrypted archive over max_file_size is never submitted; at the top level it follows the encrypted policy, in a plain zip it is opened (max_file_size bounds only what is submitted) and follows the encrypted policy too.
func TestE2E_anEncryptedArchiveOverMaxFileSizeIsNotSubmitted(t *testing.T) {
	t.Parallel()
	enc := harness.File{Path: "enc.zip", Content: fixtureOf(t, "enc_zipcrypto.zip")}
	nestedRaw := fixtureOf(t, "nested_in_plain.zip")
	nested := harness.File{Path: "n.zip", Content: nestedRaw, Members: plainZipMembers(t, nestedRaw)}
	notGiven := harness.Outcome{ServiceVerdict: harness.NotGiven}
	tests := []struct {
		name   string
		file   harness.File
		policy string
		want   map[string]harness.Outcome
	}{
		{name: "top level", file: enc, policy: "error", want: map[string]harness.Outcome{
			"enc.zip": {In: harness.Input, Error: errEncryptedText, ServiceVerdict: harness.NotGiven},
		}},
		{name: "top level", file: enc, policy: "pass", want: map[string]harness.Outcome{
			"enc.zip": {In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedEncrypted, ServiceVerdict: harness.NotGiven},
		}},
		{name: "top level", file: enc, policy: "mitigate", want: map[string]harness.Outcome{
			"enc.zip": {In: harness.Quarantine, Malware: datamodel.Encrypted, ServiceVerdict: harness.NotGiven},
		}},
		{name: "in a plain zip", file: nested, policy: "error", want: map[string]harness.Outcome{
			"n.zip":           {In: harness.Input, Error: "first: inner.zip: file is encrypted and cannot be analyzed"},
			"n.zip/inner.zip": notGiven,
		}},
		{name: "in a plain zip", file: nested, policy: "pass", want: map[string]harness.Outcome{
			"n.zip":           {In: harness.Output, NotAnalyzedMembers: &harness.MemberList{Reason: datamodel.NotAnalyzedEncrypted, Count: 1, Includes: "inner.zip"}},
			"n.zip/inner.zip": notGiven,
		}},
		{name: "in a plain zip", file: nested, policy: "mitigate", want: map[string]harness.Outcome{
			"n.zip":           {In: harness.Quarantine, Malware: datamodel.Encrypted},
			"n.zip/inner.zip": notGiven,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/"+tt.policy, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config: map[string]any{
					"max_file_size":       fmt.Sprintf("%dB", len(enc.Content)-1),
					"unanalyzable_policy": map[string]any{"encrypted": tt.policy, "too_big": "error"},
				},
				Files: []harness.File{tt.file},
				Want:  tt.want,
			})
		})
	}
}

// From TestPipeline_realKnownPasswordIsExtractedNormally: an archive opened by a default password is extracted as any other, whatever the policies.
func TestE2E_aKnownPasswordOpensTheArchive(t *testing.T) {
	t.Parallel()
	raw := fixtureOf(t, "known_password.zip")
	k := harness.File{Path: "k.zip", Content: raw, Members: sevenZipMembers(t, raw, "infected")}
	tests := []struct {
		policy string
		want   map[string]harness.Outcome
	}{
		{policy: "error", want: map[string]harness.Outcome{"k.zip": {In: harness.Output, NotAnalyzedMembers: harness.NoMembers()}, "k.zip/a.txt": {Submissions: 1}}},
		{policy: "pass", want: map[string]harness.Outcome{"k.zip": {In: harness.Output, NotAnalyzedMembers: harness.NoMembers()}, "k.zip/a.txt": {Submissions: 1}}},
		{policy: "mitigate", want: map[string]harness.Outcome{"k.zip": {In: harness.Output, NotAnalyzedMembers: harness.NoMembers()}, "k.zip/a.txt": {Submissions: 1}}},
	}
	for _, tt := range tests {
		t.Run(tt.policy, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  map[string]any{"unanalyzable_policy": map[string]any{"encrypted": tt.policy, "too_big": tt.policy}},
				Files:   []harness.File{k},
				Want:    tt.want,
			})
		})
	}
}

// From TestExtract_realEncryptionOrCorruption: what an encryption explains follows the encrypted policy, a corruption stays in INPUT as damaged.
func TestE2E_encryptionIsToldFromCorruption(t *testing.T) {
	t.Parallel()
	encrypted := harness.Outcome{In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedEncrypted}
	damaged := harness.Outcome{In: harness.Input, Error: errDamagedText}
	tests := []struct {
		name      string
		fixture   string
		passwords []string
		want      harness.Outcome
	}{
		{name: "(a) AES with the known password, one flipped byte", fixture: "aes_one_corrupt.zip", passwords: []string{"infected"}, want: damaged},
		{name: "(b) the same with an intact member next to it", fixture: "aes_two_corrupt.zip", passwords: []string{"infected"}, want: damaged},
		{name: "(c) ZipCrypto with an unknown password, six members", fixture: "zc6.zip", passwords: []string{"infected"}, want: encrypted},
		{name: "(d) 7z with encrypted content", fixture: "enc_content.7z", passwords: []string{"infected"}, want: encrypted},
		{name: "(d) 7z with encrypted headers", fixture: "enc_headers.7z", passwords: []string{"infected"}, want: encrypted},
		{name: "(e) a configured password that is wrong, after the known one that opened it", fixture: "aes_one_corrupt.zip", passwords: []string{"infected", "another-password"}, want: damaged},
		{name: "(f) a forged archive comment and a method 7-Zip does not know", fixture: "forged_comment.zip", passwords: []string{"infected"}, want: damaged},
		{name: "(g) non-solid 7z, known password, one member corrupted and one intact", fixture: "seven_two_corrupt.7z", passwords: []string{"infected"}, want: damaged},
		{name: "(g) solid 7z, known password, the last of three members corrupted", fixture: "solid3_corrupt.7z", passwords: []string{"infected"}, want: damaged},
		{name: "(h) two members with the same name, the first one corrupted, known password", fixture: "dup_corrupt.7z", passwords: []string{"infected"}, want: damaged},
		{name: "a plain member and an encrypted homonym with an unknown password", fixture: "homonym_mixed.7z", passwords: []string{"infected"}, want: damaged},
		{name: "six encrypted members and an empty one, unknown password", fixture: "enc_with_empty.7z", passwords: []string{"infected"}, want: encrypted},
		{name: "250 plain members and one ZipCrypto member with an unknown password: partial encryption", fixture: "mixed_many.zip", passwords: []string{"infected"}, want: encrypted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": {"default_passwords": tt.passwords}},
				Config:  map[string]any{"unanalyzable_policy": map[string]any{"encrypted": "pass"}},
				Files:   []harness.File{{Path: tt.fixture, Content: fixtureOf(t, tt.fixture)}},
				Want:    map[string]harness.Outcome{tt.fixture: tt.want},
			})
		})
	}
}
