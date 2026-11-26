//go:build linux && (e2e || e2e_plugins)

package plugins

import (
	"archive/zip"
	"bytes"
	le "encoding/binary"
	"hash/crc32"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

func zipOf(t *testing.T, members map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	// Sorted: the same members give the same bytes, hence the same SHA256.
	for _, name := range slices.Sorted(maps.Keys(members)) {
		content := members[name]
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.WriteString(w, content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func archive(t *testing.T, path string, pack func(*testing.T, map[string]string) []byte, members ...harness.File) harness.File {
	t.Helper()
	contents := make(map[string]string, len(members))
	for _, m := range members {
		contents[m.Path] = string(m.Content)
	}
	return harness.File{Path: path, Content: pack(t, contents), Members: members}
}

// P8/P9: an archive whose members are clean is delivered whole once every
// member was analyzed; one with a malicious member is quarantined whole and
// nothing of it reaches OUTPUT.
func TestE2E_archives(t *testing.T) {
	t.Parallel()
	one := []byte(strings.Repeat("member one ", 200))
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a clean zip and one with a malware",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Files: []harness.File{
					archive(t, "good.zip", zipOf,
						harness.File{Path: "m1.txt", Content: one},
						harness.File{Path: "m2.txt", Content: []byte(strings.Repeat("member two ", 200))},
					),
					archive(t, "bad.zip", zipOf,
						harness.File{Path: "ok.txt", Content: one},
						harness.File{Path: "evil.exe", Content: []byte(strings.Repeat("this member is a malware ", 100)), Verdict: harness.Malicious},
					),
				},
				Want: map[string]harness.Outcome{
					"good.zip": {In: harness.Output},
					"bad.zip":  {In: harness.Quarantine, Malware: datamodel.MalwareDetected},
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

// fixtureOf reads a fixture of the extract plugin's tests.
func fixtureOf(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(filepath.Join(harness.RepoRoot(t), "cmd", "plugins", "extract", "testdata", "archives", name)))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// T17b: a damaged archive that may hide an encryption, or a member path the
// extraction cannot handle, is never delivered as a plain file, whatever
// extract_error says: it stays in INPUT in error. Mirrors
// TestPipeline_asFileFollowsTheEncryptedPolicyWhenEncryptionIsPossible.
func TestE2E_extractErrorAsFile(t *testing.T) {
	t.Parallel()
	plain := zipOf(t, map[string]string{"a.txt": strings.Repeat("a plain member ", 100)})
	enc := fixtureOf(t, "enc_zipcrypto.zip")
	longName := strings.Repeat("a", 300)
	deep := strings.Repeat("d/", 70) + "x.txt"
	huge := strings.Repeat("h", 4100)
	const encryptedOrDamaged = "the archive is encrypted, or damaged and it cannot be told which"
	stored := storedZip(t, map[string]string{"a.txt": "plain member"})
	tests := []struct {
		name    string
		policy  string
		path    string
		content []byte
		err     string
	}{
		{name: "a cut plain archive stays under error", policy: "error", path: "a.zip", content: plain[:len(plain)*66/100], err: "damaged or inconsistent"},
		{name: "a cut encrypted archive stays under as_file", policy: "as_file", path: "a.zip", content: enc[:len(enc)*66/100], err: errEncryptedText},
		{name: "a cut encrypted archive stays under error", policy: "error", path: "a.zip", content: enc[:len(enc)*66/100], err: errEncryptedText},
		{name: "a plain archive followed by an encrypted one stays under as_file", policy: "as_file", path: "a.zip", content: append(append([]byte(nil), plain...), enc...), err: encryptedOrDamaged},
		{name: "a member with a path component over 255 bytes stays under as_file", policy: "as_file", path: "a.zip", content: zipOf(t, map[string]string{"d/" + longName + "/x.txt": "member"}), err: encryptedOrDamaged},
		{name: "a member with a path over 4096 bytes stays under as_file", policy: "as_file", path: "a.zip", content: zipOf(t, map[string]string{huge + "/x.txt": "member"}), err: encryptedOrDamaged},
		{name: "a member 70 folders deep stays under as_file", policy: "as_file", path: "a.zip", content: zipOf(t, map[string]string{deep: "member"}), err: encryptedOrDamaged},
		{name: "a 7z with a plain and an encrypted member of the same name stays under as_file", policy: "as_file", path: "homonym_mixed.7z", content: fixtureOf(t, "homonym_mixed.7z"), err: encryptedOrDamaged},
		{name: "a ZipCrypto zip whose password check collides with a default password stays under as_file", policy: "as_file", path: "zc_collision.zip", content: fixtureOf(t, "zc_collision.zip"), err: encryptedOrDamaged},
		{name: "an AES zip with a flipped byte stays under as_file", policy: "as_file", path: "aes_one_corrupt.zip", content: fixtureOf(t, "aes_one_corrupt.zip"), err: encryptedOrDamaged},
		{name: "a ZipCrypto zip whose local headers say not encrypted stays under as_file", policy: "as_file", path: "bit0.zip", content: clearLocalEncryptionBit(t, enc), err: encryptedOrDamaged},
		{name: "a plain zip with a CRC error stays under as_file", policy: "as_file", path: "damaged.zip", content: damagedPlainZip(t), err: encryptedOrDamaged},
		{name: "a 7z with encrypted headers cut at 50% stays under as_file", policy: "as_file", path: "cut50-enc_headers.7z", content: cut(fixtureOf(t, "enc_headers.7z"), 50), err: encryptedOrDamaged},
		{name: "a 7z with encrypted headers cut at 90% stays under as_file", policy: "as_file", path: "cut90-enc_headers.7z", content: cut(fixtureOf(t, "enc_headers.7z"), 90), err: encryptedOrDamaged},
		{name: "a 7z with encrypted content cut at 25% stays under as_file", policy: "as_file", path: "cut25-enc_content.7z", content: cut(fixtureOf(t, "enc_content.7z"), 25), err: encryptedOrDamaged},
		{name: "a 7z with encrypted content cut at 50% stays under as_file", policy: "as_file", path: "cut50-enc_content.7z", content: cut(fixtureOf(t, "enc_content.7z"), 50), err: encryptedOrDamaged},
		{name: "a 7z with encrypted content cut at 90% stays under as_file", policy: "as_file", path: "cut90-enc_content.7z", content: cut(fixtureOf(t, "enc_content.7z"), 90), err: encryptedOrDamaged},
		{name: "a plain zip followed by an encrypted 7z stays under as_file", policy: "as_file", path: "plain_then_enc7.zip", content: concat(stored, fixtureOf(t, "enc_content.7z")), err: encryptedOrDamaged},
		{name: "a plain zip followed by an AES zip stays under as_file", policy: "as_file", path: "plain_then_aes.zip", content: concat(stored, fixtureOf(t, "enc_aes.zip")), err: encryptedOrDamaged},
		{name: "a member name over the limit stays under as_file", policy: "as_file", path: "longname.zip", content: storedZip(t, map[string]string{"a.txt": "plain member", strings.Repeat("n", maxMemberNameLen+10): "plain too"}), err: encryptedOrDamaged},
		{name: "a member 64 folders deep stays under as_file", policy: "as_file", path: "deep.zip", content: storedZip(t, map[string]string{"a.txt": "plain member", strings.Repeat("f/", maxMemberDepth) + "deep.exe": "left out"}), err: encryptedOrDamaged},
		{name: "a zip folder entry that holds data stays under as_file", policy: "as_file", path: "folderdata.zip", content: folderDataZip(t), err: encryptedOrDamaged},
		{name: "a zip folder named with a slash that holds data stays under as_file", policy: "as_file", path: "slashfolder.zip", content: slashFolderZip(), err: encryptedOrDamaged},
		{name: "a tar directory that holds data stays under as_file", policy: "as_file", path: "folderdata.tar", content: folderDataTar(t), err: encryptedOrDamaged},
		{name: "a plain 7z followed by an encrypted 7z stays under as_file", policy: "as_file", path: "plain7_then_enc7.7z", content: concat(sevenZipOf(t, "7z", map[string][]byte{"a.txt": []byte("plain member")}), fixtureOf(t, "enc_content.7z")), err: encryptedOrDamaged},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  map[string]any{"unanalyzable_policy": map[string]any{"extract_error": tt.policy}},
				Files:   []harness.File{{Path: tt.path, Content: tt.content}},
				Want: map[string]harness.Outcome{
					tt.path: {In: harness.Input, Error: tt.err},
				},
			})
		})
	}
}

// D6: a detection always wins. An archive with a member that carries a
// detection and an analysis error, beside a member in analysis error, is
// malware: quarantined, never delivered, never left as a plain error; the report
// says malicious with the reason malware-detected, and the console is told it is
// a malware.
func TestE2E_aDetectionWithAnAnalysisErrorInAnArchiveIsMalware(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "archive",
			scenario: harness.Scenario{
				Agent:   true,
				Plugins: map[string]map[string]any{"extract": nil},
				Files: []harness.File{
					archive(t, "a.zip", zipOf,
						harness.File{Path: "evil.exe", Content: []byte(strings.Repeat("a member that is a malware with an error ", 40)), Verdict: harness.MaliciousWithError},
						harness.File{Path: "broken.txt", Content: []byte(strings.Repeat("a member whose analysis fails ", 40)), Verdict: harness.AnalysisError},
					),
				},
				Want: map[string]harness.Outcome{
					"a.zip": {In: harness.Quarantine, Malware: datamodel.MalwareDetected},
				},
				WantMitigations: []string{"malware"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// D6, guard of shipped behaviour: a detection wins in an archive. A plugin that
// waives a nested archive (its logical path is a skipped path) does not discard
// the detection of a member beside it: the outer archive is quarantined, never
// delivered. The detected member sorts first and the waived archive last. This
// does not exercise the T55 race (a waiver judged after the detection of the
// waived archive's own members): with the shipped plugins the waiver is judged
// first, so no e2e ordering fails before T55; the race is covered by the unit
// regression tests of T55, with a slow plugin hook.
func TestE2E_aDetectionBesideAWaivedNestedArchiveWins(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a detected member beside a skipped nested zip",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config: map[string]any{
					"workers":         4,
					"filepath_filter": map[string]any{"skipped_paths": []string{`outer\.zip/z-inner\.zip$`}},
				},
				Files: []harness.File{
					archive(t, "outer.zip", zipOf,
						harness.File{Path: "a-bad.bin", Content: []byte(strings.Repeat("a member that is a malware ", 40)), Verdict: harness.Malicious},
						archive(t, "z-inner.zip", zipOf, harness.File{Path: "x.txt", Content: []byte(strings.Repeat("a member of the waived archive ", 40))}),
					),
				},
				Want: map[string]harness.Outcome{
					"outer.zip": {In: harness.Quarantine, Malware: datamodel.MalwareDetected},
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

// D6, guard of shipped behaviour: a detection also outranks an archive that
// cannot be examined. An archive with a detected member and a nested encrypted
// archive (the policy of the encrypted files is error, which keeps a file in
// INPUT) is quarantined, not left in INPUT in error.
func TestE2E_aDetectionBeatsAnUnexaminableNestedArchive(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a detected member beside an encrypted nested zip",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Files: []harness.File{
					archive(t, "outer.zip", zipOf,
						harness.File{Path: "a-bad.bin", Content: []byte(strings.Repeat("a member that is a malware ", 40)), Verdict: harness.Malicious},
						harness.File{Path: "z-enc.zip", Content: fixtureOf(t, "enc_zipcrypto.zip")},
					),
				},
				Want: map[string]harness.Outcome{
					"outer.zip": {In: harness.Quarantine, Malware: datamodel.MalwareDetected, Error: "1 extracted file(s) in error, first: z-enc.zip: " + errEncryptedText},
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

// modeExecutable is the mode of the copy of the embedded 7-Zip.
const modeExecutable os.FileMode = 0o700

// sevenZip returns a copy of the embedded 7-Zip of the extract plugin that the
// tests can run, or skips the test when it is not there.
func sevenZip(t *testing.T) string {
	t.Helper()
	src := filepath.Join(harness.RepoRoot(t), "cmd", "plugins", "extract", "7zzs")
	in, err := os.Open(filepath.Clean(src))
	if err != nil {
		t.Skipf("embedded 7-Zip not available: %v", err)
	}
	defer func() {
		if e := in.Close(); e != nil {
			t.Logf("close: %v", e)
		}
	}()
	bin := filepath.Join(t.TempDir(), "7zzs")
	out, err := os.OpenFile(filepath.Clean(bin), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(bin, modeExecutable); err != nil {
		t.Fatal(err)
	}
	return bin
}

// headerEncrypted7z builds a 7z with the embedded 7-Zip whose headers and
// content are encrypted with "infected" (-mhe=on), the way samples are commonly
// shared. members maps a path in the archive to its content.
func headerEncrypted7z(t *testing.T, members map[string]string) []byte {
	t.Helper()
	bin := sevenZip(t)
	src := t.TempDir()
	paths := make([]string, 0, len(members))
	for name, content := range members {
		p := filepath.Join(src, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		harness.Write(t, p, []byte(content))
		paths = append(paths, name)
	}
	archive := filepath.Join(t.TempDir(), "he.7z")
	if out, err := harness.RunCommand(src, bin, append([]string{"a", "-t7z", "-mhe=on", "-pinfected", archive}, paths...)...); err != nil {
		t.Fatalf("cannot build the archive: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(filepath.Clean(archive))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A 7z with encrypted headers, whose password is a default one ("infected"), is
// extracted like any archive: with clean members it is delivered, after its members
// were analyzed; with a detected member it is quarantined.
func TestE2E_aHeaderEncryptedSevenZipWithADefaultPassword(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		other harness.Verdict
		want  map[string]harness.Outcome
	}{
		{name: "clean members", other: harness.Clean, want: map[string]harness.Outcome{
			"he.7z":             {In: harness.Output},
			"he.7z/d/clean.txt": {ServiceVerdict: harness.Given},
			"he.7z/other.bin":   {ServiceVerdict: harness.Given},
		}},
		{name: "a detected member", other: harness.Malicious, want: map[string]harness.Outcome{
			"he.7z": {In: harness.Quarantine, Malware: datamodel.MalwareDetected},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Files: []harness.File{
					archive(t, "he.7z", headerEncrypted7z,
						harness.File{Path: "d/clean.txt", Content: []byte(strings.Repeat("a clean member of the archive ", 40))},
						harness.File{Path: "other.bin", Content: []byte(strings.Repeat("a member that may be a malware ", 40)), Verdict: tt.other},
					),
				},
				Want: tt.want,
			})
		})
	}
}

// T51b: an archive with a member whose analysis failed follows the same value:
// under error it is counted in error (its report says members could not be
// analyzed) and stays in INPUT; under mitigate it is malware; under pass it is
// delivered, the member listed as not analyzed.
func TestE2E_analysisErrorInAnArchiveMember(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		value   string
		archive harness.Outcome
	}{
		{value: "error", archive: harness.Outcome{In: harness.Input, Error: "1 extracted file(s) could not be analyzed"}},
		{value: "mitigate", archive: harness.Outcome{In: harness.Quarantine, Malware: datamodel.AnalysisError}},
		{value: "pass", archive: harness.Outcome{In: harness.Output, NotAnalyzedMembers: &harness.MemberList{Reason: datamodel.NotAnalyzedAnalysisError}}},
	} {
		t.Run(tt.value, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  map[string]any{"unanalyzable_policy": map[string]any{"analysis_error": tt.value}},
				Files: []harness.File{
					archive(t, "a.zip", zipOf,
						harness.File{Path: "broken.txt", Content: []byte(strings.Repeat("a member whose analysis fails ", 40)), Verdict: harness.AnalysisError},
						harness.File{Path: "fine.txt", Content: []byte(strings.Repeat("a member analyzed without problem ", 40))},
					),
				},
				Want: map[string]harness.Outcome{
					"a.zip": tt.archive,
				},
			})
		})
	}
}

// T51b: pass never bypasses another policy. With analysis_error pass, an
// encrypted archive and a file above max_file_size still follow encrypted and
// too_big (error: they stay in INPUT).
func TestE2E_passNeverBypassesTheOtherPolicies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "an encrypted zip and a too big file",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config: map[string]any{
					"max_file_size":       "1MiB",
					"unanalyzable_policy": map[string]any{"analysis_error": "pass", "encrypted": "error", "too_big": "error"},
				},
				Files: []harness.File{
					{Path: "enc.zip", Content: fixtureOf(t, "enc_zipcrypto.zip")},
					{Path: "big.bin", Content: make([]byte, 2<<20)},
				},
				Want: map[string]harness.Outcome{
					"enc.zip": {In: harness.Input, Error: errEncryptedText},
					"big.bin": {In: harness.Input, Error: "file is too big to be analyzed"},
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

// rawEntry is one record of a hand-made ZIP: a file or a folder written stored,
// with the sizes it says (declared ones may lie), possibly never listed in the
// central directory, possibly followed by padding.
type rawEntry struct {
	name   string
	data   string
	folder bool
	// unlisted: the local record is written but the central directory does not
	// list it.
	unlisted bool
	// padAfter zero bytes follow the record.
	padAfter int
	// declared overrides the uncompressed size written in both headers (a lie
	// about a member whose packed size is zero), when not zero.
	declared uint32
}

// rawZip writes the entries as a ZIP, record by record, then the central
// directory of the listed ones. trailing follows the end of directory; decoy
// puts a copy of the directory and an end of directory that leads to it in the
// comment of the real one.
type rawZip struct {
	entries  []rawEntry
	trailing []byte
	decoy    bool
}

// u16 and u32 keep the low bits of a length for a header field: the hand-made
// archives of the tests are small.
func u16(n int) uint16 { return uint16(n & 0xFFFF) }

func u32(n int) uint32 { return uint32(n & 0xFFFFFFFF) }

func (z rawZip) bytes() []byte {
	var out, dir []byte
	listed := 0
	for _, e := range z.entries {
		offset := u32(len(out))
		data := []byte(e.data)
		crc := crc32.ChecksumIEEE(data)
		comp, uncomp := u32(len(data)), u32(len(data))
		if e.declared != 0 {
			uncomp = e.declared
		}
		name := e.name
		if e.folder && !strings.HasSuffix(name, "/") {
			name += "/"
		}
		out = le.LittleEndian.AppendUint32(out, 0x04034b50)
		out = le.LittleEndian.AppendUint16(out, 20)
		out = le.LittleEndian.AppendUint16(out, 0)
		out = le.LittleEndian.AppendUint16(out, 0)
		out = le.LittleEndian.AppendUint32(out, 0)
		out = le.LittleEndian.AppendUint32(out, crc)
		out = le.LittleEndian.AppendUint32(out, comp)
		out = le.LittleEndian.AppendUint32(out, uncomp)
		out = le.LittleEndian.AppendUint16(out, u16(len(name)))
		out = le.LittleEndian.AppendUint16(out, 0)
		out = append(out, name...)
		out = append(out, data...)
		out = append(out, make([]byte, e.padAfter)...)
		if e.unlisted {
			continue
		}
		listed++
		dir = le.LittleEndian.AppendUint32(dir, 0x02014b50)
		dir = le.LittleEndian.AppendUint16(dir, 20)
		dir = le.LittleEndian.AppendUint16(dir, 20)
		dir = le.LittleEndian.AppendUint16(dir, 0)
		dir = le.LittleEndian.AppendUint16(dir, 0)
		dir = le.LittleEndian.AppendUint32(dir, 0)
		dir = le.LittleEndian.AppendUint32(dir, crc)
		dir = le.LittleEndian.AppendUint32(dir, comp)
		dir = le.LittleEndian.AppendUint32(dir, uncomp)
		dir = le.LittleEndian.AppendUint16(dir, u16(len(name)))
		dir = le.LittleEndian.AppendUint16(dir, 0)
		dir = le.LittleEndian.AppendUint16(dir, 0)
		dir = le.LittleEndian.AppendUint16(dir, 0)
		dir = le.LittleEndian.AppendUint16(dir, 0)
		dir = le.LittleEndian.AppendUint32(dir, 0)
		dir = le.LittleEndian.AppendUint32(dir, offset)
		dir = append(dir, name...)
	}
	cdOffset := u32(len(out))
	eocd := func(offset uint32, comment []byte) []byte {
		b := le.LittleEndian.AppendUint32(nil, 0x06054b50)
		b = le.LittleEndian.AppendUint16(b, 0)
		b = le.LittleEndian.AppendUint16(b, 0)
		b = le.LittleEndian.AppendUint16(b, u16(listed))
		b = le.LittleEndian.AppendUint16(b, u16(listed))
		b = le.LittleEndian.AppendUint32(b, u32(len(dir)))
		b = le.LittleEndian.AppendUint32(b, offset)
		b = le.LittleEndian.AppendUint16(b, u16(len(comment)))
		return append(b, comment...)
	}
	var comment []byte
	if z.decoy {
		copyAt := cdOffset + u32(len(dir)) + 22
		comment = append(append([]byte(nil), dir...), eocd(copyAt, nil)...)
	}
	out = append(out, dir...)
	out = append(out, eocd(cdOffset, comment)...)
	return append(out, z.trailing...)
}

// T17d: the headers of a ZIP are walked. A record that the directory does not
// list (hidden between two entries, or after an empty folder) is an anomaly: the
// archive stays in INPUT, never delivered. The same archive without that record
// (the control), zero padding between entries, and a stored jar inside a jar are
// honest: the archive is delivered after each of its members was analyzed. A
// second end of directory that also ends the file, hidden in the comment of the
// real one, is a decoy: an anomaly, with or without a byte after the real end.
// One byte after the end of the archive is an anomaly too.
func TestE2E_theHeadersOfAZipAreWalked(t *testing.T) {
	t.Parallel()
	member := []byte(strings.Repeat("a plain member of the archive ", 40))
	second := []byte(strings.Repeat("a plain member of the archive ", 40) + "!")
	evil := strings.Repeat("a record the directory does not list ", 40)
	manifest := []byte("Manifest-Version: 1.0\n")
	inner := rawZip{entries: []rawEntry{{name: "Inner.class", data: string(member)}}}.bytes()
	held := harness.Outcome{In: harness.Input, Error: "damaged or inconsistent"}
	delivered := harness.Outcome{In: harness.Output}
	tests := []struct {
		name string
		zip  rawZip
		want harness.Outcome
		// members of a delivered archive, and the ones the service must have analyzed.
		members  []harness.File
		analyzed []string
	}{
		{name: "an empty folder and a member, with no hidden record (the control)", zip: rawZip{entries: []rawEntry{
			{name: "d", folder: true}, {name: "a.txt", data: string(member)},
		}}, want: delivered, members: []harness.File{{Path: "a.txt", Content: member}}, analyzed: []string{"a.zip/a.txt"}},
		{name: "a record hidden after an empty folder", zip: rawZip{entries: []rawEntry{
			{name: "d", folder: true}, {name: "evil.exe", data: evil, unlisted: true}, {name: "a.txt", data: string(member)},
		}}, want: held},
		{name: "a record hidden between two entries", zip: rawZip{entries: []rawEntry{
			{name: "a.txt", data: string(member)}, {name: "evil.exe", data: evil, unlisted: true}, {name: "b.txt", data: string(second)},
		}}, want: held},
		{name: "zero padding between entries", zip: rawZip{entries: []rawEntry{
			{name: "a.txt", data: string(member), padAfter: 64}, {name: "b.txt", data: string(second)},
		}}, want: delivered, members: []harness.File{{Path: "a.txt", Content: member}, {Path: "b.txt", Content: second}}, analyzed: []string{"a.zip/a.txt", "a.zip/b.txt"}},
		{name: "a stored jar inside a jar", zip: rawZip{entries: []rawEntry{
			{name: "inner.jar", data: string(inner)}, {name: "META-INF/MANIFEST.MF", data: string(manifest)},
		}}, want: delivered, members: []harness.File{
			{Path: "inner.jar", Content: inner, Members: []harness.File{{Path: "Inner.class", Content: member}}},
			{Path: "META-INF/MANIFEST.MF", Content: manifest},
		}, analyzed: []string{"a.zip/inner.jar/Inner.class", "a.zip/META-INF/MANIFEST.MF"}},
		{name: "one byte after the end of the archive", zip: rawZip{trailing: []byte{0}, entries: []rawEntry{
			{name: "a.txt", data: string(member)},
		}}, want: held},
		{name: "a decoy end of directory alone", zip: rawZip{decoy: true, entries: []rawEntry{
			{name: "a.txt", data: string(member)},
		}}, want: held},
		{name: "a decoy end of directory and one byte after the real one", zip: rawZip{decoy: true, trailing: []byte{0}, entries: []rawEntry{
			{name: "a.txt", data: string(member)},
		}}, want: held},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := map[string]harness.Outcome{"a.zip": tt.want}
			for _, key := range tt.analyzed {
				want[key] = harness.Outcome{ServiceVerdict: harness.Given}
			}
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Files:   []harness.File{{Path: "a.zip", Content: tt.zip.bytes(), Members: tt.members}},
				Want:    want,
			})
		})
	}
}

// p3/T59: a member is submitted to GLIMPS Malware Detect under the host path of
// its archive followed by its path inside it, nested archives included, and
// never under a path of the work folder. A plain file keeps its host path.
func TestE2E_anArchiveMemberIsSubmittedUnderItsArchivePath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a member, a member of a nested archive and a plain file",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Files: []harness.File{
					archive(t, "a.zip", zipOf, harness.File{Path: "d/evil.bin", Content: []byte(strings.Repeat("an unknown member of an archive ", 40))}),
					archive(t, "o/outer.zip", zipOf,
						archive(t, "inner.zip", zipOf, harness.File{Path: "sub/x.bin", Content: []byte(strings.Repeat("a member of an archive in an archive ", 40))}),
					),
					{Path: "plain.txt", Content: []byte(strings.Repeat("an ordinary deposit ", 40))},
				},
				Want: map[string]harness.Outcome{
					"a.zip":                           {In: harness.Output},
					"a.zip/d/evil.bin":                {SubmittedAs: []string{"a.zip/d/evil.bin"}},
					"o/outer.zip":                     {In: harness.Output},
					"o/outer.zip/inner.zip/sub/x.bin": {SubmittedAs: []string{"o/outer.zip/inner.zip/sub/x.bin"}},
					"plain.txt":                       {In: harness.Output, SubmittedAs: []string{"plain.txt"}},
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

// p3/T59 (F6): a label over 4096 bytes is cut to 4096 at most, keeps its tail
// after a leading "…", and stays valid UTF-8.
func TestE2E_aLongLabelIsCappedKeepingTheTail(t *testing.T) {
	tests := []struct {
		name              string
		hostDirs, members int
	}{
		{name: "15 host folders and 6 member folders of 199 bytes", hostDirs: 15, members: 6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := gmalware.New(t)
			in := harness.Start(t, gm, harness.Options{Plugins: map[string]map[string]any{"extract": nil}})
			evil := []byte(strings.Repeat("a member with a very long path ", 40))
			memberDir := strings.TrimSuffix(strings.Repeat(strings.Repeat("m", 199)+"/", tt.members), "/")
			member := memberDir + "/last.bin"
			archive := zipOf(t, map[string]string{member: string(evil)})
			in.Expect.Archive(archive, evil)
			hostDir := strings.TrimSuffix(strings.Repeat(strings.Repeat("h", 199)+"/", tt.hostDirs), "/")
			archivePath := in.Drop(t, hostDir+"/a.zip", archive)
			full := archivePath + "/" + member
			if len(full) <= 4096 {
				t.Fatalf("the label is only %d bytes: the cap is not exercised", len(full))
			}
			names := in.NamesOf(t, evil)
			if len(names) != 1 {
				t.Fatalf("names = %d, want 1", len(names))
			}
			label := names[0]
			if len(label) > 4096 {
				t.Errorf("label of %d bytes, want at most 4096", len(label))
			}
			if len(label) < 4096-8 {
				t.Errorf("label of %d bytes: cut much more than needed", len(label))
			}
			if !strings.HasPrefix(label, "…") {
				t.Errorf("label starts with %.20q, want the ellipsis", label)
			}
			if !utf8.ValidString(label) {
				t.Error("label is not valid UTF-8")
			}
			if tail := strings.TrimPrefix(label, "…"); !strings.HasSuffix(full, tail) || !strings.HasSuffix(label, "/last.bin") {
				t.Errorf("label does not keep the tail of the path: ends with %q", label[max(0, len(label)-40):])
			}
		})
	}
}

// T11: an archive whose outcome is final (a member over max_file_size leaves
// it out of the extraction) is extracted once, not at every rescan: its failed
// extraction is reported once (the archive is watched in INPUT for
// harness.NotDeliveredWindow, about 12 rescans).
func TestE2E_anArchiveWithATooBigMemberIsExtractedOnlyOnce(t *testing.T) {
	tests := []struct {
		name    string
		members map[string]string
		want    harness.Outcome
	}{
		{
			name:    "about 12 rescans",
			members: map[string]string{"ok.txt": strings.Repeat("a normal member ", 100), "huge.bin": strings.Repeat("\x00", 2<<20)},
			want:    harness.Outcome{In: harness.Input, Error: "file is too big to be analyzed"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archive := zipOf(t, tt.members)
			in := harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config: map[string]any{
					"max_file_size": "1MiB",
					"actions":       map[string]any{"move": false},
					"monitoring":    map[string]any{"disable_fs_watcher": true, "period": time.Second.String()},
				},
				Files: []harness.File{{Path: "bomb.zip", Content: archive}},
				Want:  map[string]harness.Outcome{"bomb.zip": tt.want},
			})
			// The stop writes the report of the open session: an extraction at a rescan
			// would be in it.
			in.Stop(t)
			if got := len(in.ReportsOf(t, archive)); got != 1 {
				t.Errorf("the archive was reported %d times, want 1: an archive whose outcome is final must not be extracted at every rescan", got)
			}
		})
	}
}
