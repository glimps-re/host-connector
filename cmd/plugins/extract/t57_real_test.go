package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

// headerEncrypted7z builds, with the embedded 7-Zip, a 7z whose headers and
// content are encrypted with the password "infected" (-mhe=on), the way samples
// are commonly shared. members maps a path inside the archive to its content.
func headerEncrypted7z(t *testing.T, plugin *SevenZipExtractPlugin, members map[string]string) string {
	t.Helper()
	src := t.TempDir()
	paths := make([]string, 0, len(members))
	for name, content := range members {
		p := filepath.Join(src, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, name)
	}
	archive := filepath.Join(t.TempDir(), "he.7z")
	// 7-Zip stores the paths it is given: run it in the source folder.
	args := append([]string{"a", "-t7z", "-mhe=on", "-pinfected", archive}, paths...)
	if out, err := runCmdIn(t.Context(), src, plugin.sze.sevenZipPath, args...); err != nil {
		t.Fatalf("cannot build the archive: %v\n%s", err, out)
	}
	return archive
}

// A 7z whose headers are encrypted, with a password that is a default one, is
// extracted: the members are listed and written, and no unclassified error comes
// of the first attempt, made without the password.
func TestExtract_aHeaderEncryptedSevenZipWithADefaultPassword(t *testing.T) {
	cases := map[string]map[string]string{
		"no folder":       {"a.txt": "a plain member", "b.txt": "another plain member"},
		"folder and file": {"d/c.txt": "a member in a folder", "top.txt": "a member at the top"},
	}
	for name, members := range cases {
		t.Run(name, func(t *testing.T) {
			plugin := realPlugin(t)
			plugin.sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
			archive := headerEncrypted7z(t, plugin, members)

			out := t.TempDir()
			extraction, err := plugin.ExtractFile(archive, out, plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100, MaxTotalSize: 1 << 30})
			if err != nil {
				t.Fatalf("the extraction failed: %v", err)
			}
			got := map[string]bool{}
			for _, f := range extraction.Files {
				rel, relErr := filepath.Rel(out, f)
				if relErr != nil {
					t.Fatal(relErr)
				}
				got[rel] = true
			}
			for member := range members {
				if !got[member] {
					t.Errorf("member %q not extracted; got %v", member, extraction.Files)
				}
			}
		})
	}
}

// Checking such an archive, which is done without any password, says that it is
// encrypted: its headers cannot be read.
func TestCheckOnly_aHeaderEncryptedSevenZipIsEncrypted(t *testing.T) {
	plugin := realPlugin(t)
	plugin.sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
	archive := headerEncrypted7z(t, plugin, map[string]string{"a.txt": "a plain member"})
	_, err := plugin.ExtractFile(archive, t.TempDir(), plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100, MaxTotalSize: 1 << 30, CheckOnly: true})
	if !errors.Is(err, plugins.ErrEncrypted) {
		t.Fatalf("the check = %v, want plugins.ErrEncrypted", err)
	}
}

// 7-Zip 25.01 refuses an archive with encrypted headers on one line when it lists
// it and on two when it extracts it. Both are a wrong password; the second counts
// only right after the line of the archive's path.
func TestClassifyStderr_aRefusalOfAnArchiveWithEncryptedHeaders(t *testing.T) {
	const archive = "/work/he.7z"
	tests := []struct {
		name   string
		stderr string
		want   sevenZipOutput
	}{
		{"listing, one line", "ERROR: " + archive + " : Cannot open encrypted archive. Wrong password?\n\nERRORS:\nHeaders Error\n", sevenZipOutput{wrongPassword: true, recoverable: true}},
		{"extraction, two lines", "ERROR: " + archive + "\nCannot open encrypted archive. Wrong password?\n\nERRORS:\nHeaders Error\n", sevenZipOutput{wrongPassword: true, recoverable: true}},
		{"extraction, the spelling of p7zip 16.02", "ERROR: " + archive + "\nCan not open encrypted archive. Wrong password?\n", sevenZipOutput{wrongPassword: true}},
		{"the sentence alone is not a refusal", "Cannot open encrypted archive. Wrong password?\n\nERRORS:\nHeaders Error\n", sevenZipOutput{recoverable: true}},
		{"after another line than the path", "ERROR: /elsewhere/x\nCannot open encrypted archive. Wrong password?\n", sevenZipOutput{other: true}},
		{"after a line of a member", "ERROR: Data Error : a.txt\nCannot open encrypted archive. Wrong password?\n", sevenZipOutput{recoverable: true}},
		{"the path alone is an unknown error", "ERROR: " + archive + "\n", sevenZipOutput{other: true}},
		{"the path then another sentence", "ERROR: " + archive + "\nsomething else\n", sevenZipOutput{other: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if out := classifyStderr(tt.stderr, []string{archive}); !reflect.DeepEqual(out, tt.want) {
				t.Errorf("classifyStderr() = %+v, want %+v", out, tt.want)
			}
		})
	}
}

// 7-Zip is run on a name of ours, so that the path it prints in an error is one that
// can be neutralized, whatever the depositor named the archive: 7-Zip prints a
// control character of a name in another form than the one it was given.
func TestExtract_anArchiveNamedByTheDepositorIsRunUnderAName(t *testing.T) {
	plugin := realPlugin(t)
	plugin.sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
	source := headerEncrypted7z(t, plugin, map[string]string{"a.txt": "a plain member"})
	for _, name := range []string{"n\nx.7z", "tab\there.7z", "esc\x1b[31m.7z", "bidi\u202ename.7z", "-option.7z", "ünï côde.7z", "invalid\xff\xfe.7z", strings.Repeat("long", 80) + ".7z"} {
		t.Run(strconv.Quote(name), func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), name)
			if err := os.Link(source, archive); err != nil {
				if err = os.Symlink(source, archive); err != nil {
					t.Skipf("cannot name the archive: %v", err)
				}
			}
			out := t.TempDir()
			extraction, err := plugin.ExtractFile(archive, out, plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100, MaxTotalSize: 1 << 30})
			if err != nil || len(extraction.Files) != 1 {
				t.Fatalf("ExtractFile() = %v, %v, want the member extracted", extraction.Files, err)
			}
			// With no password to give, the refusal is the one of an encrypted archive.
			plugin.sze.config = extractorConfig{}
			if _, err = plugin.ExtractFile(archive, t.TempDir(), plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100, MaxTotalSize: 1 << 30}); !errors.Is(err, plugins.ErrEncrypted) {
				t.Errorf("without the password: ExtractFile() = %v, want plugins.ErrEncrypted", err)
			}
			plugin.sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
		})
	}
}

func TestStagedName(t *testing.T) {
	for in, want := range map[string]string{
		"a.7z":                   "a.7z",
		"n\nx.7z":                "n_x.7z",
		"x.txt.gz":               "x.txt.gz",
		"-option.7z":             "archive-option.7z",
		"...":                    "archive...",
		"":                       "archive",
		"ünï.7z":                 "_n_.7z",
		"a b+c@d=e,f~g(h)-i.zip": "a b+c@d=e,f~g(h)-i.zip",
		"a\xffb":                 "a_b",
		"\u202eevil.7z":          "_evil.7z",
	} {
		if got := stagedName(in); got != want {
			t.Errorf("stagedName(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("a", 300) + ".7z"
	if got := stagedName(long); len(got) != maxStagedName || !strings.HasSuffix(got, ".7z") {
		t.Errorf("stagedName(long) = %q, want %d bytes ending with .7z", got, maxStagedName)
	}
}

// The file inside a single-file compressor is named after the archive: staging keeps
// the name, so the member is named as it was.
func TestExtract_aSingleFileCompressorKeepsTheNameOfItsMember(t *testing.T) {
	plugin := realPlugin(t)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte("the content of the member")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "report.txt.gz")
	if err := os.WriteFile(archive, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	extraction, err := plugin.ExtractFile(archive, out, plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100, MaxTotalSize: 1 << 30})
	if err != nil || len(extraction.Files) != 1 || filepath.Base(extraction.Files[0]) != "report.txt" {
		t.Errorf("ExtractFile() = %v, %v, want the member report.txt", extraction.Files, err)
	}
}

// Staging leaves nothing behind, whether the extraction works or fails, and a work
// directory that cannot be used is a failure of the host, not of the archive.
func TestStage_leavesNothingBehind(t *testing.T) {
	plugin := realPlugin(t)
	work := t.TempDir()
	plugin.sze.workDir = work
	archive := headerEncrypted7z(t, plugin, map[string]string{"a.txt": "a plain member"})
	plugin.sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
	limits := plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100, MaxTotalSize: 1 << 30}
	if _, err := plugin.ExtractFile(archive, t.TempDir(), limits); err != nil {
		t.Fatal(err)
	}
	plugin.sze.config = extractorConfig{}
	if _, err := plugin.ExtractFile(archive, t.TempDir(), limits); !errors.Is(err, plugins.ErrEncrypted) {
		t.Fatalf("ExtractFile() = %v, want plugins.ErrEncrypted", err)
	}
	limits.CheckOnly = true
	if _, err := plugin.ExtractFile(archive, t.TempDir(), limits); !errors.Is(err, plugins.ErrEncrypted) {
		t.Fatalf("the check = %v, want plugins.ErrEncrypted", err)
	}
	if entries, err := os.ReadDir(work); err != nil || len(entries) != 0 {
		t.Errorf("work directory = %v (%v), want it empty", entries, err)
	}

	plugin.sze.workDir = filepath.Join(work, "absent")
	_, err := plugin.ExtractFile(archive, t.TempDir(), plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100, MaxTotalSize: 1 << 30})
	if err == nil || errors.Is(err, plugins.ErrEncrypted) || errors.Is(err, plugins.ErrArchiveAnomaly) || errors.Is(err, plugins.ErrUnsupportedFormat) {
		t.Errorf("ExtractFile() in a work directory that is missing = %v, want a plain failure of the host", err)
	}
}
