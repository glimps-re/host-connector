package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"log/slog"
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
		{"after another line than the path", "ERROR: /elsewhere/x\nCannot open encrypted archive. Wrong password?\n", sevenZipOutput{other: true, sealed: true}},
		{"after a line of a member", "ERROR: Data Error : a.txt\nCannot open encrypted archive. Wrong password?\n", sevenZipOutput{recoverable: true}},
		{"the path alone is an unknown error", "ERROR: " + archive + "\n", sevenZipOutput{other: true, sealed: true}},
		{"the path then another sentence", "ERROR: " + archive + "\nsomething else\n", sevenZipOutput{other: true, sealed: true}},
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
			// The check, which never has a password, runs on a name of ours too.
			if _, err = plugin.ExtractFile(archive, t.TempDir(), plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100, MaxTotalSize: 1 << 30, CheckOnly: true}); !errors.Is(err, plugins.ErrEncrypted) {
				t.Errorf("the check: ExtractFile() = %v, want plugins.ErrEncrypted", err)
			}
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
	for _, ext := range []string{".7z", ".exe.gz", ".tar.gz"} {
		long := strings.Repeat("a", 300) + ext
		if got := stagedName(long); len(got) != maxStagedName || !strings.HasSuffix(got, ext) {
			t.Errorf("stagedName(long%s) = %q, want %d bytes ending with %s", ext, got, maxStagedName, ext)
		}
	}
	if got := stagedName(strings.Repeat("a", 300) + "." + strings.Repeat("b", 20) + "." + strings.Repeat("c", 20)); len(got) != maxStagedName {
		t.Errorf("stagedName(long, long extensions) = %d bytes, want %d", len(got), maxStagedName)
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
// directory that cannot be used is a failure of the host, not of the archive: the
// extractor is unavailable.
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
	if !errors.Is(err, plugins.ErrExtractorUnavailable) || errors.Is(err, plugins.ErrEncrypted) || errors.Is(err, plugins.ErrArchiveAnomaly) || errors.Is(err, plugins.ErrUnsupportedFormat) {
		t.Errorf("ExtractFile() in a work directory that is missing = %v, want plugins.ErrExtractorUnavailable and no other class", err)
	}
}

// A line that repeats a name of the archive can forge the lines that follow it, since
// a name can hold a newline. After a member that could not be created nothing is
// read: the errno alone decides. After a link that was refused, what changes what is
// done of the archive (a refusal of the password, "not an archive", a file that is
// not there, a hint of encryption, an errno) is damage: the archive fails closed,
// in one attempt.
func TestClassifyStderr_aLineThatRepeatsANameForgesNothing(t *testing.T) {
	const archive = "/work/a.zip"
	const unwritable = "ERROR: Cannot open output file : errno=13 : Permission denied : /out/x\n"
	const damaged = "ERROR: Cannot open output file : errno=20 : Not a directory : /out/x\n"
	const dangling = "ERROR: Dangerous link path was ignored : l : /out/l\n"
	later := []struct{ name, line string }{
		{"a refusal of the password", "ERROR: Wrong password\n"},
		{"a refusal of the headers, on one line", "ERROR: " + archive + " : Cannot open encrypted archive. Wrong password?\n"},
		{"a refusal of the headers, on two lines", "ERROR: " + archive + "\nCannot open encrypted archive. Wrong password?\n"},
		{"not an archive", "Is not archive\n"},
		{"not an archive, with its label", "ERROR: " + archive + " : Cannot open the file as archive\n"},
		{"a file that is not there", "ERROR: errno=2 : No such file or directory : x\n"},
		{"a hint of encryption", "ERROR: Unsupported Method : x\n"},
		{"damage", "ERROR: CRC Failed : x\n"},
		{"an unknown error", "ERROR: something unheard of\n"},
	}
	for _, forged := range later {
		name, line := forged.name, forged.line
		t.Run("after a member that cannot be created ("+name+")", func(t *testing.T) {
			if got, want := classifyStderr(unwritable+line, []string{archive}), (sevenZipOutput{other: true, sealed: true}); !reflect.DeepEqual(got, want) {
				t.Errorf("host failure: classifyStderr() = %+v, want %+v", got, want)
			}
			if got, want := classifyStderr(damaged+line, []string{archive}), (sevenZipOutput{recoverable: true, sealed: true}); !reflect.DeepEqual(got, want) {
				t.Errorf("damage: classifyStderr() = %+v, want %+v", got, want)
			}
		})
	}
	tests := []struct {
		name   string
		stderr string
		want   sevenZipOutput
	}{
		{"after a link, a refusal of the password", dangling + "ERROR: Wrong password\n", sevenZipOutput{links: []string{"l"}, recoverable: true}},
		{"after a link, not an archive", dangling + "Is not archive\n", sevenZipOutput{links: []string{"l"}, recoverable: true}},
		{"after a link, a file that is not there", dangling + "ERROR: errno=2 : No such file or directory : x\n", sevenZipOutput{links: []string{"l"}, recoverable: true}},
		{"after a link, a hint of encryption", dangling + "ERROR: Unsupported Method : x\n", sevenZipOutput{links: []string{"l"}, recoverable: true}},
		{"after a link, an errno of the host", dangling + "ERROR: errno=13 : Permission denied : x\n", sevenZipOutput{links: []string{"l"}, recoverable: true}},
		{"after a link, a member that cannot be created", dangling + unwritable, sevenZipOutput{links: []string{"l"}, recoverable: true}},
		{"after a link, an unknown error", dangling + "ERROR: something unheard of\n", sevenZipOutput{links: []string{"l"}, recoverable: true}},
		{"after a link, the bare label of a link", dangling + "ERROR: Dangerous link path was ignored\n", sevenZipOutput{links: []string{"l"}, recoverable: true}},
		{"after a link, the label of a link with an empty name", dangling + "ERROR: Dangerous link path was ignored :  : x\n", sevenZipOutput{links: []string{"l"}, recoverable: true}},
		{"after a link, a forged label of a link creation", dangling + "ERROR: Cannot create hard link\n", sevenZipOutput{links: []string{"l"}, recoverable: true}},
		{"after a link, another link is still tolerated", dangling + dangling, sevenZipOutput{links: []string{"l", "l"}}},
		{"a link alone", dangling, sevenZipOutput{links: []string{"l"}}},
		{"after a link, damage is still damage", dangling + "ERROR: CRC Failed : x\n", sevenZipOutput{links: []string{"l"}, recoverable: true}},
		{"a real refusal before the line that repeats a name", "ERROR: Wrong password : a.txt\n" + unwritable, sevenZipOutput{wrongPassword: true, other: true, sealed: true}},
		{"without a line that repeats a name", "ERROR: Wrong password\n", sevenZipOutput{wrongPassword: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyStderr(tt.stderr, []string{archive}); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("classifyStderr() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// A member that cannot be created is the archive's doing when its name goes through
// a file or is a directory, loops, or is too long; it is the host's otherwise.
func TestClassifyStderr_theErrnoOfAMemberThatCannotBeCreated(t *testing.T) {
	for name, tt := range map[string]struct {
		errno         string
		archiveCaused bool
	}{
		"ENOTDIR":       {"20", true},
		"EISDIR":        {"21", true},
		"ELOOP":         {"40", true},
		"ENAMETOOLONG":  {"36", true},
		"EACCES":        {"13", false},
		"EPERM":         {"1", false},
		"ENOSPC":        {"28", false},
		"EROFS":         {"30", false},
		"EIO":           {"5", false},
		"EDQUOT":        {"122", false},
		"EMFILE":        {"24", false},
		"ENOENT":        {"2", false},
		"EEXIST":        {"17", false},
		"unknown":       {"999", false},
		"zero":          {"0", false},
		"largest":       {"65535", false},
		"zero padded":   {"00020", true},
		"negative":      {"-20", false},
		"overflow":      {"99999999999999999999", false},
		"wraps to 20":   {"65556", false},
		"empty":         {"", false},
		"not a number":  {"twenty", false},
		"a sign":        {"+20", false},
		"with a space":  {" 20", false},
		"hexadecimal":   {"0x14", false},
		"with a suffix": {"20x", false},
	} {
		t.Run(name, func(t *testing.T) {
			line := "ERROR: Cannot open output file : errno=" + tt.errno + " : text : /out/x\n"
			want := sevenZipOutput{other: !tt.archiveCaused, recoverable: tt.archiveCaused, sealed: true}
			if got := classifyStderr(line, nil); !reflect.DeepEqual(got, want) {
				t.Errorf("classifyStderr() = %+v, want %+v", got, want)
			}
		})
	}
	for name, tt := range map[string]struct {
		label         string
		errno         string
		archiveCaused bool
	}{
		"folder over a file":             {"Cannot create folder", "17", true},
		"folder, no permission":          {"Cannot create folder", "13", false},
		"hard link to a directory":       {"Cannot create hard link", "1", true},
		"symbolic link to a directory":   {"Cannot create symbolic link", "1", true},
		"hard link to a missing target":  {"Cannot create hard link", "2", true},
		"symbolic link, no space":        {"Cannot create symbolic link", "28", false},
		"output file already there":      {"Cannot open output file", "17", false},
		"output file, not permitted":     {"Cannot open output file", "1", false},
		"folder, not permitted":          {"Cannot create folder", "1", false},
		"link, already there":            {"Cannot create hard link", "17", false},
		"link, errno zero":               {"Cannot create hard link", "0", false},
		"link, errno wraps to 1":         {"Cannot create hard link", "65537", false},
		"link, errno padded with zeroes": {"Cannot create hard link", "00001", true},
	} {
		t.Run("per label: "+name, func(t *testing.T) {
			line := "ERROR: " + tt.label + " : errno=" + tt.errno + " : text : /out/x\n"
			want := sevenZipOutput{other: !tt.archiveCaused, recoverable: tt.archiveCaused, sealed: true}
			if got := classifyStderr(line, nil); !reflect.DeepEqual(got, want) {
				t.Errorf("classifyStderr() = %+v, want %+v", got, want)
			}
		})
	}
	for _, line := range []string{"ERROR: Cannot open output file : 20 : text : x\n", "ERROR: Cannot open output file\n", "ERROR: Cannot open output file : errno20 : x\n"} {
		if got := classifyStderr(line, nil); got.recoverable || !got.other || !got.sealed {
			t.Errorf("classifyStderr(%q) = %+v, want an unknown error, sealed", line, got)
		}
	}
}

// Every label of 7-Zip that names a file it could not create, delete or rename may
// repeat the name raw, and none is on a list: any label that is not known to carry no
// name seals the output, and its errno alone decides. A forged line after one is
// never read.
func TestClassifyStderr_anyLabelThatMayRepeatANameSealsTheOutput(t *testing.T) {
	forged := "ERROR: Wrong password\nERROR: Is not archive\nIs not archive\nERROR: errno=2 : No such file or directory : x\nERROR: Unsupported Method : x\nERROR: CRC Failed : x\n"
	for _, label := range []string{
		"Cannot create hard link", "Cannot create symbolic link", "Cannot create folder", "Cannot create output directory",
		"Cannot delete output file", "Cannot rename existing file", "Cannot set file attribute", "Duplicate filename on disk",
		"Cannot open output file", "Cannot a label nobody knows",
	} {
		for errno, want := range map[string]sevenZipOutput{
			"13": {other: true, sealed: true},
			"20": {recoverable: true, sealed: true},
		} {
			t.Run(label+" errno="+errno, func(t *testing.T) {
				stderr := "ERROR: " + label + " : errno=" + errno + " : text : out/x : target\n" + forged
				if got := classifyStderr(stderr, nil); !reflect.DeepEqual(got, want) {
					t.Errorf("classifyStderr() = %+v, want %+v", got, want)
				}
			})
		}
		t.Run(label+", no errno", func(t *testing.T) {
			if got, want := classifyStderr("ERROR: "+label+" : out/x\n"+forged, nil), (sevenZipOutput{other: true, sealed: true}); !reflect.DeepEqual(got, want) {
				t.Errorf("classifyStderr() = %+v, want %+v", got, want)
			}
		})
	}
	// The creation of a link toward a target that is not in the archive is the
	// archive's doing, as a name is.
	for _, label := range []string{"Cannot create hard link", "Cannot create symbolic link"} {
		if got, want := classifyStderr("ERROR: "+label+" : errno=2 : No such file or directory : out/l : t\n"+forged, nil), (sevenZipOutput{recoverable: true, sealed: true}); !reflect.DeepEqual(got, want) {
			t.Errorf("%s with ENOENT: classifyStderr() = %+v, want %+v", label, got, want)
		}
	}
	// The labels that carry no raw name are still read.
	for line, want := range map[string]sevenZipOutput{
		"ERROR: Wrong password : a.txt\n":                               {wrongPassword: true},
		"ERROR: Unsupported Method : a.txt\n":                           {encryptionHint: true, hintMembers: map[string]struct{}{"a.txt": {}}},
		"ERROR: CRC Failed : a.txt\n":                                   {recoverable: true},
		"ERROR: " + "\x00path" + " : Cannot open the file as archive\n": {notAnArchive: true},
	} {
		if got := classifyStderr(strings.ReplaceAll(line, "\x00path", "/work/a"), []string{"/work/a"}); !reflect.DeepEqual(got, want) {
			t.Errorf("classifyStderr(%q) = %+v, want %+v", line, got, want)
		}
	}
}

// A hard link of a tar to a target that is not in the archive: 7-Zip repeats the
// target, raw, in the error of the link. A target with a newline writes a line of
// its own, here a real "Wrong password": the archive is not taken for an encrypted
// one, a tar that cannot be.
func TestExtract_aLinkTargetCannotForgeARefusalOfThePassword(t *testing.T) {
	plugin := realPlugin(t)
	plugin.sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range []*tar.Header{
		{Name: "f", Typeflag: tar.TypeReg, Mode: 0o600, Size: 3},
		{Name: "hl", Typeflag: tar.TypeLink, Linkname: "missing\nERROR: Wrong password\nm", Mode: 0o600},
	} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write([]byte("abc")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "h.tar")
	if err := os.WriteFile(archive, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := plugin.ExtractFile(archive, t.TempDir(), plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100, MaxTotalSize: 1 << 30})
	if errors.Is(err, plugins.ErrEncrypted) || !errors.Is(err, plugins.ErrArchiveAnomaly) {
		t.Errorf("ExtractFile() = %v, want an anomaly of the archive and not an encrypted archive", err)
	}
}

// The error of the run is the one of the classification: a forged refusal is not
// ErrInvalidPassword, a real one is.
func TestHandleSevenZipError_aForgedRefusalIsNotAWrongPassword(t *testing.T) {
	exit := errors.New("exit status 2")
	forged := "ERROR: Cannot open output file : errno=13 : Permission denied : /out/x\nERROR: Wrong password\n"
	if _, err := handleSevenZipError(exit, forged, slog.New(slog.DiscardHandler), "/work/a.zip"); errors.Is(err, ErrInvalidPassword) || errors.Is(err, errSevenZipRecoverable) || err == nil {
		t.Errorf("a forged refusal after a host failure: error = %v, want a plain failure", err)
	}
	damaged := "ERROR: Cannot open output file : errno=20 : Not a directory : /out/x\nERROR: Wrong password\n"
	if _, err := handleSevenZipError(exit, damaged, slog.New(slog.DiscardHandler), "/work/a.zip"); errors.Is(err, ErrInvalidPassword) || !errors.Is(err, errSevenZipRecoverable) {
		t.Errorf("a forged refusal after damage: error = %v, want a recoverable error", err)
	}
	const link = "ERROR: Dangerous link path was ignored : l : /etc/passwd\n"
	for _, later := range []struct{ name, line string }{{"a refusal", "ERROR: Wrong password\n"}, {"an errno of the host", "ERROR: errno=13 : Permission denied : x\n"}, {"not an archive", "Is not archive\n"}} {
		name, forgedLine := later.name, later.line
		if _, err := handleSevenZipError(exit, link+forgedLine, slog.New(slog.DiscardHandler), "/work/a.zip"); !errors.Is(err, errSevenZipRecoverable) || errors.Is(err, ErrInvalidPassword) || errors.Is(err, ErrUnsupportedFormat) {
			t.Errorf("%s after a refused link: error = %v, want a damaged archive, in one attempt", name, err)
		}
	}
	if links, err := handleSevenZipError(exit, link, slog.New(slog.DiscardHandler), "/work/a.zip"); err != nil || len(links) != 1 {
		t.Errorf("a refused link alone: links %v, error %v, want it tolerated", links, err)
	}
	if _, err := handleSevenZipError(exit, "ERROR: Wrong password : a.txt\n", slog.New(slog.DiscardHandler), "/work/a.zip"); !errors.Is(err, ErrInvalidPassword) {
		t.Errorf("a real refusal: error = %v, want ErrInvalidPassword", err)
	}
}

// Extracting into a folder that cannot be written is the failure of the host, never
// the one of the password.
func TestExtract_anOutputFolderThatCannotBeWrittenIsNotAnEncryptedArchive(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes wherever it wants")
	}
	plugin := realPlugin(t)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("ok.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "f.zip")
	if err = os.WriteFile(archive, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out")
	if err = os.Mkdir(out, 0o500); err != nil {
		t.Fatal(err)
	}
	_, err = plugin.ExtractFile(archive, out, plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100, MaxTotalSize: 1 << 30})
	if err == nil || errors.Is(err, plugins.ErrEncrypted) || errors.Is(err, plugins.ErrArchiveAnomaly) {
		t.Errorf("ExtractFile() = %v, want the failure of the host: neither an encrypted archive nor a damaged one, so that it is retried", err)
	}
}

// The proof of a binary stages its reference archive in the work directory it is
// given, not in the temporary directory of the system: with that one unusable it
// still passes.
func TestProve_stagesInTheWorkDirectory(t *testing.T) {
	plugin := realPlugin(t)
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))
	if err := prove(plugin.sze, t.TempDir()); err != nil {
		t.Errorf("prove() = %v, want the proof to pass with the work directory it was given", err)
	}
}

// A member name is repeated by 7-Zip, raw, when it cannot create the file, and a name
// with newlines can write lines of its own: here a real "Wrong password" line. The
// member "a/b..." cannot be created because "a" is a file, so 7-Zip echoes its name.
// The archive is not taken for an encrypted one.
func TestExtract_aMemberNameCannotForgeARefusalOfThePassword(t *testing.T) {
	plugin := realPlugin(t)
	plugin.sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, m := range []struct{ name, content string }{
		{"a", "a plain file"},
		{"a/b\nERROR: Wrong password : z\nx", "payload"},
		{"evil.exe", "MZ a malware"},
	} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: m.name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte(m.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "forge.zip")
	if err := os.WriteFile(archive, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, check := range []bool{false, true} {
		extraction, err := plugin.ExtractFile(archive, t.TempDir(), plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100, MaxTotalSize: 1 << 30, CheckOnly: check})
		if errors.Is(err, plugins.ErrEncrypted) {
			t.Errorf("check = %v: the archive was taken for an encrypted one: %v", check, err)
		}
		// The members extracted are discarded by the scanner with the archive.
		if !check && (!errors.Is(err, plugins.ErrArchiveAnomaly) || !errors.Is(err, plugins.ErrEncryptionPossible)) {
			t.Errorf("the extraction gave error %v (%d file(s)), want an anomaly with encryption possible", err, len(extraction.Files))
		}
	}
}

func extractTar(t *testing.T, headers []*tar.Header) error {
	t.Helper()
	plugin := realPlugin(t)
	plugin.sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range headers {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write(bytes.Repeat([]byte("a"), int(h.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "h.tar")
	if err := os.WriteFile(archive, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := plugin.ExtractFile(archive, t.TempDir(), plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100, MaxTotalSize: 1 << 30})
	return err
}

// Real 7-Zip: a folder over a file made before (EEXIST), and a hard link toward a
// directory (EPERM), are damage of the archive and not a failure of the host to retry.
func TestExtract_aMemberThatTheArchiveMakesImpossibleIsAnAnomaly(t *testing.T) {
	for name, headers := range map[string][]*tar.Header{
		"a folder over a file": {
			{Name: "a", Typeflag: tar.TypeReg, Mode: 0o600, Size: 3},
			{Name: "a/", Typeflag: tar.TypeDir, Mode: 0o700},
		},
		"a hard link toward a folder": {
			{Name: "d/", Typeflag: tar.TypeDir, Mode: 0o700},
			{Name: "hl", Typeflag: tar.TypeLink, Linkname: "d", Mode: 0o600},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := extractTar(t, headers); !errors.Is(err, plugins.ErrArchiveAnomaly) {
				t.Errorf("ExtractFile() = %v, want an anomaly of the archive", err)
			}
		})
	}
}

const forgedLine = "ERROR: Wrong password : z"

// 7-Zip 25.01 prints a newline of a member name as "_" in the lines of the labels
// that carry a name: the refusals of the password and the hints of encryption rely on
// it. A member named with a forged line must not put that line on a line of its own.
func TestSevenZip_aNewlineOfAMemberNameIsPrintedAsAnUnderscoreByTheKnownLabels(t *testing.T) {
	plugin := realPlugin(t)
	name := "m\n" + forgedLine
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, name), []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	encrypted := filepath.Join(work, "e.zip")
	if out, err := runCmdIn(t.Context(), src, plugin.sze.sevenZipPath, "a", "-tzip", "-pSECRET", encrypted, name); err != nil {
		t.Fatalf("cannot build the archive: %v\n%s", err, out)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateRaw(&zip.FileHeader{Name: name, Method: 20, CRC32: 1, CompressedSize64: 3, UncompressedSize64: 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	unsupported := filepath.Join(work, "u.zip")
	if err = os.WriteFile(unsupported, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	for label, tt := range map[string]struct{ archive, password string }{
		"a refusal of the password":  {encrypted, "-pWRONG"},
		"an unsupported compression": {unsupported, "-p-"},
	} {
		t.Run(label, func(t *testing.T) {
			out, _ := runCmdIn(t.Context(), t.TempDir(), plugin.sze.sevenZipPath, "t", tt.password, tt.archive)
			if !strings.Contains(out, "_"+forgedLine) {
				t.Fatalf("7-Zip does not print the newline as an underscore, output:\n%s", out)
			}
			for line := range strings.SplitSeq(out, "\n") {
				if strings.HasPrefix(line, forgedLine) {
					t.Errorf("the forged line is on a line of its own: %q", line)
				}
			}
		})
	}
	plugin.sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
	if _, err = plugin.ExtractFile(unsupported, t.TempDir(), plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100, MaxTotalSize: 1 << 30}); errors.Is(err, plugins.ErrEncrypted) {
		t.Errorf("ExtractFile() = %v, want no encrypted archive: the name forged nothing", err)
	}
}

func TestExtract_aSymbolicLinkCannotForgeARefusalOfThePassword(t *testing.T) {
	const forged = "\nERROR: Wrong password\nm"
	for name, h := range map[string]*tar.Header{
		"in its target": {Name: "s", Typeflag: tar.TypeSymlink, Linkname: "../out" + forged, Mode: 0o600},
		"in its name":   {Name: "s" + forged, Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o600},
	} {
		t.Run(name, func(t *testing.T) {
			err := extractTar(t, []*tar.Header{{Name: "f", Typeflag: tar.TypeReg, Mode: 0o600, Size: 3}, h})
			if errors.Is(err, plugins.ErrEncrypted) {
				t.Errorf("ExtractFile() = %v, want no encrypted archive", err)
			}
		})
	}
}

func TestExtract_twoMembersOfOneNameAreNotAnEncryptedArchive(t *testing.T) {
	err := extractTar(t, []*tar.Header{
		{Name: "a", Typeflag: tar.TypeReg, Mode: 0o600, Size: 3},
		{Name: "a", Typeflag: tar.TypeReg, Mode: 0o600, Size: 4},
	})
	if errors.Is(err, plugins.ErrEncrypted) {
		t.Errorf("ExtractFile() = %v, want no encrypted archive", err)
	}
}
