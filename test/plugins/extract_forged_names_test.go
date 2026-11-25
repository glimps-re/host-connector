//go:build linux && (e2e || e2e_plugins)

package plugins

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// tarMember is an entry of a tar and the data that follows its header.
type tarMember struct {
	header *tar.Header
	data   string
}

func tarOf(t *testing.T, members ...tarMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range members {
		if err := tw.WriteHeader(m.header); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(m.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// regular is a regular file of the tar holding size bytes "a".
func regular(name string, size int) tarMember {
	return tarMember{header: &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(size)}, data: strings.Repeat("a", size)}
}

func link(typ byte, name, target string) tarMember {
	return tarMember{header: &tar.Header{Name: name, Typeflag: typ, Linkname: target, Mode: 0o600}}
}

// mitigateEncrypted quarantines what is taken for an encrypted archive.
var mitigateEncrypted = map[string]any{"unanalyzable_policy": map[string]any{"encrypted": "mitigate"}}

// From TestExtract_aLinkTargetCannotForgeARefusalOfThePassword: a link target that writes a "Wrong password" line does not make the tar an encrypted archive.
func TestE2E_aLinkTargetCannotForgeARefusalOfThePassword(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		content []byte
		want    harness.Outcome
	}{
		{
			name: "a hard link to a missing target with a newline",
			content: tarOf(t,
				tarMember{header: &tar.Header{Name: "f", Typeflag: tar.TypeReg, Mode: 0o600, Size: 3}, data: "abc"},
				link(tar.TypeLink, "hl", "missing\nERROR: Wrong password\nm"),
			),
			want: harness.Outcome{In: harness.Input, Error: errDamagedText},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  mitigateEncrypted,
				Files:   []harness.File{{Path: "h.tar", Content: tt.content}},
				Want:    map[string]harness.Outcome{"h.tar": tt.want},
			})
		})
	}
}

// From TestExtract_aMemberNameCannotForgeARefusalOfThePassword: a member name that 7-Zip repeats with a "Wrong password" line does not make the zip an encrypted archive.
func TestE2E_aMemberNameCannotForgeARefusalOfThePassword(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		members []struct{ name, content string }
		want    harness.Outcome
	}{
		{
			name: "a member below a file, named with a forged line",
			members: []struct{ name, content string }{
				{"a", "a plain file"},
				{"a/b\nERROR: Wrong password : z\nx", "payload"},
				{"evil.exe", "MZ a malware"},
			},
			want: harness.Outcome{In: harness.Input, Error: errDamagedText},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			for _, m := range tt.members {
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
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  mitigateEncrypted,
				Files:   []harness.File{{Path: "forge.zip", Content: buf.Bytes()}},
				Want:    map[string]harness.Outcome{"forge.zip": tt.want},
			})
		})
	}
}

// From TestExtract_aSymbolicLinkCannotForgeARefusalOfThePassword: a symbolic link whose target or name writes a "Wrong password" line does not make the tar an encrypted archive.
func TestE2E_aSymbolicLinkCannotForgeARefusalOfThePassword(t *testing.T) {
	t.Parallel()
	const forged = "\nERROR: Wrong password\nm"
	tests := []struct {
		name string
		link tarMember
		want harness.Outcome
	}{
		{name: "in its target", link: link(tar.TypeSymlink, "s", "../out"+forged), want: harness.Outcome{In: harness.Input, Error: errDamagedText}},
		{name: "in its name", link: link(tar.TypeSymlink, "s"+forged, "/etc/passwd"), want: harness.Outcome{In: harness.Input, Error: errDamagedText}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  mitigateEncrypted,
				Files:   []harness.File{{Path: "h.tar", Content: tarOf(t, regular("f", 3), tt.link)}},
				Want:    map[string]harness.Outcome{"h.tar": tt.want},
			})
		})
	}
}

// From TestExtract_twoMembersOfOneNameAreNotAnEncryptedArchive: a tar of two members of one name is not an encrypted archive.
func TestE2E_twoMembersOfOneNameAreNotAnEncryptedArchive(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		members []tarMember
		want    harness.Outcome
	}{
		{name: "two members named a", members: []tarMember{regular("a", 3), regular("a", 4)}, want: harness.Outcome{In: harness.Output}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var members []harness.File
			for _, m := range tt.members {
				members = append(members, harness.File{Path: m.header.Name, Content: []byte(m.data)})
			}
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  mitigateEncrypted,
				Files:   []harness.File{{Path: "h.tar", Content: tarOf(t, tt.members...), Members: members}},
				Want:    map[string]harness.Outcome{"h.tar": tt.want},
			})
		})
	}
}

// From TestExtract_aMemberThatTheArchiveMakesImpossibleIsAnAnomaly: a folder over a file and a hard link to a folder are damage of the archive, reported once.
func TestE2E_aMemberThatTheArchiveMakesImpossibleIsAnAnomaly(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		content []byte
		want    harness.Outcome
	}{
		{
			name:    "a folder over a file",
			content: tarOf(t, regular("a", 3), tarMember{header: &tar.Header{Name: "a/", Typeflag: tar.TypeDir, Mode: 0o700}}),
			want:    harness.Outcome{In: harness.Input, Error: errDamagedText},
		},
		{
			name:    "a hard link toward a folder",
			content: tarOf(t, tarMember{header: &tar.Header{Name: "d/", Typeflag: tar.TypeDir, Mode: 0o700}}, link(tar.TypeLink, "hl", "d")),
			want:    harness.Outcome{In: harness.Input, Error: errDamagedText},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Files:   []harness.File{{Path: "h.tar", Content: tt.content}},
				Want:    map[string]harness.Outcome{"h.tar": tt.want},
			})
			if n := len(in.ReportsOf(t, tt.content)); n != 1 {
				t.Errorf("%d report entries, want 1: damage of the archive is not retried", n)
			}
		})
	}
}

// From TestExtract_anArchiveNamedByTheDepositorIsRunUnderAName: whatever the depositor named the archive, it is extracted, and without the password it is an encrypted archive.
func TestE2E_anArchiveNamedByTheDepositorIsRunUnderAName(t *testing.T) {
	t.Parallel()
	member := harness.File{Path: "a.txt", Content: []byte("a plain member")}
	he := archive(t, "", headerEncrypted7z, member)
	type row struct {
		name      string
		passwords []string
		want      harness.Outcome
		member    harness.Outcome
	}
	var tests []row
	for _, name := range []string{"n\nx.7z", "tab\there.7z", "esc\x1b[31m.7z", "bidi" + string(rune(0x202e)) + "name.7z", "-option.7z", "ünï côde.7z", "invalid\xff\xfe.7z"} {
		tests = append(tests,
			row{name: name, passwords: []string{"infected"}, want: harness.Outcome{In: harness.Output}, member: harness.Outcome{Submissions: 1}},
			row{name: name, passwords: []string{}, want: harness.Outcome{In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedEncrypted}, member: harness.Outcome{ServiceVerdict: harness.NotGiven}},
		)
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q/passwords %q", tt.name, tt.passwords), func(t *testing.T) {
			f := he
			f.Path = tt.name
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": {"default_passwords": tt.passwords}},
				Config:  map[string]any{"unanalyzable_policy": map[string]any{"encrypted": "pass"}},
				Files:   []harness.File{f},
				Want:    map[string]harness.Outcome{tt.name: tt.want, tt.name + "/a.txt": tt.member},
			})
		})
	}
}

// From TestExtract_aSingleFileCompressorKeepsTheNameOfItsMember: the member of a gzip is named after the archive.
func TestE2E_aSingleFileCompressorKeepsTheNameOfItsMember(t *testing.T) {
	t.Parallel()
	gzipOf := func(t *testing.T, members map[string]string) []byte {
		t.Helper()
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write([]byte(members["report.txt"])); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	tests := []struct {
		name   string
		file   harness.File
		member string
		want   harness.Outcome
	}{
		{
			name:   "report.txt.gz",
			file:   archive(t, "report.txt.gz", gzipOf, harness.File{Path: "report.txt", Content: []byte("the content of the member")}),
			member: "report.txt.gz/report.txt",
			want:   harness.Outcome{SubmittedAs: []string{"report.txt.gz/report.txt"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Files:   []harness.File{tt.file},
				Want:    map[string]harness.Outcome{tt.file.Path: {In: harness.Output}, tt.member: tt.want},
			})
		})
	}
}
