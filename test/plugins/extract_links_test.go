//go:build linux && (e2e || e2e_plugins)

package plugins

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

func zipWithLinks(t *testing.T, links [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(h *zip.FileHeader, data string) {
		t.Helper()
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	add(&zip.FileHeader{Name: "ok.txt", Method: zip.Store}, "content of ok")
	add(&zip.FileHeader{Name: "empty.txt", Method: zip.Store}, "")
	for _, l := range links {
		h := &zip.FileHeader{Name: l[0], Method: zip.Store}
		h.SetMode(os.ModeSymlink | 0o777)
		add(h, l[1])
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func listsExactly(want map[string]datamodel.NotAnalyzedReason) func(datamodel.Report) string {
	return func(r datamodel.Report) string {
		if r.NotAnalyzedExtractedCount != len(want) {
			return fmt.Sprintf("NotAnalyzedExtractedCount = %d, want %d (listed %v)", r.NotAnalyzedExtractedCount, len(want), r.NotAnalyzedExtractedFiles)
		}
		got := map[string]datamodel.NotAnalyzedReason{}
		for _, f := range r.NotAnalyzedExtractedFiles {
			got[f.FileName] = f.Reason
		}
		for name, reason := range want {
			if got[name] != reason {
				return fmt.Sprintf("member %q has reason %q, want %q (listed %v)", name, got[name], reason, r.NotAnalyzedExtractedFiles)
			}
		}
		if len(got) != len(want) {
			return fmt.Sprintf("listed %v, want only %v", got, want)
		}
		return ""
	}
}

// The harness takes the reasons of a scenario from NotAnalyzedMembers, which
// holds one: the archive of links only declares symlink for the whole run, and
// the mixed archives are checked by Entry.
func TestE2E_anArchiveWithLinksAndAnEmptyMemberIsDeliveredAndListsThem(t *testing.T) {
	members := []harness.File{{Path: "ok.txt", Content: []byte("content of ok")}}
	okMember := tarMember{header: &tar.Header{Name: "ok.txt", Typeflag: tar.TypeReg, Mode: 0o600, Size: 13}, data: "content of ok"}
	mixed := map[string]datamodel.NotAnalyzedReason{
		"empty.txt": datamodel.NotAnalyzedEmpty,
		"abs":       datamodel.NotAnalyzedSymlink,
		"up":        datamodel.NotAnalyzedSymlink,
	}
	harness.Run(t, harness.Scenario{
		Plugins: map[string]map[string]any{"extract": nil},
		Files: []harness.File{
			{
				Path:    "mixed.tar",
				Content: tarOf(t, okMember, regular("empty.txt", 0), link(tar.TypeSymlink, "abs", "/etc/passwd"), link(tar.TypeSymlink, "up", "../../etc/shadow")),
				Members: members,
			},
			{
				Path:    "mixed.zip",
				Content: zipWithLinks(t, [][2]string{{"abs", "/etc/passwd"}, {"up", "../../etc/shadow"}}),
				Members: members,
			},
			{
				Path:    "only.tar",
				Content: tarOf(t, link(tar.TypeSymlink, "a", "/etc/passwd"), link(tar.TypeSymlink, "b", "../x")),
			},
		},
		Want: map[string]harness.Outcome{
			"mixed.tar": {In: harness.Output, Entry: listsExactly(mixed)},
			"mixed.zip": {In: harness.Output, Entry: listsExactly(mixed)},
			"only.tar": {
				In:                 harness.Output,
				NotAnalyzedMembers: &harness.MemberList{Reason: datamodel.NotAnalyzedSymlink, Count: 2, Includes: "a"},
			},
		},
	})
}
