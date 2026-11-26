//go:build linux

package main

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

func TestLinksOf(t *testing.T) {
	out := t.TempDir()
	tests := []struct {
		name  string
		paths []string
		want  []string
	}{
		{"none", nil, nil},
		{"named by 7z", []string{"d/link"}, []string{"d/link"}},
		{"found on disk", []string{filepath.Join(out, "d", "link")}, []string{"d/link"}},
		{"refused traversal kept as text", []string{"../../x"}, []string{"../../x"}},
		{"outside the output folder", []string{"/elsewhere/x/link"}, []string{"link"}},
		{"control and bidi characters kept as text", []string{"a\x1b[31m\u202eexe.txt"}, []string{"a\x1b[31m\u202eexe.txt"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			links, count := linksOf(out, tt.paths)
			if count != len(tt.paths) || len(links) != len(tt.want) {
				t.Fatalf("linksOf() = %v, %d; want %v, %d", links, count, tt.want, len(tt.paths))
			}
			for i, l := range links {
				if l.FileName != tt.want[i] || l.Reason != datamodel.NotAnalyzedSymlink || l.Size != 0 {
					t.Errorf("link %d = %+v, want %q, reason symlink, no size", i, l, tt.want[i])
				}
			}
		})
	}
}

func TestLinksOf_isBounded(t *testing.T) {
	const n = 5000
	paths := make([]string, n)
	for i := range paths {
		paths[i] = "l" + strconv.Itoa(i)
	}
	paths[0] = strings.Repeat("é", datamodel.MaxListedNameLen)
	paths[1] = "bad\xff\xfe"
	links, count := linksOf(t.TempDir(), paths)
	if count != n || len(links) != datamodel.MaxListedSubfiles {
		t.Fatalf("linksOf() = %d links, count %d; want %d, %d", len(links), count, datamodel.MaxListedSubfiles, n)
	}
	if len(links[0].FileName) > datamodel.MaxListedNameLen {
		t.Errorf("a name of %d bytes, want at most %d", len(links[0].FileName), datamodel.MaxListedNameLen)
	}
}

func TestRealSevenZip_linksAreReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "links.zip")
	writeZip(t, path, "",
		zipMember{name: "a.txt", data: "A"},
		zipMember{name: "out", data: "/etc/passwd", symlink: true},
		zipMember{name: "d/in", data: "../a.txt", symlink: true},
	)
	ex, err := realPlugin(t).ExtractFile(path, t.TempDir(), openLimits)
	if err != nil || ex.SkippedCount != 0 {
		t.Fatalf("ExtractFile() = %+v, %v, want a clean extraction", ex, err)
	}
	if got := baseNames(ex.Files); len(got) != 1 {
		t.Errorf("files = %v, want a.txt only", got)
	}
	names := map[string]bool{}
	for _, l := range ex.Links {
		if l.Reason != datamodel.NotAnalyzedSymlink {
			t.Errorf("link %+v, want reason symlink", l)
		}
		names[l.FileName] = true
	}
	if ex.LinksCount != 2 || !names["out"] || !names["d/in"] {
		t.Errorf("links = %+v (count %d), want out and d/in", ex.Links, ex.LinksCount)
	}
}
