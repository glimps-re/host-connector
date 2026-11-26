//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

var wideLimits = plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100000, MaxTotalSize: 1 << 30}

func writeSecret(t *testing.T) string {
	t.Helper()
	secret := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secret, []byte(secretContent), 0o600); err != nil {
		t.Fatal(err)
	}
	return secret
}

func assertNoLinkFollowed(t *testing.T, files []string) {
	t.Helper()
	for _, f := range files {
		if b, err := os.ReadFile(filepath.Clean(f)); err != nil || string(b) == secretContent {
			t.Errorf("%s holds the content of the target (%v): a link was followed", f, err)
		}
	}
}

const secretContent = "do not read me"

func TestRealSevenZip_hostileLinksAreBoundedAndNeverFollowed(t *testing.T) {
	const manyLinks = 1500
	secret := writeSecret(t)
	bidi := strings.Repeat("d\u202e\u2066"+strings.Repeat("é", 90)+"/", 12) + "link"

	many := make([]zipMember, 0, manyLinks+1)
	many = append(many, zipMember{name: "ok.txt", data: "ok"})
	for i := range manyLinks {
		many = append(many, zipMember{name: "l/" + strconv.Itoa(i), data: secret, symlink: true})
	}
	tests := []struct {
		name      string
		members   []zipMember
		wantLinks int
		wantFiles []string
	}{
		{
			name:      "links only, pointing outside",
			members:   []zipMember{{name: "abs", data: secret, symlink: true}, {name: "up", data: "../../../" + secret, symlink: true}},
			wantLinks: 2,
		},
		{
			name:      "a link of 2 KiB made of bidi components",
			members:   []zipMember{{name: "ok.txt", data: "ok"}, {name: bidi, data: secret, symlink: true}},
			wantLinks: 1,
			wantFiles: []string{"ok.txt"},
		},
		{"more links than the list holds", many, manyLinks, []string{"ok.txt"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "h.zip")
			writeZip(t, path, "", tt.members...)
			out := t.TempDir()
			ex, err := realPlugin(t).ExtractFile(path, out, wideLimits)
			if err != nil {
				t.Errorf("ExtractFile() = %v, want nil", err)
			}
			if ex.LinksCount != tt.wantLinks {
				t.Errorf("LinksCount = %d, want %d", ex.LinksCount, tt.wantLinks)
			}
			if len(ex.Links) > datamodel.MaxListedSubfiles {
				t.Errorf("%d links listed, want at most %d", len(ex.Links), datamodel.MaxListedSubfiles)
			}
			if tt.wantLinks > datamodel.MaxListedSubfiles && len(ex.Links) != datamodel.MaxListedSubfiles {
				t.Errorf("%d links listed, want %d", len(ex.Links), datamodel.MaxListedSubfiles)
			}
			for _, l := range ex.Links {
				if len(l.FileName) > datamodel.MaxListedNameLen || !utf8.ValidString(l.FileName) {
					t.Errorf("link name of %d bytes, valid=%v: want a cut, valid name", len(l.FileName), utf8.ValidString(l.FileName))
				}
				if l.Reason != datamodel.NotAnalyzedSymlink || l.Size != 0 {
					t.Errorf("link %+v, want reason symlink and no size", l)
				}
			}
			if got := baseNames(ex.Files); strings.Join(got, ",") != strings.Join(tt.wantFiles, ",") {
				t.Errorf("files = %v, want %v: a link must give no file", got, tt.wantFiles)
			}
			assertNoLinkFollowed(t, ex.Files)
		})
	}
}

func TestRealSevenZip_aHostileLinkNameDamagesTheArchiveAndIsNeverFollowed(t *testing.T) {
	tests := []struct {
		name string
		link string
		want string
	}{
		{"control characters", "a\x1b[31m\u202e\x00exe", "control character"},
		{"64 KiB with control and bidi characters", "a\x1b\u202e" + strings.Repeat("x", 65000), "longer than"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := writeSecret(t)
			path := filepath.Join(t.TempDir(), "h.zip")
			writeZip(t, path, "", zipMember{name: "ok.txt", data: "ok"}, zipMember{name: tt.link, data: secret, symlink: true})
			ex, err := realPlugin(t).ExtractFile(path, t.TempDir(), wideLimits)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ExtractFile() error = %v, want a damaged archive (%s)", err, tt.want)
			}
			assertNoLinkFollowed(t, ex.Files)
		})
	}
}

func TestRealSevenZip_linksBeyondTheFileLimitAreNotSilent(t *testing.T) {
	const total = 300
	members := make([]zipMember, 0, total)
	for i := range total {
		members = append(members, zipMember{name: "l" + strconv.Itoa(i), data: "x", symlink: true})
	}
	path := filepath.Join(t.TempDir(), "h.zip")
	writeZip(t, path, "", members...)
	ex, err := realPlugin(t).ExtractFile(path, t.TempDir(), openLimits)
	if err != nil {
		t.Fatalf("ExtractFile() = %v, want nil", err)
	}
	if ex.LinksCount != openLimits.MaxFiles || ex.LinksCount+ex.SkippedCount != total {
		t.Errorf("LinksCount = %d, SkippedCount = %d, want %d and %d together %d", ex.LinksCount, ex.SkippedCount, openLimits.MaxFiles, total-openLimits.MaxFiles, total)
	}
	if len(ex.Skipped) == 0 || ex.Skipped[0].Reason != datamodel.NotAnalyzedExtractLimit {
		t.Errorf("Skipped = %v, want entries with reason extract-limit", ex.Skipped)
	}
}
