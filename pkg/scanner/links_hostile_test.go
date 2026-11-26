package scanner

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

func TestLinks_hostileNamesOf64KiBAreCut(t *testing.T) {
	long := "a\x00\x1b[31m\u202e\u2066" + strings.Repeat("é", 32*1024)
	links := make([]datamodel.NotAnalyzedFile, datamodel.MaxListedSubfiles+1)
	for i := range links {
		links[i] = datamodel.NotAnalyzedFile{FileName: long + strconv.Itoa(i), Reason: datamodel.NotAnalyzedSymlink}
	}
	r := runAcc(t, accSetup{
		policy:  Unanalyzable{TooBig: PolicyError},
		files:   map[string]string{"a.zip": zipOf(t, 0)},
		extract: linkExtractor(t, "a.zip", map[string]string{"ok.bin": "ok"}, links, len(links), ""),
	})
	got := r.one(t, "a.zip")
	if got.result.Error != nil || got.result.Malware {
		t.Fatalf("result = %+v, want a delivered archive", got.result)
	}
	if got.result.NotAnalyzedSubfilesCount != len(links) {
		t.Errorf("NotAnalyzedSubfilesCount = %d, want %d", got.result.NotAnalyzedSubfilesCount, len(links))
	}
	if len(got.result.NotAnalyzedSubfiles) != datamodel.MaxListedSubfiles {
		t.Errorf("listed %d, want %d", len(got.result.NotAnalyzedSubfiles), datamodel.MaxListedSubfiles)
	}
	for _, f := range got.result.NotAnalyzedSubfiles {
		if len(f.FileName) > datamodel.MaxListedNameLen || !utf8.ValidString(f.FileName) {
			t.Fatalf("a link name of %d bytes, valid=%v", len(f.FileName), utf8.ValidString(f.FileName))
		}
		if f.Reason != datamodel.NotAnalyzedSymlink {
			t.Fatalf("reason = %q", f.Reason)
		}
	}
}
