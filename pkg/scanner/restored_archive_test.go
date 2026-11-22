package scanner

import (
	"archive/zip"
	"bytes"
	"cmp"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// A restored archive is listed, never extracted nor analyzed, when paths are
// forbidden: a member at a forbidden path refuses it, members that cannot be known
// refuse it with an error that is final, and an extractor that is down is retried.
func TestRestored_anArchiveIsListedAgainstForbiddenPaths(t *testing.T) {
	forbidExe := mustPathFilter(t, []string{`\.exe$`}, nil)
	tests := []struct {
		name         string
		content      string
		slow         bool
		filter       *PathFilter
		list         *listing
		wantListings int32
		wantResults  int
		wantMalware  bool
		wantErr      error
		wantRestored bool
		wantMember   string
		wantKind     OutcomeKind
		wantLocks    int
	}{
		{
			name: "a member is forbidden", filter: forbidExe, list: &listing{names: []string{"docs/a.txt", "run/bad.exe"}},
			wantListings: 1, wantResults: 1, wantMalware: true, wantMember: "run/bad.exe", wantKind: OutcomeFinal, wantLocks: 1,
		},
		{
			name: "no member is forbidden", filter: forbidExe, list: &listing{names: []string{"docs/a.txt"}},
			wantListings: 1, wantResults: 1, wantRestored: true, wantKind: OutcomeFinal,
		},
		{
			name: "the names are not known", filter: forbidExe, list: &listing{},
			wantListings: 1, wantResults: 1, wantErr: errRestoredUnchecked, wantKind: OutcomeFinal,
		},
		{
			name: "the extractor cannot list", filter: forbidExe, list: &listing{err: plugins.ErrListingUnsupported},
			wantListings: 1, wantResults: 1, wantErr: errRestoredUnchecked, wantKind: OutcomeFinal,
		},
		{
			name: "a listed name is over 4096 bytes", filter: forbidExe, list: &listing{names: []string{strings.Repeat("a", 5000)}},
			wantListings: 1, wantResults: 1, wantErr: errPathTooLong, wantKind: OutcomeFinal,
		},
		{
			name: "the matching is too slow", filter: forbidExe, list: &listing{names: []string{"a.txt", "b.txt"}}, slow: true,
			wantListings: 1, wantResults: 1, wantErr: errPathRulesSlow, wantKind: OutcomeFinal,
		},
		{
			name: "the extractor is down", filter: forbidExe, list: &listing{err: plugins.ErrExtractorUnavailable},
			wantListings: 1, wantKind: OutcomeRetry,
		},
		{
			name: "a document of the zip family has no members to match", content: docxOf(t), filter: forbidExe, list: &listing{names: []string{"run/bad.exe"}},
			wantResults: 1, wantRestored: true, wantKind: OutcomeFinal,
		},
		{
			name: "no path is forbidden", filter: mustPathFilter(t, nil, []string{`pack\.zip$`}), list: &listing{names: []string{"run/bad.exe"}},
			wantResults: 1, wantRestored: true, wantKind: OutcomeFinal,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.slow {
				now := time.Now()
				prev := pathRulesClock
				pathRulesClock = func() time.Time { now = now.Add(20 * time.Second); return now }
				t.Cleanup(func() { pathRulesClock = prev })
			}
			content := cmp.Or(tt.content, zipOf(t, 10))
			done := &outcomes{}
			stillRestored := false
			r := runAcc(t, accSetup{
				files: map[string]string{"pack.zip": content}, restored: []string{"pack.zip"},
				extract: tt.list.extract, pathFilter: tt.filter, onDone: done.add,
				after: func(c *Connector) {
					var err error
					if stillRestored, err = c.quarantiner.IsRestored(t.Context(), "", shaOf(content)); err != nil {
						t.Error(err)
					}
				},
			})
			if len(r.captures) != tt.wantResults {
				t.Fatalf("the actions ran %d time(s), want %d", len(r.captures), tt.wantResults)
			}
			if tt.list.listings.Load() != tt.wantListings || tt.list.extracted.Load() != 0 || r.submitted.Load() != 0 {
				t.Errorf("%d listings, %d extractions, %d analyses; want %d, none, none", tt.list.listings.Load(), tt.list.extracted.Load(), r.submitted.Load(), tt.wantListings)
			}
			if got := done.get(); len(got) != 1 || got[0].Kind != tt.wantKind {
				t.Errorf("outcomes = %+v, want one of kind %v", got, tt.wantKind)
			}
			if !stillRestored {
				t.Error("the content is no longer restored")
			}
			if n := r.quarantined(t); n != tt.wantLocks {
				t.Errorf("%d quarantined, want %d", n, tt.wantLocks)
			}
			if tt.wantResults == 0 {
				return
			}
			got := r.captures[0].result
			if got.Malware != tt.wantMalware || got.Restored != tt.wantRestored || !errors.Is(got.Error, tt.wantErr) {
				t.Errorf("result = malware %t, restored %t, error %v; want %t, %t, %v", got.Malware, got.Restored, got.Error, tt.wantMalware, tt.wantRestored, tt.wantErr)
			}
			if tt.wantMalware && (got.MalwareReason != datamodel.FilteredFilePath || len(got.MaliciousSubfiles) != 1 || got.Filename != got.Location) {
				t.Errorf("result = reason %q, %d members, filename %q; want the path, one member and the location as name", got.MalwareReason, len(got.MaliciousSubfiles), got.Filename)
			}
			if tt.wantMember != "" {
				if _, ok := got.MaliciousSubfiles[filepath.Join(r.in, "pack.zip", tt.wantMember)]; !ok {
					t.Errorf("members = %v, want %q named", got.MaliciousSubfiles, tt.wantMember)
				}
			}
		})
	}
}

func docxOf(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"[Content_Types].xml", "word/document.xml"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte("<x/>")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}
