package scanner

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// A file released at its location skips the path rules, the OnScanFile chain and
// the size limit, as it skips the analysis. The same filters still hold the file
// when it was not released, or when another content was released at its path.
func TestRestored_theFiltersAreLifted(t *testing.T) {
	forbidExe := mustPathFilter(t, []string{`\.exe$`}, nil)
	refuseAll := func(string, string, string, bool) *datamodel.Result {
		return &datamodel.Result{Malware: true, Malwares: []string{"type"}, MalwareReason: datamodel.FilteredFileType}
	}
	type row struct {
		name    string
		content string
		filter  *PathFilter
		refuse  bool
		archive bool
		tooBig  bool
	}
	rows := map[string]row{
		"a forbidden path":          {name: "run.exe", content: "released content", filter: forbidExe},
		"a type the plugins refuse": {name: "ok.bin", content: "released content", refuse: true},
		"over the size limit":       {name: "big.bin", content: strings.Repeat("x", accMax+100), tooBig: true},
		// Skipped, so that the archive is listed, never extracted, against forbidden_paths.
		"an archive with a forbidden member": {name: "pack.zip", content: zipOf(t, 10), filter: mustPathFilter(t, []string{`\.exe$`}, []string{`pack\.zip$`}), archive: true},
	}
	variants := []string{"released", "not released", "another content released at its path"}
	for rowName, tt := range rows {
		for _, variant := range variants {
			t.Run(rowName+"/"+variant, func(t *testing.T) {
				var scanFile, fileScanned atomic.Int32
				list := &listing{names: []string{"run/bad.exe"}}
				var extract plugins.ExtractFile
				if tt.archive {
					extract = list.extract
				}
				done := &outcomes{}
				setup := accSetup{
					files: map[string]string{tt.name: tt.content}, extract: extract, pathFilter: tt.filter, onDone: done.add,
					scanFile: func(filename, raw, path string, isArchive bool) *datamodel.Result {
						scanFile.Add(1)
						if tt.refuse {
							return refuseAll(filename, raw, path, isArchive)
						}
						return nil
					},
					scanned: func(string, string, datamodel.Result) *datamodel.Result {
						fileScanned.Add(1)
						return nil
					},
				}
				switch variant {
				case "released":
					setup.restored = []string{tt.name}
				case "another content released at its path":
					setup.restored = []string{tt.name}
					setup.restoredAs = map[string]string{tt.name: "another content"}
				}
				r := runAcc(t, setup)
				got := r.one(t, tt.name).result
				delivered := r.exists(r.out, tt.name)

				if variant == "released" {
					if !got.Restored || got.Malware || got.Error != nil || got.NotAnalyzedReason != datamodel.NotAnalyzedRestored {
						t.Errorf("result = restored %t, malware %t, error %v, reason %q; want restored, clean, %q", got.Restored, got.Malware, got.Error, got.NotAnalyzedReason, datamodel.NotAnalyzedRestored)
					}
					if scanFile.Load() != 0 || fileScanned.Load() != 1 {
						t.Errorf("OnScanFile %d, OnFileScanned %d; want 0 and 1", scanFile.Load(), fileScanned.Load())
					}
					if r.submitted.Load() != 0 || r.quarantined(t) != 0 {
						t.Errorf("%d analyses, %d quarantined; want none", r.submitted.Load(), r.quarantined(t))
					}
					if !delivered {
						t.Error("the released file is not in OUTPUT")
					}
					if o := done.get(); len(o) != 1 || o[0].Kind != OutcomeFinal {
						t.Errorf("outcomes = %+v, want one final", o)
					}
					if tt.archive && (list.listings.Load() != 0 || list.extracted.Load() != 0) {
						t.Errorf("%d listings, %d extractions of the released archive; want none", list.listings.Load(), list.extracted.Load())
					}
					return
				}

				if got.Restored || delivered {
					t.Errorf("restored %t, delivered %t; want neither", got.Restored, delivered)
				}
				if tt.tooBig {
					if !errors.Is(got.Error, errFileTooBig) && got.NotAnalyzedReason != datamodel.NotAnalyzedTooBig {
						t.Errorf("result = error %v, reason %q; want too big", got.Error, got.NotAnalyzedReason)
					}
					if r.submitted.Load() != 0 {
						t.Errorf("%d analyses, want none", r.submitted.Load())
					}
					return
				}
				if !got.Malware || r.quarantined(t) != 1 {
					t.Errorf("malware %t, %d quarantined; want refused and quarantined once", got.Malware, r.quarantined(t))
				}
				if tt.archive && list.listings.Load() == 0 {
					t.Error("the archive was not listed")
				}
			})
		}
	}
}
