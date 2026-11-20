package datamodel

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func worstReport() Report {
	name := strings.Repeat("\x01", 60<<10)
	r := Report{Filename: name, Error: name, Malwares: make([]string, 500)}
	for i := range r.Malwares {
		r.Malwares[i] = name
	}
	r.ErrorExtractedFiles = map[string]string{}
	for i := range 5000 {
		r.NotAnalyzedExtractedFiles = append(r.NotAnalyzedExtractedFiles, NotAnalyzedFile{FileName: name, Reason: NotAnalyzedTooBig})
		r.ErrorExtractedFiles[fmt.Sprintf("%d%s", i, name[:900])] = name[:1000]
		r.MaliciousExtractedFiles = append(r.MaliciousExtractedFiles, ExtractedFile{
			FileName: fmt.Sprintf("%d%s", i, name), Malwares: r.Malwares,
			ExtractedFiles: []ExtractedFile{{FileName: name, Malwares: r.Malwares}},
		})
	}
	r.NotAnalyzedExtractedCount = 5000
	return r
}

func TestReportBound_worstCaseFitsMaxReportSize(t *testing.T) {
	r := worstReport()
	r.Bound()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > MaxReportSize {
		t.Errorf("encoded report = %d bytes, want <= %d", len(b), MaxReportSize)
	}
	if len(r.Malwares) > MaxReportMalwares || r.NotAnalyzedExtractedCount != 5000 {
		t.Errorf("malwares %d, count %d: lists must be cut and counters exact", len(r.Malwares), r.NotAnalyzedExtractedCount)
	}
}

func TestReportBound_smallReportIsUntouched(t *testing.T) {
	r := Report{Filename: "/in/f", Malwares: []string{"m"}, NotAnalyzedExtractedFiles: []NotAnalyzedFile{{FileName: "a"}}}
	r.Bound()
	if r.Filename != "/in/f" || len(r.Malwares) != 1 || len(r.NotAnalyzedExtractedFiles) != 1 || r.Error != "" {
		t.Errorf("report changed: %+v", r)
	}
}

func BenchmarkReportBound_worstCase(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		r := worstReport()
		r.Bound()
	}
}

func encodedLen(t *testing.T, r Report) int {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return len(b)
}

// One field of several MiB, in any place, does not get past the limit.
func TestReportBound_oneHugeValueIsCut(t *testing.T) {
	huge := strings.Repeat("\x01", 5<<20)
	tests := map[string]Report{
		"error value":   {ErrorExtractedFiles: map[string]string{"a": huge}},
		"error key":     {ErrorExtractedFiles: map[string]string{huge: "a"}},
		"gmalware url":  {GMalwareURL: huge},
		"moved to":      {MovedTo: huge},
		"type":          {FileType: huge},
		"node url":      {MaliciousExtractedFiles: []ExtractedFile{{FileName: "a", GMalwareURL: huge}}},
		"nested node":   {MaliciousExtractedFiles: []ExtractedFile{{FileName: "a", ExtractedFiles: []ExtractedFile{{FileName: huge}}}}},
		"quarantine":    {QuarantineLocation: huge},
		"many errors":   {ErrorExtractedFiles: manyErrors(5000, huge[:1000])},
		"node malwares": {MaliciousExtractedFiles: []ExtractedFile{{FileName: "a", Malwares: manyNames(1000, huge[:5000])}}},
	}
	for name, r := range tests {
		t.Run(name, func(t *testing.T) {
			r.Bound()
			if n := encodedLen(t, r); n > MaxReportSize {
				t.Errorf("encoded report = %d bytes, want <= %d", n, MaxReportSize)
			}
		})
	}
}

func manyErrors(n int, text string) map[string]string {
	m := make(map[string]string, n)
	for i := range n {
		m[fmt.Sprintf("m%d", i)] = text
	}
	return m
}

func manyNames(n int, text string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = text
	}
	return out
}

// What attests a passage without analysis is cut last: other content that
// bloats the report is cut first, and the list of the files not analyzed stays
// whole.
func TestReportBound_theListOfFilesNotAnalyzedIsCutLast(t *testing.T) {
	name := strings.Repeat("x", 100)
	r := Report{ErrorExtractedFiles: manyErrors(1000, strings.Repeat("\x01", 1000)), Malwares: manyNames(64, strings.Repeat("\x01", 1000))}
	for range 1000 {
		r.NotAnalyzedExtractedFiles = append(r.NotAnalyzedExtractedFiles, NotAnalyzedFile{FileName: name, Reason: NotAnalyzedTooBig})
	}
	r.Bound()
	if len(r.NotAnalyzedExtractedFiles) != 1000 {
		t.Errorf("%d files not analyzed kept, want all 1000: other content must give way first", len(r.NotAnalyzedExtractedFiles))
	}
	if n := encodedLen(t, r); n > MaxReportSize {
		t.Errorf("encoded report = %d bytes, want <= %d", n, MaxReportSize)
	}
}

// The caller's data is not modified.
func TestReportBound_leavesWhatTheCallerSharesAlone(t *testing.T) {
	long := strings.Repeat("a", 5000)
	list := []NotAnalyzedFile{{FileName: long}}
	errs := map[string]string{"k": long}
	names := []string{long}
	r := Report{NotAnalyzedExtractedFiles: list, ErrorExtractedFiles: errs, Malwares: names}
	r.Bound()
	if list[0].FileName != long || errs["k"] != long || names[0] != long {
		t.Error("Bound changed the slices and the map of the caller")
	}
}

// Even a report far above the caps is made to fit in bounded memory and size.
// The time depends on the machine: it is logged, and asserted only with
// HC_WORST_CASE_TIME=1.
func TestReportBound_worstCaseIsCheap(t *testing.T) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	r := worstReport()
	start := time.Now()
	r.Bound()
	took := time.Since(start)
	runtime.ReadMemStats(&after)
	t.Logf("Bound took %s", took)
	if os.Getenv("HC_WORST_CASE_TIME") == "1" && took > 20*time.Second {
		t.Errorf("Bound took %s", took)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 2<<30 {
		t.Errorf("Bound allocated %d MiB", alloc>>20)
	}
	if n := encodedLen(t, r); n > MaxReportSize {
		t.Errorf("encoded report = %d bytes, want <= %d", n, MaxReportSize)
	}
}

// A value a plugin sets on every node (a hash of 1 KiB of control characters)
// is measured, not estimated: the report still fits.
func TestReportBound_nodeValuesOfAPluginAreMeasured(t *testing.T) {
	r := Report{}
	sha := strings.Repeat("\x01", MaxListedNameLen)
	for i := range MaxReportMaliciousFiles {
		r.MaliciousExtractedFiles = append(r.MaliciousExtractedFiles, ExtractedFile{FileName: fmt.Sprintf("m%d", i), SHA256: sha})
	}
	r.Bound()
	if n := encodedLen(t, r); n > MaxReportSize {
		t.Errorf("encoded report = %d bytes, want <= %d", n, MaxReportSize)
	}
}
