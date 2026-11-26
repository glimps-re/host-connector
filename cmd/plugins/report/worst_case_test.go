//go:build linux

package main

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/htmltopdf/pkg/htmltopdf"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

// longTextOf is a distinct unbreakable text of the longest length a depositor can
// give, made of unit.
func longTextOf(unit, prefix string, i int) string {
	return fmt.Sprintf("%s%d", prefix, i) + strings.Repeat(unit, datamodel.MaxListedNameLen/len(unit)+1)[:datamodel.MaxListedNameLen]
}

// manyThreatsOf is n threat names of the longest length.
func manyThreatsOf(unit string, n, seed int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = longTextOf(unit, "w", seed*1000+i)
	}
	return names
}

// hostileOf gives every text of the reports the longest length a depositor can,
// made of unit.
func hostileOf(unit string, reports []datamodel.Report) []datamodel.Report {
	var members func(files []datamodel.ExtractedFile) []datamodel.ExtractedFile
	members = func(files []datamodel.ExtractedFile) []datamodel.ExtractedFile {
		out := slices.Clone(files)
		for i := range out {
			out[i].FileName = longTextOf(unit, "m", i)
			out[i].Malwares = manyThreatsOf(unit, 256, i)
			out[i].ExtractedFiles = members(out[i].ExtractedFiles)
		}
		return out
	}
	for i := range reports {
		r := &reports[i]
		r.Filename = longTextOf(unit, "f", i)
		r.QuarantineLocation = longTextOf(unit, "q", i)
		if r.Error != "" {
			r.Error = longTextOf(unit, "e", i)
		}
		if len(r.Malwares) > 0 {
			r.Malwares = manyThreatsOf(unit, 64, i)
		}
		r.MaliciousExtractedFiles = members(r.MaliciousExtractedFiles)
		for j := range r.NotAnalyzedExtractedFiles {
			r.NotAnalyzedExtractedFiles[j].FileName = longTextOf(unit, "n", j)
		}
	}
	return reports
}

// escapingUnit is what html/template expands the most: `"` becomes &#34;, `'`
// &#39;, `&` &amp; and `<` &lt;.
const escapingUnit = `"'&<`

// The worst reports a depositor can make: every section full, long unbreakable
// texts, and the blocked archives either many or heavy; the texts are either
// plain or made of characters the HTML escaping expands. The size must stay
// under half of the cap, and the HTML under the input limit of the converter; the
// time is logged, and asserted (half of the timeout) only with HC_WORST_CASE_TIME=1,
// which depends on the machine.
func TestPDF_theWorstReportsStayUnderHalfTheLimits(t *testing.T) {
	if testing.Short() {
		t.Skip("renders big PDFs")
	}
	full := func() []datamodel.Report {
		reports := notAnalyzedReports(maxRows)
		reports = append(reports, errorReports(maxRows)...)
		return append(reports, blockedReports(maxRows)...)
	}
	for _, texts := range []struct{ name, unit string }{{"plain texts", "W"}, {"escaped texts", escapingUnit}} {
		cases := map[string][]datamodel.Report{
			"maxRows archives of one member": hostileOf(texts.unit, append(full(), archiveReports(maxRows, 1)...)),
			"one archive of maxRows members": hostileOf(texts.unit, append(full(), archiveReports(1, maxRows)...)),
		}
		for name, reports := range cases {
			t.Run(texts.name+"/"+name, func(t *testing.T) {
				p := newTestPlugin(t)
				data := mustReportData(t, scanContext(), reports)
				html, err := p.generateHTMLReport(data)
				if err != nil {
					t.Fatal(err)
				}
				maxInput := int(htmltopdf.DefaultLimits().MaxInputBytes)
				t.Logf("HTML of %d bytes, %.0f%% of the %d bytes the converter reads (margin %.2fx)",
					html.Len(), 100*float64(html.Len())/float64(maxInput), maxInput, float64(maxInput)/float64(html.Len()))
				if html.Len() > maxInput {
					t.Errorf("HTML of %d bytes, above the %d bytes the converter reads", html.Len(), maxInput)
				}
				start := time.Now()
				pdf, err := p.generatePDFReport(t.Context(), data)
				took := time.Since(start)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("%s: %d archives, %d rows in all; PDF of %.1f MiB in %s (limits: %d MiB, %s)",
					name, len(data.MitigatedArchives), len(data.MitigatedFiles)+len(data.ErrorFiles)+len(data.NotAnalyzedFiles),
					float64(pdf.Len())/(1<<20), took.Round(100*time.Millisecond), maxReportPDF>>20, renderTimeout)
				if os.Getenv("HC_WORST_CASE_TIME") == "1" && took > renderTimeout/2 {
					t.Errorf("rendered in %s, want at most half of %s", took, renderTimeout)
				}
				if pdf.Len() > maxReportPDF/2 {
					t.Errorf("PDF of %d bytes, want at most half of %d", pdf.Len(), maxReportPDF)
				}
			})
		}
	}
}
