//go:build linux

package main

import (
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

// longText is a distinct unbreakable text of the longest length a depositor can
// give.
func longText(prefix string, i int) string {
	return fmt.Sprintf("%s%d", prefix, i) + strings.Repeat("W", datamodel.MaxListedNameLen)
}

// manyThreats is n threat names of the longest length.
func manyThreats(n, seed int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = longText("w", seed*1000+i)
	}
	return names
}

// hostile gives every text of the reports the longest length a depositor can.
func hostile(reports []datamodel.Report) []datamodel.Report {
	var members func(files []datamodel.ExtractedFile) []datamodel.ExtractedFile
	members = func(files []datamodel.ExtractedFile) []datamodel.ExtractedFile {
		out := slices.Clone(files)
		for i := range out {
			out[i].FileName = longText("m", i)
			out[i].Malwares = manyThreats(256, i)
			out[i].ExtractedFiles = members(out[i].ExtractedFiles)
		}
		return out
	}
	for i := range reports {
		r := &reports[i]
		r.Filename = longText("f", i)
		r.QuarantineLocation = longText("q", i)
		if r.Error != "" {
			r.Error = longText("e", i)
		}
		if len(r.Malwares) > 0 {
			r.Malwares = manyThreats(64, i)
		}
		r.MaliciousExtractedFiles = members(r.MaliciousExtractedFiles)
		for j := range r.NotAnalyzedExtractedFiles {
			r.NotAnalyzedExtractedFiles[j].FileName = longText("n", j)
		}
	}
	return reports
}

// The worst reports a depositor can make, rendered by the real browser: every
// section full, long unbreakable texts, and the blocked archives either many or
// heavy. The size must stay under half of the cap; the time is logged, and
// asserted (half of the timeout) only with HC_WORST_CASE_TIME=1, which depends on
// the machine.
func TestRealBrowser_theWorstReportsStayUnderHalfTheLimits(t *testing.T) {
	skipWithoutBrowser(t)
	if testing.Short() {
		t.Skip("renders big PDFs")
	}
	full := func() []datamodel.Report {
		reports := notAnalyzedReports(maxRows)
		reports = append(reports, errorReports(maxRows)...)
		return append(reports, blockedReports(maxRows)...)
	}
	// Only the size is a verdict: the heaviest case takes most of the production
	// timeout when the machine is idle, and more than all of it when other
	// browsers run. The real timeout is kept for the optional time assertion.
	productionTimeout := renderTimeout
	renderTimeout = 10 * time.Minute
	t.Cleanup(func() { renderTimeout = productionTimeout })
	cases := map[string][]datamodel.Report{
		"maxRows archives of one member": hostile(append(full(), archiveReports(maxRows, 1)...)),
		"one archive of maxRows members": hostile(append(full(), archiveReports(1, maxRows)...)),
	}
	for name, reports := range cases {
		t.Run(name, func(t *testing.T) {
			p := &ReportPlugin{}
			if err := p.Init(p.GetDefaultConfig(), mock.NewMockHCContext()); err != nil {
				t.Fatal(err)
			}
			p.browser = &browserRunner{execPath: realBrowser, workDir: t.TempDir(), logger: slog.New(slog.DiscardHandler)}
			data := mustReportData(t, scanContext(), reports)
			start := time.Now()
			pdf, err := p.generatePDFReport(t.Context(), data)
			took := time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s: %d archives, %d rows in all; PDF of %.1f MiB in %s (limits: %d MiB, %s)",
				name, len(data.MitigatedArchives), len(data.MitigatedFiles)+len(data.ErrorFiles)+len(data.NotAnalyzedFiles),
				float64(pdf.Len())/(1<<20), took.Round(100*time.Millisecond), maxReportPDF>>20, productionTimeout)
			if os.Getenv("HC_WORST_CASE_TIME") == "1" && took > productionTimeout/2 {
				t.Errorf("rendered in %s, want at most half of %s", took, productionTimeout)
			}
			if pdf.Len() > maxReportPDF/2 {
				t.Errorf("PDF of %d bytes, want at most half of %d", pdf.Len(), maxReportPDF)
			}
		})
	}
}
