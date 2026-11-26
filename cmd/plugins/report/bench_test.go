//go:build linux && realbrowser

package main

import (
	"regexp"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

// [^s] excludes /Type /Pages; relies on the page dictionaries being uncompressed.
var pdfPage = regexp.MustCompile(`/Type\s*/Page[^s]`)

// benchReports mixes every section (not analyzed, errors, blocked, archives with
// nested members); at 2000 files every section goes past maxRows (300).
func benchReports(files int) []datamodel.Report {
	each := files / 4
	reports := notAnalyzedReports(each)
	reports = append(reports, errorReports(each)...)
	reports = append(reports, blockedReports(each)...)
	archives := archiveReports(each/5, 5)
	for i := range archives {
		archives[i].MaliciousExtractedFiles = append(archives[i].MaliciousExtractedFiles, maliciousTree(2, 3)...)
	}
	return append(reports, archives...)
}

// BenchmarkGeneratePDFReport times the real PDF path of the plugin; rerun it
// unchanged after the htmltopdf swap.
func BenchmarkGeneratePDFReport(b *testing.B) {
	requireBrowser(b)
	for _, bc := range []struct {
		name  string
		files int
	}{{"empty", 0}, {"small", 50}, {"capped", 2000}} {
		b.Run(bc.name, func(b *testing.B) {
			p := newTestPlugin(b)
			// Init ran with the stubbed checkBrowser of TestMain: give the real browser.
			p.browser = runner(b, realBrowser)
			data := mustReportData(b, scanContext(), benchReports(bc.files))
			var pdf []byte
			b.ReportAllocs()
			for b.Loop() {
				buf, err := p.generatePDFReport(b.Context(), data)
				if err != nil {
					b.Fatal(err)
				}
				pdf = buf.Bytes()
			}
			pages := len(pdfPage.FindAll(pdf, -1))
			if pages == 0 {
				b.Fatal("no page found in the PDF")
			}
			b.ReportMetric(float64(len(pdf)), "pdf-bytes")
			b.ReportMetric(float64(pages), "pages")
		})
	}
}

// BenchmarkStartup times the self-test of Init: the start-up cost of the plugin.
func BenchmarkStartup(b *testing.B) {
	requireBrowser(b)
	r := runner(b, realBrowser)
	b.ReportAllocs()
	for b.Loop() {
		if err := r.selfTest(b.Context()); err != nil {
			b.Fatal(err)
		}
	}
}
