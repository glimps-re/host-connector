//go:build linux

package main

import (
	"html/template"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

func mixedSession() []datamodel.Report {
	return []datamodel.Report{
		{Filename: "/in/virus.exe", Malicious: true, Malwares: []string{"evil"}, MalwareReason: datamodel.MalwareDetected},
		{Filename: "/in/a.lnk", Malicious: true, Malwares: []string{"forbidden_files"}, MalwareReason: datamodel.FilteredFilePath},
		{Filename: "/in/b.dll", Malicious: true, Malwares: []string{"forbidden_files"}, MalwareReason: datamodel.FilteredFileType},
		{Filename: "/in/clean.txt"},
		{Filename: "/in/whitelisted-path.txt", FileSize: 10, NotAnalyzedReason: datamodel.NotAnalyzedSkippedPath},
		{Filename: "/in/whitelisted-type.iso", FileSize: 20, NotAnalyzedReason: datamodel.NotAnalyzedSkippedType},
		{
			Filename: "/in/links.tar",
			NotAnalyzedExtractedFiles: []datamodel.NotAnalyzedFile{
				{FileName: "to-passwd", Reason: datamodel.NotAnalyzedSymlink},
				{FileName: "empty.txt", Reason: datamodel.NotAnalyzedEmpty},
				{FileName: "sub.zip/in-sub", Reason: datamodel.NotAnalyzedSymlink},
			},
			NotAnalyzedExtractedCount: 3,
		},
	}
}

var mixedLabels = []string{
	notAnalyzedText(datamodel.NotAnalyzedSkippedPath),
	notAnalyzedText(datamodel.NotAnalyzedSkippedType),
	notAnalyzedText(datamodel.NotAnalyzedSymlink),
	notAnalyzedText(datamodel.NotAnalyzedEmpty),
}

func TestReport_mixedSessionNumbersAndLabelsInTheHTML(t *testing.T) {
	data, html := renderReports(t, mixedSession())
	if data.TotalMalware != 1 {
		t.Errorf("TotalMalware = %d, want 1 beside a path and a type refusal", data.TotalMalware)
	}
	if data.NbFileNotAnalyzed != 5 {
		t.Errorf("NbFileNotAnalyzed = %d, want 5 (2 top-level files, 3 members)", data.NbFileNotAnalyzed)
	}
	if want := "<strong>Fichiers malveillants : </strong>1</li>"; !strings.Contains(html, want) {
		t.Errorf("HTML lacks %q", want)
	}
	for _, label := range mixedLabels {
		if !strings.Contains(html, template.HTMLEscapeString(label)) {
			t.Errorf("HTML lacks the reason %q", label)
		}
	}
	for _, name := range []string{"whitelisted-path.txt", "whitelisted-type.iso", "to-passwd", "empty.txt", "in-sub"} {
		if !strings.Contains(html, name) {
			t.Errorf("HTML lacks the file %q", name)
		}
	}
	if strings.Contains(html, "Liste blanche (non analysé)") {
		t.Error("the generic whitelist label is shown for a file whose filter is known")
	}
}

func TestReport_mixedSessionNumbersAndLabelsInThePDF(t *testing.T) {
	p := newTestPlugin(t)
	_, texts := renderPDF(t, p, mixedSession())
	text := joined(texts)
	for _, want := range append([]string{"Fichiersmalveillants:1"}, mixedLabels...) {
		if !strings.Contains(text, squash(want)) {
			t.Errorf("the PDF text lacks %q", want)
		}
	}
	if strings.Contains(text, squash("dont fichiers")) {
		t.Error("the PDF still holds the old wording")
	}
}

func TestReport_linkNamesWithControlAndBidiCharactersAreRenderedAsText(t *testing.T) {
	hostile := "evil\x1b[31m\u202e\u2066gnp.exe\x00" + strings.Repeat("é", 2000)
	links := make([]datamodel.NotAnalyzedFile, maxRows+1)
	for i := range links {
		links[i] = datamodel.NotAnalyzedFile{FileName: hostile, Reason: datamodel.NotAnalyzedSymlink}
	}
	reports := []datamodel.Report{{Filename: "/in/h.tar", NotAnalyzedExtractedFiles: links, NotAnalyzedExtractedCount: 1_000_000}}
	data, html := renderReports(t, reports)
	if data.NbFileNotAnalyzed != 1_000_000 {
		t.Errorf("NbFileNotAnalyzed = %d, want the exact count 1000000", data.NbFileNotAnalyzed)
	}
	for _, raw := range []string{"\x1b", "\u202e", "\u2066", "\x00"} {
		if strings.Contains(html, raw) {
			t.Errorf("the HTML holds the raw character %q of a hostile link name", raw)
		}
	}
	_, texts := renderPDF(t, newTestPlugin(t), reports)
	pdf := joined(texts)
	for _, raw := range []string{"\x1b", "\u202e", "\u2066", "\x00"} {
		if strings.Contains(pdf, raw) {
			t.Errorf("the PDF text holds the raw character %q of a hostile link name", raw)
		}
	}
}
