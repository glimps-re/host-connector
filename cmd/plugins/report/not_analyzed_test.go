package main

import (
	"fmt"
	"html/template"
	"math"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

func scanContext() datamodel.ScanContext {
	return datamodel.ScanContext{ScanID: "s", Start: time.Unix(0, 0), End: time.Unix(60, 0)}
}

func renderReports(t *testing.T, reports []datamodel.Report) (ReportData, string) {
	t.Helper()
	p := &ReportPlugin{}
	if err := p.Init(p.GetDefaultConfig(), mock.NewMockHCContext()); err != nil {
		t.Fatal(err)
	}
	data := mustReportData(t, scanContext(), reports)
	buf, err := p.generateHTMLReport(data)
	if err != nil {
		t.Fatal(err)
	}
	return data, buf.String()
}

// A new reason must be added here, and to notAnalyzedText.
var everyReason = map[datamodel.NotAnalyzedReason]string{
	datamodel.NotAnalyzedTooBig:        "Trop volumineux (contenu non vérifié)",
	datamodel.NotAnalyzedEmpty:         "Fichier vide",
	datamodel.NotAnalyzedEncrypted:     "Chiffré (mot de passe inconnu)",
	datamodel.NotAnalyzedExtractLimit:  "Écarté à l'extraction (limites)",
	datamodel.NotAnalyzedExtractError:  "Anomalie d'extraction",
	datamodel.NotAnalyzedPolicySkipped: "Liste blanche (non analysé)",
	datamodel.NotAnalyzedRestored:      "Restauré (précédemment bloqué)",
}

func TestNotAnalyzedText_everyReasonIsSaidAndAnUnknownOneShowsItsCode(t *testing.T) {
	for reason, text := range everyReason {
		if got := notAnalyzedText(reason); got != text {
			t.Errorf("notAnalyzedText(%q) = %q, want %q", reason, got, text)
		}
	}
	if got := notAnalyzedText("something-new"); got != "something-new" {
		t.Errorf("an unknown reason shows %q, want its code", got)
	}
}

func TestSizeText(t *testing.T) {
	for _, tt := range []struct {
		name   string
		size   int64
		reason datamodel.NotAnalyzedReason
		want   string
	}{
		{"empty file", 0, datamodel.NotAnalyzedEmpty, "0 B"},
		{"size not given", 0, datamodel.NotAnalyzedTooBig, "—"},
		{"negative size", -1, datamodel.NotAnalyzedExtractLimit, "—"},
		{"a size", 2048, datamodel.NotAnalyzedTooBig, "2.0 kB"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := sizeText(tt.size, tt.reason); got != tt.want {
				t.Errorf("sizeText(%d, %q) = %q, want %q", tt.size, tt.reason, got, tt.want)
			}
		})
	}
}

func notAnalyzedReports(n int) []datamodel.Report {
	reports := make([]datamodel.Report, 0, n)
	for i := range n {
		reports = append(reports, datamodel.Report{Filename: fmt.Sprintf("/in/f%04d", i), NotAnalyzedReason: datamodel.NotAnalyzedTooBig})
	}
	return reports
}

func errorReports(n int) []datamodel.Report {
	reports := make([]datamodel.Report, 0, n)
	for i := range n {
		reports = append(reports, datamodel.Report{Filename: fmt.Sprintf("/in/e%04d", i), Error: "boom"})
	}
	return reports
}

func blockedReports(n int) []datamodel.Report {
	reports := make([]datamodel.Report, 0, n)
	for i := range n {
		reports = append(reports, datamodel.Report{Filename: fmt.Sprintf("/in/b%04d.exe", i), Malicious: true, Malwares: []string{"evil"}, MalwareReason: datamodel.MalwareDetected})
	}
	return reports
}

func archiveReports(n, members int) []datamodel.Report {
	reports := make([]datamodel.Report, 0, n)
	for i := range n {
		files := make([]datamodel.ExtractedFile, 0, members)
		for j := range members {
			files = append(files, datamodel.ExtractedFile{FileName: fmt.Sprintf("m%03d", j), Malicious: true, Malwares: []string{"evil"}})
		}
		reports = append(reports, datamodel.Report{Filename: fmt.Sprintf("/in/a%03d.zip", i), Malicious: true, MaliciousExtractedFiles: files})
	}
	return reports
}

func TestReportData_sectionsAreCappedAndTheOverflowIsCounted(t *testing.T) {
	sections := map[string]struct {
		reports func(n int) []datamodel.Report
		listed  func(d ReportData) int
		more    func(d ReportData) int
		total   func(d ReportData) int
	}{
		"not analyzed":  {notAnalyzedReports, func(d ReportData) int { return len(d.NotAnalyzedFiles) }, func(d ReportData) int { return d.MoreNotAnalyzed }, func(d ReportData) int { return d.NbFileNotAnalyzed }},
		"errors":        {errorReports, func(d ReportData) int { return len(d.ErrorFiles) }, func(d ReportData) int { return d.MoreErrorFiles }, func(d ReportData) int { return d.TotalErrors }},
		"blocked files": {blockedReports, func(d ReportData) int { return len(d.MitigatedFiles) }, func(d ReportData) int { return d.MoreMitigatedFiles }, func(d ReportData) int { return d.TotalMitigated }},
	}
	for name, sec := range sections {
		for _, n := range []int{maxRows - 1, maxRows, maxRows + 1, maxRows + 200} {
			t.Run(fmt.Sprintf("%s/%d", name, n), func(t *testing.T) {
				d := mustReportData(t, scanContext(), sec.reports(n))
				wantListed := min(n, maxRows)
				if sec.listed(d) != wantListed || sec.more(d) != n-wantListed || sec.total(d) != n {
					t.Errorf("listed %d, more %d, total %d; want %d, %d, %d", sec.listed(d), sec.more(d), sec.total(d), wantListed, n-wantListed, n)
				}
			})
		}
	}
}

func TestReportData_theArchivesAndTheirMembersShareOneBudget(t *testing.T) {
	t.Run("many archives of one member", func(t *testing.T) {
		d := mustReportData(t, scanContext(), archiveReports(maxRows, 1))
		cost := archiveRows + 1
		if len(d.MitigatedArchives) != maxRows/cost || d.MoreMitigatedArchives != maxRows-maxRows/cost {
			t.Errorf("listed %d archives, %d more; want %d, %d", len(d.MitigatedArchives), d.MoreMitigatedArchives, maxRows/cost, maxRows-maxRows/cost)
		}
		for _, a := range d.MitigatedArchives {
			if len(a.ExtractedFiles) != 1 || a.MoreExtracted != 0 {
				t.Fatalf("archive %s: %d members, %d more; want its member", a.Name, len(a.ExtractedFiles), a.MoreExtracted)
			}
		}
	})
	t.Run("one archive of many members", func(t *testing.T) {
		d := mustReportData(t, scanContext(), archiveReports(1, maxRows))
		shown := maxRows - archiveRows
		if len(d.MitigatedArchives) != 1 || len(d.MitigatedArchives[0].ExtractedFiles) != shown || d.MitigatedArchives[0].MoreExtracted != maxRows-shown {
			t.Errorf("archive = %+v, want %d members shown and %d more", d.MitigatedArchives, shown, maxRows-shown)
		}
		if d.TotalMitigated != 1 || d.MoreMitigatedArchives != 0 {
			t.Errorf("total %d, more archives %d, want 1 and 0", d.TotalMitigated, d.MoreMitigatedArchives)
		}
	})
	t.Run("nested members count too", func(t *testing.T) {
		nested := datamodel.ExtractedFile{FileName: "inner.zip", Malicious: true, ExtractedFiles: []datamodel.ExtractedFile{{FileName: "x", Malicious: true}, {FileName: "y", Malicious: true}}}
		d := mustReportData(t, scanContext(), []datamodel.Report{{Filename: "/in/a.zip", Malicious: true, MaliciousExtractedFiles: []datamodel.ExtractedFile{nested}}})
		if got := d.MitigatedArchives[0].MoreExtracted; got != 0 {
			t.Errorf("MoreExtracted = %d, want all 3 files of the tree shown", got)
		}
	})
}

func TestReportData_errorsAreCountedOnce(t *testing.T) {
	tests := []struct {
		name   string
		report datamodel.Report
		want   int
		names  []string
	}{
		{"three failed members and the summary of their archive", datamodel.Report{Filename: "/in/a.zip", Error: datamodel.ExtractedErrorsTransient + ": " + datamodel.ExtractedErrorsSummary(3, "a"), ErrorExtractedFiles: map[string]string{"c": "x", "a": "x", "b": "x"}}, 3, []string{"a", "b", "c"}},
		{"an error that only looks like the summary", datamodel.Report{Filename: "/in/a.zip", Error: "x " + datamodel.ExtractedErrorsSummary(3, "a"), ErrorExtractedFiles: map[string]string{"b": "x"}}, 2, []string{"/in/a.zip", "b"}},
		{"an error of its own", datamodel.Report{Filename: "/in/f", Error: "boom"}, 1, []string{"/in/f"}},
		{"no error", datamodel.Report{Filename: "/in/f"}, 0, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := mustReportData(t, scanContext(), []datamodel.Report{tt.report})
			if d.TotalErrors != tt.want || len(d.ErrorFiles) != tt.want {
				t.Fatalf("errors: total %d, listed %d, want %d", d.TotalErrors, len(d.ErrorFiles), tt.want)
			}
			for i, name := range tt.names {
				if d.ErrorFiles[i].Name != name {
					t.Errorf("row %d = %q, want %q (sorted by name)", i, d.ErrorFiles[i].Name, name)
				}
			}
		})
	}
}

// The failed members of an archive are counted exactly, however many there are:
// the entry that counts those the report does not list is not a failed file, has
// no row, and adds its count.
func TestReportData_theCountOfTheFailedMembersIsExactBeyondTheListedOnes(t *testing.T) {
	const failed = 1500
	errs := map[string]string{}
	for i := range failed {
		errs[fmt.Sprintf("/in/member%05d", i)] = "boom"
	}
	// As the report of an archive reaches the plugin: bounded, with the count of
	// the files not listed.
	bounded := datamodel.Report{Filename: "/in/a.zip", ErrorExtractedFiles: errs}
	bounded.Bound()
	if _, ok := bounded.ErrorExtractedFiles[datamodel.MoreErrorsKey]; !ok {
		t.Fatal("setup: the bounded report has no count of the files not listed")
	}
	data, html := renderReports(t, []datamodel.Report{bounded})
	if data.TotalErrors != failed {
		t.Errorf("TotalErrors = %d, want %d", data.TotalErrors, failed)
	}
	if len(data.ErrorFiles) != maxRows || data.MoreErrorFiles != failed-maxRows {
		t.Errorf("rows %d, more %d; want %d and %d", len(data.ErrorFiles), data.MoreErrorFiles, maxRows, failed-maxRows)
	}
	for _, row := range data.ErrorFiles {
		if strings.Contains(row.Name, "more failed file") {
			t.Fatalf("the count of the files not listed is shown as a row: %+v", row)
		}
	}
	if strings.Contains(html, "more failed file") {
		t.Error("the count of the files not listed is in the HTML")
	}
	if !strings.Contains(html, fmt.Sprintf("Fichiers en erreur : </strong>%d", failed)) {
		t.Errorf("the HTML does not give %d files in error", failed)
	}
	if !strings.Contains(html, fmt.Sprintf("… et %d autres</p>", failed-maxRows)) {
		t.Errorf("the HTML does not say that %d are left out", failed-maxRows)
	}
}

// The entry that counts the failed members not listed adds its count and never
// makes a row, whatever the report holds besides.
func TestReportData_theCountEntryAddsItsCountAndNeverARow(t *testing.T) {
	summary := datamodel.ExtractedErrorsTransient + ": " + datamodel.ExtractedErrorsSummary(40, "x: boom")
	tests := []struct {
		name      string
		reports   []datamodel.Report
		wantTotal int
		wantRows  int
	}{
		{
			"the summary error and the count alone: 40 failed, none listed",
			[]datamodel.Report{{Filename: "/in/a.zip", Error: summary, ErrorExtractedFiles: map[string]string{datamodel.MoreErrorsKey: datamodel.MoreErrorsText(40)}}},
			40, 0,
		},
		{
			"an error of its own and the count: the file and the 40",
			[]datamodel.Report{{Filename: "/in/a.zip", Error: "own", ErrorExtractedFiles: map[string]string{datamodel.MoreErrorsKey: datamodel.MoreErrorsText(40)}}},
			41, 1,
		},
		{
			"a member listed and the count",
			[]datamodel.Report{{Filename: "/in/a.zip", ErrorExtractedFiles: map[string]string{"only": "x", datamodel.MoreErrorsKey: datamodel.MoreErrorsText(40)}}},
			41, 1,
		},
		{
			"a member and a count that is not one: the member alone",
			[]datamodel.Report{{Filename: "/in/a.zip", ErrorExtractedFiles: map[string]string{"only": "x", datamodel.MoreErrorsKey: "many"}}},
			1, 1,
		},
		{
			"two archives, each with a count",
			[]datamodel.Report{
				{Filename: "/in/a.zip", ErrorExtractedFiles: map[string]string{"a": "x", datamodel.MoreErrorsKey: datamodel.MoreErrorsText(40)}},
				{Filename: "/in/b.zip", ErrorExtractedFiles: map[string]string{"b": "y", datamodel.MoreErrorsKey: datamodel.MoreErrorsText(2)}},
			},
			44, 2,
		},
		{
			"a count at the clamp",
			[]datamodel.Report{{Filename: "/in/a.zip", ErrorExtractedFiles: map[string]string{datamodel.MoreErrorsKey: datamodel.MoreErrorsText(datamodel.MaxFileCount)}}},
			datamodel.MaxFileCount, 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := mustReportData(t, scanContext(), tt.reports)
			if d.TotalErrors != tt.wantTotal || len(d.ErrorFiles) != tt.wantRows {
				t.Errorf("total %d, rows %d (%+v); want %d and %d", d.TotalErrors, len(d.ErrorFiles), d.ErrorFiles, tt.wantTotal, tt.wantRows)
			}
			for _, row := range d.ErrorFiles {
				if strings.Contains(row.Name, "more failed file") {
					t.Errorf("the count is shown as a row: %+v", row)
				}
			}
			if d.MoreErrorFiles != tt.wantTotal-tt.wantRows {
				t.Errorf("more = %d, want %d", d.MoreErrorFiles, tt.wantTotal-tt.wantRows)
			}
		})
	}
}

// The counts of a report stop at the ceiling instead of wrapping around: reports
// that each hold a count at the clamp, or an absurd one, still add up to the
// ceiling, and the lines that say how many are left out stay positive.
func TestReportData_theCountsStopAtTheCeilingInsteadOfWrapping(t *testing.T) {
	const reports = 5
	all := make([]datamodel.Report, 0, reports)
	for i := range reports {
		all = append(all, datamodel.Report{
			Filename:                  fmt.Sprintf("/in/a%d.zip", i),
			NotAnalyzedExtractedCount: math.MaxInt,
			NotAnalyzedExtractedFiles: []datamodel.NotAnalyzedFile{{FileName: "m", Reason: datamodel.NotAnalyzedExtractLimit}},
			ErrorExtractedFiles:       map[string]string{"e": "x", datamodel.MoreErrorsKey: datamodel.MoreErrorsText(datamodel.MaxFileCount)},
		})
	}
	data, html := renderReports(t, all)
	if data.NbFileNotAnalyzed != datamodel.MaxFileCount {
		t.Errorf("NbFileNotAnalyzed = %d, want the ceiling %d", data.NbFileNotAnalyzed, datamodel.MaxFileCount)
	}
	if data.TotalErrors != datamodel.MaxFileCount {
		t.Errorf("TotalErrors = %d, want the ceiling %d", data.TotalErrors, datamodel.MaxFileCount)
	}
	if data.MoreNotAnalyzed <= 0 || data.MoreErrorFiles <= 0 {
		t.Errorf("more: %d not analyzed, %d errors; want both positive", data.MoreNotAnalyzed, data.MoreErrorFiles)
	}
	for _, note := range []string{fmt.Sprintf("… et %d autres</p>", data.MoreNotAnalyzed), fmt.Sprintf("… et %d autres</p>", data.MoreErrorFiles)} {
		if !strings.Contains(html, note) {
			t.Errorf("the report lacks %q", note)
		}
	}
}

// A file whose analysis failed, with the fixed text the scanner gives it, is a
// file in error: listed so, and not counted among the analyzed files.
func TestReportData_aFileWhoseAnalysisFailedIsInErrorAndNotAnalyzed(t *testing.T) {
	d := mustReportData(t, scanContext(), []datamodel.Report{
		{Filename: "/in/clean.txt"},
		{Filename: "/in/failed.txt", Error: "the file could not be analyzed"},
	})
	if d.NbFileSubmitted != 2 || d.NbFileAnalyzed != 1 || d.TotalErrors != 1 {
		t.Errorf("submitted %d, analyzed %d, errors %d; want 2, 1 and 1", d.NbFileSubmitted, d.NbFileAnalyzed, d.TotalErrors)
	}
	if len(d.ErrorFiles) != 1 || d.ErrorFiles[0].Name != "/in/failed.txt" {
		t.Errorf("error rows = %+v, want /in/failed.txt", d.ErrorFiles)
	}
}

func TestReportData_whatCountsAsAnalyzed(t *testing.T) {
	d := mustReportData(t, scanContext(), []datamodel.Report{
		{Filename: "/in/clean"},
		{Filename: "/in/passed", NotAnalyzedReason: datamodel.NotAnalyzedPolicySkipped},
		{Filename: "/in/both", NotAnalyzedReason: datamodel.NotAnalyzedTooBig, Error: "move failed"},
		{Filename: "/in/archive.zip", NotAnalyzedExtractedFiles: []datamodel.NotAnalyzedFile{{FileName: "m", Reason: datamodel.NotAnalyzedExtractLimit}}, NotAnalyzedExtractedCount: 3},
		{Filename: "/in/inconsistent.zip", NotAnalyzedExtractedFiles: []datamodel.NotAnalyzedFile{{FileName: "a"}, {FileName: "b"}}, NotAnalyzedExtractedCount: 1},
	})
	if d.NbFileSubmitted != 5 || d.NbFileAnalyzed != 3 {
		t.Errorf("submitted %d, analyzed %d; want 5 and 3", d.NbFileSubmitted, d.NbFileAnalyzed)
	}
	// passed (1) + both (1) + archive: max(3,1) + inconsistent: max(1,2).
	if d.NbFileNotAnalyzed != 1+1+3+2 {
		t.Errorf("not analyzed = %d, want 7", d.NbFileNotAnalyzed)
	}
	if d.TotalErrors != 1 || d.ErrorFiles[0].Name != "/in/both" {
		t.Errorf("errors = %d %+v, want /in/both", d.TotalErrors, d.ErrorFiles)
	}
	if d.MoreNotAnalyzed != 7-len(d.NotAnalyzedFiles) {
		t.Errorf("more = %d, listed %d", d.MoreNotAnalyzed, len(d.NotAnalyzedFiles))
	}
	for _, f := range d.NotAnalyzedFiles {
		if f.Name == "m" && f.Origin != "/in/archive.zip" {
			t.Errorf("origin of m = %q, want its archive", f.Origin)
		}
	}
}

func TestReport_noNotAnalyzedSectionWhenNothingPassedUnanalyzed(t *testing.T) {
	data, html := renderReports(t, []datamodel.Report{{Filename: "a.txt", SHA256: "h"}})
	if data.NbFileNotAnalyzed != 0 || len(data.NotAnalyzedFiles) != 0 || data.NbFileAnalyzed != 1 {
		t.Errorf("data = %+v, want one analyzed and none not analyzed", data)
	}
	if strings.Contains(html, `id="not-analyzed-files"`) {
		t.Error("the section is there with nothing to list")
	}
	if !strings.Contains(html, "(membres d'archives inclus) : </strong>0") {
		t.Error("the counter of the files not analyzed is missing")
	}
}

func TestReport_everyReasonIsInTheHTML(t *testing.T) {
	reports := make([]datamodel.Report, 0, 2*len(everyReason)+1)
	for reason := range everyReason {
		reports = append(reports,
			datamodel.Report{Filename: "/in/own-" + string(reason), FileSize: 2048, NotAnalyzedReason: reason},
			datamodel.Report{
				Filename:                  "/in/archive-" + string(reason) + ".zip",
				NotAnalyzedExtractedFiles: []datamodel.NotAnalyzedFile{{FileName: "member-" + string(reason), Size: 10, Reason: reason}},
				NotAnalyzedExtractedCount: 1,
			})
	}
	reports = append(reports, datamodel.Report{
		Filename:                  `/in/<script>alert(1)</script>.zip`,
		NotAnalyzedReason:         datamodel.NotAnalyzedPolicySkipped,
		NotAnalyzedExtractedFiles: []datamodel.NotAnalyzedFile{{FileName: `<img src=x onerror=alert(2)>`, Reason: datamodel.NotAnalyzedExtractLimit}},
		NotAnalyzedExtractedCount: 1,
	})
	data, html := renderReports(t, reports)
	want := 2*len(everyReason) + 2
	if data.NbFileNotAnalyzed != want || len(data.NotAnalyzedFiles) != want || data.MoreNotAnalyzed != 0 {
		t.Fatalf("not analyzed = %d, listed %d, more %d, want %d", data.NbFileNotAnalyzed, len(data.NotAnalyzedFiles), data.MoreNotAnalyzed, want)
	}
	for reason, text := range everyReason {
		if !strings.Contains(html, template.HTMLEscapeString(text)) {
			t.Errorf("the reason %q is not said (%q)", reason, text)
		}
		for _, name := range []string{"own-" + string(reason), "member-" + string(reason), "archive-" + string(reason) + ".zip"} {
			if !strings.Contains(html, name) {
				t.Errorf("%s is not in the report", name)
			}
		}
	}
	for _, raw := range []string{"<script>alert(1)", "<img src=x"} {
		if strings.Contains(html, raw) {
			t.Errorf("a hostile name is in the HTML unescaped: %q", raw)
		}
	}
	if !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("the hostile name is not shown as text")
	}
	if !strings.Contains(html, `id="not-analyzed-files"`) || !strings.Contains(html, "n'a pas été vérifié") {
		t.Error("the section and its warning are missing")
	}
}

// pluralOne finds a count of 1 said in the plural, not the end of a larger number.
var pluralOne = regexp.MustCompile(`(^|\D)1 autres`)

func TestOthers(t *testing.T) {
	tests := []struct {
		n         int
		one, many string
		want      string
	}{
		{1, "", "", "1 autre"},
		{2, "", "", "2 autres"},
		{1, " archive", " archives", "1 autre archive"},
		{7, " archive", " archives", "7 autres archives"},
		{1, " fichier de l'archive", " fichiers de l'archive", "1 autre fichier de l'archive"},
		{300, " fichier de l'archive", " fichiers de l'archive", "300 autres fichiers de l'archive"},
	}
	for _, tt := range tests {
		if got := others(tt.n, tt.one, tt.many); got != tt.want {
			t.Errorf("others(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

// A single row left out is said in the singular, in every section.
func TestReport_theOverflowOfOneIsSaidInTheSingular(t *testing.T) {
	tests := []struct {
		name    string
		reports []datamodel.Report
		want    string
	}{
		{"files not analyzed", notAnalyzedReports(maxRows + 1), "… et 1 autre</p>"},
		{"files in error", errorReports(maxRows + 1), "… et 1 autre</p>"},
		{"blocked files", blockedReports(maxRows + 1), "… et 1 autre</p>"},
		{"blocked archives", slices.Concat(fillers(maxRows), archiveReports(1, 1)), "… et 1 autre archive</p>"},
		{"members of an archive", slices.Concat(fillers(maxRows-archiveRows-1), archiveReports(1, 2)), "… et 1 autre fichier de l&#39;archive</p>"}, // html/template escapes the apostrophe of the helper
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, html := renderReports(t, tt.reports)
			if !strings.Contains(html, tt.want) {
				t.Errorf("the report lacks %q", tt.want)
			}
			if pluralOne.MatchString(html) {
				t.Error("a count of 1 is said in the plural")
			}
		})
	}
}

func TestReport_theOverflowIsSaidInTheHTML(t *testing.T) {
	reports := notAnalyzedReports(maxRows + 200)
	reports = append(reports, errorReports(maxRows+300)...)
	reports = append(reports, blockedReports(maxRows+400)...)
	reports = append(reports, archiveReports(maxRows, 1)...)
	reports = append(reports, archiveReports(1, maxRows)...)
	d, html := renderReports(t, reports)
	for _, note := range []string{
		fmt.Sprintf("… et %d autres</p>", d.MoreNotAnalyzed),
		fmt.Sprintf("… et %d autres</p>", d.MoreErrorFiles),
		fmt.Sprintf("… et %d autres</p>", d.MoreMitigatedFiles),
		fmt.Sprintf("… et %d autres archives", d.MoreMitigatedArchives),
	} {
		if !strings.Contains(html, note) {
			t.Errorf("the report lacks %q", note)
		}
	}
	if d.MoreNotAnalyzed != 200 || d.MoreErrorFiles != 300 || d.MoreMitigatedFiles != 400 {
		t.Errorf("more: %d, %d, %d; want 200, 300, 400", d.MoreNotAnalyzed, d.MoreErrorFiles, d.MoreMitigatedFiles)
	}
}

func rowsOf(d ReportData) int {
	rows := len(d.NotAnalyzedFiles) + len(d.ErrorFiles) + len(d.MitigatedFiles)
	for _, a := range d.MitigatedArchives {
		rows += archiveRows + countRows(a.ExtractedFiles)
	}
	return rows
}

func countRows(files []ExtractedFileData) (n int) {
	for _, f := range files {
		n += 1 + countRows(f.ExtractedFiles)
	}
	return n
}

func maliciousTree(depth, width int) []datamodel.ExtractedFile {
	if depth == 0 {
		return nil
	}
	files := make([]datamodel.ExtractedFile, 0, width)
	for i := range width {
		files = append(files, datamodel.ExtractedFile{FileName: fmt.Sprintf("n%d-%d", depth, i), Malicious: true, ExtractedFiles: maliciousTree(depth-1, width)})
	}
	return files
}

func TestReportData_theBudgetOfTheArchivesAtItsEdges(t *testing.T) {
	archive := func(name string, files []datamodel.ExtractedFile) datamodel.Report {
		return datamodel.Report{Filename: name, Malicious: true, MaliciousExtractedFiles: files}
	}
	tests := []struct {
		name         string
		reports      []datamodel.Report
		wantArchives int
		wantMembers  int
		wantMore     int
		wantMoreArch int
	}{
		{"the budget is used up: the next archive is left out", append(archiveReports(maxRows/(archiveRows+1), 1), archiveReports(1, 1)...), maxRows / (archiveRows + 1), 1, 0, 1},
		{"a tree larger than the budget", []datamodel.Report{archive("/in/big.zip", maliciousTree(4, 6))}, 1, maxRows - archiveRows, 6 + 36 + 216 + 1296 - (maxRows - archiveRows), 0},
		{"a malicious archive with no member listed is a blocked file", []datamodel.Report{archive("/in/odd.zip", nil)}, 0, 0, 0, 0},
		{"members present and none malicious", []datamodel.Report{archive("/in/clean-members.zip", []datamodel.ExtractedFile{{FileName: "clean"}})}, 1, 0, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := mustReportData(t, scanContext(), tt.reports)
			if len(d.MitigatedArchives) != tt.wantArchives {
				t.Fatalf("archives listed = %d, want %d", len(d.MitigatedArchives), tt.wantArchives)
			}
			if got := rowsOf(d); got > maxRows {
				t.Errorf("rows = %d, over the budget of %d", got, maxRows)
			}
			if tt.wantArchives == 0 && len(d.MitigatedFiles) != len(tt.reports) {
				t.Errorf("blocked files = %d, want %d", len(d.MitigatedFiles), len(tt.reports))
			}
			if d.MoreMitigatedArchives != tt.wantMoreArch {
				t.Errorf("more archives = %d, want %d", d.MoreMitigatedArchives, tt.wantMoreArch)
			}
			if tt.wantArchives == 1 {
				if got := countRows(d.MitigatedArchives[0].ExtractedFiles); got != tt.wantMembers {
					t.Errorf("members shown = %d, want %d", got, tt.wantMembers)
				}
				if d.MitigatedArchives[0].MoreExtracted != tt.wantMore {
					t.Errorf("more members = %d, want %d", d.MitigatedArchives[0].MoreExtracted, tt.wantMore)
				}
			}
		})
	}
}

// fillers are archives of the exact cost of the budget left out: each costs
// archiveRows (a member that is not malicious, so no row), the first one more
// when the budget does not divide.
func fillers(cost int) []datamodel.Report {
	count, extra := cost/archiveRows, cost%archiveRows
	reports := make([]datamodel.Report, 0, count)
	for i := range count {
		members := []datamodel.ExtractedFile{{FileName: "clean"}}
		if i == 0 {
			for j := range extra {
				members = append(members, datamodel.ExtractedFile{FileName: fmt.Sprintf("bad%d", j), Malicious: true})
			}
		}
		reports = append(reports, datamodel.Report{Filename: fmt.Sprintf("/in/fill%03d.zip", i), Malicious: true, MaliciousExtractedFiles: members})
	}
	return reports
}

// The last archive has 3 malicious members and finds only what the others left.
func TestReportData_theLastArchiveFindsWhatIsLeftOfTheBudget(t *testing.T) {
	tests := []struct {
		remaining     int
		wantListed    bool
		wantMembers   int
		wantMore      int
		wantRowsTotal int
	}{
		{2, false, 0, 0, maxRows - 2},
		{3, true, 0, 3, maxRows},
		{4, true, 1, 2, maxRows},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("remaining %d", tt.remaining), func(t *testing.T) {
			reports := slices.Concat(fillers(maxRows-tt.remaining), archiveReports(1, 3))
			d := mustReportData(t, scanContext(), reports)
			if rows := rowsOf(d); rows != tt.wantRowsTotal {
				t.Errorf("rows = %d, want %d", rows, tt.wantRowsTotal)
			}
			last := len(d.MitigatedArchives) - 1
			if !tt.wantListed {
				if d.MoreMitigatedArchives != 1 || d.MitigatedArchives[last].Name == "/in/a000.zip" {
					t.Errorf("more archives = %d, last listed %q, want the last archive left out", d.MoreMitigatedArchives, d.MitigatedArchives[last].Name)
				}
				return
			}
			got := d.MitigatedArchives[last]
			if got.Name != "/in/a000.zip" || countRows(got.ExtractedFiles) != tt.wantMembers || got.MoreExtracted != tt.wantMore || d.MoreMitigatedArchives != 0 {
				t.Errorf("last archive = %q with %d members and %d more (more archives %d), want %d and %d",
					got.Name, countRows(got.ExtractedFiles), got.MoreExtracted, d.MoreMitigatedArchives, tt.wantMembers, tt.wantMore)
			}
		})
	}
}

func TestReportData_everyRowOfEverySectionStaysInTheBudget(t *testing.T) {
	reports := notAnalyzedReports(maxRows)
	reports = append(reports, errorReports(maxRows)...)
	reports = append(reports, blockedReports(maxRows)...)
	reports = append(reports, archiveReports(10, 100)...)
	d := mustReportData(t, scanContext(), reports)
	if got := len(d.MitigatedFiles) + len(d.ErrorFiles) + len(d.NotAnalyzedFiles); got > 3*maxRows {
		t.Errorf("rows = %d, over %d", got, 3*maxRows)
	}
	archiveRowsShown := rowsOf(d) - len(d.MitigatedFiles) - len(d.ErrorFiles) - len(d.NotAnalyzedFiles)
	if archiveRowsShown > maxRows {
		t.Errorf("archive rows = %d, over %d", archiveRowsShown, maxRows)
	}
}

func TestReportData_failedMembersAndTheReservedNameErrorAreBothListed(t *testing.T) {
	d := mustReportData(t, scanContext(), []datamodel.Report{{
		Filename:            "/in/report-session-x.zip",
		Error:               "file name reserved for session reports",
		ErrorExtractedFiles: map[string]string{"a": "x", "b": "y"},
	}})
	if d.TotalErrors != 3 || len(d.ErrorFiles) != 3 {
		t.Fatalf("errors: total %d, listed %d, want 3 (2 members and the reserved name once)", d.TotalErrors, len(d.ErrorFiles))
	}
	if d.ErrorFiles[0].Name != "/in/report-session-x.zip" || d.ErrorFiles[1].Name != "a" || d.ErrorFiles[2].Name != "b" {
		t.Errorf("rows = %+v", d.ErrorFiles)
	}
}

func TestCellText(t *testing.T) {
	ascii := func(n int) string { return strings.Repeat("a", n) }
	long := ascii(200)
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"99 bytes unchanged", ascii(99), ascii(99)},
		{"100 bytes unchanged", ascii(100), ascii(100)},
		{"101 bytes cut", "H" + ascii(98) + "T" + "x", "H" + ascii(47) + "…" + ascii(47) + "T" + "x"},
		{"long ascii", long, ascii(48) + "…" + ascii(49)},
		{"3-byte runes", strings.Repeat("€", 60), strings.Repeat("€", 16) + "…" + strings.Repeat("€", 16)},
		{"4-byte runes", strings.Repeat("😀", 40), strings.Repeat("😀", 12) + "…" + strings.Repeat("😀", 12)},
		{"mid-rune on the head side", ascii(47) + "€" + ascii(100), ascii(47) + "…" + ascii(49)},
		{"mid-rune on the tail side", ascii(100) + "€" + ascii(48), ascii(48) + "…" + ascii(48)},
		{"bidi control", "invoice\u202etxt.exe", "invoice\ufffdtxt.exe"},
		{"every bidi control", "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u061c", strings.Repeat("\ufffd", 12)},
		{"C0 controls", "a\x00b\nc\td\x1be", "a\ufffdb\ufffdc\ufffdd\ufffde"},
		{"invalid utf-8 is replaced", "a\xffb", "a\ufffdb"},
		{"zero-width space", "a\u200bb", "a\ufffdb"},
		{"tag character", "a\U000e0041b", "a\ufffdb"},
		{"line separator and filler", "a\u2028b\u3164c", "a\ufffdb\ufffdc"},
		{"replacement lengthens the text past the bound", strings.Repeat("\x01", 40), strings.Repeat("\ufffd", 16) + "…" + strings.Repeat("\ufffd", 16)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cellText(tt.in)
			if got != tt.want {
				t.Errorf("cellText = %q, want %q", got, tt.want)
			}
			if len(got) > maxCellBytes || !utf8.ValidString(got) {
				t.Errorf("%q is over %d bytes or not valid UTF-8", got, maxCellBytes)
			}
		})
	}
}

func TestNotAnalyzedText_anUnknownReasonIsCut(t *testing.T) {
	if got := notAnalyzedText(datamodel.NotAnalyzedReason(strings.Repeat("W", 1024))); len(got) > maxCellBytes {
		t.Errorf("an unknown reason shows %d bytes, want at most %d", len(got), maxCellBytes)
	}
}

func TestThreatNames(t *testing.T) {
	names := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("w%d", i)
		}
		return out
	}
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"none", nil, []string{}},
		{"at the bound", names(maxThreatNames), names(maxThreatNames)},
		{"one over", names(maxThreatNames + 1), append(names(maxThreatNames), "… (+1 autre)")},
		{"many", names(64), append(names(maxThreatNames), fmt.Sprintf("… (+%d autres)", 64-maxThreatNames))},
		{"long names are cut", []string{strings.Repeat("W", 1024)}, []string{cellText(strings.Repeat("W", 1024))}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := threatNames(tt.in); !slices.Equal(got, tt.want) {
				t.Errorf("threatNames = %q, want %q", got, tt.want)
			}
		})
	}
}

// exempt are the strings of ReportData that a depositor does not control: made
// by the connector, by the analysis service or by the report itself.
var exempt = map[string]bool{
	"ScanID": true, "FileVolume": true, "AnalyzedVolume": true, "FilteredVolume": true,
	"ScanStartTime": true, "Duration": true, "Size": true, "Reason": true,
	"MitigationReason": true, "SHA256": true, "GMalwareURL": true,
}

// fillStrings gives every string of a value, however nested, the longest length
// a depositor can give, so that a text the report shows uncut is found.
func fillStrings(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		if v.CanSet() {
			v.SetString(strings.Repeat("W", datamodel.MaxListedNameLen))
		}
	case reflect.Slice:
		for i := range v.Len() {
			fillStrings(v.Index(i))
		}
	case reflect.Struct:
		for _, field := range v.Fields() {
			fillStrings(field)
		}
	case reflect.Map:
		for _, key := range v.MapKeys() {
			elem := reflect.New(v.Type().Elem()).Elem()
			fillStrings(elem)
			v.SetMapIndex(key, elem)
		}
	}
}

func checkStrings(t *testing.T, v reflect.Value, path string) {
	t.Helper()
	switch v.Kind() {
	case reflect.String:
		name := path[strings.LastIndex(path, ".")+1:]
		if !exempt[name] && len(v.String()) > maxCellBytes {
			t.Errorf("%s: a text of %d bytes is shown whole", path, len(v.String()))
		}
	case reflect.Slice:
		for i := range v.Len() {
			checkStrings(t, v.Index(i), path)
		}
	case reflect.Map:
		for _, key := range v.MapKeys() {
			checkStrings(t, key, path)
			checkStrings(t, v.MapIndex(key), path)
		}
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			checkStrings(t, v.Elem(), path)
		}
	case reflect.Struct:
		for field, value := range v.Fields() {
			checkStrings(t, value, path+"."+field.Name)
		}
	}
}

func TestReportData_everyTextOfADepositorIsCut(t *testing.T) {
	longThreats := func() []string {
		names := make([]string, 64)
		for i := range names {
			names[i] = fmt.Sprintf("%02d", i) + strings.Repeat("W", datamodel.MaxListedNameLen)
		}
		return names
	}
	var nested datamodel.ExtractedFile
	fillStrings(reflect.ValueOf(&nested).Elem())
	nested.Malicious, nested.ExtractedFiles, nested.Malwares = true, nil, longThreats()
	var member datamodel.ExtractedFile
	fillStrings(reflect.ValueOf(&member).Elem())
	member.Malicious, member.ExtractedFiles, member.Malwares = true, []datamodel.ExtractedFile{nested}, longThreats()
	report := datamodel.Report{Malicious: true, NotAnalyzedExtractedCount: 1}
	fillStrings(reflect.ValueOf(&report).Elem())
	report.Malicious = true
	report.Malwares = longThreats()
	report.NotAnalyzedReason = datamodel.NotAnalyzedTooBig
	report.MaliciousExtractedFiles = []datamodel.ExtractedFile{member}
	report.ErrorExtractedFiles = map[string]string{strings.Repeat("W", 1024): strings.Repeat("W", 1024)}
	report.NotAnalyzedExtractedFiles = []datamodel.NotAnalyzedFile{{FileName: strings.Repeat("W", 1024), Reason: datamodel.NotAnalyzedExtractLimit}}
	blocked := report
	blocked.MaliciousExtractedFiles = nil
	d := mustReportData(t, scanContext(), []datamodel.Report{report, blocked})
	if len(d.NotAnalyzedFiles) == 0 || len(d.ErrorFiles) == 0 || len(d.MitigatedFiles) == 0 || len(d.MitigatedArchives) == 0 {
		t.Fatalf("a section is empty: %+v", d)
	}
	checkStrings(t, reflect.ValueOf(d), "ReportData")
	var rows [][]string
	for _, f := range d.MitigatedFiles {
		rows = append(rows, f.Malwares)
	}
	var walk func(files []ExtractedFileData)
	walk = func(files []ExtractedFileData) {
		for _, f := range files {
			rows = append(rows, f.Malwares)
			walk(f.ExtractedFiles)
		}
	}
	for _, a := range d.MitigatedArchives {
		walk(a.ExtractedFiles)
	}
	if len(rows) != 3 {
		t.Fatalf("%d rows with threats, want a blocked file, a member and a nested member", len(rows))
	}
	for _, names := range rows {
		if len(names) != maxThreatNames+1 {
			t.Errorf("a row shows %d threat entries, want %d (the names and the count of the others)", len(names), maxThreatNames+1)
		}
	}
}
