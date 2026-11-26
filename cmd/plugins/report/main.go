//go:build linux

// Package main implements a PDF/HTML report generation plugin.
//
// Generates scan reports from templates using htmltopdf (pure Go, no browser)
// for PDF conversion.
package main

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"iter"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/dustin/go-humanize"
	"github.com/glimps-re/host-connector/internal/displaytext"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// ReportPlugin generates PDF and HTML reports from scan results.
type ReportPlugin struct {
	templ         *template.Template
	pdf           *renderer
	logger        *slog.Logger
	consoleLogger *slog.Logger
}

var (
	_ plugins.Plugin    = &ReportPlugin{}
	_ plugins.Validator = &ReportPlugin{}

	// HCPlugin is the exported plugin instance.
	HCPlugin ReportPlugin

	// defaultTemplate is the embedded HTML template for reports.
	//
	//go:embed report.html.tmpl
	defaultTemplate string
)

// Config defines the template path for report generation.
type Config struct {
	TemplatePath string `mapstructure:"template_path"`
	// Deprecated: ignored; the PDF is rendered without a browser.
	ChromePath string `mapstructure:"chrome_path"`
}

// chromePathDeprecated is logged when the configuration still sets chrome_path.
const chromePathDeprecated = "chrome_path is deprecated and ignored: the report plugin renders PDFs without a browser; remove it from the configuration"

// GetDefaultConfig returns the default configuration.
func (p *ReportPlugin) GetDefaultConfig() (config any) {
	config = new(Config)
	return
}

// Validate loads the template and builds the PDF renderer like Init does,
// without changing the plugin.
func (p *ReportPlugin) Validate(rawConfig any, vc plugins.ValidationContext) error {
	config, ok := rawConfig.(*Config)
	if !ok {
		return errors.New("bad config passed to report")
	}
	if _, err := parseTemplate(config.TemplatePath); err != nil {
		return err
	}
	_, err := startRenderer(context.Background(), config, vc.GetLogger())
	return err
}

// startRenderer warns when the deprecated chrome_path is set, then builds the
// PDF renderer and proves it renders a PDF.
func startRenderer(ctx context.Context, config *Config, logger *slog.Logger) (*renderer, error) {
	if config.ChromePath != "" {
		logger.WarnContext(ctx, chromePathDeprecated, slog.String("chrome_path", config.ChromePath))
	}
	return newRenderer(ctx, logger)
}

// parseTemplate parses the template at path, or the embedded one when path is
// empty.
func parseTemplate(path string) (*template.Template, error) {
	// ParseFiles names the parsed template after the base name of the file: the
	// root must carry that name, or Execute finds it empty.
	name := "report"
	if path != "" {
		name = filepath.Base(path)
	}
	templ := template.New(name).Funcs(template.FuncMap{
		"mergeArgsIntoSlice": mergeArgsIntoSlice,
		"formatDuration":     formatDuration,
		"others":             others,
		"add":                func(a, b int) int { return a + b }, // used to increment depth for recursive calls
		"mul":                func(a, b int) int { return a * b }, // used to calculates indentation (depth * 10px)
		"min": func(a, b int) int { // used to cap indentation depth
			if a < b {
				return a
			}
			return b
		},
	})

	if path != "" {
		return templ.ParseFiles(filepath.Clean(path))
	}
	return templ.Parse(defaultTemplate)
}

// Init loads the template, builds the PDF renderer and registers the report
// generator. The plugin is changed only when everything succeeded.
func (p *ReportPlugin) Init(rawConfig any, hcc plugins.HCContext) error {
	config, ok := rawConfig.(*Config)
	if !ok {
		return errors.New("bad config passed to report")
	}
	templ, err := parseTemplate(config.TemplatePath)
	if err != nil {
		return err
	}
	pdf, err := startRenderer(context.Background(), config, hcc.GetLogger())
	if err != nil {
		return err
	}
	p.logger = hcc.GetLogger().With(slog.String("plugin", "report"))
	p.consoleLogger = hcc.GetConsoleLogger()
	p.templ, p.pdf = templ, pdf
	if config.ChromePath != "" {
		p.consoleLogger.Warn(chromePathDeprecated, slog.String("chrome_path", config.ChromePath))
	}

	template := "default"
	if config.TemplatePath != "" {
		template = config.TemplatePath
	}
	p.logger.Info("plugin initialized", slog.String("template", template))
	p.consoleLogger.Info("report plugin initialized, template: " + template)
	hcc.RegisterGenerateReport(p.GenerateReport)
	return nil
}

// Close cleans up plugin resources (no-op for this plugin).
func (p *ReportPlugin) Close(context.Context) error {
	return nil
}

// moreThreatsFormat is the last entry of the threats of a row, after the first
// maxThreatNames: the count of the others, in the words of others.
const moreThreatsFormat = "… (+%s)"

// others says how many are left out, in French: "1 autre" and "N autres", the
// noun after the word, in the form that goes with the count.
func others(n int, one, many string) string {
	if n == 1 {
		return "1 autre" + one
	}
	return fmt.Sprintf("%d autres%s", n, many)
}

// mergeArgsIntoSlice is a template helper that combines arguments into a slice.
func mergeArgsIntoSlice(args ...any) []any {
	return args
}

// formatDuration formats a time.Duration as "XmYs" or "Xs".
func formatDuration(d time.Duration) string {
	totalSeconds := int(d.Seconds())
	minutes := totalSeconds / 60
	seconds := totalSeconds % 60
	if minutes <= 0 {
		return fmt.Sprintf("%ds", seconds)
	}
	return fmt.Sprintf("%dm%ds", minutes, seconds)
}

// FileReportData contains individual file information for reports.
type FileReportData struct {
	Name               string
	SHA256             string
	Size               string
	Malwares           []string
	MitigationReason   string
	QuarantineLocation string
	GMalwareURL        string
}

// ArchiveReportData contains archive scan information for reports.
type ArchiveReportData struct {
	Name               string
	SHA256             string
	Size               string
	QuarantineLocation string
	FileCount          int
	ExtractedFiles     []ExtractedFileData
	// MoreExtracted is the number of malicious members of the archive left out of
	// ExtractedFiles by the budget of the section.
	MoreExtracted int
}

// ExtractedFileData contains extracted file information from archives.
type ExtractedFileData struct {
	Name             string
	SHA256           string
	Malwares         []string
	Size             string
	MitigationReason string
	GMalwareURL      string
	ExtractedFiles   []ExtractedFileData
}

// ErrorFileData contains error information for files that failed analysis.
type ErrorFileData struct {
	Name  string
	Error string
}

// maxRows bounds every section of the report: a hostile archive cannot make the
// PDF as long as it has members. The blocked archives and their malicious members
// share one budget, an archive costing archiveRows rows more than its members. The
// counters stay exact, and what is not listed is counted in the More fields.
const (
	maxRows = 300
	// archiveRows is what an archive costs in its section, on top of one row for
	// each of its members shown: its title, its details and the head of its table.
	archiveRows = 3
	// maxCellBytes bounds every text of a depositor shown in the PDF (a name, an
	// error, a threat): the time to render grows with the length of the texts,
	// and a name can be 1 KiB. The full texts stay in the JSON report.
	maxCellBytes = 100
	// maxThreatNames bounds the threat names shown in a row.
	maxThreatNames = 2
)

// NotAnalyzedFileData is a file, or a member of an archive, that reached the
// output without a complete analysis.
type NotAnalyzedFileData struct {
	Name   string
	Size   string
	Reason string
	// Origin is the archive the file was found in, "" for a file of its own.
	Origin string
}

// ReportData contains complete scan report data for template rendering.
type ReportData struct {
	ScanID          string
	NbFileSubmitted int
	// NbFileAnalyzed counts the reports of files that were analyzed: not those
	// passed without analysis, nor those in error.
	NbFileAnalyzed int
	// NbFileNotAnalyzed is the exact number of files and members not analyzed,
	// whatever the number listed.
	NbFileNotAnalyzed int
	NotAnalyzedFiles  []NotAnalyzedFileData
	// More* are the numbers of rows left out of the lists, which are cut at maxRows.
	MoreNotAnalyzed       int
	MoreMitigatedFiles    int
	MoreMitigatedArchives int
	MoreErrorFiles        int
	FileVolume            string
	AnalyzedVolume        string
	FilteredVolume        string
	TotalMitigated        int
	// TotalMalware counts the reports whose content was detected as malware
	// (MalwareDetected); refusals by path, type or policy are blocked, not counted here.
	TotalMalware      int
	TotalErrors       int
	MitigatedFiles    []FileReportData
	MitigatedArchives []ArchiveReportData
	ErrorFiles        []ErrorFileData
	ScanStartTime     string
	Duration          string
}

// GenerateReport generates a PDF report from scan results. The reports are read
// once, as they come.
func (p *ReportPlugin) GenerateReport(ctx context.Context, reportContext datamodel.ScanContext, reports iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
	p.consoleLogger.Debug("generate pdf report")
	data, err := reportDataFrom(ctx, reportContext, reports)
	if err != nil {
		return plugins.GeneratedReport{}, err
	}
	buffer, err := p.generatePDFReport(ctx, data)
	if err != nil {
		return plugins.GeneratedReport{}, err
	}
	return plugins.GeneratedReport{Content: io.NopCloser(buffer), Extension: ".pdf"}, nil
}

func toUint(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

// reportDataFrom converts scan results to ReportData for template rendering, in
// a single pass over the reports. A report that fails to be read, or the end of ctx, ends it. Every
// section stops at maxRows rows; the More fields are what the counters hold
// beyond what is listed.
func reportDataFrom(ctx context.Context, reportContext datamodel.ScanContext, reports iter.Seq2[datamodel.Report, error]) (reportData ReportData, err error) {
	reportData = ReportData{
		ScanID:        reportContext.ScanID,
		ScanStartTime: reportContext.Start.Format(time.RFC3339),
		Duration:      reportContext.End.Sub(reportContext.Start).Round(time.Second).String(),
	}
	var totalSizeAnalyzed, totalSizeFile, totalSizeFiltered int64
	var blockedFiles, blockedArchives int
	archiveBudget := maxRows
	for report, readErr := range reports {
		if readErr != nil {
			return ReportData{}, readErr
		}
		if err = ctx.Err(); err != nil {
			return ReportData{}, err
		}
		reportData.NbFileSubmitted++
		// A file whose action failed carries an Error too: it is listed among the
		// errors and not counted as analyzed.
		if report.NotAnalyzedReason == "" && report.Error == "" {
			reportData.NbFileAnalyzed++
		}
		totalSizeAnalyzed += report.AnalyzedVolume
		totalSizeFiltered += report.FilteredVolume
		totalSizeFile += report.FileSize
		reportData.addErrors(report)
		if report.NotAnalyzedReason != "" {
			reportData.NbFileNotAnalyzed = datamodel.AddCount(reportData.NbFileNotAnalyzed, 1)
			reportData.NotAnalyzedFiles = appendCapped(reportData.NotAnalyzedFiles, func() NotAnalyzedFileData {
				return NotAnalyzedFileData{
					Name:   cellText(report.Filename),
					Size:   sizeText(report.FileSize, report.NotAnalyzedReason),
					Reason: notAnalyzedText(report.NotAnalyzedReason),
				}
			})
		}
		// datamodel.Report.Bound cuts the list of the members, the count is kept (up to
		// datamodel.MaxFileCount). The sums below saturate whatever Bound did: the
		// report may not have been bounded.
		reportData.NbFileNotAnalyzed = datamodel.AddCount(reportData.NbFileNotAnalyzed, max(report.NotAnalyzedExtractedCount, len(report.NotAnalyzedExtractedFiles)))
		for _, member := range report.NotAnalyzedExtractedFiles {
			reportData.NotAnalyzedFiles = appendCapped(reportData.NotAnalyzedFiles, func() NotAnalyzedFileData {
				return NotAnalyzedFileData{
					Name:   cellText(member.FileName),
					Size:   sizeText(member.Size, member.Reason),
					Reason: notAnalyzedText(member.Reason),
					Origin: cellText(report.Filename),
				}
			})
		}
		if !report.Malicious {
			continue
		}
		reportData.TotalMitigated++
		if report.MalwareReason == datamodel.MalwareDetected {
			reportData.TotalMalware++
		}
		if len(report.MaliciousExtractedFiles) == 0 {
			blockedFiles++
			reportData.MitigatedFiles = appendCapped(reportData.MitigatedFiles, func() FileReportData {
				return FileReportData{
					Name:               cellText(report.Filename),
					SHA256:             report.SHA256,
					Size:               humanize.Bytes(toUint(report.FileSize)),
					Malwares:           threatNames(report.Malwares),
					QuarantineLocation: cellText(report.QuarantineLocation),
					GMalwareURL:        report.GMalwareURL,
					MitigationReason:   getCompleteReason(report.MalwareReason),
				}
			})
			continue
		}
		blockedArchives++
		if archiveBudget < archiveRows {
			continue
		}
		archiveBudget -= archiveRows
		aReport := ArchiveReportData{
			Name:               cellText(report.Filename),
			SHA256:             report.SHA256,
			Size:               humanize.Bytes(toUint(report.FileSize)),
			QuarantineLocation: cellText(report.QuarantineLocation),
			FileCount:          report.TotalExtractedFile,
		}
		before := archiveBudget
		aReport.ExtractedFiles = convertExtractedFiles(report.MaliciousExtractedFiles, &archiveBudget)
		aReport.MoreExtracted = countMalicious(report.MaliciousExtractedFiles) - (before - archiveBudget)
		reportData.MitigatedArchives = append(reportData.MitigatedArchives, aReport)
	}
	reportData.MoreNotAnalyzed = reportData.NbFileNotAnalyzed - len(reportData.NotAnalyzedFiles)
	reportData.MoreErrorFiles = reportData.TotalErrors - len(reportData.ErrorFiles)
	reportData.MoreMitigatedFiles = blockedFiles - len(reportData.MitigatedFiles)
	reportData.MoreMitigatedArchives = blockedArchives - len(reportData.MitigatedArchives)
	reportData.AnalyzedVolume = humanize.Bytes(toUint(totalSizeAnalyzed))
	reportData.FileVolume = humanize.Bytes(toUint(totalSizeFile))
	reportData.FilteredVolume = humanize.Bytes(toUint(totalSizeFiltered))
	return reportData, nil
}

// addErrors counts and lists the errors of a report: its own, unless it is the
// summary of its failed members (which are not counted again), then those of its
// extracted files, in the order of their names. The entry that counts the failed
// files the report does not list (datamodel.MoreErrorsKey) is not a failed file
// and has no row: its count is added to the total, so the total is exact however
// many members failed.
func (d *ReportData) addErrors(report datamodel.Report) {
	isSummary := len(report.ErrorExtractedFiles) > 0 && datamodel.IsExtractedErrorsSummary(report.Error)
	if report.Error != "" && !isSummary {
		d.addError(report.Filename, report.Error)
	}
	for _, name := range slices.Sorted(maps.Keys(report.ErrorExtractedFiles)) {
		if name == datamodel.MoreErrorsKey {
			continue
		}
		d.addError(name, report.ErrorExtractedFiles[name])
	}
	d.TotalErrors = datamodel.AddCount(d.TotalErrors, datamodel.ParseMoreErrors(report.ErrorExtractedFiles[datamodel.MoreErrorsKey]))
}

func (d *ReportData) addError(name, text string) {
	// Saturating, like every sum of counts here: the total can already stand at the
	// ceiling after the count of a report.
	d.TotalErrors = datamodel.AddCount(d.TotalErrors, 1)
	d.ErrorFiles = appendCapped(d.ErrorFiles, func() ErrorFileData { return ErrorFileData{Name: cellText(name), Error: cellText(text)} })
}

// cellText is a text of a depositor as the PDF shows it. Its control characters
// and those that reorder text (the bidirectional controls, which can make a name
// ending in "exe.txt" read the other way) are replaced by U+FFFD; then it is
// shortened to maxCellBytes bytes, head and tail around a "…", never splitting a
// character. It is a cut for display; the storage cut of the reports is the one
// of package datamodel.
func cellText(s string) string {
	const ellipsis = "…"
	s = displaytext.Sanitize(s)
	if len(s) <= maxCellBytes {
		return s
	}
	keep := maxCellBytes - len(ellipsis)
	head, tail := keep/2, keep-keep/2
	for head > 0 && !utf8.RuneStart(s[head]) {
		head--
	}
	start := len(s) - tail
	for start < len(s) && !utf8.RuneStart(s[start]) {
		start++
	}
	return s[:head] + ellipsis + s[start:]
}

// threatNames is what a row shows of the threats of a file: the first
// maxThreatNames, as cellText, then the count of the others (moreThreatsFormat). A depositor can
// attach many names to a file; they weigh on the rendering as rows do.
func threatNames(names []string) []string {
	shown := make([]string, 0, min(len(names), maxThreatNames+1))
	for _, name := range names[:min(len(names), maxThreatNames)] {
		shown = append(shown, cellText(name))
	}
	if len(names) > maxThreatNames {
		shown = append(shown, fmt.Sprintf(moreThreatsFormat, others(len(names)-maxThreatNames, "", "")))
	}
	return shown
}

// sizeText is a size for the report. A member of which the archive does not
// say the size shows "—"; only an empty one is 0.
func sizeText(size int64, reason datamodel.NotAnalyzedReason) string {
	if size <= 0 && reason != datamodel.NotAnalyzedEmpty {
		return "—"
	}
	return humanize.Bytes(toUint(size))
}

// appendCapped appends the row built by row unless the list already holds
// maxRows rows: a row left out is not built.
func appendCapped[T any](list []T, row func() T) []T {
	if len(list) >= maxRows {
		return list
	}
	return append(list, row())
}

// notAnalyzedText says in plain words why a file was not analyzed.
func notAnalyzedText(reason datamodel.NotAnalyzedReason) string {
	switch reason {
	case datamodel.NotAnalyzedTooBig:
		return "Trop volumineux (contenu non vérifié)"
	case datamodel.NotAnalyzedEmpty:
		return "Fichier vide"
	case datamodel.NotAnalyzedEncrypted:
		return "Chiffré (mot de passe inconnu)"
	case datamodel.NotAnalyzedExtractLimit:
		return "Écarté à l'extraction (limites)"
	case datamodel.NotAnalyzedExtractError:
		return "Anomalie d'extraction"
	case datamodel.NotAnalyzedPolicySkipped:
		return "Liste blanche (non analysé)"
	case datamodel.NotAnalyzedRestored:
		return "Restauré (précédemment bloqué)"
	case datamodel.NotAnalyzedAnalysisError:
		return "Analyse en échec (contenu non vérifié)"
	case datamodel.NotAnalyzedSkippedPath:
		return "Liste blanche par chemin (non analysé)"
	case datamodel.NotAnalyzedSkippedType:
		return "Liste blanche par type (non analysé)"
	case datamodel.NotAnalyzedSymlink:
		return "Lien symbolique (non suivi)"
	default:
		return cellText(string(reason))
	}
}

// convertExtractedFiles recursively converts datamodel.ExtractedFile to
// ExtractedFileData, one row of budget for each malicious file; what the budget
// does not cover is left out. The depth of the recursion is that of the tree,
// which datamodel.Report.Bound keeps to at most a thousand nodes.
func convertExtractedFiles(files []datamodel.ExtractedFile, budget *int) (result []ExtractedFileData) {
	for _, f := range files {
		if !f.Malicious {
			continue
		}
		if *budget <= 0 {
			return result
		}
		*budget--
		efd := ExtractedFileData{
			Name:             cellText(f.FileName),
			SHA256:           f.SHA256,
			Malwares:         threatNames(f.Malwares),
			MitigationReason: getCompleteReason(f.MalwareReason),
			Size:             humanize.Bytes(toUint(f.Size)),
			GMalwareURL:      f.GMalwareURL,
		}
		if len(f.ExtractedFiles) > 0 {
			efd.ExtractedFiles = convertExtractedFiles(f.ExtractedFiles, budget)
		}
		result = append(result, efd)
	}
	return
}

// countMalicious is the number of malicious files of a tree.
func countMalicious(files []datamodel.ExtractedFile) (n int) {
	for _, f := range files {
		if f.Malicious {
			n += 1 + countMalicious(f.ExtractedFiles)
		}
	}
	return n
}

// generateHTMLReport renders the configured template with report data.
func (p *ReportPlugin) generateHTMLReport(data ReportData) (htmlBuf *bytes.Buffer, err error) {
	htmlBuf = new(bytes.Buffer)
	err = p.templ.Execute(htmlBuf, data)
	if err != nil {
		return nil, err
	}
	return
}

// generatePDFReport renders the report data to PDF; a partial PDF is discarded.
func (p *ReportPlugin) generatePDFReport(ctx context.Context, data ReportData) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	if err := p.pdf.render(ctx, p.templ, data, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func getCompleteReason(mitigationReason datamodel.MalwareReason) (reason string) {
	switch mitigationReason {
	case datamodel.AnalysisError:
		reason = "Erreur lors de l'analyse du fichier"
	case datamodel.FilteredFileType:
		reason = "Type de fichier filtré"
	case datamodel.FilteredFilePath:
		reason = "Path de fichier filtré"
	case datamodel.MalwareDetected:
		reason = "Fichier malveillant"
	case datamodel.TooBig:
		reason = "Taille du fichier trop importante"
	}
	return
}

func main() {}
