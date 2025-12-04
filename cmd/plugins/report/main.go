// Package main implements a PDF/HTML report generation plugin.
//
// Generates scan reports from templates using chromedp for PDF conversion.
package main

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/dustin/go-humanize"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

var (
	logger        = slog.New(slog.DiscardHandler)
	consoleLogger = slog.New(slog.DiscardHandler)
)

// ReportPlugin generates PDF and HTML reports from scan results.
type ReportPlugin struct {
	templ *template.Template
}

var (
	_ plugins.Plugin = &ReportPlugin{}

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
}

// GetDefaultConfig returns the default configuration.
func (p *ReportPlugin) GetDefaultConfig() (config any) {
	config = new(Config)
	return
}

// Init loads the template and registers the report generator.
func (p *ReportPlugin) Init(rawConfig any, hcc plugins.HCContext) (err error) {
	templ := template.New("report").Funcs(template.FuncMap{
		"mergeArgsIntoSlice": mergeArgsIntoSlice,
		"formatDuration":     formatDuration,
	})

	config, ok := rawConfig.(*Config)
	if !ok {
		err = errors.New("bad config passed to report")
		return
	}
	logger = hcc.GetLogger().With(slog.String("plugin", "report"))
	consoleLogger = hcc.GetConsoleLogger()

	if config.TemplatePath != "" {
		if p.templ, err = templ.ParseFiles(filepath.Clean(config.TemplatePath)); err != nil {
			return
		}
		logger.Info("plugin initialized", slog.String("template", config.TemplatePath))
		consoleLogger.Info("report plugin initialized, template: " + config.TemplatePath)

		hcc.RegisterGenerateReport(p.GenerateReport)
		return
	}
	if p.templ, err = templ.Parse(defaultTemplate); err != nil {
		return
	}
	logger.Info("plugin initialized", slog.String("template", "default"))
	consoleLogger.Info("report plugin initialized, default template")

	hcc.RegisterGenerateReport(p.GenerateReport)
	return nil
}

// Close cleans up plugin resources (no-op for this plugin).
func (p *ReportPlugin) Close(context.Context) error {
	return nil
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
}

// ExtractedFileData contains extracted file information from archives.
type ExtractedFileData struct {
	Name             string
	SHA256           string
	Malwares         []string
	Size             string
	MitigationReason string
	GMalwareURL      string
}

// ReportData contains complete scan report data for template rendering.
type ReportData struct {
	ScanID            string
	NbFileSubmitted   int
	NbFileAnalyzed    int
	FileVolume        string
	AnalyzedVolume    string
	FilteredVolume    string
	TotalMitigated    int
	TotalMalware      int
	MitigatedFiles    []FileReportData
	MitigatedArchives []ArchiveReportData
	ScanStartTime     string
	Duration          string
}

// GenerateReport generates a PDF report from scan results.
func (p *ReportPlugin) GenerateReport(reportContext datamodel.ScanContext, reports []datamodel.Report) (o io.Reader, err error) {
	consoleLogger.Debug(fmt.Sprintf("generate pdf report for %d analysis", len(reports)))
	buffer, err := p.generatePDFReport(reportContext, reports)
	o = buffer
	return
}

func toUint(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

// scanResToReportData converts scan results to ReportData for template rendering.
func scanResToReportData(reportContext datamodel.ScanContext, reports []datamodel.Report) (reportData ReportData) {
	reportData = ReportData{
		ScanID:          reportContext.ScanID,
		ScanStartTime:   reportContext.Start.Format(time.RFC3339),
		Duration:        reportContext.End.Sub(reportContext.Start).Round(time.Second).String(),
		NbFileSubmitted: len(reports),
	}
	var totalSizeAnalyzed int64 = 0
	var totalSizeFile int64 = 0
	var totalSizeFiltered int64 = 0
	for _, report := range reports {
		reportData.NbFileAnalyzed++
		totalSizeAnalyzed += report.AnalyzedVolume
		totalSizeFiltered += report.FilteredVolume
		totalSizeFile += report.FileSize
		if !report.Malicious {
			continue
		}
		reportData.TotalMitigated++
		if len(report.Malwares) > 0 {
			reportData.TotalMalware++
		}
		if len(report.MaliciousExtractedFiles) == 0 {
			fReport := FileReportData{
				Name:               report.Filename,
				SHA256:             report.SHA256,
				Size:               humanize.Bytes(toUint(report.FileSize)),
				Malwares:           report.Malwares,
				QuarantineLocation: report.QuarantineLocation,
				GMalwareURL:        report.GMalwareURL,
				MitigationReason:   getCompleteReason(report.MalwareReason),
			}
			reportData.MitigatedFiles = append(reportData.MitigatedFiles, fReport)
			continue
		}

		aReport := ArchiveReportData{
			Name:               report.Filename,
			SHA256:             report.SHA256,
			Size:               humanize.Bytes(toUint(report.FileSize)),
			QuarantineLocation: report.QuarantineLocation,
			FileCount:          report.TotalExtractedFile,
		}

		for _, extractedFile := range report.MaliciousExtractedFiles {
			if !extractedFile.Malicious {
				continue
			}
			aReport.ExtractedFiles = append(aReport.ExtractedFiles, ExtractedFileData{
				Name:             extractedFile.FileName,
				SHA256:           extractedFile.SHA256,
				Malwares:         extractedFile.Malwares,
				MitigationReason: getCompleteReason(extractedFile.MalwareReason),
				Size:             humanize.Bytes(toUint(extractedFile.Size)),
				GMalwareURL:      extractedFile.GMalwareURL,
			})
		}
		reportData.MitigatedArchives = append(reportData.MitigatedArchives, aReport)
	}
	reportData.AnalyzedVolume = humanize.Bytes(toUint(totalSizeAnalyzed))
	reportData.FileVolume = humanize.Bytes(toUint(totalSizeFile))
	reportData.FilteredVolume = humanize.Bytes(toUint((totalSizeFiltered)))
	return
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

// generatePDFReport converts HTML report to PDF using chromedp.
func (p *ReportPlugin) generatePDFReport(reportContext datamodel.ScanContext, reports []datamodel.Report) (pdfBuf *bytes.Buffer, err error) {
	pdfBuf = new(bytes.Buffer)

	data := scanResToReportData(reportContext, reports)
	htmlBuf, err := p.generateHTMLReport(data)
	if err != nil {
		return
	}

	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	if err = chromedp.Run(ctx,
		chromedp.Navigate("about:blank"),
		chromedp.ActionFunc(func(ctx context.Context) (err error) {
			frameTree, err := page.GetFrameTree().Do(ctx)
			if err != nil {
				return
			}

			return page.SetDocumentContent(frameTree.Frame.ID, htmlBuf.String()).Do(ctx)
		}),
		chromedp.ActionFunc(func(ctx context.Context) (err error) {
			buf, _, err := page.PrintToPDF().
				WithPreferCSSPageSize(false).
				WithScale(0.9).
				WithDisplayHeaderFooter(true).
				WithPaperWidth(8.27).
				WithPaperHeight(11.69).
				WithLandscape(false).
				WithMarginTop(1).
				WithMarginRight(0.3).
				WithMarginBottom(1.3).
				WithMarginLeft(0.3).
				WithPrintBackground(true).
				WithHeaderTemplate(`<span></span>`).
				WithFooterTemplate(`<h4 id="footer-template" style="font-size:10px !important; width: 100%; margin-left:30px; margin-right:30px; display: flex; justify-content: space-between;"><span style="background-color: #000000; color: #FFC000">TLP:AMBER</span><span></span><span>Page <span class='pageNumber'></span> of <span class='totalPages'></span></span></h4>`).
				Do(ctx)
			if err != nil {
				return
			}

			pdfBuf = bytes.NewBuffer(buf)
			return
		}),
	); err != nil {
		return
	}
	return
}

func getCompleteReason(mitigationReason datamodel.MalwareReason) (reason string) {
	switch mitigationReason {
	case datamodel.AnalysisError:
		reason = "Erreur lors de l'analyse du fichier"
	case datamodel.FilteredFileType:
		reason = "Type de fichier filtré"
	case datamodel.MalwareDetected:
		reason = "Fichier malveillant"
	case datamodel.TooBig:
		reason = "Taille du fichier trop importante"
	}
	return
}

func main() {}
