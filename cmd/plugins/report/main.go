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
	"github.com/dustin/go-humanize"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// ReportPlugin generates PDF and HTML reports from scan results.
type ReportPlugin struct {
	templ         *template.Template
	browser       *browserRunner
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
	// ChromePath is the browser that renders the PDF; empty: found in PATH.
	ChromePath string `mapstructure:"chrome_path"`
}

// GetDefaultConfig returns the default configuration.
func (p *ReportPlugin) GetDefaultConfig() (config any) {
	config = new(Config)
	return
}

// Validate loads the template and starts the browser on an empty page like
// Init does, without any effect: the browser profile lives in the scratch
// directory of the validation.
func (p *ReportPlugin) Validate(rawConfig any, vc plugins.ValidationContext) error {
	config, ok := rawConfig.(*Config)
	if !ok {
		return errors.New("bad config passed to report")
	}
	if _, err := parseTemplate(config.TemplatePath); err != nil {
		return err
	}
	_, err := startBrowser(config.ChromePath, vc)
	return err
}

// startBrowser refuses root, declares the browser and proves it renders a PDF.
func startBrowser(chromePath string, vc plugins.ValidationContext) (*browserRunner, error) {
	if err := refuseRoot(); err != nil {
		return nil, err
	}
	path, err := declareBrowser(chromePath, vc)
	if err != nil {
		return nil, err
	}
	runner := &browserRunner{execPath: path, workDir: vc.GetWorkDir(), logger: vc.GetLogger()}
	if err := checkBrowser(context.Background(), runner); err != nil {
		return nil, err
	}
	vc.GetLogger().Info("report browser checked", slog.String("path", path), slog.Bool("configured", chromePath != ""))
	return runner, nil
}

// parseTemplate parses the template at path, or the embedded one when path is
// empty.
func parseTemplate(path string) (*template.Template, error) {
	templ := template.New("report").Funcs(template.FuncMap{
		"mergeArgsIntoSlice": mergeArgsIntoSlice,
		"formatDuration":     formatDuration,
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

// Init loads the template, checks the browser and registers the report
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
	runner, err := startBrowser(config.ChromePath, hcc)
	if err != nil {
		return err
	}
	p.logger = hcc.GetLogger().With(slog.String("plugin", "report"))
	p.consoleLogger = hcc.GetConsoleLogger()
	p.templ, p.browser = templ, runner

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
	ExtractedFiles   []ExtractedFileData
}

// ErrorFileData contains error information for files that failed analysis.
type ErrorFileData struct {
	Name  string
	Error string
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
	TotalErrors       int
	MitigatedFiles    []FileReportData
	MitigatedArchives []ArchiveReportData
	ErrorFiles        []ErrorFileData
	ScanStartTime     string
	Duration          string
}

// GenerateReport generates a PDF report from scan results.
func (p *ReportPlugin) GenerateReport(ctx context.Context, reportContext datamodel.ScanContext, reports []datamodel.Report) (o io.Reader, err error) {
	p.consoleLogger.Debug(fmt.Sprintf("generate pdf report for %d analysis", len(reports)))
	buffer, err := p.generatePDFReport(ctx, reportContext, reports)
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
		for filename, errMsg := range report.ErrorExtractedFiles {
			reportData.ErrorFiles = append(reportData.ErrorFiles, ErrorFileData{
				Name:  filename,
				Error: errMsg,
			})
			reportData.TotalErrors++
		}
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

		aReport.ExtractedFiles = convertExtractedFiles(report.MaliciousExtractedFiles)
		reportData.MitigatedArchives = append(reportData.MitigatedArchives, aReport)
	}
	reportData.AnalyzedVolume = humanize.Bytes(toUint(totalSizeAnalyzed))
	reportData.FileVolume = humanize.Bytes(toUint(totalSizeFile))
	reportData.FilteredVolume = humanize.Bytes(toUint(totalSizeFiltered))
	return
}

// convertExtractedFiles recursively converts datamodel.ExtractedFile to ExtractedFileData.
func convertExtractedFiles(files []datamodel.ExtractedFile) (result []ExtractedFileData) {
	for _, f := range files {
		if !f.Malicious {
			continue
		}
		efd := ExtractedFileData{
			Name:             f.FileName,
			SHA256:           f.SHA256,
			Malwares:         f.Malwares,
			MitigationReason: getCompleteReason(f.MalwareReason),
			Size:             humanize.Bytes(toUint(f.Size)),
			GMalwareURL:      f.GMalwareURL,
		}
		if len(f.ExtractedFiles) > 0 {
			efd.ExtractedFiles = convertExtractedFiles(f.ExtractedFiles)
		}
		result = append(result, efd)
	}
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
func (p *ReportPlugin) generatePDFReport(ctx context.Context, reportContext datamodel.ScanContext, reports []datamodel.Report) (pdfBuf *bytes.Buffer, err error) {
	pdfBuf = new(bytes.Buffer)

	data := scanResToReportData(reportContext, reports)
	htmlBuf, err := p.generateHTMLReport(data)
	if err != nil {
		return
	}

	pdf, err := p.browser.render(ctx, htmlBuf.String(), page.PrintToPDF().
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
		WithFooterTemplate(`<h4 id="footer-template" style="font-size:10px !important; width: 100%; margin-left:30px; margin-right:30px; display: flex; justify-content: space-between;"><span style="background-color: #000000; color: #FFC000">TLP:AMBER</span><span></span><span>Page <span class='pageNumber'></span> of <span class='totalPages'></span></span></h4>`), maxReportPDF)
	if err != nil {
		return nil, err
	}
	return bytes.NewBuffer(pdf), nil
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
