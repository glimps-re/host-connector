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
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/report"
)

var logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))

// ReportPlugin implements the Plugin interface for generating PDF and HTML reports
// from scan results using HTML templates and chromedp for PDF conversion.
type ReportPlugin struct {
	templ *template.Template
}

var (
	_ plugins.Plugin = &ReportPlugin{}
	// HCPlugin is the exported plugin instance required by the plugin loader
	HCPlugin ReportPlugin

	// defaultTemplate contains the embedded HTML template for report generation
	//
	//go:embed report.html.tmpl
	defaultTemplate string
)

type Config struct {
	TemplatePath string `mapstructure:"templatePath"`
}

func (p *ReportPlugin) GetDefaultConfig() (config any) {
	config = new(Config)
	return
}

// Init implements the Plugin interface, initializing the report plugin with the given configuration.
// If configPath is empty, uses the embedded default template. Otherwise, loads template from the file path.
// Registers the GenerateReport function with the host connector context.
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
	logger = hcc.GetLogger()

	if config.TemplatePath != "" {
		if p.templ, err = templ.ParseFiles(filepath.Clean(config.TemplatePath)); err != nil {
			return
		}
		logger.Info("plugin initialized", slog.String("template", config.TemplatePath))
		hcc.RegisterGenerateReport(p.GenerateReport)
	}
	if p.templ, err = templ.Parse(defaultTemplate); err != nil {
		return
	}
	logger.Info("plugin initialized", slog.String("template", "default"))
	hcc.RegisterGenerateReport(p.GenerateReport)
	return nil
}

// Close implements the Plugin interface, performing cleanup when the plugin is shut down.
// Currently no cleanup is required for the report plugin.
func (p *ReportPlugin) Close(context.Context) error {
	return nil
}

// mergeArgsIntoSlice is a template function that merges multiple arguments into a slice.
// Used within HTML templates to combine template variables.
func mergeArgsIntoSlice(args ...any) []any {
	return args
}

func humanizeFileSize(size int64) string {
	sizes := []string{"o", "Ko", "Mo", "Go", "To", "Po", "Eo"}
	if size < 10 {
		return fmt.Sprintf("%d o", size)
	}
	e := math.Floor(math.Log(float64(size)) / math.Log(1000)) // number of Ko
	suffix := sizes[int(e)]
	val := math.Floor(float64(size)/math.Pow(1000, e)*10+0.5) / 10
	f := "%.0f %s"
	if val < 10 {
		f = "%.1f %s"
	}
	return fmt.Sprintf(f, val, suffix)
}

// formatDuration is a template function that formats a time.Duration into a human-readable string.
// Formats durations as "XmYs" for minutes and seconds, or "Xs" for seconds only.
func formatDuration(d time.Duration) string {
	totalSeconds := int(d.Seconds())
	minutes := totalSeconds / 60
	seconds := totalSeconds % 60
	if minutes <= 0 {
		return fmt.Sprintf("%ds", seconds)
	}
	return fmt.Sprintf("%dm%ds", minutes, seconds)
}

// FileReportData represents the data structure for individual file information in reports.
// Contains file metadata, scan results, and any detected malware information.
type FileReportData struct {
	Name             string   // File name
	Sha256           string   // SHA256 hash of the file
	Error            string   // Any error encountered during scanning
	Size             string   // Human-readable file size
	Malwares         []string // List of detected malware names
	MalwareChildName string   // Name of child file that triggered malware detection
	Warning          string   // Any warnings from the scan
}

// ReportData represents the complete data structure for scan reports.
// Contains summary statistics and categorized file results for template rendering.
type ReportData struct {
	ScanID          string           // Unique identifier for the scan
	NbFileSubmitted int              // Total number of files submitted for scanning
	NbFileAnalyzed  int              // Total number of files that were analyzed
	VolumeAnalyzed  string           // Human-readable total volume of data analyzed
	FilesInError    []FileReportData // Files that encountered errors during scanning
	FilesSafe       []FileReportData // Files determined to be safe/clean
	FilesMalware    []FileReportData // Files identified as malware
	FilesIgnored    []FileReportData // Files that were ignored during scanning
	FilesPartial    []FileReportData // Files with partial scan results
	ScanStartTime   string           // ISO formatted start time of the scan
	Duration        string           // Human-readable duration of the scan
}

// GenerateReport implements the GenerateReport function for the plugin interface.
// Generates a PDF report from the scan context and results by delegating to GeneratePdfReport.
func (p *ReportPlugin) GenerateReport(reportContext report.ScanContext, reports []report.Report) (o io.Reader, err error) {
	buffer, err := p.generatePDFReport(reportContext, reports)
	o = buffer
	return
}

// scanResToReportData converts scan results into the ReportData structure for template rendering.
// Categorizes files into safe, malware, error, ignored, and partial result groups.
func scanResToReportData(reportContext report.ScanContext, reports []report.Report) (reportData ReportData) {
	reportData = ReportData{
		ScanID:          reportContext.ScanID,
		ScanStartTime:   reportContext.Start.Format(time.RFC3339),
		Duration:        reportContext.End.Sub(reportContext.Start).String(),
		NbFileSubmitted: len(reports),
	}
	var totalSizeAnalyzed int64 = 0
	for _, r := range reports {
		fReport := FileReportData{
			Name:     r.FileName,
			Sha256:   r.Sha256,
			Size:     humanizeFileSize(r.Size),
			Malwares: r.Malware,
		}
		reportData.NbFileAnalyzed++
		totalSizeAnalyzed += r.Size
		if r.Malicious {
			reportData.FilesMalware = append(reportData.FilesMalware, fReport)
			continue
		}
		reportData.FilesSafe = append(reportData.FilesSafe, fReport)
	}
	reportData.VolumeAnalyzed = humanizeFileSize(totalSizeAnalyzed)
	return
}

// generateHTMLReport builds an HTML report from the provided ReportData using the configured template.
// Returns a buffer containing the rendered HTML content.
func (p *ReportPlugin) generateHTMLReport(data ReportData) (htmlBuf *bytes.Buffer, err error) {
	htmlBuf = new(bytes.Buffer)
	err = p.templ.Execute(htmlBuf, data)
	if err != nil {
		return nil, err
	}
	return
}

// generatePDFReport builds a PDF report from scan results using chromedp for HTML-to-PDF conversion.
// First generates HTML content, then uses a headless browser to convert it to PDF format.
// Returns a buffer containing the PDF content.
func (p *ReportPlugin) generatePDFReport(reportContext report.ScanContext, reports []report.Report) (pdfBuf *bytes.Buffer, err error) {
	pdfBuf = new(bytes.Buffer)

	data := scanResToReportData(reportContext, reports)
	// Fill in html buffer with template
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
				WithScale(1).
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

func main() {}
