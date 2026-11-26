//go:build linux

package main

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"strings"
	"time"

	"github.com/glimps-re/htmltopdf/pkg/htmltopdf"
)

//go:embed fonts/*.ttf
var fontFiles embed.FS

// reportFonts maps each embedded font file to its family. 'Segoe UI' and Arial,
// asked first by the template, are absent: sans-serif resolves to Liberation Sans,
// metric-compatible with Arial, and DejaVu Sans draws what Liberation lacks.
var reportFonts = []struct{ file, family string }{
	{"fonts/LiberationSans-Regular.ttf", "Liberation Sans"},
	{"fonts/LiberationSans-Bold.ttf", "Liberation Sans"},
	{"fonts/LiberationSans-Italic.ttf", "Liberation Sans"},
	{"fonts/LiberationSans-BoldItalic.ttf", "Liberation Sans"},
	{"fonts/DejaVuSans.ttf", "DejaVu Sans"},
	{"fonts/DejaVuSans-Bold.ttf", "DejaVu Sans"},
}

// The paper and scale Chrome used for PrintToPDF (8.27x11.69 in, scale 0.9), and
// limits lowered from htmltopdf.DefaultLimits, never raised: the data is hostile.
const (
	pageWidthPx  = 794.56
	pageHeightPx = 1122.56
	pageScale    = 0.9

	// maxReportPDF caps the PDF of a report, kept in memory (worst case 0.9 MiB).
	maxReportPDF = 64 << 20
	// Worst case measured: ≤ 15 000 boxes, ≤ 50 styles, ≤ 2 M work units.
	maxReportBoxes  = 60_000
	maxReportStyles = 2_000
	maxReportWork   = 20_000_000
	// renderTimeout bounds one rendering (worst case ~1 s on an idle machine).
	renderTimeout = 60 * time.Second
)

// pageCSS reproduces the PrintToPDF margins (1/0.3/1.3/0.3 in, floored to px by
// Chrome) and its footer template; values measured against Chrome by htmltopdf M1.
// Chrome never printed the footer background: TLP:AMBER stays yellow on white.
const pageCSS = `@page {
	margin: 96px 28px 124px 28px;
	@bottom-left { content: "TLP:AMBER"; color: #FFC000; font-family: "DejaVu Sans"; font-weight: bold; font-size: 10px; vertical-align: bottom; padding: 0 0 33.5px 2px; }
	@bottom-right { content: "Page " counter(page) " of " counter(pages); font-family: "DejaVu Sans"; font-weight: bold; font-size: 10px; vertical-align: bottom; padding: 0 1.9px 33.5px 0; }
}`

const pdfMagic = "%PDF-"

// renderSlots bounds the renderings running at the same time: Limits bound the
// memory of one, GenerateReport may be called concurrently.
var renderSlots = make(chan struct{}, 2)

// renderer renders the report template to PDF. It is safe for concurrent use.
type renderer struct {
	conv   *htmltopdf.Converter
	logger *slog.Logger
}

// reportOptions returns the page, fonts and limits of the report PDF.
func reportOptions() (htmltopdf.Options, error) {
	fonts := make([]htmltopdf.Font, 0, len(reportFonts))
	for _, f := range reportFonts {
		data, err := fs.ReadFile(fontFiles, f.file)
		if err != nil {
			return htmltopdf.Options{}, fmt.Errorf("reading the embedded font %s: %w", f.file, err)
		}
		fonts = append(fonts, htmltopdf.Font{Data: data, Family: f.family})
	}
	return htmltopdf.Options{
		Fonts:    fonts,
		Generic:  htmltopdf.GenericFamilies{SansSerif: "Liberation Sans"},
		Fallback: []string{"DejaVu Sans"},
		ExtraCSS: pageCSS,
		Scale:    pageScale,
		PageSize: htmltopdf.PageSize{Width: pageWidthPx, Height: pageHeightPx},
		// The zero fields keep DefaultLimits: MaxPages (500) leaves no room above the
		// worst case (366), and the CSS limits bound the operator template, not the
		// depositor data.
		Limits: htmltopdf.Limits{
			MaxOutputBytes: maxReportPDF,
			MaxBoxes:       maxReportBoxes,
			MaxStyles:      maxReportStyles,
			MaxWork:        maxReportWork,
			Timeout:        renderTimeout,
		},
	}, nil
}

// newRenderer builds the converter and proves it renders a PDF; any error
// refuses the start.
func newRenderer(ctx context.Context, logger *slog.Logger) (*renderer, error) {
	opts, err := reportOptions()
	if err != nil {
		return nil, err
	}
	conv, err := htmltopdf.New(opts)
	if err != nil {
		return nil, fmt.Errorf("building the PDF converter: %w", err)
	}
	r := &renderer{conv: conv, logger: logger}
	if err := r.selfTest(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// render executes t with data and writes the PDF to dst, once a render slot is
// free. On error dst may hold a partial PDF that must be discarded; the error
// wraps the htmltopdf one (ErrLimit, *LimitError, context errors).
func (r *renderer) render(ctx context.Context, t *template.Template, data any, dst io.Writer) error {
	select {
	case renderSlots <- struct{}{}:
		defer func() { <-renderSlots }()
	case <-ctx.Done():
		return fmt.Errorf("waiting for a render slot: %w", ctx.Err())
	}
	start := time.Now()
	res, err := r.conv.RenderTemplate(ctx, t, data, dst)
	r.logWarnings(ctx, res)
	if err != nil {
		if le, ok := errors.AsType[*htmltopdf.LimitError](err); ok {
			r.logger.WarnContext(ctx, "the report PDF exceeds a limit", slog.String("limit", string(le.Limit)), slog.Int64("max", le.Max))
		}
		return fmt.Errorf("rendering the report PDF: %w", err)
	}
	r.logger.DebugContext(ctx, "report PDF rendered", slog.Int("pages", res.Pages), slog.Int64("bytes", res.Bytes), slog.Duration("duration", time.Since(start)))
	return nil
}

// logWarnings logs what the converter dropped or replaced. The details are
// hostile text, already sanitised and cut to 80 bytes by htmltopdf.
func (r *renderer) logWarnings(ctx context.Context, res *htmltopdf.Result) {
	if res == nil {
		return
	}
	for _, w := range res.Warnings {
		r.logger.DebugContext(ctx, "report PDF warning", slog.String("code", string(w.Code)), slog.String("detail", w.Detail), slog.Int("count", w.Count))
	}
	if res.WarningsDropped > 0 {
		r.logger.DebugContext(ctx, "report PDF warnings dropped", slog.Int("count", res.WarningsDropped))
	}
}

// selfTest renders an empty page and checks the result is a one-page PDF.
func (r *renderer) selfTest(ctx context.Context) error {
	var buf bytes.Buffer
	res, err := r.conv.Render(ctx, strings.NewReader("<html><body></body></html>"), &buf)
	if err != nil {
		return fmt.Errorf("PDF converter self-test: %w", err)
	}
	if res.Pages != 1 || !bytes.HasPrefix(buf.Bytes(), []byte(pdfMagic)) {
		return fmt.Errorf("PDF converter self-test: got %d pages and a document starting with %q, want 1 page of PDF", res.Pages, buf.Bytes()[:min(buf.Len(), len(pdfMagic))])
	}
	return nil
}
