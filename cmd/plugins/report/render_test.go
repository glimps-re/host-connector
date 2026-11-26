//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glimps-re/htmltopdf/pkg/htmltopdf"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

type logRecord struct {
	level slog.Level
	msg   string
	attrs map[string]any
}

// recorder is a slog.Handler keeping every record, Debug included.
type recorder struct {
	mu      *sync.Mutex
	records *[]logRecord
	attrs   []slog.Attr
}

func newRecorder() *recorder {
	return &recorder{mu: new(sync.Mutex), records: new([]logRecord)}
}

func (h *recorder) Enabled(context.Context, slog.Level) bool { return true }

func (h *recorder) Handle(_ context.Context, r slog.Record) error {
	rec := logRecord{level: r.Level, msg: r.Message, attrs: map[string]any{}}
	for _, a := range h.attrs {
		rec.attrs[a.Key] = a.Value.Any()
	}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.Any()
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	*h.records = append(*h.records, rec)
	return nil
}

func (h *recorder) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &recorder{mu: h.mu, records: h.records, attrs: append(append([]slog.Attr{}, h.attrs...), attrs...)}
}

func (h *recorder) WithGroup(string) slog.Handler { return h }

func (h *recorder) all() []logRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]logRecord(nil), *h.records...)
}

func (h *recorder) withMessage(msg string) []logRecord {
	var out []logRecord
	for _, r := range h.all() {
		if r.msg == msg {
			out = append(out, r)
		}
	}
	return out
}

// recordedPlugin inits a real plugin whose logger and console logger are recorded.
func recordedPlugin(t *testing.T, config *Config) (p *ReportPlugin, logs, console *recorder) {
	t.Helper()
	logs, console = newRecorder(), newRecorder()
	hcc := mock.NewMockHCContext()
	hcc.Logger = slog.New(logs)
	hcc.ConsoleLogger = slog.New(console)
	p = &ReportPlugin{}
	if err := p.Init(config, hcc); err != nil {
		t.Fatal(err)
	}
	return p, logs, console
}

func writeTemplate(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.tmpl")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func squash(s string) string {
	return strings.Join(strings.Fields(s), "")
}

func joined(texts []string) string {
	return squash(strings.Join(texts, "\n"))
}

func renderPDF(t *testing.T, p *ReportPlugin, reports []datamodel.Report) ([]byte, []string) {
	t.Helper()
	data := mustReportData(t, scanContext(), reports)
	buf, err := p.generatePDFReport(t.Context(), data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte(pdfMagic)) {
		t.Fatalf("not a PDF: starts with %q", buf.Bytes()[:min(buf.Len(), 8)])
	}
	return buf.Bytes(), pdfPageTexts(t, buf.Bytes())
}

func assertFooters(t *testing.T, texts []string) {
	t.Helper()
	n := len(texts)
	for i, text := range texts {
		if c := strings.Count(squash(text), "TLP:AMBER"); c != 1 {
			t.Errorf("page %d/%d has %d TLP:AMBER, want 1", i+1, n, c)
		}
		if !pageNumberFooter(i+1, n).MatchString(text) {
			t.Errorf("page %d/%d has no \"Page %d of %d\" footer; text ends with %q", i+1, n, i+1, n, tail(text, 80))
		}
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// Page counts measured on benchReports with the embedded template; ±1 absorbs font-metric drift.
func TestPDF_pageCountStaysNearTheReference(t *testing.T) {
	p := newTestPlugin(t)
	for _, tc := range []struct {
		name  string
		files int
		want  int
	}{{"empty", 0, 1}, {"small", 50, 5}, {"capped", 2000, 50}} {
		t.Run(tc.name, func(t *testing.T) {
			pdf, texts := renderPDF(t, p, benchReports(tc.files))
			if got := len(pdfPage.FindAll(pdf, -1)); got != len(texts) {
				t.Errorf("pdfPage regexp counts %d pages, pdfcpu reads %d", got, len(texts))
			}
			if len(texts) < tc.want-1 || len(texts) > tc.want+1 {
				t.Errorf("%d pages, want %d ±1", len(texts), tc.want)
			}
		})
	}
}

func TestPDF_footerOnEveryPage(t *testing.T) {
	p := newTestPlugin(t)
	for _, tc := range []struct {
		name  string
		files int
	}{{"empty", 0}, {"small", 50}, {"capped", 2000}} {
		t.Run(tc.name, func(t *testing.T) {
			_, texts := renderPDF(t, p, benchReports(tc.files))
			assertFooters(t, texts)
		})
	}
}

func TestPDF_everyTextOfTheReportIsThere(t *testing.T) {
	p := newTestPlugin(t)
	reports := benchReports(50)
	reports[0].SHA256 = strings.Repeat("ab", 32)
	for i := range reports {
		if reports[i].Malicious && reports[i].SHA256 == "" {
			reports[i].SHA256 = fmt.Sprintf("%064x", i+1)
		}
	}
	data := mustReportData(t, scanContext(), reports)
	buf, err := p.generatePDFReport(t.Context(), data)
	if err != nil {
		t.Fatal(err)
	}
	text := joined(pdfPageTexts(t, buf.Bytes()))

	want := make([]string, 0, 64)
	want = append(want, data.ScanID, data.FileVolume, data.AnalyzedVolume, data.ScanStartTime, data.Duration)
	for _, n := range []int{data.NbFileSubmitted, data.NbFileAnalyzed, data.NbFileNotAnalyzed, data.TotalMitigated, data.TotalMalware, data.TotalErrors} {
		want = append(want, strconv.Itoa(n))
	}
	for _, f := range data.NotAnalyzedFiles {
		want = append(want, f.Name)
	}
	for _, f := range data.ErrorFiles {
		want = append(want, f.Name)
	}
	for _, f := range data.MitigatedFiles {
		want = append(want, f.Name, f.SHA256)
	}
	for _, a := range data.MitigatedArchives {
		want = append(want, a.Name)
		for _, m := range a.ExtractedFiles {
			want = append(want, m.Name)
		}
	}
	if len(data.NotAnalyzedFiles) == 0 || len(data.ErrorFiles) == 0 || len(data.MitigatedFiles) == 0 || len(data.MitigatedArchives) == 0 {
		t.Fatalf("the fixture misses a section: %d, %d, %d, %d rows", len(data.NotAnalyzedFiles), len(data.ErrorFiles), len(data.MitigatedFiles), len(data.MitigatedArchives))
	}
	for _, w := range want {
		if w == "" || strings.Contains(text, squash(w)) {
			continue
		}
		// A row can be cut by a page break (header and footer land inside the
		// cell text): a 64-char hash is then found in two pieces.
		if len(w) == 64 && strings.Contains(text, w[:16]) && strings.Contains(text, w[48:]) {
			t.Logf("%s is split by a page break", w)
			continue
		}
		t.Errorf("%q is not in the PDF text", w)
	}
}

func TestPDF_hostileDataIsPrintedAsText(t *testing.T) {
	p, logs, _ := recordedPlugin(t, &Config{})

	names := []string{
		`<script>alert(1)</script>`,
		`</td></tr></table><h1>X</h1>`,
		`<img src="file:///etc/passwd">`,
		`<a href="javascript:x">`,
		`<style>@page{margin:0}</style>`,
		"ctrl\x00\x01\x07\x1b\x7f-chars",
		strings.Repeat("L", 10_000),
	}
	reports := make([]datamodel.Report, 0, 3*len(names)+3)
	for i, n := range names {
		reports = append(reports,
			datamodel.Report{Filename: n, Malicious: true, Malwares: []string{n}, SHA256: fmt.Sprintf("%064x", i), MalwareReason: datamodel.MalwareDetected},
			datamodel.Report{Filename: n + "-err", Error: n},
			datamodel.Report{Filename: n + "-na", NotAnalyzedReason: datamodel.NotAnalyzedTooBig},
		)
	}
	reports = append(reports, archiveReports(2, 2)...)
	archive := datamodel.Report{Filename: names[0] + ".zip", Malicious: true, MaliciousExtractedFiles: []datamodel.ExtractedFile{{FileName: names[2], Malicious: true, Malwares: []string{names[3]}}}}
	reports = append(reports, archive)

	data := mustReportData(t, scanContext(), reports)
	buf, err := p.generatePDFReport(t.Context(), data)
	if err != nil {
		t.Fatal(err)
	}
	texts := pdfPageTexts(t, buf.Bytes())
	text := joined(texts)
	for _, n := range names[:5] {
		if !strings.Contains(text, squash(n)) {
			t.Errorf("%q is not printed as text", n)
		}
	}
	if !strings.Contains(text, strings.Repeat("L", 40)) {
		t.Error("the head of the 10 000-char name is not printed")
	}
	if strings.Contains(text, strings.Repeat("L", 5_000)) {
		t.Error("the 10 000-char name is not cut")
	}
	assertFooters(t, texts)
	for _, rec := range logs.all() {
		if rec.msg != "report PDF warning" {
			continue
		}
		switch code := fmt.Sprint(rec.attrs["code"]); code {
		case "unsupported-element", "blocked-link", "unsupported-at-rule":
			t.Errorf("hostile data was interpreted as markup: warning %s (%v)", code, rec.attrs["detail"])
		}
	}
}

func TestPDF_aLimitHitIsACleanError(t *testing.T) {
	const wrap = "<html><body>%s</body></html>"
	tests := []struct {
		name      string
		body      string
		wantLimit htmltopdf.Limit
	}{
		{"input over 2 MiB", "<p>" + strings.Repeat("lorem ", 400_000) + "</p>", htmltopdf.LimitInputBytes},
		{"40 000 paragraphs", strings.Repeat("<p>a</p>", 40_000), htmltopdf.LimitBoxes},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTemplate(t, fmt.Sprintf(wrap, tt.body))
			p, logs, _ := recordedPlugin(t, &Config{TemplatePath: path})
			buf, err := p.generatePDFReport(t.Context(), ReportData{})
			if err == nil {
				t.Fatal("no error")
			}
			if buf != nil {
				t.Errorf("a %d-byte buffer is returned with the error, want nil", buf.Len())
			}
			if !errors.Is(err, htmltopdf.ErrLimit) {
				t.Errorf("error %v does not match htmltopdf.ErrLimit", err)
			}
			var le *htmltopdf.LimitError
			if !errors.As(err, &le) {
				t.Fatalf("error %v is not a *htmltopdf.LimitError", err)
			}
			if le.Limit != tt.wantLimit {
				t.Errorf("limit %s, want %s", le.Limit, tt.wantLimit)
			}
			warns := logs.withMessage("the report PDF exceeds a limit")
			if len(warns) != 1 || warns[0].level != slog.LevelWarn || warns[0].attrs["limit"] != string(tt.wantLimit) {
				t.Errorf("limit warnings = %+v, want one Warn with limit=%s", warns, tt.wantLimit)
			}
		})
	}
}

func TestPDF_aFailingTemplateReturnsNoBuffer(t *testing.T) {
	path := writeTemplate(t, "<html>{{ .NoSuchField }}</html>")
	p, _, _ := recordedPlugin(t, &Config{TemplatePath: path})
	buf, err := p.generatePDFReport(t.Context(), ReportData{})
	if err == nil || buf != nil {
		t.Fatalf("buffer %v, error %v; want no buffer and an error", buf, err)
	}
	if errors.Is(err, htmltopdf.ErrLimit) {
		t.Errorf("a template error is not a limit: %v", err)
	}
}

func TestPDF_aCancelledContextStopsTheRendering(t *testing.T) {
	p := newTestPlugin(t)
	data := mustReportData(t, scanContext(), benchReports(50))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	// Both a free slot and the cancellation are ready: every outcome must be Canceled.
	for range 20 {
		buf, err := p.generatePDFReport(ctx, data)
		if !errors.Is(err, context.Canceled) || buf != nil {
			t.Fatalf("buffer %v, error %v; want no buffer and context.Canceled", buf, err)
		}
	}
}

func TestPDF_successIsLoggedAtDebug(t *testing.T) {
	p, logs, _ := recordedPlugin(t, &Config{})
	renderPDF(t, p, benchReports(50))
	got := logs.withMessage("report PDF rendered")
	if len(got) != 1 || got[0].level != slog.LevelDebug {
		t.Fatalf("records = %+v, want one Debug \"report PDF rendered\"", got)
	}
	for _, k := range []string{"pages", "bytes", "duration"} {
		if _, ok := got[0].attrs[k]; !ok {
			t.Errorf("attribute %q is missing", k)
		}
	}
}

func TestPDF_theWarningsOfTheConverterAreLoggedAtDebug(t *testing.T) {
	path := writeTemplate(t, `<html><body><iframe src="x"></iframe><a href="javascript:x">l</a><p style="frobnicate:1">{{ .ScanID }}</p></body></html>`)
	p, logs, _ := recordedPlugin(t, &Config{TemplatePath: path})
	if _, err := p.generatePDFReport(t.Context(), ReportData{ScanID: "id"}); err != nil {
		t.Fatal(err)
	}
	warns := logs.withMessage("report PDF warning")
	if len(warns) == 0 {
		t.Fatal("no warning logged for an iframe, a javascript: link and an unknown property")
	}
	for _, w := range warns {
		if w.level != slog.LevelDebug {
			t.Errorf("warning logged at %s, want Debug", w.level)
		}
		for _, k := range []string{"code", "detail", "count"} {
			if _, ok := w.attrs[k]; !ok {
				t.Errorf("warning without %q: %+v", k, w)
			}
		}
	}
}

func TestReportOptions_limitsAreNeverAboveTheDefaults(t *testing.T) {
	opts, err := reportOptions()
	if err != nil {
		t.Fatal(err)
	}
	got, def := reflect.ValueOf(opts.Limits), reflect.ValueOf(htmltopdf.DefaultLimits())
	for i := range got.NumField() {
		name := got.Type().Field(i).Name
		if k := got.Field(i).Kind(); k != reflect.Int && k != reflect.Int64 {
			t.Errorf("%s has kind %s: teach this test to compare it with the default", name, k)
			continue
		}
		g, d := got.Field(i).Int(), def.Field(i).Int()
		if g != 0 && g > d {
			t.Errorf("%s = %d, above the default %d", name, g, d)
		}
	}
	if opts.Limits.MaxOutputBytes != maxReportPDF {
		t.Errorf("MaxOutputBytes = %d, want maxReportPDF = %d", opts.Limits.MaxOutputBytes, maxReportPDF)
	}
	if opts.Limits.Timeout != renderTimeout || renderTimeout > htmltopdf.DefaultLimits().Timeout {
		t.Errorf("Timeout = %s, renderTimeout = %s, default %s", opts.Limits.Timeout, renderTimeout, htmltopdf.DefaultLimits().Timeout)
	}
	if len(opts.Fonts) != len(reportFonts) {
		t.Errorf("%d fonts, want %d", len(opts.Fonts), len(reportFonts))
	}
	for _, f := range opts.Fonts {
		if len(f.Data) == 0 {
			t.Errorf("empty font of family %q", f.Family)
		}
	}
}

func TestPDF_concurrentRendersGiveTheSamePDF(t *testing.T) {
	p := newTestPlugin(t)
	data := mustReportData(t, scanContext(), benchReports(50))
	const n = 8
	out := make([][]byte, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			buf, err := p.generatePDFReport(t.Context(), data)
			if err == nil {
				out[i] = buf.Bytes()
			}
			errs[i] = err
		})
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("render %d: %v", i, errs[i])
		}
		if !bytes.Equal(out[i], out[0]) {
			t.Errorf("render %d differs from render 0 (%d vs %d bytes)", i, len(out[i]), len(out[0]))
		}
	}
}

func TestPDF_aFullSlotPoolDoesNotBlockPastTheContext(t *testing.T) {
	p := newTestPlugin(t)
	data := mustReportData(t, scanContext(), benchReports(0))
	for range cap(renderSlots) {
		renderSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for range cap(renderSlots) {
			<-renderSlots
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	buf, err := p.generatePDFReport(ctx, data)
	if err == nil || buf != nil || !strings.Contains(err.Error(), "waiting for a render slot") {
		t.Fatalf("buffer %v, error %v; want no buffer and \"waiting for a render slot\"", buf, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v does not wrap context.DeadlineExceeded", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("returned after %s", time.Since(start))
	}
}

func TestChromePath_isDeprecatedAndIgnored(t *testing.T) {
	findWarning := func(r *recorder) []logRecord { return r.withMessage(chromePathDeprecated) }

	t.Run("exact message", func(t *testing.T) {
		const want = "chrome_path is deprecated and ignored: the report plugin renders PDFs without a browser; remove it from the configuration"
		if chromePathDeprecated != want {
			t.Errorf("chromePathDeprecated = %q, want %q", chromePathDeprecated, want)
		}
	})
	t.Run("Validate", func(t *testing.T) {
		logs := newRecorder()
		hcc := mock.NewMockHCContext()
		hcc.Logger = slog.New(logs)
		var p ReportPlugin
		if err := p.Validate(&Config{ChromePath: "/nonexistent/chromium"}, hcc); err != nil {
			t.Fatal(err)
		}
		got := findWarning(logs)
		if len(got) != 1 || got[0].level != slog.LevelWarn || got[0].attrs["chrome_path"] != "/nonexistent/chromium" {
			t.Errorf("records = %+v, want one Warn with chrome_path=/nonexistent/chromium", got)
		}
	})
	t.Run("Init", func(t *testing.T) {
		_, logs, console := recordedPlugin(t, &Config{ChromePath: "/nonexistent/chromium"})
		for name, r := range map[string]*recorder{"logger": logs, "console logger": console} {
			got := findWarning(r)
			if len(got) != 1 || got[0].level != slog.LevelWarn || got[0].attrs["chrome_path"] != "/nonexistent/chromium" {
				t.Errorf("%s: records = %+v, want one Warn with chrome_path", name, got)
			}
		}
	})
	t.Run("not set", func(t *testing.T) {
		_, logs, console := recordedPlugin(t, &Config{})
		for name, r := range map[string]*recorder{"logger": logs, "console logger": console} {
			if got := findWarning(r); len(got) != 0 {
				t.Errorf("%s: unexpected deprecation warning %+v", name, got)
			}
		}
	})
}

func TestReportPlugin_startsWithTheRealConverter(t *testing.T) {
	p := newTestPlugin(t)
	if p.pdf == nil || p.templ == nil {
		t.Fatalf("pdf %v, template %v: both must be set after Init", p.pdf, p.templ)
	}
	if err := p.pdf.selfTest(t.Context()); err != nil {
		t.Errorf("selfTest: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := p.pdf.selfTest(ctx); err == nil {
		t.Error("selfTest passed with a cancelled context")
	}
}

func TestReportPlugin_aFailingStartLeavesThePluginUnchanged(t *testing.T) {
	var p ReportPlugin
	err := p.Init(&Config{TemplatePath: filepath.Join(t.TempDir(), "missing.tmpl")}, mock.NewMockHCContext())
	if err == nil {
		t.Fatal("no error for a missing template")
	}
	if p.templ != nil || p.pdf != nil {
		t.Errorf("plugin changed by a failed Init: template %v, pdf %v", p.templ, p.pdf)
	}
	hcc := mock.NewMockHCContext()
	if err := p.Init(&Config{TemplatePath: filepath.Join(t.TempDir(), "missing.tmpl")}, hcc); err == nil || hcc.GenerateReportFunc != nil {
		t.Errorf("error %v, GenerateReport registered: %t", err, hcc.GenerateReportFunc != nil)
	}
}
