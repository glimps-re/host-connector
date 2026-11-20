package main

import (
	"context"
	"errors"
	"io"
	"iter"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

func sessionWithGenerator(t *testing.T, gen plugins.GenerateReport) (*SessionPlugin, *Session, string) {
	t.Helper()
	export := t.TempDir()
	hcc := mock.NewMockHCContext()
	hcc.GenerateReportFunc = gen
	plugin := &SessionPlugin{}
	plugin.config = Config{ReportTimeout: time.Minute, InflightTimeout: 24 * time.Hour, RootFolder: t.TempDir(), Depth: 1, Delay: time.Hour}
	plugin.sessions = make(map[string]*Session)
	plugin.hcc = hcc
	plugin.stop = make(chan struct{})
	plugin.logger = slog.New(slog.DiscardHandler)
	plugin.consoleLogger = slog.New(slog.DiscardHandler)
	dir := filepath.Join(export, "team")
	return plugin, &Session{ID: "team", StartTime: time.Unix(1_700_000_000, 0), Paths: []string{dir}, CompletedReports: []datamodel.Report{{Filename: "a"}, {Filename: "b"}}}, dir
}

func entriesOf(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// The extension of the report file is the one the generator gives.
func TestSession_theReportFileHasTheExtensionOfTheGenerator(t *testing.T) {
	for _, ext := range []string{".json", ".pdf", ".csv"} {
		t.Run(ext, func(t *testing.T) {
			closed := false
			plugin, session, dir := sessionWithGenerator(t, func(_ context.Context, _ datamodel.ScanContext, reports iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
				for _, err := range reports {
					if err != nil {
						return plugins.GeneratedReport{}, err
					}
				}
				return plugins.GeneratedReport{Content: &closeRecorder{Reader: strings.NewReader("content"), closed: &closed}, Extension: ext}, nil
			})
			_ = plugin.writeSessionReport(t.Context(), newClosing(session), viaGenerator)
			names := entriesOf(t, dir)
			if len(names) != 1 || !strings.HasPrefix(names[0], datamodel.SessionReportPrefix) || !strings.HasSuffix(names[0], ext) {
				t.Errorf("files = %v, want one %s<session>-<start>%s", names, datamodel.SessionReportPrefix, ext)
			}
			if !closed {
				t.Error("the content of the report must be closed")
			}
		})
	}
}

type closeRecorder struct {
	io.Reader
	closed *bool
}

func (c *closeRecorder) Close() error {
	*c.closed = true
	return nil
}

// An extension that could name another place is refused, nothing is written.
func TestSession_aGeneratorCannotChooseWhereTheReportGoes(t *testing.T) {
	for _, ext := range []string{"", "pdf", ".", "./../x", ".p/df", ".a b", ".json\x00", "." + strings.Repeat("a", 40)} {
		t.Run(ext, func(t *testing.T) {
			plugin, session, dir := sessionWithGenerator(t, func(context.Context, datamodel.ScanContext, iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
				return plugins.GeneratedReport{Content: io.NopCloser(strings.NewReader("content")), Extension: ext}, nil
			})
			_ = plugin.writeSessionReport(t.Context(), newClosing(session), viaGenerator)
			if names := entriesOf(t, dir); len(names) != 0 {
				t.Errorf("files = %v, want none for the extension %q", names, ext)
			}
		})
	}
}

type failingReader struct {
	data string
	err  error
	read bool
}

func (f *failingReader) Read(p []byte) (int, error) {
	if !f.read {
		f.read = true
		return copy(p, f.data), nil
	}
	return 0, f.err
}

// A generator that fails midway leaves no partial report behind.
func TestSession_aFailingGeneratorLeavesNoPartialReport(t *testing.T) {
	boom := errors.New("generation failed")
	plugin, session, dir := sessionWithGenerator(t, func(context.Context, datamodel.ScanContext, iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
		return plugins.GeneratedReport{Content: io.NopCloser(&failingReader{data: "[{\"filename\":\"a\"}", err: boom}), Extension: ".json"}, nil
	})
	_ = plugin.writeSessionReport(t.Context(), newClosing(session), viaGenerator)
	if names := entriesOf(t, dir); len(names) != 0 {
		t.Errorf("files = %v, want none: a half report must not pass for a report", names)
	}
}

func TestSession_aGeneratorErrorWritesNothing(t *testing.T) {
	plugin, session, dir := sessionWithGenerator(t, func(context.Context, datamodel.ScanContext, iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
		return plugins.GeneratedReport{}, errors.New("no generator")
	})
	_ = plugin.writeSessionReport(t.Context(), newClosing(session), viaGenerator)
	if names := entriesOf(t, dir); len(names) != 0 {
		t.Errorf("files = %v, want none", names)
	}
}

// A close that fails after a good copy leaves a truncated file: the report is
// not "saved", and none of the files is kept.
func TestSession_aFailingCloseLeavesNoReport(t *testing.T) {
	prev := closeReportFile
	t.Cleanup(func() { closeReportFile = prev })
	closeReportFile = func(f *os.File) error { return errors.Join(f.Close(), errors.New("disk full at close")) }
	plugin, _, dir := sessionWithGenerator(t, nil)
	if res := plugin.saveReport(writeString("content"), filepath.Join(dir, "r.json")); len(res) != 1 || res[0].err == nil {
		t.Fatal("saveReport() must report the failed close")
	}
	if names := entriesOf(t, dir); len(names) != 0 {
		t.Errorf("files = %v, want none", names)
	}
}

// No file could be created: nothing is saved, and it is said.
func TestSession_savingWithoutAnyFileIsAnError(t *testing.T) {
	plugin, _, _ := sessionWithGenerator(t, nil)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := plugin.saveReport(writeString("content"), filepath.Join(blocker, "sub", "r.json")); len(res) != 1 || res[0].err == nil {
		t.Error("saveReport() with no file created must be an error, not a success")
	}
}

// A generator that breaks the contract (no content, no error) does not make the
// plugin panic.
func TestSession_aGeneratorWithoutContentIsTolerated(t *testing.T) {
	plugin, session, dir := sessionWithGenerator(t, func(context.Context, datamodel.ScanContext, iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
		return plugins.GeneratedReport{Extension: ".json"}, nil
	})
	_ = plugin.writeSessionReport(t.Context(), newClosing(session), viaGenerator)
	if names := entriesOf(t, dir); len(names) != 0 {
		t.Errorf("files = %v, want none", names)
	}
}

func writeString(s string) func(io.Writer) error {
	return func(w io.Writer) error {
		_, err := io.WriteString(w, s)
		return err
	}
}
