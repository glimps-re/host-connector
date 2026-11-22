package scanner

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

func TestOnScanFile_decisionRules(t *testing.T) {
	waiver := func(tag string) *datamodel.Result { return &datamodel.Result{Filename: tag} }
	refusal := func(tag string) *datamodel.Result { return &datamodel.Result{Filename: tag, Malware: true} }
	analysisErr := func(tag string) *datamodel.Result { return &datamodel.Result{Filename: tag, AnalysisError: "boom"} }
	withError := func(tag string) *datamodel.Result { return &datamodel.Result{Filename: tag, Error: errors.New("boom")} }

	tests := []struct {
		name       string
		results    []*datamodel.Result
		wantTag    string
		wantCalled int
	}{
		{"no result", []*datamodel.Result{nil, nil}, "", 2},
		{"waiver then refusal: refusal wins", []*datamodel.Result{waiver("w"), refusal("r")}, "r", 2},
		{"refusal then waiver: refusal stops the chain", []*datamodel.Result{refusal("r"), waiver("w")}, "r", 1},
		{"waiver then waiver: first waiver, all called", []*datamodel.Result{waiver("w1"), waiver("w2")}, "w1", 2},
		{"refusal then refusal: first refusal", []*datamodel.Result{refusal("r1"), refusal("r2")}, "r1", 1},
		{"waiver, nil, refusal", []*datamodel.Result{waiver("w"), nil, refusal("r")}, "r", 3},
		{"AnalysisError without Malware is a refusal", []*datamodel.Result{waiver("w"), analysisErr("a")}, "a", 2},
		{"AnalysisError then waiver stops", []*datamodel.Result{analysisErr("a"), waiver("w")}, "a", 1},
		{"Error without Malware is a refusal", []*datamodel.Result{waiver("w"), withError("e")}, "e", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Connector{}
			called := 0
			for _, r := range tt.results {
				c.RegisterOnScanFile(func(string, string, string, bool) *datamodel.Result {
					called++
					return r
				})
			}
			got := c.onScanFile("f", "/f", "sha", false)
			switch {
			case tt.wantTag == "" && got != nil:
				t.Errorf("onScanFile() = %+v, want nil", got)
			case tt.wantTag != "" && (got == nil || got.Filename != tt.wantTag):
				t.Errorf("onScanFile() = %+v, want %q", got, tt.wantTag)
			}
			if called != tt.wantCalled {
				t.Errorf("callbacks called = %d, want %d", called, tt.wantCalled)
			}
		})
	}
}

func TestOnScanFile_concurrent(t *testing.T) {
	c := &Connector{}
	var calls [3]atomic.Int64
	c.RegisterOnScanFile(func(name, _, _ string, _ bool) *datamodel.Result {
		calls[0].Add(1)
		return &datamodel.Result{Filename: name}
	})
	c.RegisterOnScanFile(func(name, _, _ string, _ bool) *datamodel.Result {
		calls[1].Add(1)
		return &datamodel.Result{Filename: name, Malware: true}
	})
	c.RegisterOnScanFile(func(string, string, string, bool) *datamodel.Result {
		calls[2].Add(1)
		return nil
	})

	const n = 64
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := range n {
		wg.Go(func() {
			name := fmt.Sprintf("f%d", i)
			r := c.onScanFile(name, "/p/"+name, "sha", false)
			if r == nil || r.Filename != name || !r.Malware {
				errs <- name
			}
		})
	}
	wg.Wait()
	close(errs)
	for name := range errs {
		t.Errorf("onScanFile(%q): want the refusal of the second callback", name)
	}
	if calls[0].Load() != n || calls[1].Load() != n || calls[2].Load() != 0 {
		t.Errorf("calls = [%d %d %d], want [%d %d 0]", calls[0].Load(), calls[1].Load(), calls[2].Load(), n, n)
	}
}

// A forbidden path of the configuration beats the waiver of a plugin (a text/plain
// type), and a path that is not forbidden keeps it.
func TestOnScanFile_aForbiddenPathBeatsTheWaiverOfAPlugin(t *testing.T) {
	c := &Connector{config: Config{PathFilter: mustPathFilter(t, []string{`^.*\.exe$`}, nil)}}
	c.RegisterOnScanFile(func(fn, loc, sha string, _ bool) *datamodel.Result {
		return &datamodel.Result{Filename: fn, Location: loc, SHA256: sha, Score: -500}
	})
	if got := c.onScanFile("/in/a.exe", "/tmp/a.exe", "sha", false); got == nil || !got.Malware || got.MalwareReason != datamodel.FilteredFilePath {
		t.Errorf("text/plain at a forbidden path = %+v, want malicious", got)
	}
	if got := c.onScanFile("/in/alice/a.zip/x/y.txt", "/tmp/gmhost-1/extract/x/y.txt", "sha", false); got == nil || got.Malware {
		t.Errorf("text/plain member under a temporary location = %+v, want a waiver: the temporary folder is not matched", got)
	}
	if got := c.onScanFile("/in/a.txt", "/home/u/a.txt", "sha", false); got == nil || got.Malware {
		t.Errorf("text/plain at an allowed path = %+v, want a waiver", got)
	}
}

func TestOnScanFile_noCallbackReturnsNil(t *testing.T) {
	c := &Connector{}
	if r := c.onScanFile("f", "/f", "sha", false); r != nil {
		t.Errorf("onScanFile() = %v, want nil", r)
	}
}

func TestOnFileScanned_softeningWarnNamesPlugin(t *testing.T) {
	var buf bytes.Buffer
	prev := logger
	logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	t.Cleanup(func() { logger = prev })

	c := &Connector{}
	c.loadingPlugin = "error_filter"
	c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
		r.Error = nil
		r.Malware = false
		return &r
	})
	got := c.onFileScanned("/f", "sha", datamodel.Result{Error: errors.New("boom"), Malware: true})
	if got == nil || got.Error == nil || !got.Malware {
		t.Fatalf("onFileScanned() = %+v, want hardened values restored", got)
	}
	out := buf.String()
	if !strings.Contains(out, `"level":"WARN"`) || !strings.Contains(out, "error_filter") {
		t.Errorf("log = %q, want a Warn naming error_filter", out)
	}
}

func TestAnalyzeFile_pluginsReceiveTheLogicalPathAndFilenameStaysInternal(t *testing.T) {
	c := &Connector{}
	var gotName, gotLocation string
	c.RegisterOnScanFile(func(name, location, _ string, _ bool) *datamodel.Result {
		gotName, gotLocation = name, location
		return &datamodel.Result{Filename: "chosen by the plugin", Malware: true, Malwares: []string{"m"}}
	})
	in := fileToAnalyze{
		filename:    "x/y.exe",
		logicalPath: "/in/alice/a.zip/x/y.exe",
		location:    "/work/extract/x/y.exe",
	}
	res := c.analyzeFile(in)
	if gotName != in.logicalPath || gotLocation != in.location {
		t.Errorf("plugin got (%q, %q), want (%q, %q)", gotName, gotLocation, in.logicalPath, in.location)
	}
	if res.Filename != in.filename {
		t.Errorf("Result.Filename = %q, want the internal name %q", res.Filename, in.filename)
	}
	top := fileToAnalyze{filename: "/in/a.bin", location: "/in/a.bin"}
	c.analyzeFile(top)
	if gotName != "/in/a.bin" {
		t.Errorf("first-level file: plugin got %q, want its location", gotName)
	}
}
