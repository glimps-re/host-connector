package scanner

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/datamodel"
)

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := logger
	logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	t.Cleanup(func() { logger = prev })
	return &buf
}

func TestIsWaiver(t *testing.T) {
	tests := []struct {
		name string
		r    datamodel.Result
		want bool
	}{
		{"plain waiver", datamodel.Result{Score: -500}, true},
		{"malware", datamodel.Result{Malware: true}, false},
		{"error", datamodel.Result{Error: errors.New("x")}, false},
		{"analysis error", datamodel.Result{AnalysisError: "x"}, false},
		{"malware reason", datamodel.Result{MalwareReason: datamodel.FilteredFilePath}, false},
		{"malwares", datamodel.Result{Malwares: []string{"Evil"}}, false},
		{"malicious subfiles", datamodel.Result{MaliciousSubfiles: map[string]datamodel.Result{"a": {}}}, false},
		{"error subfiles", datamodel.Result{ErrorSubfiles: map[string]string{"a": "b"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isWaiver(&tt.r); got != tt.want {
				t.Errorf("isWaiver() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestOnScanFile_inconsistentRefusalSetsDefinitiveError(t *testing.T) {
	traces := map[string]datamodel.Result{
		"malwares":           {Malwares: []string{"Evil"}},
		"malware reason":     {MalwareReason: datamodel.MalwareDetected},
		"malicious subfiles": {MaliciousSubfiles: map[string]datamodel.Result{"a": {Malware: true}}},
		"error subfiles":     {ErrorSubfiles: map[string]string{"a": "b"}},
	}
	for name, res := range traces {
		t.Run(name, func(t *testing.T) {
			buf := captureLogs(t)
			c := &Connector{loadingPlugin: "sloppy"}
			c.RegisterOnScanFile(func(_, _, _ string, _ bool) *datamodel.Result { r := res; return &r })
			analyzed := false
			c.loadingPlugin = "after"
			c.RegisterOnScanFile(func(_, _, _ string, _ bool) *datamodel.Result { analyzed = true; return nil })

			got := c.onScanFile("a", "/in/a", "sha", false)
			if got == nil || !errors.Is(got.Error, errInconsistentPluginResult) {
				t.Fatalf("onScanFile() = %+v, want errInconsistentPluginResult", got)
			}
			if analyzed {
				t.Error("callbacks after a refusal must not run")
			}
			if out := buf.String(); !strings.Contains(out, `"level":"WARN"`) || !strings.Contains(out, "sloppy") {
				t.Errorf("log = %q, want a Warn naming the plugin", out)
			}
		})
	}
}

func TestOnScanFile_inconsistentBeatsEarlierWaiver(t *testing.T) {
	c := &Connector{}
	c.RegisterOnScanFile(func(_, _, _ string, _ bool) *datamodel.Result { return &datamodel.Result{Score: -500} })
	c.RegisterOnScanFile(func(_, _, _ string, _ bool) *datamodel.Result {
		return &datamodel.Result{Malwares: []string{"Evil"}}
	})
	if got := c.onScanFile("a", "/in/a", "sha", false); got == nil || got.Error == nil {
		t.Errorf("onScanFile() = %+v, want a refusal", got)
	}
}

func TestOnFileScanned_cannotEraseTraces(t *testing.T) {
	prev := datamodel.Result{
		MalwareReason:     datamodel.MalwareDetected,
		Malwares:          []string{"Evil"},
		MaliciousSubfiles: map[string]datamodel.Result{"a": {Malware: true}},
		ErrorSubfiles:     map[string]string{"b": "boom"},
	}
	buf := captureLogs(t)
	c := &Connector{loadingPlugin: "eraser"}
	c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
		return &datamodel.Result{Filename: r.Filename, Score: 1}
	})
	got := c.onFileScanned("/f", "sha", prev)
	if got == nil || got.MalwareReason != datamodel.MalwareDetected || len(got.Malwares) != 1 ||
		len(got.MaliciousSubfiles) != 1 || len(got.ErrorSubfiles) != 1 {
		t.Fatalf("onFileScanned() = %+v, want traces restored", got)
	}
	if !strings.Contains(buf.String(), "eraser") {
		t.Errorf("log = %q, want a Warn naming the plugin", buf.String())
	}
}

func TestOnFileScanned_deepCopy(t *testing.T) {
	input := datamodel.Result{
		Malwares:          []string{"Evil"},
		MaliciousSubfiles: map[string]datamodel.Result{"a": {Malwares: []string{"Sub"}}},
		ErrorSubfiles:     map[string]string{"b": "boom"},
	}
	var kept datamodel.Result
	c := &Connector{}
	c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
		r.Malwares[0] = "tampered"
		r.ErrorSubfiles["b"] = "tampered"
		delete(r.ErrorSubfiles, "b")
		r.MaliciousSubfiles["a"].Malwares[0] = "tampered"
		delete(r.MaliciousSubfiles, "a")
		kept = r
		return nil
	})
	if got := c.onFileScanned("/f", "sha", input); got != nil {
		t.Errorf("onFileScanned() = %+v, want nil", got)
	}
	if input.Malwares[0] != "Evil" || input.ErrorSubfiles["b"] != "boom" || input.MaliciousSubfiles["a"].Malwares[0] != "Sub" {
		t.Errorf("caller result modified in place: %+v", input)
	}

	c2 := &Connector{}
	c2.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
		r.Score = 7
		kept = r
		return &r
	})
	got := c2.onFileScanned("/f", "sha", input)
	kept.Malwares[0] = "tampered-later"
	if got == nil || got.Malwares[0] != "Evil" {
		t.Errorf("result shares memory with the plugin: %+v", got)
	}
}

func TestCheckPluginFiles(t *testing.T) {
	dir := t.TempDir()
	so := filepath.Join(dir, "a.so")
	if err := os.WriteFile(so, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "b.so")
	if err := os.Symlink(so, link); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "c.so")
	if err := os.WriteFile(other, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkPluginFiles([]PluginConfig{{Name: "a", File: so}, {Name: "c", File: other}}); err != nil {
		t.Errorf("distinct files refused: %v", err)
	}
	for _, second := range []string{so, link, filepath.Join(dir, ".", "a.so")} {
		err := checkPluginFiles([]PluginConfig{{Name: "a", File: so}, {Name: "b", File: second}})
		if !errors.Is(err, errDuplicateFile) {
			t.Errorf("same file via %q: error = %v, want errDuplicateFile", second, err)
		}
	}
}

func BenchmarkOnFileScanned(b *testing.B) {
	result := datamodel.Result{
		Malware:           true,
		Malwares:          []string{"Evil", "Worse"},
		MalwareReason:     datamodel.MalwareDetected,
		ErrorSubfiles:     map[string]string{"a": "b", "c": "d"},
		MaliciousSubfiles: map[string]datamodel.Result{"x": {Malware: true, Malwares: []string{"Sub"}}},
	}
	c := &Connector{}
	for range 3 {
		c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
			r.Score++
			return &r
		})
	}
	b.ReportAllocs()
	for b.Loop() {
		if c.onFileScanned("/f", "sha", result) == nil {
			b.Fatal("result must change")
		}
	}
}

func TestRestoreHardened_partialSoftening(t *testing.T) {
	prev := func() datamodel.Result {
		return datamodel.Result{
			Malware:       true,
			Malwares:      []string{"A", "B"},
			ErrorSubfiles: map[string]string{"e1": "x", "e2": "y"},
			MaliciousSubfiles: map[string]datamodel.Result{
				"m1": {Malware: true, Malwares: []string{"S1", "S2"}},
				"m2": {Malware: true},
			},
		}
	}
	tests := []struct {
		name  string
		next  func() datamodel.Result
		check func(t *testing.T, got datamodel.Result)
	}{
		{
			name: "one malware removed",
			next: func() datamodel.Result { r := prev(); r.Malwares = []string{"A"}; return r },
			check: func(t *testing.T, got datamodel.Result) {
				if !slices.Contains(got.Malwares, "B") {
					t.Errorf("Malwares = %v, want B restored", got.Malwares)
				}
			},
		},
		{
			name: "one error subfile removed",
			next: func() datamodel.Result { r := prev(); delete(r.ErrorSubfiles, "e2"); return r },
			check: func(t *testing.T, got datamodel.Result) {
				if got.ErrorSubfiles["e2"] != "y" {
					t.Errorf("ErrorSubfiles = %v, want e2 restored", got.ErrorSubfiles)
				}
			},
		},
		{
			name: "one malicious subfile removed",
			next: func() datamodel.Result { r := prev(); delete(r.MaliciousSubfiles, "m2"); return r },
			check: func(t *testing.T, got datamodel.Result) {
				if !got.MaliciousSubfiles["m2"].Malware {
					t.Errorf("MaliciousSubfiles = %v, want m2 restored", got.MaliciousSubfiles)
				}
			},
		},
		{
			name: "subfile turned clean",
			next: func() datamodel.Result {
				r := prev()
				r.MaliciousSubfiles["m1"] = datamodel.Result{Malware: false, Malwares: []string{"S1"}}
				return r
			},
			check: func(t *testing.T, got datamodel.Result) {
				m1 := got.MaliciousSubfiles["m1"]
				if !m1.Malware || !slices.Contains(m1.Malwares, "S2") {
					t.Errorf("m1 = %+v, want Malware and S2 restored", m1)
				}
			},
		},
		{
			name: "everything added is kept",
			next: func() datamodel.Result {
				r := prev()
				r.Malwares = append(r.Malwares, "C")
				r.ErrorSubfiles["e3"] = "z"
				return r
			},
			check: func(t *testing.T, got datamodel.Result) {
				if !slices.Contains(got.Malwares, "C") || got.ErrorSubfiles["e3"] != "z" {
					t.Errorf("additions lost: %+v", got)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := tt.next()
			restored := restoreHardened(prev(), &next)
			wantRestored := tt.name != "everything added is kept"
			if restored != wantRestored {
				t.Errorf("restored = %t, want %t", restored, wantRestored)
			}
			tt.check(t, next)
		})
	}
}

func TestOnFileScanned_partialSofteningWarns(t *testing.T) {
	buf := captureLogs(t)
	c := &Connector{loadingPlugin: "trimmer"}
	c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
		r.Malwares = r.Malwares[:1]
		return &r
	})
	got := c.onFileScanned("/f", "sha", datamodel.Result{Malware: true, Malwares: []string{"A", "B"}})
	if got == nil || len(got.Malwares) != 2 {
		t.Fatalf("onFileScanned() = %+v, want Malwares restored", got)
	}
	if !strings.Contains(buf.String(), "trimmer") {
		t.Errorf("log = %q, want a Warn naming the plugin", buf.String())
	}
}

func TestRegisterOnScanFile_resultIsCopied(t *testing.T) {
	shared := &datamodel.Result{Malwares: []string{"A"}, ErrorSubfiles: map[string]string{"a": "b"}}
	c := &Connector{loadingPlugin: "p"}
	c.RegisterOnScanFile(func(_, _, _ string, _ bool) *datamodel.Result { return shared })
	got := c.onScanFile("a", "/in/a", "sha", false)
	if got == nil || got == shared {
		t.Fatalf("onScanFile() = %p, want a copy of %p", got, shared)
	}
	shared.Malwares[0] = "tampered"
	shared.ErrorSubfiles["a"] = "tampered"
	delete(shared.ErrorSubfiles, "a")
	if got.Malwares[0] != "A" || got.ErrorSubfiles["a"] != "b" {
		t.Errorf("core result shares memory with the plugin: %+v", got)
	}
}

func TestRegister_ignoredOnceSealed(t *testing.T) {
	buf := captureLogs(t)
	c := &Connector{}
	c.setSealed(true)
	c.setLoading("late")
	c.RegisterOnScanFile(func(_, _, _ string, _ bool) *datamodel.Result { return &datamodel.Result{Malware: true} })
	c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result { return &r })
	c.RegisterOnStartScanFile(func(string, string) {})
	c.RegisterOnReport(func(*datamodel.Report) {})
	c.RegisterWithWaitForOptions(func(*gdetect.WaitForOptions, string) {})
	c.RegisterGenerateReport(nil)
	if len(c.onScanFileCbs)+len(c.onFileScannedCbs)+len(c.onStartScanFileCbs)+len(c.onReportCbs)+len(c.withWaitForOptionsFunc) != 0 || c.generateReport != nil {
		t.Error("a callback was registered after loading")
	}
	if n := strings.Count(buf.String(), "registration outside Init ignored"); n != 6 {
		t.Errorf("warnings = %d, want 6: %s", n, buf.String())
	}
}

func TestRegister_concurrentWithSealing(t *testing.T) {
	c := &Connector{}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				c.RegisterOnStartScanFile(func(string, string) {})
				c.RegisterOnScanFile(func(_, _, _ string, _ bool) *datamodel.Result { return nil })
			}
		})
	}
	wg.Go(func() {
		c.setLoading("p")
		c.setSealed(true)
	})
	wg.Wait()
}

func TestRestoreHardened_scoreNeverLowered(t *testing.T) {
	next := datamodel.Result{Score: 10}
	if !restoreHardened(datamodel.Result{Score: 900}, &next) || next.Score != 900 {
		t.Errorf("Score = %d, want 900 restored", next.Score)
	}
}

func TestSetExtractFile_ignoredOnceSealed(t *testing.T) {
	prev := ExtractFile
	t.Cleanup(func() { ExtractFile = prev })
	called := false
	c := &Connector{}
	c.setSealed(true)
	c.SetExtractFile(func(string, string) (uint64, []string, []string, error) { called = true; return 0, nil, nil, nil })
	if ExtractFile != nil {
		if _, _, _, _ = ExtractFile("a", "b"); called {
			t.Error("ExtractFile replaced after loading")
		}
	}
	c2 := &Connector{}
	c2.SetExtractFile(func(string, string) (uint64, []string, []string, error) { called = true; return 0, nil, nil, nil })
	if _, _, _, _ = ExtractFile("a", "b"); !called {
		t.Error("SetExtractFile before sealing must apply")
	}
}
