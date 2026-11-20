package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

type validatingPlugin struct {
	validateErr error
	panics      bool
	validated   atomic.Int32
	inited      atomic.Int32
	closed      atomic.Int32
	seenWorkDir string
	declare     func(vc plugins.ValidationContext) error
}

func (p *validatingPlugin) GetDefaultConfig() any {
	return &struct {
		Value string `mapstructure:"value"`
	}{}
}

func (p *validatingPlugin) Init(any, plugins.HCContext) error { p.inited.Add(1); return nil }

func (p *validatingPlugin) Close(context.Context) error { p.closed.Add(1); return nil }

func (p *validatingPlugin) Validate(_ any, vc plugins.ValidationContext) error {
	p.validated.Add(1)
	p.seenWorkDir = vc.GetWorkDir()
	if p.panics {
		panic("boom")
	}
	if p.declare != nil {
		if err := p.declare(vc); err != nil {
			return err
		}
	}
	return p.validateErr
}

type plainPlugin struct{ inited atomic.Int32 }

func (p *plainPlugin) GetDefaultConfig() any             { return nil }
func (p *plainPlugin) Init(any, plugins.HCContext) error { p.inited.Add(1); return nil }
func (p *plainPlugin) Close(context.Context) error       { return nil }
func opener(m map[string]plugins.Plugin) func(string) (plugins.Plugin, error) {
	return func(file string) (plugins.Plugin, error) {
		if p, ok := m[file]; ok {
			return p, nil
		}
		return nil, errors.New("open: no such plugin file")
	}
}

func TestValidatePlugins(t *testing.T) {
	good := &validatingPlugin{}
	failing := &validatingPlugin{validateErr: errors.New("7z not found")}
	panicking := &validatingPlugin{panics: true}
	plain := &plainPlugin{}
	files := map[string]plugins.Plugin{"good.so": good, "failing.so": failing, "panic.so": panicking, "plain.so": plain}
	tests := []struct {
		name    string
		config  []PluginConfig
		wantErr []string
	}{
		{name: "none"},
		{name: "valid", config: []PluginConfig{{Name: "a", File: "good.so"}, {Name: "p", File: "plain.so"}}},
		{name: "Validate error names the plugin", config: []PluginConfig{{Name: "f", File: "failing.so"}}, wantErr: []string{"plugin f", "7z not found"}},
		{name: "panic is an error", config: []PluginConfig{{Name: "x", File: "panic.so"}}, wantErr: []string{"plugin x", "panicked"}},
		{name: "unknown config key", config: []PluginConfig{{Name: "a", File: "good.so", Config: map[string]any{"valu": "x"}}}, wantErr: []string{"unknown config key", "valu"}},
		{name: "plugin taking no config", config: []PluginConfig{{Name: "p", File: "plain.so", Config: map[string]any{"k": 1}}}, wantErr: []string{"takes no configuration"}},
		{name: "missing file key", config: []PluginConfig{{Name: "a"}}, wantErr: []string{"missing"}},
		{name: "unopenable file", config: []PluginConfig{{Name: "a", File: "nope.so"}}, wantErr: []string{"plugin a", "no such plugin file"}},
		{name: "every failure is reported", config: []PluginConfig{{Name: "f", File: "failing.so"}, {Name: "a", File: "nope.so"}}, wantErr: []string{"plugin f", "plugin a"}},
		{name: "duplicate name", config: []PluginConfig{{Name: "a", File: "good.so"}, {Name: "a", File: "good.so"}}, wantErr: []string{"duplicate"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vc, err := NewValidationContext(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			err = validatePlugins(tt.config, vc, opener(files))
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("validatePlugins() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("validatePlugins() error = nil")
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q misses %q", err, want)
				}
			}
		})
	}
	if good.inited.Load() != 0 || failing.inited.Load() != 0 || plain.inited.Load() != 0 {
		t.Error("validation must never call Init")
	}
}

func TestValidationContext_scratchDirectory(t *testing.T) {
	base := t.TempDir()
	vc, err := NewValidationContext(base)
	if err != nil {
		t.Fatal(err)
	}
	dir := vc.GetWorkDir()
	if filepath.Dir(dir) != base || !strings.HasPrefix(filepath.Base(dir), "gmhost-validate-") {
		t.Errorf("work dir = %q, want validate-<random> under %q", dir, base)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("scratch directory mode = %v (err %v), want 0700", info, err)
	}
	if err = os.WriteFile(filepath.Join(dir, "left-by-the-plugin"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = vc.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err = os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the scratch directory must be removed with its content (stat error = %v)", err)
	}
}

func TestValidationContext_declarations(t *testing.T) {
	vc, err := NewValidationContext(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = vc.Close() })
	if err = vc.DeclareOutputDir("relative/dir"); err == nil {
		t.Error("a relative output directory must be refused")
	}
	if err = vc.DeclareExecutable("relative-binary"); !errors.Is(err, plugins.ErrUnsafeExecutable) {
		t.Errorf("DeclareExecutable(relative) error = %v, want ErrUnsafeExecutable", err)
	}
	out := t.TempDir()
	for range 2 {
		if err = vc.DeclareOutputDir(out); err != nil {
			t.Fatal(err)
		}
	}
	if got := vc.Declarations().OutputDirs; len(got) != 1 || got[0] != out {
		t.Errorf("OutputDirs = %v, want %q once", got, out)
	}
	if got := vc.Declarations().Executables; len(got) != 0 {
		t.Errorf("a refused executable must not be recorded: %v", got)
	}
}

func TestValidatePlugin_leavesRunningConnectorUntouched(t *testing.T) {
	c := &Connector{}
	before := ExtractFile
	p := &validatingPlugin{declare: func(vc plugins.ValidationContext) error {
		return vc.DeclareOutputDir(t.TempDir())
	}}
	vc, err := NewValidationContext(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = vc.Close() })
	if err = validatePlugins([]PluginConfig{{Name: "a", File: "a.so"}}, vc, opener(map[string]plugins.Plugin{"a.so": p})); err != nil {
		t.Fatal(err)
	}
	if got := c.Declarations(); len(got.OutputDirs) != 0 || len(got.Executables) != 0 {
		t.Errorf("a validation must not declare on the connector: %+v", got)
	}
	if len(c.onScanFileCbs) != 0 || len(c.onFileScannedCbs) != 0 {
		t.Error("a validation must not register callbacks")
	}
	if reflectFuncPointer(ExtractFile) != reflectFuncPointer(before) {
		t.Error("a validation must not touch ExtractFile")
	}
	if p.validated.Load() != 1 {
		t.Errorf("Validate called %d times, want 1", p.validated.Load())
	}
}

func reflectFuncPointer(f any) uintptr {
	return reflect.ValueOf(f).Pointer()
}

func TestNewValidationContext_missingBaseIsCreatedAndAbsolute(t *testing.T) {
	base := filepath.Join(t.TempDir(), "not", "yet")
	vc, err := NewValidationContext(base)
	if err != nil {
		t.Fatalf("NewValidationContext() error = %v", err)
	}
	t.Cleanup(func() { _ = vc.Close() })
	if !filepath.IsAbs(vc.GetWorkDir()) || filepath.Dir(vc.GetWorkDir()) != base {
		t.Errorf("work dir = %q, want an absolute directory under %q", vc.GetWorkDir(), base)
	}
}

func TestReservedEventKeysAreIgnored(t *testing.T) {
	rec := &recordingEventHandler{}
	prev := EventHandler
	EventHandler = rec
	t.Cleanup(func() { EventHandler = prev })
	c := &Connector{}
	for _, key := range []string{"host-config-rejected", "host-bad-config", "gmalware", "gmalware-bad-config"} {
		c.NotifyError(t.Context(), key, errors.New("x"))
		c.NotifyResolution(t.Context(), key, "x")
	}
	c.NotifyError(t.Context(), "my-plugin-event", errors.New("x"))
	if rec.errors != 1 || rec.resolutions != 0 {
		t.Errorf("errors = %d, resolutions = %d, want only the plugin's own event", rec.errors, rec.resolutions)
	}
}

type recordingEventHandler struct {
	events.NoopEventHandler
	errors, resolutions int
}

func (r *recordingEventHandler) NotifyError(context.Context, events.ErrorEventType, error) error {
	r.errors++
	return nil
}

func (r *recordingEventHandler) NotifyResolution(context.Context, string, ...events.ErrorEventType) error {
	r.resolutions++
	return nil
}
