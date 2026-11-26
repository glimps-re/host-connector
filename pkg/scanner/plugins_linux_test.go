//go:build linux

package scanner

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

func TestLoadPlugins_errors(t *testing.T) {
	c := &Connector{}
	if err := c.LoadPlugins([]PluginConfig{{Name: "a", File: "a.so"}, {Name: "a", File: "b.so"}}); !errors.Is(err, errDuplicatePlugin) {
		t.Errorf("duplicate: error = %v, want %v", err, errDuplicatePlugin)
	}
	if err := c.LoadPlugins([]PluginConfig{{Name: "typo"}}); !errors.Is(err, errInvalidPlugin) {
		t.Errorf("missing file: error = %v, want %v", err, errInvalidPlugin)
	}
	if err := c.LoadPlugins([]PluginConfig{{Name: "nofile", File: "/nonexistent/x.so"}}); err == nil {
		t.Error("unreadable plugin file: error = nil")
	}
}

// The name of a plugin is quoted in every error of its loading.
func TestLoadPlugin_aHostileNameIsQuoted(t *testing.T) {
	const hostile = "x\nERROR forged\x1b[31m\u202e"
	prev := openPlugin
	t.Cleanup(func() { openPlugin = prev })
	openPlugin = func(file string) (plugins.Plugin, error) {
		switch file {
		case "plain.so":
			return &plainPlugin{}, nil
		case "failing.so":
			return &initFailingPlugin{}, nil
		}
		return nil, errors.New("open: no such plugin file")
	}
	tests := []struct {
		name   string
		config PluginConfig
	}{
		{"missing file key", PluginConfig{Name: hostile}},
		{"unopenable file", PluginConfig{Name: hostile, File: "nope.so"}},
		{"no configuration taken", PluginConfig{Name: hostile, File: "plain.so", Config: map[string]any{"k": 1}}},
		{"Init fails", PluginConfig{Name: hostile, File: "failing.so"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (&Connector{}).loadPlugin(tt.config)
			if err == nil {
				t.Fatal("loadPlugin() error = nil")
			}
			for _, raw := range []string{"\n", "\x1b", "\u202e"} {
				if strings.Contains(err.Error(), raw) {
					t.Errorf("error holds the raw %q: %q", raw, err)
				}
			}
			if !strings.Contains(err.Error(), strconv.Quote(hostile)) {
				t.Errorf("error %q lacks the quoted name", err)
			}
		})
	}
}

type initFailingPlugin struct{ plainPlugin }

func (*initFailingPlugin) Init(any, plugins.HCContext) error { return errors.New("init failed") }
