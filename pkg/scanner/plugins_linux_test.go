//go:build linux

package scanner

import (
	"errors"
	"testing"
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
