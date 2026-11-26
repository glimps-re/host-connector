//go:build windows

package scanner

import (
	"errors"
	"testing"
)

func TestLoadPlugins_windows(t *testing.T) {
	c := &Connector{}
	if err := c.LoadPlugins(nil); err != nil {
		t.Errorf("LoadPlugins(nil) error = %v", err)
	}
	if err := c.LoadPlugins([]PluginConfig{{Name: "a"}}); !errors.Is(err, errInvalidPlugin) {
		t.Errorf("LoadPlugins() error = %v, want %v", err, errInvalidPlugin)
	}
}
