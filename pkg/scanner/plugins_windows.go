//go:build windows

package scanner

import "fmt"

// LoadPlugins fails as soon as a plugin is configured: plugins are not supported
// on Windows, and starting without the configured filters would fail open.
func (c *Connector) LoadPlugins(pluginsConfig []PluginConfig) error {
	defer c.setSealed(true)
	if err := checkPluginNames(pluginsConfig); err != nil {
		return err
	}
	if len(pluginsConfig) > 0 {
		return fmt.Errorf("%w: plugin %q configured but plugins are not supported on windows", errInvalidPlugin, pluginsConfig[0].Name)
	}
	return nil
}
