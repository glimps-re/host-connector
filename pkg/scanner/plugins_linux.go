//go:build linux

package scanner

import (
	"errors"
	"fmt"
	"log/slog"
	"plugin"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

// LoadPlugins loads the plugins in slice order. A duplicate name is an error.
func (c *Connector) LoadPlugins(pluginsConfig []PluginConfig) error {
	defer c.setSealed(true)
	if err := checkPluginNames(pluginsConfig); err != nil {
		return err
	}
	if err := checkPluginFiles(pluginsConfig); err != nil {
		return err
	}
	for _, pluginConfig := range pluginsConfig {
		if err := c.loadPlugin(pluginConfig); err != nil {
			return err
		}
	}
	return nil
}

func (c *Connector) loadPlugin(pluginConfig PluginConfig) error {
	pluginName := pluginConfig.Name
	if pluginConfig.File == "" {
		return fmt.Errorf("plugin %s: %w: missing %q", pluginName, errInvalidPlugin, "file")
	}
	plug, err := plugin.Open(pluginConfig.File)
	if err != nil {
		return fmt.Errorf("plugin %s: open: %w", pluginName, err)
	}
	p, err := plug.Lookup(plugins.PluginExportedName)
	if err != nil {
		return fmt.Errorf("plugin %s: lookup: %w", pluginName, err)
	}
	pp, ok := p.(plugins.Plugin)
	if !ok {
		return errors.Join(errInvalidPlugin, fmt.Errorf("plugin: %#v", p))
	}

	config := pp.GetDefaultConfig()
	if config != nil {
		if err = plugins.DecodeConfig(pluginName, pluginConfig.Config, config); err != nil {
			return err
		}
	} else if len(pluginConfig.Config) > 0 {
		return fmt.Errorf("plugin %s: %w: it takes no configuration", pluginName, errInvalidPlugin)
	}

	c.setLoading(pluginName)
	defer c.setLoading("")
	if err = pp.Init(config, c); err != nil {
		// The config is not logged: it can hold secrets (e.g. archive passwords).
		logger.Error("could not load plugin", slog.String("plugin", pluginName), slog.String("error", err.Error()))
		return fmt.Errorf("error loading plugin %s: %w", pluginName, err)
	}
	c.loadedPlugins = append(c.loadedPlugins, pp)
	return nil
}
