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
	pp, err := openPlugin(pluginConfig.File)
	if err != nil {
		return fmt.Errorf("plugin %s: %w", pluginName, err)
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

// openPlugin opens a plugin file and returns its exported plugin. A variable so
// tests can open fakes.
var openPlugin = func(file string) (plugins.Plugin, error) {
	// Loading runs the code of the file in this process: check it first.
	warnings, err := plugins.CheckPluginFile(file)
	if err != nil {
		return nil, err
	}
	for _, w := range warnings {
		logger.Warn(w)
	}
	plug, err := plugin.Open(file)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	p, err := plug.Lookup(plugins.PluginExportedName)
	if err != nil {
		return nil, fmt.Errorf("lookup: %w", err)
	}
	pp, ok := p.(plugins.Plugin)
	if !ok {
		return nil, errors.Join(errInvalidPlugin, fmt.Errorf("plugin: %#v", p))
	}
	return pp, nil
}

// ValidatePlugins checks the configuration of every plugin and runs their
// Validate, without initializing anything or touching the running connector.
func ValidatePlugins(pluginsConfig []PluginConfig, vc *ValidationContext) error {
	return validatePlugins(pluginsConfig, vc, openPlugin)
}
