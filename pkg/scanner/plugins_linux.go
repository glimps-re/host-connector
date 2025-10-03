//go:build linux
// +build linux

package scanner

import (
	"errors"
	"fmt"
	"log/slog"
	"plugin"

	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/go-viper/mapstructure/v2"
)

func (c *Connector) LoadPlugins(pluginsConfig map[string]PluginConfig) (err error) {
	for pluginName, pluginConfig := range pluginsConfig {
		plug, err := plugin.Open(pluginConfig.File)
		if err != nil {
			return err
		}
		p, err := plug.Lookup(plugins.PluginExportedName)
		if err != nil {
			return err
		}
		pp, ok := p.(plugins.Plugin)
		if !ok {
			return errors.Join(ErrInvalidPlugin, fmt.Errorf("plugin: %#v", p))
		}

		config := pp.GetDefaultConfig()
		// Clean the path to prevent directory traversal
		err = mapstructure.Decode(pluginConfig.Config, config)
		if err != nil {
			return fmt.Errorf("failed to read config for %s plugin, error: %w", pluginName, err)
		}

		err = pp.Init(config, c)
		if err != nil {
			logger.Error("could not load plugin", slog.String("plugin", pluginName), slog.Any("config", config), slog.String("error", err.Error()))
			return err
		}
		c.loadedPlugins = append(c.loadedPlugins, pp)
	}
	return nil
}
