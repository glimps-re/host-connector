//go:build windows

package scanner

import "log/slog"

func (c *Connector) LoadPlugins(pluginsConfig map[string]PluginConfig) error {
	for pluginName := range pluginsConfig {
		logger.Error("could not load plugin, not supported on windows platform", slog.String("plugin-name", pluginName))
	}
	return nil
}
