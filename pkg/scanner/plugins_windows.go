//go:build windows
// +build windows

package scanner

import "log/slog"

func (c *Connector) LoadPlugins(conf Config) error {
	for pluginName := range conf.Plugins {
		Logger.Error("could not load plugin, not supported on windows platform", slog.String("plugin-name", pluginName))
	}
	return nil
}
