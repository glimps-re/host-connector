//go:build linux
// +build linux

package scanner

import (
	"errors"
	"fmt"
	"path"
	"plugin"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

func (c *Connector) LoadPlugins(conf Config) error {
	for pluginName, configPath := range conf.Plugins {
		pluginPath := path.Join(conf.PluginsDir, pluginName)
		plug, err := plugin.Open(pluginPath)
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

		configPath = path.Clean(configPath)
		err = pp.Init(configPath, c)
		if err != nil {
			return err
		}
		c.loadedPlugins = append(c.loadedPlugins, pp)
	}
	return nil
}
