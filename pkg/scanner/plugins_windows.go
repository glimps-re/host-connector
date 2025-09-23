//go:build windows
// +build windows

package scanner

func (c *Connector) LoadPlugins(conf Config) error {
	for pluginName, _ := range conf.Plugins {
		Logger.Errorf("could not load %s, plugin not supported on windows platform", pluginName)
	}
	return nil
}
