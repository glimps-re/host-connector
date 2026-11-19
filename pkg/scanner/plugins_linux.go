//go:build linux

package scanner

import (
	"errors"
	"fmt"
	"log/slog"
	"plugin"
	"reflect"
	"time"

	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/go-viper/mapstructure/v2"
)

// LoadPlugins loads the plugins in slice order. A duplicate name is an error.
func (c *Connector) LoadPlugins(pluginsConfig []PluginConfig) error {
	if err := checkPluginNames(pluginsConfig); err != nil {
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
		return err
	}
	p, err := plug.Lookup(plugins.PluginExportedName)
	if err != nil {
		return err
	}
	pp, ok := p.(plugins.Plugin)
	if !ok {
		return errors.Join(errInvalidPlugin, fmt.Errorf("plugin: %#v", p))
	}

	config := pp.GetDefaultConfig()
	if config != nil {
		decoder, decodeErr := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			DecodeHook: decodeDuration,
			Result:     config,
		})
		if decodeErr != nil {
			return fmt.Errorf("failed to create config decoder for %s plugin, error: %w", pluginName, decodeErr)
		}
		if err = decoder.Decode(pluginConfig.Config); err != nil {
			return fmt.Errorf("failed to read config for %s plugin, error: %w", pluginName, err)
		}
	}

	c.loadingPlugin = pluginName
	defer func() { c.loadingPlugin = "" }()
	if err = pp.Init(config, c); err != nil {
		// The config is not logged: it can hold secrets (e.g. archive passwords).
		logger.Error("could not load plugin", slog.String("plugin", pluginName), slog.String("error", err.Error()))
		return fmt.Errorf("error loading plugin %s: %w", pluginName, err)
	}
	c.loadedPlugins = append(c.loadedPlugins, pp)
	return nil
}

func decodeDuration(fromType reflect.Type, toType reflect.Type, from any) (any, error) {
	if toType == reflect.TypeFor[time.Duration]() && fromType.Kind() == reflect.String {
		strDuration, ok := from.(string)
		if !ok {
			return from, nil
		}
		duration, err := time.ParseDuration(strDuration)
		if err != nil {
			return nil, fmt.Errorf("failed to parse duration %s, error: %w", strDuration, err)
		}
		return duration, nil
	}
	return from, nil
}
