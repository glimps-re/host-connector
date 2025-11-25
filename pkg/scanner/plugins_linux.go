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
		if config != nil {
			decoder, decodeErr := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: decodeDuration,
				Result:     config,
			})
			if decodeErr != nil {
				return fmt.Errorf("failed to create config decoder for %s plugin, error: %w", pluginName, decodeErr)
			}
			// Clean the path to prevent directory traversal
			err = decoder.Decode(pluginConfig.Config)
			if err != nil {
				return fmt.Errorf("failed to read config for %s plugin, error: %w", pluginName, err)
			}
		}

		err = pp.Init(config, c)
		if err != nil {
			logger.Error("could not load plugin", slog.String("plugin", pluginName), slog.Any("config", config), slog.String("error", err.Error()))
			return fmt.Errorf("error loading plugin %s: %w", pluginName, err)
		}
		c.loadedPlugins = append(c.loadedPlugins, pp)
	}
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
