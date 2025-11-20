//go:build windows

package config

import (
	"os"
	"path/filepath"
)

var (
	DefaultConfigPath         = filepath.Join(os.Getenv("AppData"), "gmhost", "config.yml")
	DefaultCacheLocation      = filepath.Join(os.Getenv("AppData"), "gmhost", "cache.db")
	DefaultQuarantineLocation = filepath.Join(os.Getenv("AppData"), "gmhost", "quarantine")
	DefaultPluginsLocation    = filepath.Join(os.Getenv("AppData"), "gmhost", "plugins")
)

func GetConfigFile() (config string, err error) {
	config = DefaultConfigPath
	home := os.Getenv("APPDATA")
	cfg := filepath.Join(home, "gmhost", "config.yml")
	if _, err := os.Stat(cfg); err == nil {
		return cfg, nil
	}
	if _, err := os.Stat(config); err != nil {
		_, err = os.Create(filepath.Clean(config))
		if err != nil {
			return config, err
		}
	}
	return
}
