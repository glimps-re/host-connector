//go:build linux
// +build linux

package config

import (
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

var (
	DefaultConfigPath         = "/etc/gmhost/config.yml"
	DefaultCacheLocation      = ""
	DefaultQuarantineLocation = "/var/lib/gmhost/quarantine"
	DefaultPluginsLocation    = "/var/lib/gmhost/plugins"
)

func GetConfigFile() (config string, err error) {
	config = DefaultConfigPath
	home, err := homedir.Dir()
	if err != nil {
		return
	}
	cfg := filepath.Join(home, ".config", "gmhost", "config.yml")
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
