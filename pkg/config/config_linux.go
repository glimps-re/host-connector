//go:build linux

package config

import (
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

var (
	DefaultConfigPath         = "/etc/gmhost/config.yml"
	DefaultQuarantineLocation = "/var/lib/gmhost/quarantine"
	DefaultPluginsLocation    = "/var/lib/gmhost/plugins"
)

func GetConfigFile() (config string, err error) {
	home, err := homedir.Dir()
	if err != nil {
		return
	}
	cfg := filepath.Join(home, ".config", "gmhost", "config.yml")
	if _, err := os.Stat(cfg); err == nil {
		return cfg, nil
	}

	config = DefaultConfigPath
	if _, err := os.Stat(config); err != nil {
		_, err = os.OpenFile(filepath.Clean(config), os.O_RDONLY|os.O_CREATE, 0o600)
		if err != nil {
			return config, err
		}
	}
	return
}
