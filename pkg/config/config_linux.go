//go:build linux

package config

import (
	"log/slog"
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
		f, err := os.OpenFile(filepath.Clean(config), os.O_RDONLY|os.O_CREATE, 0o600)
		if err != nil {
			return config, err
		}
		if e := f.Close(); e != nil {
			slog.Warn("could not close config file", slog.String("file", filepath.Clean(config)), slog.String("error", e.Error()))
		}
	}
	return
}
