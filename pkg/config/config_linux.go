//go:build linux

package config

import (
	"log/slog"
	"os"
	"path/filepath"
)

var (
	DefaultConfigPath         = "/etc/gmhost/config.yml"
	DefaultQuarantineLocation = "/var/lib/gmhost/quarantine"
)

func GetConfigFile() (config string, err error) {
	home, err := os.UserHomeDir()
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
