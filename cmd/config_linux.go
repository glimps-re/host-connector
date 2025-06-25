//go:build linux
// +build linux

package cmd

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

var (
	DefaultConfigPath         = "/etc/gmhost/config.yml"
	DefaultCacheLocation      = ""
	DefaultQuarantineLocation = "/var/lib/gmhost/quarantine"
)

func getConfigFile() (config string) {
	config = DefaultConfigPath
	home, err := homedir.Dir()
	if err != nil {
		return
	}
	cfg := filepath.Join(home, ".config", "gmhost", "config.yml")
	if _, err := os.Stat(cfg); err == nil {
		return cfg
	}
	if _, err := os.Stat(config); err != nil {
		_, err = os.Create(config) //nolint:gosec // we create config file
		if err != nil {
			Logger.Error("could not create config file", slog.String("location", config))
		}
	}
	return
}
