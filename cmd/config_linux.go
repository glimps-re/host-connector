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
	DefaultConfigPath         = "/etc/gmhost/config"
	DefaultCacheLocation      = ""
	DefaultQuarantineLocation = "/var/lib/gmhost/quarantine"
)

func getConfigFile() (config string) {
	config = DefaultConfigPath
	home, err := homedir.Dir()
	if err != nil {
		return
	}
	cfg := filepath.Join(home, ".config", "gmhost", "config")
	if _, err := os.Stat(cfg); err == nil {
		return cfg
	}
	if _, err := os.Stat(config); err != nil {
		_, err = os.Create(config)
		if err != nil {
			Logger.Error("could not create config file", slog.String("location", config))
		}
	}
	return
}
