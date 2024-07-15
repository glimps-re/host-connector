//go:build windows
// +build windows

package cmd

import (
	"log/slog"
	"os"
	"path/filepath"
)

var (
	DefaultConfigPath         = filepath.Join(os.Getenv("AppData"), "gmhost", "config.yml")
	DefaultCacheLocation      = filepath.Join(os.Getenv("AppData"), "gmhost", "cache.db")
	DefaultQuarantineLocation = filepath.Join(os.Getenv("AppData"), "gmhost", "quarantine")
)

func getConfigFile() (config string) {
	config = DefaultConfigPath
	home := os.Getenv("APPDATA")
	cfg := filepath.Join(home, "gmhost", "config.yml")
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
