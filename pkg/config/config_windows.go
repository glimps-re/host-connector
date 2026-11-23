//go:build windows

package config

import (
	"log/slog"
	"os"
	"path/filepath"
)

var (
	DefaultConfigPath         = filepath.Join(os.Getenv("APPDATA"), "gmhost", "config.yml")
	DefaultQuarantineLocation = filepath.Join(os.Getenv("APPDATA"), "gmhost", "quarantine")
)

func GetConfigFile() (config string, err error) {
	config = DefaultConfigPath
	if _, err := os.Stat(config); err != nil {
		f, err := os.Create(filepath.Clean(config))
		if err != nil {
			return config, err
		}
		if e := f.Close(); e != nil {
			slog.Warn("could not close config file", slog.String("file", filepath.Clean(config)), slog.String("error", e.Error()))
		}
	}
	return
}
