//go:build windows
// +build windows

package cmd

import (
	"os"
	"path/filepath"
)

var (
	DefaultConfigPath         = filepath.Join(os.Getenv("AppData"), "gmhost", "config.yml")
	DefaultCacheLocation      = filepath.Join(os.Getenv("AppData"), "gmhost", "cache.db")
	DefaultQuarantineLocation = filepath.Join(os.Getenv("AppData"), "gmhost", "quarantine")
	DefaultExportLocation     = filepath.Join(os.Getenv("AppData"), "gmhost", "export")
)

func getConfigFile() (config string) {
	config = DefaultConfigPath
	home := os.Getenv("APPDATA")
	cfg := filepath.Join(home, "gmhost", "config")
	if _, err := os.Stat(cfg); err == nil {
		return cfg
	}
	return
}

var defaultConfigUsage = "config file (default is %ProgramFiles%/gmhost/config)"
