//go:build windows
// +build windows

package main

import (
	"os"
	"path/filepath"
)

var (
	DefaultConfigPath         = filepath.Join(os.Getenv("PROGRAMDATA"), "gmhost", "config")
	DefaultCacheLocation      = "" // filepath.Join(os.Getenv("PROGRAMDATA"), "gmhost", "cache")
	DefaultQuarantineLocation = filepath.Join(os.Getenv("PROGRAMDATA"), "gmhost", "quarantine")
	DefaultExportLocation     = filepath.Join(os.Getenv("PROGRAMDATA"), "gmhost", "export")
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

var defaultConfigUsage = "config file (default is %PROGRAMDATA%/gmhost/config)"
