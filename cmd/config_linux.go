//go:build linux
// +build linux

package main

import (
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

var (
	DefaultConfigPath         = "/etc/gmhost/config"
	DefaultCacheLocation      = ""
	DefaultQuarantineLocation = "/var/lib/gmhost/quarantine"
	DefaultExportLocation     = "/var/lib/gmhost/export"
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
	return
}

var defaultConfigUsage = "config file (default is /etc/gmhost/config)"
