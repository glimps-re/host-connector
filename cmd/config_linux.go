//go:build linux
// +build linux

package cmd

import (
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
	return
}
