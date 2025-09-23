package config

import (
	"time"

	"github.com/glimps-re/connector-integration/sdk"
)

var (
	DefaultTimeout           = sdk.Duration(5 * time.Minute)
	DefaultWorkers           = 4
	DefaultExtractWorkers    = 2
	DefaultScanValidity      = sdk.Duration(time.Hour * 24 * 7)
	DefaultModificationDelay = sdk.Duration(time.Second * 30)
	DefaultMaxFileSize       = "100MiB"
)

type Config struct {
	// global
	sdk.HostConfig `yaml:",inline" mapstructure:",squash"`
	Config         string                           `yaml:"config" desc:"path to configuration file"`
	Console        sdk.ConnectorManagerClientConfig `mapstructure:"console" desc:"connector manager configuration"`
	Gui            bool
}
