package config

import (
	"time"

	"github.com/glimps-re/connector-manager/pkg/shared"
)

var (
	DefaultTimeout           = 5 * time.Minute
	DefaultWorkers           = 4
	DefaultScanValidity      = time.Hour * 24 * 7
	DefaultModificationDelay = time.Second * 30
	DefaultMaxFileSize       = "100MiB"
)

type GdetectConfig struct {
	Timeout   time.Duration `mapstructure:"timeout" yaml:"timeout" desc:"timeout allow to scan a single file"`
	Syndetect bool          `mapstructure:"syndetect" yaml:"syndetect" desc:"use syndetect API to analyze files"`
}

type PrintConfig struct {
	Location string `mapstructure:"location" yaml:"location" desc:"location of the report logs"`
}

type Config struct {
	// global
	Config string `yaml:"config" desc:"path to configuration file"`
	shared.HostConfig
	Console shared.ConnectorManagerClientConfig `mapstructure:"console" desc:"connector manager configuration"`
	Debug   bool                                `mapstructure:"debug" yaml:"debug" desc:"print debug strings"`
	Verbose bool                                `mapstructure:"verbose" yaml:"verbose" desc:"print information strings"`
	Quiet   bool                                `mapstructure:"quiet" yaml:"quiet" desc:"print no information strings"`
	Print   PrintConfig                         `mapstructure:"print" yaml:"print" desc:"print report configuration"`
	Gui     bool
}
