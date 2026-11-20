package config

import (
	"time"

	"github.com/glimps-re/connector-integration/sdk"
)

const (
	DefaultTimeout                  = sdk.Duration(5 * time.Minute)
	DefaultWorkers                  = 4
	DefaultExtractWorkers           = 2
	DefaultModificationDelay        = sdk.Duration(time.Second * 30)
	DefaultMaxFileSize              = "100MiB"
	DefaultExtractMinSize           = "8KB" // minimum size to attempt extraction
	DefaultRecursiveExtractMaxDepth = 10    // arbitrary
	DefaultRecursiveExtractMaxSize  = "5GB"
	DefaultRecursiveExtractMaxFiles = 10000
)

var Version = "dev"

type Config struct {
	// global
	sdk.HostConfig `yaml:",inline" mapstructure:",squash"`
	Config         string                           `yaml:"config" desc:"path to configuration file"`
	Console        sdk.ConnectorManagerClientConfig `mapstructure:"console" desc:"connector manager configuration"`
	Gui            bool
	// ShutdownTimeout bounds a stop on a signal. It belongs to the deployment
	// (the delay of the orchestrator), not to the console: it is not part of
	// the configuration the console manages.
	ShutdownTimeout sdk.Duration `mapstructure:"shutdown_timeout" yaml:"shutdown_timeout" desc:"time allowed to stop on a signal (default 8s, at least 2s): keep it under the delay of the orchestrator"`
}
