package plugins

import (
	"context"
	"fmt"

	"golift.io/xtractr"
)

type XtractFileFunc = func(xFile *xtractr.XFile) (int64, []string, []string, error)

// Plugin interface must be implemented by host-connector plugins
type Plugin interface {
	Init(configPath string, hcc HCContext) error
	Close(ctx context.Context) error
}

type HCContext interface {
	SetXTractFile(f XtractFileFunc)
}

// ErrUnhandledMethod is return when a plugin does not handle the request method
var ErrUnhandledMethod = fmt.Errorf("unhandled method")

var PluginExportedName = "HCPlugin"
