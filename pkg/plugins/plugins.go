package plugins

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/report"
	"golift.io/xtractr"
)

type XtractFileFunc = func(xFile *xtractr.XFile) (int64, []string, []string, error)

type (
	OnStartScanFile = func(file string, sha256 string) *gdetect.Result
	OnFileScanned   = func(file string, sha256 string, result gdetect.Result, err error)
	OnReport        = func(report *report.Report)
)

type GenerateReport = func(reportConntext report.ScanContext, reports []report.Report) (io.Reader, error)

// Plugin interface must be implemented by host-connector plugins
type Plugin interface {
	Init(configPath string, hcc HCContext) error
	Close(ctx context.Context) error
}

type HCContext interface {
	SetXTractFile(f XtractFileFunc)

	RegisterOnStartScanFile(f OnStartScanFile)
	RegisterOnFileScanned(f OnFileScanned)
	RegisterOnReport(f OnReport)

	RegisterGenerateReport(f GenerateReport)
	GenerateReport(reportContext report.ScanContext, reports []report.Report) (io.Reader, error)

	GetLogger() *slog.Logger
}

// ErrUnhandledMethod is return when a plugin does not handle the request method
var ErrUnhandledMethod = errors.New("unhandled method")

var PluginExportedName = "HCPlugin"
