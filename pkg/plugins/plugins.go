package plugins

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

type (
	ExtractFile     = func(archiveLocation, outputDir string) (size int64, files []string, volumes []string, err error)
	OnStartScanFile = func(file string, sha256 string)
	OnScanFile      = func(filename string, location string, sha256 string, isArchive bool) (result *datamodel.Result)
	OnFileScanned   = func(file string, sha256 string, result datamodel.Result) (newResult *datamodel.Result)
	OnReport        = func(report *datamodel.Report)
)

type GenerateReport = func(reportConntext datamodel.ScanContext, reports []datamodel.Report) (io.Reader, error)

// Plugin interface must be implemented by host-connector plugins
type Plugin interface {
	// GetDefaultConfig MUST be used to get a default config, where we can unmarshall read yaml config, and pass it to Init
	GetDefaultConfig() (config any)
	Init(config any, hcc HCContext) error
	Close(ctx context.Context) error
}

type HCContext interface {
	SetExtractFile(f ExtractFile)

	RegisterOnStartScanFile(f OnStartScanFile)
	RegisterOnScanFile(f OnScanFile)
	RegisterOnFileScanned(f OnFileScanned)
	RegisterOnReport(f OnReport)

	RegisterGenerateReport(f GenerateReport)
	GenerateReport(reportContext datamodel.ScanContext, reports []datamodel.Report) (io.Reader, error)

	GetLogger() *slog.Logger
	GetConsoleLogger() *slog.Logger
}

// ErrUnhandledMethod is return when a plugin does not handle the request method
var ErrUnhandledMethod = errors.New("unhandled method")

var PluginExportedName = "HCPlugin"
