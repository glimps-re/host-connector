package plugins

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/datamodel"
)

type (
	ExtractFile            = func(archiveLocation, outputDir string) (size int64, files []string, volumes []string, err error)
	OnStartScanFile        = func(file string, sha256 string)
	OnScanFile             = func(filename string, location string, sha256 string, isArchive bool) (result *datamodel.Result)
	OnFileScanned          = func(file string, sha256 string, result datamodel.Result) (newResult *datamodel.Result)
	OnReport               = func(report *datamodel.Report)
	WithWaitForOptionsFunc = func(opts *gdetect.WaitForOptions, location string)
)

type GenerateReport = func(ctx context.Context, reportContext datamodel.ScanContext, reports []datamodel.Report) (io.Reader, error)

// Plugin interface must be implemented by host-connector plugins
type Plugin interface {
	// GetDefaultConfig MUST be used to get a default config, where we can unmarshall read yaml config, and pass it to Init
	GetDefaultConfig() (config any)
	Init(config any, hcc HCContext) error
	Close(ctx context.Context) error
}

// ExtractConfig holds extraction limits provided by the host connector.
type ExtractConfig struct {
	MaxFileSize           int64 // Max size per extracted file in bytes
	MaxExtractedFiles     int   // Max number of files to extract
	MaxTotalExtractedSize int64 // Max total size to extract from one archive in bytes
}

type HCContext interface {
	SetExtractFile(f ExtractFile)

	RegisterOnStartScanFile(f OnStartScanFile)
	RegisterOnScanFile(f OnScanFile)
	RegisterWithWaitForOptions(f WithWaitForOptionsFunc)
	RegisterOnFileScanned(f OnFileScanned)
	RegisterOnReport(f OnReport)

	RegisterGenerateReport(f GenerateReport)
	GenerateReport(ctx context.Context, reportContext datamodel.ScanContext, reports []datamodel.Report) (io.Reader, error)

	GetLogger() *slog.Logger
	GetConsoleLogger() *slog.Logger
	GetExtractConfig() ExtractConfig
}

// ErrUnhandledMethod is return when a plugin does not handle the request method
var ErrUnhandledMethod = errors.New("unhandled method")

var PluginExportedName = "HCPlugin"
