package plugins

import (
	"context"
	"io"
	"log/slog"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/datamodel"
)

type (
	ExtractFile            = func(archiveLocation, outputDir string) (size uint64, files []string, volumes []string, err error)
	OnStartScanFile        = func(file string, sha256 string)
	OnScanFile             = func(filename string, location string, sha256 string, isArchive bool) (result *datamodel.Result)
	OnFileScanned          = func(file string, sha256 string, result datamodel.Result) (newResult *datamodel.Result)
	OnReport               = func(report *datamodel.Report)
	WithWaitForOptionsFunc = func(opts *gdetect.WaitForOptions, location string)
)

type GenerateReport = func(ctx context.Context, reportContext datamodel.ScanContext, reports []datamodel.Report) (io.Reader, error)

// Plugin interface must be implemented by host-connector plugins.
//
// Close has no effect when called a second time, or on a plugin whose Init was
// never called or failed. An Init that fails leaves nothing behind: no
// goroutine, file or process.
type Plugin interface {
	// GetDefaultConfig MUST be used to get a default config, where we can unmarshall read yaml config, and pass it to Init
	GetDefaultConfig() (config any)
	Init(config any, hcc HCContext) error
	Close(ctx context.Context) error
}

type HCContext interface {
	ValidationContext

	SetExtractFile(f ExtractFile)

	// The Register* methods are only valid during Init.
	RegisterOnStartScanFile(f OnStartScanFile)
	// RegisterOnScanFile callbacks run in plugin file order. A result that is
	// not malware, has no Error, no AnalysisError and no detection trace
	// (MalwareReason, Malwares, MaliciousSubfiles, ErrorSubfiles) is a waiver
	// (the file is not analyzed); any other non-nil result is a refusal. A
	// refusal that sets none of Malware, Error and AnalysisError gets an
	// "inconsistent plugin result" Error from the core. The first refusal wins
	// and stops the chain; a waiver is kept while later callbacks still run, and
	// the first waiver applies when there is no refusal. A waived archive waives
	// its whole content.
	RegisterOnScanFile(f OnScanFile)
	RegisterWithWaitForOptions(f WithWaitForOptionsFunc)
	// RegisterOnFileScanned callbacks all run, in plugin file order, each one
	// receiving the current result; a non-nil return replaces it. A callback can
	// harden a result but not soften it: a non-nil Error, Malware=true and a
	// non-empty AnalysisError, MalwareReason, Malwares, MaliciousSubfiles and
	// ErrorSubfiles are restored by the core. The result is a deep copy.
	RegisterOnFileScanned(f OnFileScanned)
	RegisterOnReport(f OnReport)

	RegisterGenerateReport(f GenerateReport)
	GenerateReport(ctx context.Context, reportContext datamodel.ScanContext, reports []datamodel.Report) (io.Reader, error)

	// NotifyError raises an error event on the connector manager under key;
	// NotifyResolution clears it. Both are no-ops without a connector manager.
	NotifyError(ctx context.Context, key string, err error)
	NotifyResolution(ctx context.Context, key string, message string)
}

// ValidationContext is what a plugin may use while validating a configuration.
// It gives no way to register a hook or change the running connector.
type ValidationContext interface {
	GetLogger() *slog.Logger
	GetConsoleLogger() *slog.Logger
	// GetWorkDir returns a private directory. During Validate it is a scratch
	// directory removed when Validate returns; once the plugin is running it is
	// the connector private working directory, which never holds user deposits
	// (plugins must ignore paths under it).
	GetWorkDir() string
	// DeclareExecutable checks that path is safe to execute (absolute, resolved,
	// a regular executable file, owned by root or the connector account, not
	// writable by others) and records it. It must be called before running the
	// binary, in Validate as in Init.
	DeclareExecutable(path string) error
	// DeclareOutputDir records a directory the plugin writes results to. The
	// core refuses one that is, or is under, a monitored path.
	DeclareOutputDir(path string) error
}

// Validator is optional. Validate checks config and everything Init needs
// (binaries, paths) without changing the state of the plugin in service: write
// it as a function of the package that receives the configuration, not as a
// method that writes into the receiver. Everything it creates goes under
// vc.GetWorkDir(), removed when it returns.
type Validator interface {
	Validate(config any, vc ValidationContext) error
}

var PluginExportedName = "HCPlugin"
