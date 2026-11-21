package plugins

import (
	"context"
	"errors"
	"io"
	"iter"
	"log/slog"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/datamodel"
)

type (
	// ExtractFile extracts the archive into outputDir within limits. An error
	// wrapping ErrUnsupportedFormat means the file is not an archive and is
	// handled as a plain file; ErrEncrypted, ErrExtractorUnavailable and any other
	// error leave the archive unhandled.
	//
	// Each kind of failure has one channel:
	//   - damage of the archive is returned as an error wrapping ErrArchiveAnomaly,
	//     with ErrEncryptionPossible unless the extractor proved that the archive
	//     holds no encrypted content; an extract-error entry of Skipped may
	//     accompany it, for the report only;
	//   - a failure of the host (output folder unreadable, unmeasurable or not
	//     removable) is a plain error, never an anomaly nor an entry of Skipped:
	//     the archive is retried;
	//   - a breach of a limit of ExtractLimits leaves the members concerned in
	//     Skipped as extract-limit or too-big, without an error: the policy of the
	//     files too big decides.
	ExtractFile            = func(archiveLocation, outputDir string, limits ExtractLimits) (Extraction, error)
	OnStartScanFile        = func(file string, sha256 string)
	OnScanFile             = func(filename string, location string, sha256 string, isArchive bool) (result *datamodel.Result)
	OnFileScanned          = func(file string, sha256 string, result datamodel.Result) (newResult *datamodel.Result)
	OnReport               = func(report *datamodel.Report)
	WithWaitForOptionsFunc = func(opts *gdetect.WaitForOptions, location string)
)

// GeneratedReport is a rendered report. The caller must close Content.
type GeneratedReport struct {
	Content io.ReadCloser
	// Extension is the extension of the file the content belongs in, with its
	// leading dot: ".pdf", ".json".
	Extension string
}

// GenerateReport renders the reports of a scan. The reports are given as a
// sequence, read once: a generator never needs them all in memory. A sequence
// that fails ends the generation with that error, and nothing partial is given
// back.
type GenerateReport = func(ctx context.Context, reportContext datamodel.ScanContext, reports iter.Seq2[datamodel.Report, error]) (GeneratedReport, error)

// Extraction is the result of one ExtractFile call.
type Extraction struct {
	// Size is the total size in bytes of Files.
	Size uint64
	// Files are the extracted files, as absolute paths under the output directory.
	Files []string
	// Skipped lists what was not extracted, at most datamodel.MaxListedSubfiles
	// entries with names truncated to datamodel.MaxListedNameLen bytes.
	Skipped []datamodel.NotAnalyzedFile
	// SkippedCount is the exact total of skipped members.
	SkippedCount int
}

// ExtractLimits bounds one extraction; the values come from the global
// configuration. A zero or negative budget means: extract nothing.
type ExtractLimits struct {
	// MaxFileSize bounds one member.
	MaxFileSize int64
	// MaxFiles is the remaining budget of files.
	MaxFiles int
	// MaxTotalSize is the remaining budget of bytes.
	MaxTotalSize int64
}

var (
	// ErrEncrypted is returned, wrapped, when no known password opens the archive.
	ErrEncrypted = errors.New("archive is encrypted and no known password opens it")
	// ErrUnsupportedFormat is returned, wrapped, when the file is not an archive
	// the extractor knows: it is then handled as a plain file. It is the only
	// extraction failure that is.
	ErrUnsupportedFormat = errors.New("not an archive the extractor supports")
	// ErrExtractorUnavailable is returned, wrapped, when the extraction process
	// could not be started, whatever the cause.
	ErrExtractorUnavailable = errors.New("the extractor is unavailable")
	// ErrArchiveAnomaly is returned, wrapped, when the extractor recognized an
	// archive and found it damaged or inconsistent (data error, listing that does
	// not match what was extracted, data after the end, twin members). It is never
	// returned for a timeout, a killed extractor, a cancelled context, an I/O
	// error of the host or an unavailable extractor.
	ErrArchiveAnomaly = errors.New("the archive is damaged or inconsistent")
	// ErrEncryptionPossible is returned, always joined to ErrArchiveAnomaly, when
	// the extractor could not establish that the archive holds no encrypted
	// content: an encryption hint, a member whose Encrypted flag is not "-", a
	// technical listing that is incomplete or unreadable, a member that failed
	// its data check, a member that was not extracted, or an archive cut before
	// its encryption could be read.
	ErrEncryptionPossible = errors.New("the archive may hold encrypted content")
)

// CloseGrace is how long, in all, the connector still waits for the plugins
// closing once the deadline of the context of their Close is over. A plugin
// must end any work still running at that deadline, such as a fallback written
// at the last moment, within CloseGrace of it: after that the process ends and
// the result is lost. It stays under the grace of the process guard of the stop.
const CloseGrace = 900 * time.Millisecond

// Plugin interface must be implemented by host-connector plugins.
//
// Close has no effect when called a second time, or on a plugin whose Init was
// never called or failed. An Init that fails leaves nothing behind: no
// goroutine, file or process.
//
// Init may be called again after Close; it fails if work of the previous run is
// still going, rather than start a new run beside it.
//
// At stop the connector calls the Close of all its plugins concurrently, under
// one context whose deadline ends the closing time: a plugin must not rely on
// the order of the Close calls, nor on another plugin still being open. The
// work a Close still has at the deadline is bound by CloseGrace.
type Plugin interface {
	// GetDefaultConfig MUST be used to get a default config, where we can unmarshall read yaml config, and pass it to Init
	GetDefaultConfig() (config any)
	Init(config any, hcc HCContext) error
	Close(ctx context.Context) error
}

// Interrupter is implemented by plugins that run work the connector cannot
// cancel through a context. Interrupt makes the running calls return promptly
// with an error. It is called at most once per stop, before Close.
type Interrupter interface{ Interrupt() }

type HCContext interface {
	ValidationContext

	SetExtractFile(f ExtractFile)

	// SetTrackingOwners declares how files below root are grouped into owners
	// for the fair sharing of the monitoring table: one owner per directory at
	// the given depth below root. It must be called during Init. It fails if
	// root is not an absolute path, if depth < 1, or if root equals, contains
	// or is contained in an already declared root.
	SetTrackingOwners(root string, depth int) error

	// PendingFiles returns how many files the monitoring has detected under
	// the owner whose folder is dir and has not finished processing: waiting
	// for their stability delay, waiting for a worker, or being processed.
	// Files waiting for a retry are not counted. dir is the folder of an owner
	// as declared with SetTrackingOwners: root followed by depth directories.
	// It returns 0 when dir is not the folder of a known owner (a parent, a
	// sub-folder or a file of an owner is not) or when nothing is monitored. It
	// is safe for concurrent use and must not be called during Init.
	PendingFiles(dir string) int

	// NotifyReportWritten tells the connector manager that a session report
	// was written, so that operators can authenticate it by name and digest.
	NotifyReportWritten(ctx context.Context, sessionID, path, sha256 string)

	// The Register* methods are only valid during Init.
	RegisterOnStartScanFile(f OnStartScanFile)
	// RegisterOnScanFile callbacks run in plugin file order. filename is the
	// logical path of the file: its real path, or for a file extracted from an
	// archive the path of the top-level archive followed by the member's path,
	// joined by "/" (control characters become "_"); the form is ambiguous:
	// /in/a.zip/b.zip/x names a file of a folder b.zip as well as one of a nested
	// archive. location is the real path. The core sets Result.Filename back to
	// its own value after the callback. A result that is
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
	GenerateReport(ctx context.Context, reportContext datamodel.ScanContext, reports iter.Seq2[datamodel.Report, error]) (GeneratedReport, error)

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
