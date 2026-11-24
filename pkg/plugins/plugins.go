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
//
// After Content.Close returns, the generator no longer reads reports: Close may
// wait for the generator to end its current step, so the sequence must return
// promptly and the generator must honour ctx. The generator stops when ctx ends,
// even if nobody reads Content, and the end of ctx reaches the reader as the
// error of Content.Read. The caller always closes Content. A connector that
// enforces this ends the sequence for a generator that goes on reading after
// Close (at most one report already in flight may still be delivered): it sees a
// normal end of sequence, not an error, which is harmless because its content is
// closed and its output discarded.
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
	// Names are the paths of the files of the archive as it lists them, filled in
	// NamesOnly mode only: nil says that the names are not known (a listing that is
	// not whole, over MaxFiles, with anything the extractor finds wrong in the
	// archive), an empty non-nil slice that the archive holds no file.
	Names []string
}

// ExtractLimits bounds one extraction; the values come from the global
// configuration. A zero or negative budget means: extract nothing.
type ExtractLimits struct {
	// MaxFileSize bounds one member. The core sets it to MaxTotalSize: a member is
	// bounded only by what is left of the budget (max_file_size bounds only what is
	// submitted for analysis, not what is extracted).
	MaxFileSize int64
	// MaxFiles is the remaining budget of files.
	MaxFiles int
	// MaxTotalSize is the remaining budget of bytes.
	MaxTotalSize int64

	// CheckOnly asks the extractor to check the archive without writing anything:
	// its technical listing, held to MaxFiles, MaxTotalSize and a ratio that is not a
	// bomb (MaxFileSize does not apply), and an integrity test of every member with a
	// password that nobody knows. A member that needs one, a password the extractor
	// knows included, makes the archive encrypted, since nothing is extracted and
	// nothing would be analyzed. The Extraction is empty unless the listing is over
	// the budget (see below); the error says what was
	// found, with the same sentinels as an extraction (nil: readable and not
	// encrypted); ErrUnsupportedFormat means the file is damaged. A listing over
	// MaxFiles or MaxTotalSize, with nothing else wrong, is not tested: every
	// member listed, within the budget or not, is given back as skipped
	// (Extraction.Skipped, at most datamodel.MaxListedSubfiles entries, and
	// SkippedCount, the exact total), with no error, and the caller decides what
	// the file becomes. A MaxFiles or MaxTotalSize of 0 means that none is left:
	// every member is over the budget, it is not unlimited. The technical listing of such a file is still read, with no
	// decompression: a member it marks encrypted makes the file encrypted
	// (ErrEncrypted), and a listing that does not mark every member as plain is
	// damage with an encryption possible (ErrArchiveAnomaly joined to
	// ErrEncryptionPossible). An extractor must honour the
	// field: one that ignores it extracts into outputDir, which the caller removes,
	// and a document would then be extracted, not only checked.
	CheckOnly bool

	// NamesOnly asks for the names of the members (Extraction.Names) and nothing
	// else: the technical listing, and for a zip the walk of its headers; no
	// integrity test, no decompression, no budget of sizes (nothing is written or
	// decompressed). MaxFiles still bounds the names; MaxFileSize and MaxTotalSize
	// are only safety caps, no size of the archive is held to them. An extractor
	// that cannot list without extracting returns ErrListingUnsupported; one that
	// does not know the field extracts, which the caller notices (Files are set) and
	// discards.
	NamesOnly bool
}

// ErrListingUnsupported is returned, wrapped, by an extractor that cannot list the
// names of the members of an archive without extracting it (the default extractor).
var ErrListingUnsupported = errors.New("the extractor cannot list member names")

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
	// its whole content. On Linux a location of the form /proc/self/fd/<N> (or
	// /proc/<pid>/fd/<N>) is the connector's own open descriptor of the file: it is
	// valid for the duration of the call, may be read or typed through that name,
	// and must be neither closed nor used after the callback returns. Opening that
	// name again checks the permissions again: a file made unreadable after the
	// connector opened it cannot be reopened.
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
