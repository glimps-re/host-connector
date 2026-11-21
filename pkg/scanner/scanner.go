package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alecthomas/units"
	"github.com/gabriel-vasile/mimetype"
	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/connector-integration/sdk/metrics"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/internal/pathutil"
	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/quarantine"
	"golift.io/xtractr"
)

const (
	logReasonKey = "reason"
	logErrorKey  = "error"

	// actionTimeoutPerGB is the time budget per GB for the action chain (~100MB/s throughput).
	actionTimeoutPerGB = 30 * time.Second

	defaultExtractMinThreshold int64 = 8 * 1000 // minimum size to try extraction, in bytes (8KB)

	errSubmitPrefix = "error submitting file to detect"
)

// actionTimeoutForSize computes a timeout proportional to file size,
// accounting for I/O-heavy actions like quarantine (read + encrypt + write).
func actionTimeoutForSize(fileSize int64) time.Duration {
	return time.Duration(fileSize/(1024*1024*1024)+1) * actionTimeoutPerGB
}

// actionTimeout is the time the action chain is given for a file of size
// bytes: the move of a copy is given the time its own throughput floor allows.
func (c *Connector) actionTimeout(size int64) time.Duration {
	d := actionTimeoutForSize(size)
	if c.config.Actions.Move && c.config.MoveMode.copies() {
		d = satAdd(d, moveTimeout(size, c.config.MoveMinThroughput))
	}
	return d
}

var (
	LogLevel                                = &slog.LevelVar{}
	logger                                  = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: LogLevel}))
	EventHandler    events.EventHandler     = events.NoopEventHandler{}
	ConsoleLogger                           = slog.New(slog.DiscardHandler)
	MetricCollecter metrics.MetricCollecter = metrics.NoopMetricCollecter{}

	errFileTooBig = errors.New("file is too big to be analyzed")
	errEmptyFile  = errors.New("file is empty")
	errEncrypted  = errors.New("file is encrypted and cannot be analyzed")
	// errEncryptedOrDamaged is errEncrypted for an archive that is damaged and
	// may be encrypted: the report says that it cannot be told which.
	errEncryptedOrDamaged error = undeterminedEncryption{}
	errScannerClosed            = errors.New("scanner instance is closing and is no longer accepting new files")

	// An archive with a failed extracted file is never moved. These sentinels
	// only tell whether retrying can change the outcome: permanent wins when
	// both apply.
	errInnerTransient = errors.New(datamodel.ExtractedErrorsTransient)
	errInnerPermanent = errors.New(datamodel.ExtractedErrorsPermanent)
)

// accepted MIME types for extraction.
// (func to have a const map)
func extractableTypes() map[string]struct{} {
	return map[string]struct{}{
		"application/x-archive":                 {}, // .ar
		"application/x-arj":                     {}, // .arj
		"application/vnd.ms-cab-compressed":     {}, // .cab
		"application/x-cpio":                    {}, // .cpio
		"application/x-iso9660-image":           {}, // .iso
		"application/x-qemu-disk":               {}, // .qcow, .qcow2
		"application/x-lha":                     {}, // .lha
		"application/x-lzh-compressed":          {}, // .lzh
		"application/vnd.rar":                   {}, // .rar
		"application/x-virtualbox-vhd":          {}, // .vhd, .vhdx
		"application/x-7z-compressed":           {}, // .7z
		"application/x-xz":                      {}, // .xz, .tar.xz
		"application/x-bzip2":                   {}, // .bz2, .tar.bz2
		"application/gzip":                      {}, // .gz, .tar.gz, .tgz
		"application/x-tar":                     {}, // .tar
		"application/x-lzma":                    {}, // .lzma, .tar.lzma
		"application/vnd.ms-htmlhelp":           {}, // .chm
		"application/x-ms-wim":                  {}, // .wim
		"application/x-compress":                {}, // .Z
		"application/zip":                       {}, // .zip
		"application/x-rpm":                     {}, // .rpm
		"application/x-apple-diskimage":         {}, // .dmg
		"application/vnd.debian.binary-package": {}, // .deb
		"application/zstd":                      {}, // .zst, .tar.zst
		"application/x-xar":                     {}, // .xar, .pkg
		"application/x-lz4":                     {}, // .lz4, .tar.lz4

		// mimetype fallback, kept to still try extraction (in case identification failed, or for specific raw file formats like flat VMDK)
		"application/octet-stream": {},

		// MIME types absent from default libmagic database
		"application/x-vmdk":           {}, // .vmdk
		"application/x-lzh":            {}, // .lzh
		"application/x-lzh-archive":    {}, // .lzh
		"application/x-rar-compressed": {}, // .rar
		"application/x-vhd":            {}, // .vhd, .vhdx
		"application/x-virtualbox-vdi": {}, // .vdi
		"application/vnd.squashfs":     {}, // .squashfs, .snap, .appimage
		"application/x-squashfs":       {}, // .squashfs
	}
}

type Config struct {
	QuarantineFolder         string
	Workers                  int
	ExtractWorkers           int
	Password                 string
	Timeout                  sdk.Duration
	WaitOpts                 gdetect.WaitForOptions
	Actions                  Actions
	CustomActions            []Action
	Extract                  bool
	MaxFileSize              int64
	ExtractMinThreshold      int64 // minimum file size to attempt extraction; falls back to default when <= 0
	RecursiveExtractMaxDepth int
	RecursiveExtractMaxSize  int64
	RecursiveExtractMaxFiles int
	MoveTo                   string
	MoveFrom                 string
	// MoveMode is how the move action puts files in MoveTo: copy (default when
	// empty) or rename.
	MoveMode MoveMode
	// MoveMinThroughput is the throughput, in bytes per second, below which a
	// copy is given up; DefaultMoveMinThroughput when not positive.
	MoveMinThroughput int64
	FollowSymlinks    bool
	// Roots are the monitored paths: a path is checked for symbolic links from
	// the root that contains it. Without a root, the scan argument is the root.
	Roots []string
	// WorkDir is the base under which the connector creates its private
	// working directory; empty means os.TempDir().
	WorkDir string
	// OnFileDone is called exactly once per file accepted by SubmitFile or
	// ScanFile, from a pipeline goroutine, when its processing ends. It must
	// not block (it is called while the pipeline holds nothing, but a slow stat
	// on a network file system would hold a worker). May be nil.
	OnFileDone func(FileOutcome)
	// PendingFiles tells how many files detected under the owner whose folder is
	// dir have not finished processing; plugins read it through
	// HCContext.PendingFiles. May be nil (the scan command): it is then 0.
	PendingFiles func(dir string) int
	// Unanalyzable is the policy for the files that cannot be analyzed.
	Unanalyzable Unanalyzable
}

type fileToAnalyze struct {
	sha256             string
	location           string
	filename           string
	logicalPath        string
	identity           FileIdentity // observed by the monitor, checked before every action
	input              *inputFD     // descriptor of the deposited file, nil for an extracted one
	run                *ongoing     // the run of the top-level file this belongs to
	size               int64
	archiveTopLocation string
	archiveID          string
	archiveLocation    string
	archiveLogicalPath string // logical path of archiveLocation, what plugins are told
	archiveSHA256      string
	archiveSize        int64
	// encrypted is set by the extraction for a member whose password is unknown.
	encrypted bool
	// limitSkipped is set for an archive the limits of the extraction did not let
	// open: the policy of the files too big decides, as for the members left out.
	limitSkipped bool
	// extractError is set for an archive the extractor found damaged or
	// inconsistent, under the policy PolicyAsFile: it is analyzed as a plain file.
	extractError bool
	// undetermined is set with encrypted for an archive that is damaged, when
	// nothing proves that it holds no encrypted content: it is not told from an
	// encrypted one.
	undetermined bool
}

// named is the file with a name: the location of a deposited one.
func (f fileToAnalyze) named() fileToAnalyze {
	if f.filename == "" {
		f.filename = f.location
	}
	return f
}

// encryptedFailure is the failure of the file under the policy that fails the
// encrypted files.
func (f fileToAnalyze) encryptedFailure() error {
	if f.undetermined {
		return errEncryptedOrDamaged
	}
	return errEncrypted
}

// logical is the path plugins see for the file: its real path for a top-level
// file, else the path of its top-level archive followed by the relative paths
// of the successive extractions, joined by "/".
func (f fileToAnalyze) logical() string {
	if f.logicalPath != "" {
		return f.logicalPath
	}
	return sanitizeControl(f.location)
}

// archiveLogical is the logical path of the archive the file comes from.
func (f fileToAnalyze) archiveLogical() string {
	if f.archiveLogicalPath != "" {
		return f.archiveLogicalPath
	}
	return sanitizeControl(f.archiveLocation)
}

// sanitizeControl replaces the control characters of a path by "_": a newline
// in a name would otherwise let it slip past a rule such as
// `^/in/alice/.*\.exe$`, where "." does not match it.
func sanitizeControl(p string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, p)
}

// memberLogicalPath builds the logical path of an extracted file from rel, the
// path it was really extracted to relative to the extraction folder, never from
// the name the archive declares. A member that resolved outside that folder
// (inside is false) keeps only its base name. Control characters become "_"
// (see sanitizeControl). The result is ambiguous
// by nature: "/in/a.zip/b.zip/x" names a file of a folder b.zip as well as one
// of a nested archive b.zip.
func memberLogicalPath(parent, rel string, inside bool, location string) string {
	if !inside {
		rel = filepath.Base(location)
	}
	return path.Join(filepath.ToSlash(parent), sanitizeControl(filepath.ToSlash(rel)))
}

type archiveToAnalyze struct {
	sha256   string
	location string
	identity FileIdentity
	input    *inputFD
	run      *ongoing
	size     int64
}

// submission is one file queued by SubmitFile.
type submission struct {
	location string
	want     FileIdentity
	run      *ongoing
}

type Connector struct {
	submitter   gdetect.ControllerExtendedGDetectSubmitter
	quarantiner quarantine.Quarantiner

	closeOnce sync.Once
	// extractorDown is set while the console error of an unavailable extractor is raised.
	extractorDown atomic.Bool

	// workCtx is the parent of the contexts of analyses, actions and checks of
	// the files being processed: Shutdown cancels it when the drain ends. The
	// contexts of console events stay independent of it.
	workCtx    context.Context
	cancelWork context.CancelFunc

	stopIncoming chan struct{} // closed first in Close() to reject new inputChan sends
	stopWorker   chan struct{}
	stopOnce     sync.Once

	config Config
	work   *workDir

	// scanRoots holds the roots named by the operator for command line scans
	// only: a monitoring connector never adds to it.
	scanRoots sync.Map
	rootsOnce sync.Once
	absRoots  []string // Config.Roots made absolute, computed once
	owners    []OwnerRule

	dispatchWg sync.WaitGroup
	extractWg  sync.WaitGroup
	analysisWg sync.WaitGroup

	dispatchChan chan submission
	extractChan  chan archiveToAnalyze
	analysisChan chan fileToAnalyze

	action                 Action
	archiveStatus          *archiveStatusHandler
	loadedPlugins          []plugins.Plugin
	onStartScanFileCbs     []plugins.OnStartScanFile
	onScanFileCbs          []plugins.OnScanFile
	withWaitForOptionsFunc []plugins.WithWaitForOptionsFunc
	onFileScannedCbs       []namedFileScanned
	loadingPlugin          string
	declared               declarations
	pluginsMu              sync.Mutex
	pluginsSealed          bool
	onReportCbs            []plugins.OnReport
	generateReport         plugins.GenerateReport
	ongoingAnalysis        sync.Map
	fdLinks                bool           // plugins and the extractor read through /proc/<pid>/fd (set at Start)
	scansWg                sync.WaitGroup // tracks files from ScanFile entry to ongoingAnalysis removal
	typesToExtract         map[string]struct{}
}

const restoredCheckTimeout = 10 * time.Second

func NewConnector(cfg Config, quarantiner quarantine.Quarantiner, submitter gdetect.ControllerExtendedGDetectSubmitter) (*Connector, error) {
	if cfg.Workers < 1 {
		cfg.Workers = config.DefaultWorkers
	}

	if cfg.ExtractWorkers < 1 {
		cfg.ExtractWorkers = config.DefaultExtractWorkers
	}

	if cfg.MaxFileSize <= 0 {
		maxFileSize, err := units.ParseStrictBytes(config.DefaultMaxFileSize)
		if err != nil {
			return nil, fmt.Errorf("could not parse DefaultMaxFileSize %q: %w", config.DefaultMaxFileSize, err)
		}
		cfg.MaxFileSize = maxFileSize
	}

	if cfg.RecursiveExtractMaxDepth < 1 {
		cfg.RecursiveExtractMaxDepth = config.DefaultRecursiveExtractMaxDepth
		logger.Debug("using default value for recursive_extract_max_depth", slog.Int("value", config.DefaultRecursiveExtractMaxDepth))
	}

	if cfg.RecursiveExtractMaxSize <= 0 {
		recursiveExtractMaxSize, err := units.ParseStrictBytes(config.DefaultRecursiveExtractMaxSize)
		if err != nil {
			return nil, fmt.Errorf("could not parse DefaultRecursiveExtractMaxSize %q: %w", config.DefaultRecursiveExtractMaxSize, err)
		}
		cfg.RecursiveExtractMaxSize = recursiveExtractMaxSize
		logger.Debug("using default value for recursive_extract_max_size", slog.Int64("value", cfg.RecursiveExtractMaxSize))
	}

	if cfg.RecursiveExtractMaxFiles < 1 {
		cfg.RecursiveExtractMaxFiles = config.DefaultRecursiveExtractMaxFiles
		logger.Debug("using default value for recursive_extract_max_files", slog.Int("value", config.DefaultRecursiveExtractMaxFiles))
	}

	if cfg.ExtractMinThreshold <= 0 {
		cfg.ExtractMinThreshold = defaultExtractMinThreshold
	}

	resolved, fallback, err := cfg.Unanalyzable.resolve(EffectiveMoveMode(cfg.Actions.Move, cfg.MoveMode))
	if err != nil {
		return nil, err
	}
	cfg.Unanalyzable = resolved
	if fallback {
		const msg = "unanalyzable_policy.empty is not set and move.mode is rename: empty files are skipped (set move.mode to copy to deliver them as new empty files)"
		logger.Warn(msg)
		ConsoleLogger.Warn(msg)
	}

	action, err := newAction(cfg, quarantiner)
	if err != nil {
		return nil, err
	}
	work, err := newWorkDir(cfg.WorkDir)
	if err != nil {
		return nil, err
	}

	workCtx, cancelWork := context.WithCancel(context.Background())
	return &Connector{
		workCtx:        workCtx,
		cancelWork:     cancelWork,
		work:           work,
		submitter:      submitter,
		quarantiner:    quarantiner,
		dispatchChan:   make(chan submission, cfg.Workers),
		extractChan:    make(chan archiveToAnalyze, cfg.ExtractWorkers),
		analysisChan:   make(chan fileToAnalyze, cfg.Workers),
		config:         cfg,
		archiveStatus:  newArchiveStatusHandler(),
		action:         action,
		generateReport: defaultGenerateReport,
		stopIncoming:   make(chan struct{}),
		stopWorker:     make(chan struct{}),
		typesToExtract: extractableTypes(),
	}, nil
}

func newAction(cfg Config, quarantiner quarantine.Quarantiner) (*MultiAction, error) {
	action := NewMultiAction(&ReportAction{})
	if cfg.Actions.Log {
		action.Actions = append(action.Actions, &LogAction{logger: logger})
	}
	if cfg.Actions.Quarantine {
		action.Actions = append(action.Actions, NewQuarantineAction(quarantiner))
	}
	if cfg.Actions.Deleted {
		action.Actions = append(action.Actions, &RemoveFileAction{})
	}
	if cfg.Actions.Move {
		move, err := NewMoveActionWithMode(cfg.MoveTo, cfg.MoveFrom, cfg.MoveMode, cfg.MoveMinThroughput)
		if err != nil {
			return nil, fmt.Errorf("move action: %w", err)
		}
		action.Actions = append(action.Actions, move)
	}
	if cfg.Actions.Inform {
		action.Actions = append(action.Actions, &PrintAction{Verbose: cfg.Actions.Verbose, Out: cfg.Actions.InformDest})
	}
	action.Actions = append(action.Actions, cfg.CustomActions...)
	return action, nil
}

func (c *Connector) Start() (err error) {
	if err = c.checkDescriptorLinks(); err != nil {
		return err
	}
	for range c.config.Workers {
		c.dispatchWg.Go(func() { c.dispatchWorker() })
		c.analysisWg.Go(func() { c.analysisWorker() })
	}
	for range c.config.ExtractWorkers {
		c.extractWg.Go(func() { c.extractWorker() })
	}
	return
}

// ExtractFile can be used to override xtract.ExtractFile method
//
// The default extractor applies no limit of its own. Only a file whose type it
// does not know is reported as plugins.ErrUnsupportedFormat (and handled as a plain
// file); any other failure is an extraction error.
var ExtractFile plugins.ExtractFile = func(archiveLocation, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
	xFile := &xtractr.XFile{
		FilePath:  archiveLocation,
		OutputDir: outputDir,
		FileMode:  0o600,
		DirMode:   0o700,
	}
	size, files, _, err := xtractr.ExtractFile(xFile)
	switch {
	case errors.Is(err, xtractr.ErrUnknownArchiveType):
		return plugins.Extraction{}, fmt.Errorf("%w: %w", plugins.ErrUnsupportedFormat, err)
	case err != nil:
		return plugins.Extraction{}, err
	}
	return plugins.Extraction{Size: size, Files: files}, nil
}

func (c *Connector) ScanFile(ctx context.Context, input string) (err error) {
	input, info, err := c.examineInput(input)
	if err != nil {
		if errors.Is(err, ErrRefused) {
			return nil
		}
		return err
	}
	if info.IsDir() {
		return c.scanDir(ctx, input)
	}
	if _, err = c.submit(ctx, input, IdentityOf(info), info); errors.Is(err, ErrRefused) {
		return nil
	}
	return err
}

// ErrRefused is returned, wrapped, by SubmitFile for a file that is refused
// without failure: a symbolic link not followed, a temporary file, a file of
// the work directory, an empty file or a folder. Its outcome is final until the
// file changes: asking again would only be refused again.
var ErrRefused = errors.New("file refused")

// examineInput cleans input and describes what the connector will read. It
// fails with ErrRefused for a temporary file, a file of the connector work
// directory or a link not to be followed, and with errScannerClosed when the
// connector is closing. It remembers the root of a scan.
func (c *Connector) examineInput(input string) (clean string, info fs.FileInfo, err error) {
	select {
	case <-c.stopIncoming:
		return input, nil, errScannerClosed
	default:
	}
	clean = filepath.Clean(input)
	inputLogger := logger.With(slog.String("input file", clean))
	if quarantine.IsTempFile(clean) {
		inputLogger.Debug("skip file", slog.String(logReasonKey, "temporary file"))
		return clean, nil, fmt.Errorf("%w: temporary file", ErrRefused)
	}
	if c.IsInternalPath(clean) {
		inputLogger.Debug("skip file", slog.String(logReasonKey, "connector work directory"))
		return clean, nil, fmt.Errorf("%w: connector work directory", ErrRefused)
	}
	info, err = c.statInput(clean)
	if err != nil {
		if errors.Is(err, errSkippedLink) {
			return clean, nil, fmt.Errorf("%w: symbolic link", ErrRefused)
		}
		return clean, nil, err
	}
	c.noteScanRoot(clean)
	return clean, info, nil
}

// errFileReplaced is returned when a file no longer has the identity it was
// submitted with: it is not acted upon.
var errFileReplaced = errors.New("file changed during analysis")

// checkIdentity returns errFileReplaced unless location still has the
// identity want.
func (c *Connector) checkIdentity(location string, want FileIdentity) error {
	info, err := c.statInput(location)
	if err != nil {
		return fmt.Errorf("%w: %w", errFileReplaced, err)
	}
	if !IdentityOf(info).Equal(want) {
		ConsoleLogger.Error(fmt.Sprintf("file %s changed during analysis, it is left untouched", location))
		return errFileReplaced
	}
	return nil
}

// errSkippedLink marks a symbolic link that must not be followed.
var errSkippedLink = errors.New("symbolic link not followed")

// statInput describes input as the connector will read it: the link itself
// unless links are followed. A link that must not be followed, or that leads
// into the connector work directory, is reported as errSkippedLink.
func (c *Connector) statInput(input string) (fs.FileInfo, error) {
	linfo, err := os.Lstat(input)
	if err != nil {
		return nil, err
	}
	if linfo.Mode()&os.ModeSymlink == 0 {
		return linfo, nil
	}
	inputLogger := logger.With(slog.String("input file", input))
	if !c.config.FollowSymlinks {
		inputLogger.Debug("skip file", slog.String(logReasonKey, "symbolic link"))
		return nil, errSkippedLink
	}
	if c.work != nil && c.work.containsResolved(input) {
		inputLogger.Debug("skip file", slog.String(logReasonKey, "link to the connector work directory"))
		return nil, errSkippedLink
	}
	return os.Stat(input)
}

// SubmitFile queues one regular file whose stability was observed as want.
// accepted is false with an error wrapping ErrRefused when the file is refused
// without failure (symbolic link, internal path, temporary file, empty file),
// and with a nil error when it is already in progress. The file is analyzed only if it still has the identity want when
// the pipeline reads it, and acted upon only if it still has it afterwards.
func (c *Connector) SubmitFile(ctx context.Context, input string, want FileIdentity) (accepted bool, err error) {
	input, info, err := c.examineInput(input)
	if err != nil {
		return false, err
	}
	if info.IsDir() {
		return false, fmt.Errorf("%w: folder", ErrRefused)
	}
	return c.submit(ctx, input, want, info)
}

// submit queues the regular file input, described by info, unless it is empty
// or already being processed.
func (c *Connector) submit(ctx context.Context, input string, want FileIdentity, info fs.FileInfo) (accepted bool, err error) {
	inputLogger := logger.With(slog.String("input file", input))
	if !info.Mode().IsRegular() {
		inputLogger.Warn("skip file", slog.String(logReasonKey, "not a regular file"), slog.String("mode", info.Mode().String()))
		// What is not a regular file (a FIFO swapped in, a device) is never read:
		// its size says nothing, and an empty policy that delivers must not let it by.
		return false, fmt.Errorf("%w: not a regular file", ErrRefused)
	}
	if info.Size() == 0 && c.config.Unanalyzable.Empty == PolicySkip {
		inputLogger.Warn("skip file", slog.String(logReasonKey, "size 0"))
		return false, fmt.Errorf("%w: empty file", ErrRefused)
	}

	run := &ongoing{want: want}
	if _, loaded := c.ongoingAnalysis.LoadOrStore(input, run); loaded {
		inputLogger.Debug("skip file", slog.String(logReasonKey, "ongoing analysis"))
		return false, nil
	}
	c.scansWg.Add(1)

	defer func() {
		if !accepted {
			c.discardAnalysis(input, run)
		}
	}()

	select {
	case <-ctx.Done():
		return false, context.Canceled
	case <-c.stopIncoming:
		return false, errScannerClosed
	case c.dispatchChan <- submission{location: input, want: want, run: run}:
		return true, nil
	}
}

func (c *Connector) handleRestoredFile(location string, sha256 string, size int64, want FileIdentity, run *ongoing, in *inputFD) (err error) {
	res := datamodel.Result{
		Filename: filepath.Base(location),
		Location: location,
		SHA256:   sha256,
		FileSize: size,
		Restored: true,
	}
	if newres := c.fileScanned(location, run, sha256, res); newres != nil {
		res = *newres
	}
	// A plugin may return another result: the file was restored all the same.
	res.Restored = true
	if pathErr := c.checkPath(location); pathErr != nil {
		refusePath(location, pathErr)
		c.setFinal(location, run)
		return pathErr
	}
	if idErr := c.checkIdentity(location, want); idErr != nil {
		return idErr
	}
	report := &datamodel.Report{}
	actionCtx, cancel := context.WithTimeout(c.workContext(), c.actionTimeout(size))
	defer cancel()
	err = c.action.Handle(actionCtx, in.source(location, want, sha256), res, report)
	if err != nil {
		logger.Error("could not handle file action", slog.String("file", location), slog.String(logErrorKey, err.Error()))
	}
	// The report goes out whatever the actions did: a restored file whose move
	// failed is in error in its report, as any other file.
	c.addReport(report)
	return
}

func (c *Connector) checkExtractedFile(location string) (fileSHA256 string, fileSize int64, err error) {
	info, err := os.Stat(location)
	if err != nil {
		return
	}
	fileSize = info.Size()
	if info.Size() <= 0 {
		err = errEmptyFile
		return
	}
	fileSHA256, err = getFileSHA256(location)
	if err != nil {
		return
	}
	return
}

func (c *Connector) scanDir(ctx context.Context, input string) (err error) {
	// WalkDir seems to not handle correctly path without ending /
	input += string(filepath.Separator)

	err = filepath.WalkDir(input, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			logger.Error("could not access path during walk", slog.String("path", path), slog.String("err", walkErr.Error()))
			return nil
		}
		if c.IsInternalPath(path) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 && IsLinkToFolder(path) {
			logger.Warn("link to a folder ignored", slog.String("path", path), slog.String(datamodel.LogSourceKey, "scanDir"))
			return nil
		}

		err := c.ScanFile(ctx, path)
		if err != nil {
			logger.Error("could not scan file", slog.String("path", path), slog.String("err", err.Error()), slog.String(datamodel.LogSourceKey, "scanDir"))
			return nil // continue to next file
		}
		return nil
	})
	return
}

// dispatchWorker consumes from dispatchChan, and dispatches
// to either extractChan or analysisChan. This is the first stage of the pipeline.
func (c *Connector) dispatchWorker() {
	for {
		select {
		case <-c.stopWorker:
			// must call finishAnalysis for any item in channel before exiting, to ensure scansWg is properly decremented
			c.drainQueues()
			return
		case sub := <-c.dispatchChan:
			c.dispatchFile(sub)
		}
	}
}

// extractWorker consumes from extractChan and performs extraction.
// Extracted sub-files are sent to analysisChan via sendForAnalyze.
func (c *Connector) extractWorker() {
	for {
		select {
		case <-c.stopWorker:
			c.drainQueues()
			return
		case archive := <-c.extractChan:
			archiveLogger := logger.With(slog.String("file", archive.location))
			if err := c.tryExtract(archive); err != nil {
				archiveLogger.Error("could not extract file", slog.String(logErrorKey, err.Error()))
				ConsoleLogger.Error(fmt.Sprintf("could not handle file %s, error: %s", archive.location, err.Error()))
				c.concludeOutcome(archive.location, archive.run, resultView{err: err}, nil)
				c.reportExtractFailure(archive, err)
				c.finishRun(archive.location, archive.run)
			}
		}
	}
}

// reportExtractFailure gives a report with its error to an archive that failed for
// good (a permanent error): it stays in INPUT, and the failure is as visible as
// the one of a file analyzed in error. A transient failure is retried and says
// nothing yet; one that is a cut or an extractor down says nothing about the file.
func (c *Connector) reportExtractFailure(archive archiveToAnalyze, err error) {
	if !errors.Is(err, errInnerPermanent) && !errors.Is(err, errFileTooBig) && !errors.Is(err, errEncrypted) {
		return
	}
	result := datamodel.Result{Filename: archive.location, Location: archive.location, SHA256: archive.sha256, FileSize: archive.size, Error: err}
	report := &datamodel.Report{}
	if e := (&ReportAction{}).Handle(context.Background(), archive.input.source(archive.location, archive.identity, archive.sha256), result, report); e != nil {
		logger.Error("could not report the failure of an archive", slog.String("file", archive.location), slog.String(logErrorKey, e.Error()))
		return
	}
	c.addReport(report)
}

// analysisWorker consumes from analysisChan and performs malware analysis.
func (c *Connector) analysisWorker() {
	for {
		select {
		case <-c.stopWorker:
			c.drainQueues()
			return
		case input := <-c.analysisChan:
			c.processFile(input)
		}
	}
}

// prepareFile stats the file, computes its SHA256, and checks quarantine restored status.
// Returns the populated fileToAnalyze and whether the file should be skipped.
func (c *Connector) prepareFile(location string, want FileIdentity, run *ongoing) (file fileToAnalyze, skip bool) {
	inputLogger := logger.With(slog.String("file", location))

	if err := c.checkPath(location); err != nil {
		refusePath(location, err)
		c.setFinal(location, run)
		skip = true
		return
	}

	// One descriptor for the identity, the hash and everything read later:
	// what is read is what was observed, whatever happens to the name meanwhile.
	// It never blocks on a FIFO put there after the stability check.
	in, err := c.openInput(location)
	if err != nil {
		inputLogger.Error("could not open file, stop processing", slog.String("error", err.Error()))
		skip = true
		return
	}
	f := in.f
	defer func() {
		if skip {
			closeInput(in)
		}
	}()
	info, err := f.Stat()
	if err != nil {
		inputLogger.Error("could not stat file, stop processing", slog.String("error", err.Error()))
		skip = true
		return
	}
	identity := IdentityOf(info)
	if !identity.Equal(want) {
		inputLogger.Info("skip file", slog.String(logReasonKey, "changed since its stability was observed"), slog.String("differs", identity.Diff(want)))
		skip = true
		return
	}

	fileSHA256, err := hashSection(f, info.Size())
	if err != nil {
		inputLogger.Error("could not compute file SHA256, stop processing", slog.String("error", err.Error()))
		skip = true
		return
	}

	var restored bool
	if c.quarantiner != nil {
		ctx, cancel := context.WithTimeout(c.workContext(), restoredCheckTimeout)
		defer cancel()
		restored, err = c.quarantiner.IsRestored(ctx, location, fileSHA256)
		if err != nil {
			inputLogger.Error("could not check file restored status", slog.String(logErrorKey, err.Error()))
			skip = true
			return
		}
	}
	if restored {
		inputLogger.Debug("consider file as safe, skip it", slog.String(logReasonKey, "restored"))
		skip = true
		// The content was read for the last time: the descriptor is checked. It
		// stays open during the action where the actions use it; elsewhere it is
		// closed first (a file that is open cannot be moved or deleted).
		if err = c.verifyContent(location, in, info.Size(), fileSHA256, identity); err == nil {
			if !holdsHandle {
				closeInput(in)
			}
			err = c.handleRestoredFile(location, fileSHA256, info.Size(), identity, run, in)
			c.concludeOutcome(location, run, resultView{}, err)
		}
		if err != nil {
			inputLogger.Error("could not handle restored file", slog.String(logErrorKey, err.Error()))
		}
		return
	}

	file = fileToAnalyze{
		filename: location,
		location: location,
		sha256:   fileSHA256,
		identity: identity,
		input:    in,
		run:      run,
		size:     info.Size(),
	}
	return
}

// finishRun ends the processing of the run of the top-level file at location:
// it is removed from ongoingAnalysis, the plugins that were told it started are
// told it ended, and OnFileDone is called. It acts on that run only: the same
// path may have been submitted again meanwhile (the monitor retries a file
// after a backoff) and what is registered under it now is another run.
// Extracted sub-files have no run of their own: they are no-ops.
func (c *Connector) finishRun(location string, run *ongoing) {
	var e *ongoing
	if run != nil {
		if !c.ongoingAnalysis.CompareAndDelete(location, run) {
			return
		}
		e = run
	} else {
		v, loaded := c.ongoingAnalysis.LoadAndDelete(location)
		if !loaded {
			return
		}
		e, _ = v.(*ongoing)
	}
	if e != nil {
		e.closeInput()
		if sha, unpaired := e.unpaired(); unpaired {
			// The plugins were told this file started: they must be told it ended,
			// or a session would wait for it forever.
			c.onFileScanned(location, sha, datamodel.Result{Filename: location, Location: location, SHA256: sha, Error: errAbandoned})
		}
		if c.config.OnFileDone != nil {
			c.config.OnFileDone(e.outcome(location))
		}
	}
	c.scansWg.Done()
}

// discardAnalysis forgets a run that was not accepted: nobody is told.
func (c *Connector) discardAnalysis(location string, run *ongoing) {
	if c.ongoingAnalysis.CompareAndDelete(location, run) {
		run.closeInput()
		c.scansWg.Done()
	}
}

// closeInput releases a descriptor held on a deposited file.
func closeInput(in *inputFD) {
	if err := in.Close(); err != nil {
		logger.Warn("could not close file correctly", slog.String("error", err.Error()))
	}
}

// releaseInput closes the descriptor of the run of the top-level file at
// location: it must be done after the last read of its content and before any
// action (Windows refuses to move or delete a file that is open).
func (c *Connector) releaseInput(location string, run *ongoing) {
	if e := c.runOf(location, run); e != nil {
		e.closeInput()
	}
}

// finishReading ends the reading of the top-level file input: the content read
// last (the second hash) is the one that was analyzed, the descriptor still is
// the file that was identified, and so is the name; then the descriptor is
// closed. It returns an error when the file must not be acted upon. A file
// without descriptor (tests) is hashed by path.
func (c *Connector) finishReading(input fileToAnalyze) error {
	if !holdsHandle {
		defer c.releaseInput(input.location, input.run)
	}
	return c.verifyContent(input.location, input.input, input.size, input.sha256, input.identity)
}

// verifyContent checks, on the descriptor, the hash and the identity of a file
// that was analyzed, then the identity of the name.
func (c *Connector) verifyContent(location string, in *inputFD, size int64, wantSHA256 string, want FileIdentity) error {
	var actual string
	var err error
	if in != nil {
		actual, err = hashSection(in.f, size)
	} else {
		actual, err = getFileSHA256(location)
	}
	if err != nil {
		return fmt.Errorf("could not compute file SHA256: %w", err)
	}
	if actual != wantSHA256 {
		ConsoleLogger.Error(fmt.Sprintf("file %s SHA256 mismatch: current hash differs from analyzed version, stop processing", location))
		return errors.New("file SHA256 mismatch, file changed during analysis")
	}
	if in != nil {
		info, statErr := in.f.Stat()
		if statErr != nil {
			return fmt.Errorf("%w: %w", errFileReplaced, statErr)
		}
		if !IdentityOf(info).Equal(want) {
			ConsoleLogger.Error(fmt.Sprintf("file %s changed during analysis, it is left untouched", location))
			return errFileReplaced
		}
	}
	return c.checkIdentity(location, want)
}

// dispatchFile performs prepareFile (SHA256, size, restored check) and routes the
// file to either extractChan (for extraction) or analysisChan (for analysis).
func (c *Connector) dispatchFile(sub submission) {
	location := sub.location
	inputLogger := logger.With(slog.String("file", location))

	input, skip := c.prepareFile(location, sub.want, sub.run)
	if skip {
		c.finishRun(location, sub.run)
		return
	}
	if sub.run != nil {
		sub.run.setInput(input.input)
	}

	// Route to extraction if applicable
	if c.config.Extract && (input.size > c.config.ExtractMinThreshold || c.isSmallArchive(input)) {
		archive := archiveToAnalyze{location: location, sha256: input.sha256, identity: input.identity, input: input.input, run: input.run, size: input.size}
		select {
		case <-c.stopWorker:
			c.finishRun(location, sub.run)
		case c.extractChan <- archive:
			inputLogger.Debug("file sent to extract worker")
		}
		return
	}

	// Route to analysis
	select {
	case <-c.stopWorker:
		c.finishRun(location, sub.run)
	case c.analysisChan <- input:
		inputLogger.Debug("file sent to analysis worker")
	}
}

// processFile handles analysis for a file that has already been prepared.
func (c *Connector) processFile(input fileToAnalyze) {
	inputLogger := logger.With(slog.String("file", input.location))

	if input.archiveID != "" {
		inputLogger.Debug("file has archive_id, handling ...")
		if err := c.analyzeArchiveFile(input); err != nil {
			inputLogger.Error("could not handle file", slog.String("archive-id", input.archiveID), slog.String("archive location", input.archiveLocation), slog.String(logErrorKey, err.Error()))
		}
		return
	}

	inputLogger.Debug("applying onStartScanFile() from plugins")
	c.startScan(input.location, input.run, input.sha256)
	var tooBig bool
	result := c.analyze(input, &tooBig)
	if errors.Is(result.Error, errSubmitContentMismatch) || errors.Is(result.Error, errNoDescriptorPath) {
		// The service answered about another content: nothing is done to the file.
		inputLogger.Error("the analysis was about another content, stop processing", slog.String(logErrorKey, result.Error.Error()))
		c.abortAnalysis(input, result, result.Error)
		return
	}
	if err := c.finishReading(input); err != nil {
		inputLogger.Error("file changed during analysis, stop processing", slog.String(logErrorKey, err.Error()))
		c.abortAnalysis(input, result, err)
		return
	}

	if result.Error != nil {
		inputLogger.Error("could not analyze file", slog.Any(logErrorKey, result.Error.Error()))
		ConsoleLogger.Error(fmt.Sprintf("could not analyze file %s: %s", input.location, result.Error.Error()))
	}
	if newres := c.fileScanned(input.location, input.run, input.sha256, result); newres != nil {
		result = *newres
	}
	if pathErr := c.checkPath(input.location); pathErr != nil {
		refusePath(input.location, pathErr)
		c.setFinal(input.location, input.run)
		c.finishRun(input.location, input.run)
		return
	}
	report := &datamodel.Report{}
	actionCtx, actionCancel := context.WithTimeout(c.workContext(), c.actionTimeout(input.size))
	defer actionCancel()
	src := input.input.source(input.location, input.identity, input.sha256)
	src.TooBig = tooBig
	actionErr := c.action.Handle(actionCtx, src, result, report)
	if actionErr != nil {
		inputLogger.Error("could not handle file action", slog.String(logErrorKey, actionErr.Error()))
		ConsoleLogger.Error(fmt.Sprintf("could not handle file action for %s: %s", input.location, actionErr.Error()))
	} else {
		inputLogger.Debug("file handled successfully")
	}
	c.addReport(report)
	if actionErr != nil {
		c.noteOwnTrace(input.location, input.run, input.identity)
	}
	c.concludeOutcome(input.location, input.run, resultView{err: result.Error, analysisError: result.AnalysisError}, actionErr)
	c.finishRun(input.location, input.run)
}

// extractorEvent is the console event raised while the extractor cannot run.
const extractorEvent events.ErrorEventType = "host-extractor-unavailable"

// eventTimeout bounds a call to the connector manager made on the way of an
// extraction.
const eventTimeout = 10 * time.Second

// extractorUnavailable raises the console error (once until it is resolved).
// The flag is put back when the manager could not be told, so that the next
// failure tries again.
func (c *Connector) extractorUnavailable(cause error) {
	if !c.extractorDown.CompareAndSwap(false, true) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), eventTimeout)
	defer cancel()
	if e := EventHandler.NotifyError(ctx, extractorEvent, fmt.Errorf("archives cannot be extracted, the extractor is unavailable: %w", cause)); e != nil {
		c.extractorDown.Store(false)
		logger.Warn("could not push console error", slog.String("error", e.Error()))
	}
}

// extractorAvailable resolves the console error once an extraction showed that
// the extractor runs, whatever it concluded about the archive. The flag is put
// back when the manager could not be told, so that the next success tries again.
func (c *Connector) extractorAvailable() {
	if !c.extractorDown.CompareAndSwap(true, false) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), eventTimeout)
	defer cancel()
	if e := EventHandler.NotifyResolution(ctx, "the extractor works again", extractorEvent); e != nil {
		c.extractorDown.Store(true)
		logger.Warn("could not push resolution event to connector manager", slog.String("error", e.Error()))
	}
}

// undeterminedEncryption is the failure of a damaged archive that may be
// encrypted: an encrypted file for what follows from it.
type undeterminedEncryption struct{}

func (undeterminedEncryption) Error() string {
	return "the archive is encrypted, or damaged and it cannot be told which"
}

func (undeterminedEncryption) Is(target error) bool { return target == errEncrypted }

// extractionAnomaly turns an extract-error entry reported by the extractor
// (an anomaly of the archive: data after its end, a mismatch between what was
// listed and what was extracted) into an error.
func extractionAnomaly(e plugins.Extraction) error {
	for _, s := range e.Skipped {
		if s.Reason == datamodel.NotAnalyzedExtractError {
			return fmt.Errorf("%w: %w: the extractor reported an anomaly in %s", plugins.ErrArchiveAnomaly, plugins.ErrEncryptionPossible, s.FileName)
		}
	}
	return nil
}

// errExtractAnomaly is the failure of an archive the extractor found damaged or
// inconsistent, under the policy that fails: it is definitive, and its text is
// fixed (the cause, which comes from the archive, stays in the log).
var errExtractAnomaly = fmt.Errorf("%w: the archive is damaged or inconsistent and could not be extracted", errInnerPermanent)

// isArchiveAnomaly tells whether an extraction failed because of the archive
// itself. Only an extractor that says so counts (ErrEncryptionPossible alone
// says it too); a cut, a timeout or a cancellation says nothing about the
// archive and wins over it, so that a transient failure never makes an archive
// definitive nor lets it through.
func isArchiveAnomaly(err error) bool {
	return (errors.Is(err, plugins.ErrArchiveAnomaly) || errors.Is(err, plugins.ErrEncryptionPossible)) &&
		!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

// tryExtract starts a recursive extraction for archive.
func (c *Connector) tryExtract(archive archiveToAnalyze) (err error) {
	archiveLogger := logger.With(slog.String("input file", archive.location), slog.String("sha256", archive.sha256))
	file := fileToAnalyze{
		location: archive.location,
		sha256:   archive.sha256,
		identity: archive.identity,
		input:    archive.input,
		run:      archive.run,
		size:     archive.size,
	}
	var totalExtractedSize int64
	var totalExtractedFiles int
	err = c.recursiveExtract(file, 0, &totalExtractedSize, &totalExtractedFiles, archiveLogger)
	return
}

// recursiveExtract checks if archive can be extracted, and if so, extracts it recursively.
// extracted files are sent for analysis (unless they are themselves an archive).
func (c *Connector) recursiveExtract(archive fileToAnalyze, depth int, totalExtractedSize *int64, totalExtractedFiles *int, archiveLogger *slog.Logger) (err error) {
	archiveLogger.Debug("checking if extraction is possible")
	if totalExtractedSize == nil {
		err = errors.New("totalExtractedSize is nil")
		return
	}
	if totalExtractedFiles == nil {
		err = errors.New("totalExtractedFiles is nil")
		return
	}
	archivePath, pathErr := c.readPath(archive)
	if pathErr != nil {
		err = fmt.Errorf("extract-error: %w", pathErr)
		return
	}
	checkErr := c.checkBeforeExtract(archivePath, totalExtractedSize, totalExtractedFiles, depth, archiveLogger)
	if checkErr != nil {
		archiveLogger.Debug("file cannot be extracted", slog.String(logReasonKey, checkErr.Error()))
		file := archive.named()
		// An archive the limits do not let us open is left out, not analyzed as a
		// plain file: submitting it whole would let its members through unseen.
		file.limitSkipped = errors.Is(checkErr, errExtractLimit) && c.isArchiveType(archivePath)
		err = c.sendForAnalyze(file, archiveLogger)
		return
	}

	outputDir, outputDirErr := os.MkdirTemp(c.work.extractDir(), "x-")
	if outputDirErr != nil {
		err = outputDirErr
		return
	}

	needCleanUp := true
	defer func() {
		if needCleanUp {
			if e := os.RemoveAll(outputDir); e != nil {
				archiveLogger.Error("could not remove temp folder after error", slog.String("folder", outputDir), slog.String(logErrorKey, e.Error()))
			}
		}
	}()

	archiveLogger.Debug("attempting to extract file")
	limits := plugins.ExtractLimits{
		MaxFileSize:  c.config.MaxFileSize,
		MaxFiles:     c.config.RecursiveExtractMaxFiles - *totalExtractedFiles,
		MaxTotalSize: c.config.RecursiveExtractMaxSize - *totalExtractedSize,
	}
	source, cleanupSource, sourceErr := c.extractSource(archive)
	if sourceErr != nil {
		err = fmt.Errorf("extract-error: %w", sourceErr)
		return
	}
	defer cleanupSource()
	extraction, extractErr := ExtractFile(source, outputDir, limits)
	cleanupSource()
	extractedSize, extractedFiles := extraction.Size, extraction.Files
	if extractErr == nil {
		extractErr = extractionAnomaly(extraction)
	}
	if errors.Is(extractErr, plugins.ErrExtractorUnavailable) {
		// Says nothing about the archive: it is neither submitted nor in
		// definitive error, and the operator is told.
		archiveLogger.Error("the extractor is unavailable", slog.String("error", extractErr.Error()))
		c.extractorUnavailable(extractErr)
		err = fmt.Errorf("extractor-unavailable: %w", extractErr)
		return
	}
	// 7z ran, whatever it concluded: an alert about the extractor is over.
	c.extractorAvailable()
	if extractErr != nil && !errors.Is(extractErr, plugins.ErrUnsupportedFormat) && !errors.Is(extractErr, plugins.ErrEncrypted) {
		// A recognized archive that could not be extracted is an error, never
		// a plain file unless the policy says so for an anomaly of the archive:
		// submitting it as is would let its content through.
		if !isArchiveAnomaly(extractErr) || c.config.Unanalyzable.ExtractError != PolicyAsFile {
			archiveLogger.Error("archive extraction failed", slog.String("error", extractErr.Error()))
		}
		switch {
		case !isArchiveAnomaly(extractErr):
			err = fmt.Errorf("extract-error: %w", extractErr)
		case c.config.Unanalyzable.ExtractError != PolicyAsFile:
			err = errExtractAnomaly
		default:
			file := archive.named()
			if errors.Is(extractErr, plugins.ErrEncryptionPossible) {
				// Nothing proves that the damage hides no encryption: the policy of
				// the encrypted files decides.
				file.encrypted, file.undetermined = true, true
			} else {
				file.extractError = true
			}
			archiveLogger.Warn("damaged archive handled as a file", slog.String(logReasonKey, extractErr.Error()), slog.Bool("possibly_encrypted", file.encrypted))
			err = c.sendForAnalyze(file, archiveLogger)
		}
		return
	}
	if extractErr != nil {
		archiveLogger.Debug("error extracting file", slog.String("error", extractErr.Error())) // debug level, because files reaching that point are not necessarily extractable, due to the authorization of type 'application/octet-stream'
		file := archive.named()
		// An archive whose password is unknown is not a plain file: the policy
		// of the encrypted files decides what becomes of it, as a member too if
		// it is a sub-archive.
		file.encrypted = errors.Is(extractErr, plugins.ErrEncrypted)
		err = c.sendForAnalyze(file, archiveLogger)
		return
	}
	if extractedSize > math.MaxInt64 {
		extractedSize = math.MaxInt64
	}
	*totalExtractedSize += int64(extractedSize)
	*totalExtractedFiles += len(extractedFiles) // add all extracted files in total, including sub-archives

	archiveLogger.Debug("archive extraction successful", slog.String("extracted files", fmt.Sprintf("%v", extractedFiles)))
	eStatus := archiveStatus{
		archiveLocation: archive.location,
		identity:        archive.identity,
		sha256:          archive.sha256,
		input:           archive.input,
		run:             archive.run,
		result: datamodel.Result{
			SHA256:            archive.sha256,
			MaliciousSubfiles: make(map[string]datamodel.Result),
			Malware:           false,
			Malwares:          []string{},
			FileSize:          archive.size,
		},
		analyzed:  0,
		total:     len(extractedFiles),
		tmpFolder: outputDir,
		parentArchive: parentArchive{
			statusID: archive.archiveID,
			relPath:  archive.filename,
		},
	}

	skipped := max(extraction.SkippedCount, len(extraction.Skipped))
	if skipped > 0 {
		// Members were left out by the limits of the extraction: they follow the
		// policy of the files too big, and are never let through unseen.
		if err = c.applyLimitSkips(extraction, skipped, &eStatus.result, archive.location); err != nil {
			return
		}
	}
	if len(extractedFiles) == 0 && skipped == 0 {
		err = c.sendForAnalyze(archive.named(), archiveLogger)
		return
	}

	archiveID := c.archiveStatus.addStatus(eStatus)
	needCleanUp = false

	if archive.archiveID == "" {
		// Top-level archive: mark as started and call onStartScanFile/onScanFile immediately.
		// This ensures session plugin tracking works even when all extracted files are sub-archives
		// that get processed recursively.
		// Mark archive as started so that handleArchive won't call onStartScanFile/onScanFile
		// a second time when extracted files arrive at workers.
		c.archiveStatus.setStarted(archiveID)
		c.startScan(archive.location, archive.run, archive.sha256)
		if archiveResult := c.onScanFile(archive.location, archive.location, archive.sha256, true); archiveResult != nil {
			// Plugin filtered the archive, skip extraction processing and clean up temp folder.
			c.endFilteredArchive(archiveID, *archiveResult, archive.location, archive.sha256, archive.size, archive.location, archive.run, archiveLogger)
			return
		}
		archive.archiveTopLocation = archive.location
	}

	if len(extractedFiles) == 0 {
		// Nothing to analyze: every member was left out and the policy lets the
		// archive end with what it lists.
		c.endArchive(archiveID, eStatus.result, archive.location, archive.archiveTopLocation, archive.run, archiveLogger)
		return
	}

	depth += 1
	// Note: files should be directly streamed to channel and not accumulated in memory
	for i, fileLocation := range extractedFiles {
		fileLogger := archiveLogger.With(slog.Int("depth", depth), slog.String("subfile", fileLocation))

		var fileSHA256 string
		var fileSize int64
		fileSHA256, fileSize, err = c.checkExtractedFile(fileLocation)
		if err != nil {
			fileLogger.Warn("skipping file", slog.String(logReasonKey, err.Error()))
			if removeErr := os.Remove(fileLocation); removeErr != nil {
				fileLogger.Warn("could not remove file")
			}
			relName := innerName(outputDir, fileLocation)
			var finished, ok bool
			if errors.Is(err, errEmptyFile) {
				finished, ok = c.archiveStatus.decreaseTotal(archiveID)
			} else {
				finished, ok = c.archiveStatus.addInnerError(archiveID, relName, memberCause(err))
			}
			// The member is dealt with: err must not leak out of the function,
			// the archive lives on and is finished by whoever ends its last file.
			err = nil
			if !ok {
				continue
			}
			if finished {
				archiveLogger.Warn("all files from archive skipped")
				if finishErr := c.finishArchiveAnalysis(archiveID); finishErr != nil {
					archiveLogger.Error("could not finish archive analysis after all files skipped", slog.String(logErrorKey, finishErr.Error()))
				}
				return
			}
			continue
		}
		relPath, relErr := filepath.Rel(outputDir, fileLocation)
		if relErr != nil {
			relPath = fileLocation
		}
		subFile := fileToAnalyze{
			location:           fileLocation,
			archiveID:          archiveID,
			filename:           relPath,
			logicalPath:        memberLogicalPath(archive.logical(), relPath, relErr == nil && pathutil.Under(outputDir, fileLocation), fileLocation),
			archiveLogicalPath: archive.logical(),
			archiveLocation:    archive.location,
			sha256:             fileSHA256,
			archiveSHA256:      archive.sha256,
			size:               fileSize,
			archiveSize:        archive.size,
			archiveTopLocation: archive.archiveTopLocation,
			run:                archive.run,
		}
		err = c.recursiveExtract(subFile, depth, totalExtractedSize, totalExtractedFiles, fileLogger)
		if err != nil {
			if errors.Is(err, plugins.ErrExtractorUnavailable) {
				// Not a verdict on this archive: the top archive is left in place
				// without a final result, like on shutdown, instead of ending in
				// definitive error for a passing failure of the extractor.
				fileLogger.Error("recursive extraction abandoned, the extractor is unavailable", slog.String(logErrorKey, err.Error()))
				c.abandonArchive(archiveID, archive.archiveTopLocation, archive.run, len(extractedFiles)-i, archiveLogger)
				return
			}
			if errors.Is(err, context.Canceled) {
				// Shutdown requested. No cleanup needed here:
				// - Temp folder: keep it, files may have been sent to workers
				// - archiveStatus: keep it, workers may still process pending files
				// Resources will be released when process exits or on next startup.
				return
			}
			fileLogger.Error("recursive extraction failed", slog.String(logErrorKey, err.Error()))
			finished, ok := c.archiveStatus.addInnerError(archiveID, innerName(outputDir, fileLocation), memberCause(err))
			err = nil
			if !ok {
				continue
			}
			if finished {
				if finishErr := c.finishArchiveAnalysis(archiveID); finishErr != nil {
					archiveLogger.Error("could not finish archive analysis after all extractions failed", slog.String(logErrorKey, finishErr.Error()))
				}
				return
			}
			continue
		}
	}
	return
}

// abandonArchive gives up an archive whose extraction was cut short: it gets no
// result, and its folder goes as soon as the members already sent are done. The
// top-level file at top is over: nothing will ever complete it (a sub-archive
// that vanishes keeps its parent waiting for a member that never comes), and the
// plugins that were told it started are told it ended.
func (c *Connector) abandonArchive(archiveID, top string, run *ongoing, unsent int, archiveLogger *slog.Logger) {
	c.setResource(top, run)
	defer c.finishRun(top, run)
	folder, removeNow, ok := c.archiveStatus.abandon(archiveID, unsent)
	if !ok || !removeNow {
		return
	}
	if err := os.RemoveAll(folder); err != nil {
		archiveLogger.Error("could not remove temp folder", slog.String("folder", folder), slog.String(logErrorKey, err.Error()))
	}
}

// memberCause strips the location of the temporary file from an I/O error: the
// member is already named by its path in the archive, and the temporary path
// (inside the work directory) means nothing to the operator.
func memberCause(err error) error {
	if pathErr, ok := errors.AsType[*fs.PathError](err); ok {
		return fmt.Errorf("extracted file unreadable: %w", pathErr.Err)
	}
	return err
}

// innerName is the name of an extracted file inside its archive.
func innerName(outputDir, location string) string {
	if rel, err := filepath.Rel(outputDir, location); err == nil {
		return rel
	}
	return location
}

func (c *Connector) sendForAnalyze(file fileToAnalyze, logger *slog.Logger) (err error) {
	logger.Debug("sending file to analysis worker...")
	select {
	case <-c.stopWorker:
		err = context.Canceled
	case c.analysisChan <- file:
		logger.Debug("file successfully sent to analysis worker")
	}
	return
}

// checkBeforeExtract checks following conditions for file at location:
//   - depth is < to max depth
//   - total extracted size/files are below limits
//   - type is an accepted extractable type
//
// returns an error if any of the conditions are not met; one that is a limit
// wraps errExtractLimit. The size of the file does not matter: an archive is
// extracted, or listed to find out it is encrypted, whatever extract_min_size.
func (c *Connector) checkBeforeExtract(location string, totalExtractedSize *int64, totalExtractedFiles *int, depth int, logger *slog.Logger) (err error) {
	if depth >= c.config.RecursiveExtractMaxDepth {
		err = fmt.Errorf("%w: max depth reached: %d", errExtractLimit, depth)
		return
	}

	if totalExtractedSize == nil {
		err = errors.New("totalExtractedSize is nil")
		return
	}
	// because size is added to totalExtractedSize after extraction completes, the actual
	// total may exceed RecursiveExtractMaxSize by up to one archive's extracted content.
	if *totalExtractedSize > c.config.RecursiveExtractMaxSize {
		err = fmt.Errorf("%w: total extracted size (%vB) reached limit (%vB)", errExtractLimit, *totalExtractedSize, c.config.RecursiveExtractMaxSize)
		return
	}
	if totalExtractedFiles == nil {
		err = errors.New("totalExtractedFiles is nil")
		return
	}
	if *totalExtractedFiles > c.config.RecursiveExtractMaxFiles {
		err = fmt.Errorf("%w: total extracted files (%v) reached limit (%v)", errExtractLimit, *totalExtractedFiles, c.config.RecursiveExtractMaxFiles)
		return
	}

	// I/O checks last
	_, err = os.Stat(location)
	if err != nil {
		return
	}

	mtype, err := mimetype.DetectFile(location) // cannot use libmagic, to remain compatible with Windows
	switch {
	// if cannot detect type, return no error to still try extraction (to not miss potential extractable files)
	case err != nil:
		logger.Warn("error detecting file type", slog.String(logReasonKey, err.Error()))
		err = nil
		return
	case mtype == nil:
		logger.Warn("error detecting file type", slog.String(logReasonKey, "result *mimetype.MIME is nil"))
		return
	default:
		logger.Debug("file type detected successfully", slog.String("MIME type", mtype.String()))
	}
	if _, ok := c.typesToExtract[mtype.String()]; !ok {
		err = fmt.Errorf("type %s does not belong to list of types to extract", mtype.String())
		return
	}
	return
}

// errExtractLimit marks a limit of the extraction (depth, files, total size).
var errExtractLimit = errors.New("limit of the extraction reached")

// isKnownArchiveType tells whether a MIME type is one of an archive format: the
// types to extract without application/octet-stream, which stands for any binary
// and is only tried by the extraction of the files large enough to be worth it.
func (c *Connector) isKnownArchiveType(mime string) bool {
	if mime == mimeOctetStream {
		return false
	}
	_, ok := c.typesToExtract[mime]
	return ok
}

// mimeOctetStream is the type of a binary file nothing more precise is known of.
const mimeOctetStream = "application/octet-stream"

// isArchiveType tells whether the file at path is an archive of a known format.
func (c *Connector) isArchiveType(path string) bool {
	mtype, err := mimetype.DetectFile(path) // cannot use libmagic, to remain compatible with Windows
	if err != nil || mtype == nil {
		return false
	}
	return c.isKnownArchiveType(mtype.String())
}

// isSmallArchive tells whether a file too small for extract_min_size is an
// archive all the same: it must reach the extractor, which is what tells that its
// password is unknown, instead of being submitted as a plain file.
func (c *Connector) isSmallArchive(input fileToAnalyze) bool {
	if input.input != nil {
		// The verified descriptor is read: no second open, and no other file.
		buf, ok := probeBuffers.Get().(*[]byte)
		if !ok {
			return false
		}
		defer probeBuffers.Put(buf)
		n, err := input.input.f.ReadAt(*buf, 0)
		if n == 0 && err != nil {
			return false
		}
		return c.isKnownArchiveType(mimetype.Detect((*buf)[:n]).String())
	}
	path, err := c.readPath(input)
	return err == nil && c.isArchiveType(path)
}

// smallTypeProbe is how many bytes of a small file are read to know its type
// (what mimetype reads by default).
const smallTypeProbe = 3072

var probeBuffers = sync.Pool{New: func() any {
	b := make([]byte, smallTypeProbe)
	return &b
}}

var sha256BufferPool = sync.Pool{
	New: func() any {
		// 128KB buffer (instead of 32KB default)
		buf := make([]byte, 128*1024)
		return &buf
	},
}

func getFileSHA256(location string) (fileSHA256 string, err error) {
	f, err := openRegular(location, true)
	if err != nil {
		return
	}
	defer func() {
		if e := f.Close(); e != nil {
			logger.Warn("could not close file correctly", slog.String("file", location), slog.String("error", e.Error()))
		}
	}()
	return hashFile(f)
}

// hashFile returns the SHA256 of what is left to read of f.
func hashFile(f io.Reader) (fileSHA256 string, err error) {
	hash := sha256.New()
	sha256Buf, ok := sha256BufferPool.Get().(*[]byte)
	if !ok {
		err = errors.New("error with sha256 computing, could not get correct buffer type from pool")
		return
	}
	defer sha256BufferPool.Put(sha256Buf)

	if _, err = io.CopyBuffer(hash, f, *sha256Buf); err != nil {
		return
	}
	fileSHA256 = hex.EncodeToString(hash.Sum(nil))
	return
}

// analyzeArchiveFile handles the analysis of a file that is part of an archive.
func (c *Connector) analyzeArchiveFile(input fileToAnalyze) (err error) {
	archiveLogger := logger.With(slog.String("archive-id", input.archiveID), slog.String("archive location", input.archiveLocation))
	status, started, ok := c.archiveStatus.claimStart(input.archiveID)
	if status.finished {
		archiveLogger.Debug("archive already analyzed", slog.String("archive-id", input.archiveID))
		return
	}
	if !ok {
		archiveLogger.Warn("could not handle archive, not found in archive handler", slog.String("archive", input.archiveLocation))
		c.finishRun(input.archiveTopLocation, input.run)
		return
	}
	if started {
		// No onStartScanFile here: a sub-archive belongs to the scan of its
		// top-level archive and must not start a session of its own.
		if archiveResult := c.onScanFile(input.archiveLogical(), input.archiveLocation, input.archiveSHA256, true); archiveResult != nil {
			c.endFilteredArchive(input.archiveID, *archiveResult, input.archiveLocation, input.archiveSHA256, input.archiveSize, input.archiveTopLocation, input.run, archiveLogger)
			return
		}
	}
	result := c.analyzeFile(input)
	if result.Error != nil {
		archiveLogger.Error("could not handle archive inner file properly", slog.String("file", input.filename), slog.Any(logErrorKey, result.Error.Error()))
		ConsoleLogger.Error(fmt.Sprintf("could not handle archive inner file %s properly: %s", input.filename, result.Error.Error()))
	}
	finished, archiveFound := c.archiveStatus.addInnerFileResult(input.archiveID, input.filename, result)
	if !archiveFound {
		archiveLogger.Warn("could not handle archive, not found in archive handler", slog.String("archive", input.archiveLocation))
		c.finishRun(input.archiveTopLocation, input.run)
		return
	}

	if finished {
		err = c.finishArchiveAnalysis(input.archiveID)
		if err != nil {
			return
		}
	}
	return
}

// endFilteredArchive ends an archive a plugin dispensed from analysis (a skipped
// type, a path rule): whatever the plugin put in the result, the hash and the
// size are the pipeline's (the checks before the action read them), and the
// archive is marked as passed without analysis unless the plugin refused it.
func (c *Connector) endFilteredArchive(archiveID string, result datamodel.Result, location, sha256 string, size int64, top string, run *ongoing, archiveLogger *slog.Logger) {
	result.Filename = location
	result.SHA256 = sha256
	result.FileSize = size
	markPolicySkipped(&result, location)
	c.endArchive(archiveID, result, location, top, run, archiveLogger)
}

// endArchive ends an archive at once, with no member left to analyze: it gets
// the result as it is, then is finished. When the archive is gone from the
// handler, the run of its top-level file is ended instead.
func (c *Connector) endArchive(archiveID string, result datamodel.Result, location, top string, run *ongoing, archiveLogger *slog.Logger) {
	if !c.archiveStatus.setArchiveResult(archiveID, result) {
		archiveLogger.Warn("could not handle archive, not found in archive handler", slog.String("archive", location))
		c.finishRun(top, run)
		return
	}
	if finishErr := c.finishArchiveAnalysis(archiveID); finishErr != nil {
		archiveLogger.Error("could not finish archive analysis", slog.String(logErrorKey, finishErr.Error()))
	}
}

func (c *Connector) finishArchiveAnalysis(archiveID string) (err error) {
	archiveLogger := logger.With(slog.String("archive-id", archiveID))

	status, claimed, found := c.archiveStatus.claimFinish(archiveID)
	if !found {
		archiveLogger.Warn("could not handle archive, not found in archive handler")
		return
	}
	if !claimed {
		return
	}
	archiveLogger = logger.With(slog.String("archive location", status.archiveLocation))

	defer func() {
		c.finishRun(status.archiveLocation, status.run)
	}()

	if status.abandoned {
		// Its extraction was cut short: no result, no action, only the cleanup.
		if removeErr := os.RemoveAll(status.tmpFolder); removeErr != nil {
			archiveLogger.Error("could not remove temp folder", slog.String("folder", status.tmpFolder), slog.String(logErrorKey, removeErr.Error()))
		}
		c.archiveStatus.deleteStatus(archiveID)
		return
	}

	isSubArchive := status.parentArchive.statusID != ""

	// SHA256 check, action and report only for top-level archives. An archive
	// that cannot be read again, or changed during the analysis, gets an Error
	// and no action; the cleanup below still runs.
	runAction := !isSubArchive
	if !isSubArchive {
		// The last read of the content is over: its hash, the descriptor and
		// the name are checked, then the descriptor is closed, before the action.
		if verifyErr := c.verifyContent(status.archiveLocation, status.input, status.result.FileSize, status.result.SHA256, status.identity); verifyErr != nil {
			archiveLogger.Error("archive changed during analysis, stop processing", slog.String(logErrorKey, verifyErr.Error()))
			status.result.Error = fmt.Errorf("%w: %w", errInnerTransient, memberCause(verifyErr))
			runAction = false
		}
		if !holdsHandle {
			c.releaseInput(status.archiveLocation, status.run)
		}
	}

	// A sub-archive is not a file of its own for the plugins: only the
	// top-level archive is paired with its start.
	scanRun := status.run
	if isSubArchive {
		scanRun = nil
	}
	if newResult := c.fileScanned(status.archiveLocation, scanRun, status.result.SHA256, status.result); newResult != nil {
		status.result = *newResult
		// don't need to save it in status handler, because it's going to be deleted at func end
	}

	if runAction {
		if pathErr := c.checkPath(status.archiveLocation); pathErr != nil {
			refusePath(status.archiveLocation, pathErr)
			c.setFinal(status.archiveLocation, status.run)
			runAction = false
		}
	}

	if runAction {
		report := &datamodel.Report{}
		ctx, cancel := context.WithTimeout(c.workContext(), c.actionTimeout(status.result.FileSize))
		defer cancel()
		err = c.action.Handle(ctx, status.input.source(status.archiveLocation, status.identity, status.sha256), status.result, report)
		if err != nil {
			c.noteOwnTrace(status.archiveLocation, status.run, status.identity)
		}
		c.concludeOutcome(status.archiveLocation, status.run, resultView{err: status.result.Error, analysisError: status.result.AnalysisError}, err)
		if err != nil {
			archiveLogger.Error("could not handle archive action", slog.String(logErrorKey, err.Error()))
			ConsoleLogger.Error(fmt.Sprintf("could not handle archive action for %s: %s", status.archiveLocation, err.Error()))
		} else {
			archiveLogger.Debug("archive handled successfully")
		}
		c.addReport(report)
	}

	removeErr := os.RemoveAll(status.tmpFolder)
	if removeErr != nil {
		archiveLogger.Error("could not remove temp folder", slog.String("folder", status.tmpFolder), slog.String(logErrorKey, removeErr.Error()))
	}
	c.archiveStatus.deleteStatus(archiveID)

	if isSubArchive {
		// Propagate to parent
		finished, ok := c.archiveStatus.addInnerFileResult(status.parentArchive.statusID, status.parentArchive.relPath, status.result)
		if ok && finished {
			err = c.finishArchiveAnalysis(status.parentArchive.statusID)
		}
	}
	return
}

func (c *Connector) analyzeFile(input fileToAnalyze) datamodel.Result {
	return c.analyze(input, nil)
}

// analyze decides what becomes of a file: its result. When the file is not
// analyzed because it is larger than max_file_size, whatever the policy, it
// sets *tooBig (if not nil): it is the pipeline's own decision, which travels
// to the Source the actions are given, and is never read back from the result.
func (c *Connector) analyze(input fileToAnalyze, tooBig *bool) (result datamodel.Result) {
	fileLogger := logger.With(slog.String("file", input.location))

	defer func() {
		fileLogger.Debug("file handled", slog.Any("result", result))
	}()

	ctx, cancel := context.WithTimeout(c.workContext(), c.analysisTimeout())
	defer cancel()

	opts := c.config.WaitOpts
	opts.Filename = input.location

	readLocation, locErr := c.readPath(input)
	if locErr != nil {
		result = datamodel.Result{Filename: input.filename, Location: input.location, SHA256: input.sha256, FileSize: input.size, Error: locErr}
		return
	}
	fileLogger.Debug("applying onScanFile() from plugins")
	res := c.onScanFile(input.logical(), readLocation, input.sha256, false)
	if res != nil {
		result = *res
		// Reports and MaliciousSubfiles are keyed by the internal name, whatever
		// the plugin put in Filename or Location.
		result.Filename = input.filename
		result.Location = input.location
		if result.SHA256 == "" {
			result.SHA256 = input.sha256
		}
		if result.FileSize == 0 {
			result.FileSize = input.size
		}
		markPolicySkipped(&result, input.location)
		return
	}

	if input.size == 0 {
		return c.unanalyzedResult(input, datamodel.NotAnalyzedEmpty, c.config.Unanalyzable.Empty, errEmptyFile)
	}
	if input.size > c.config.MaxFileSize {
		if tooBig != nil {
			*tooBig = true
		}
		if input.encrypted {
			return c.unanalyzedResult(input, datamodel.NotAnalyzedEncrypted, c.config.Unanalyzable.Encrypted, input.encryptedFailure())
		}
		if input.limitSkipped {
			return c.unanalyzedResult(input, datamodel.NotAnalyzedExtractLimit, c.limitSkippedPolicy(), errLimitSkipped)
		}
		return c.unanalyzedResult(input, datamodel.NotAnalyzedTooBig, c.config.Unanalyzable.TooBig, errFileTooBig)
	}

	// report metrics for every file actually analyzed.
	// files filtered via plugins or too big to be analyzed
	// count as neither processed nor error.
	defer func() {
		if result.Error != nil {
			MetricCollecter.AddErrorItem()
			return
		}
		MetricCollecter.AddItemProcessed(input.size)
	}()

	location := input.location
	if input.archiveID != "" {
		location = input.archiveTopLocation
		archiveName := filepath.Base(location)
		if archiveName != "." && archiveName != string(filepath.Separator) {
			opts.Tags = append(opts.Tags, "archive:"+archiveName)
		}
	}
	c.withWaitForOptions(&opts, location)
	fileLogger.Debug("sending file to detect ...")
	gdetectResult, err := c.submitContent(ctx, input, opts)
	var logArgs []any
	if err != nil {
		err = fmt.Errorf("%s: %w", errSubmitPrefix, err)
		logArgs = append(logArgs, slog.String(logErrorKey, err.Error()))
	}
	fileLogger.Debug("finished sending file to detect", logArgs...)
	httpError := new(gdetect.HTTPError)
	urlError := new(url.Error)
	switch {

	case err == nil:
		if errEvent := EventHandler.NotifyResolution(ctx, "last analysis succeeded", events.GMalwareConfigError, events.GMalwareError); errEvent != nil {
			fileLogger.Error("cannot push resolution event", slog.String("error", errEvent.Error()))
		}

	case errors.Is(err, errSubmitContentMismatch):
		// the file changed under the analysis: not a GMalware error

	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, gdetect.ErrTimeout):
		// not a GMalware error (can be file-specific) so don't send error notification

	case errors.As(err, httpError):
		// message kept free of file-specific details so repeated identical failures produce a single notification
		err := fmt.Errorf("%s: %d: %s : %s", errSubmitPrefix, httpError.Code, httpError.Status, httpError.Body)
		if errEvent := EventHandler.NotifyError(ctx, events.GMalwareError, err); errEvent != nil {
			fileLogger.Error("cannot push error event", slog.String("error", errEvent.Error()))
		}

	case errors.As(err, &urlError):
		err := fmt.Errorf("%s: error %s: %w", errSubmitPrefix, urlError.Op, urlError.Err)
		if errEvent := EventHandler.NotifyError(ctx, events.GMalwareError, err); errEvent != nil {
			fileLogger.Error("cannot push error event", slog.String("error", errEvent.Error()))
		}

	default:
		if errEvent := EventHandler.NotifyError(ctx, events.GMalwareError, err); errEvent != nil {
			fileLogger.Error("cannot push error event", slog.String("error", errEvent.Error()))
		}

	}
	if err != nil {
		result = datamodel.Result{
			Filename: input.filename,
			FileType: gdetectResult.FileType,
			Location: input.location,
			SHA256:   input.sha256,
			FileSize: input.size,
			Error:    err,
		}
		return
	}

	urlExpertView, urlExpertErr := c.submitter.ExtractExpertViewURL(&gdetectResult)
	if urlExpertErr != nil {
		urlExpertView = ""
	}

	result = datamodel.Result{
		Filename:       input.filename,
		FileType:       gdetectResult.FileType,
		Location:       input.location,
		SHA256:         input.sha256,
		Malware:        gdetectResult.Malware,
		Malwares:       gdetectResult.Malwares,
		FileSize:       gdetectResult.FileSize,
		GMalwareURL:    urlExpertView,
		AnalyzedVolume: gdetectResult.FileSize,
	}

	switch {
	case gdetectResult.Error != "":
		analysisError := gdetectResult.Error
		if len(gdetectResult.Errors) > 0 {
			gdetectErrors := make([]string, 0, len(gdetectResult.Errors))
			for k, v := range gdetectResult.Errors {
				gdetectErrors = append(gdetectErrors, fmt.Sprintf("%s: %s", k, v))
			}
			analysisError = strings.Join(gdetectErrors, ",")
		}
		ConsoleLogger.Error(fmt.Sprintf("error in %s analysis, error: %s", input.location, analysisError))
		result.AnalysisError = analysisError
	case gdetectResult.Malware:
		result.MalwareReason = datamodel.MalwareDetected
	case input.encrypted:
		result = c.policiedResult(input, result, datamodel.NotAnalyzedEncrypted, c.config.Unanalyzable.Encrypted, input.encryptedFailure())
	case input.limitSkipped:
		result = c.policiedResult(input, result, datamodel.NotAnalyzedExtractLimit, c.limitSkippedPolicy(), errLimitSkipped)
	case input.extractError:
		result = c.policiedResult(input, result, datamodel.NotAnalyzedExtractError, PolicyPass, nil)
	}
	return
}

// errLimitSkipped is the failure of an archive the limits of the extraction did
// not let open, under the policy that fails.
var errLimitSkipped = fmt.Errorf("%w: the limits of the extraction left the archive unopened", errInnerPermanent)

// limitSkippedPolicy is the policy of an archive the limits of the extraction
// did not let open: its content is unknown, and it may well be encrypted, so the
// stricter of the policies of the files too big and of the encrypted files
// applies (error, then mitigate, then pass).
func (c *Connector) limitSkippedPolicy() string {
	a, b := c.config.Unanalyzable.TooBig, c.config.Unanalyzable.Encrypted
	for _, p := range []string{PolicyError, PolicyMitigate} {
		if a == p || b == p {
			return p
		}
	}
	return PolicyPass
}

// policiedResult applies a policy to a result that found nothing: a detection or
// an analysis error has priority, and the file is marked or failed as the policy
// says. reason and failure are the file's: what the policy puts in the result.
func (c *Connector) policiedResult(input fileToAnalyze, analyzed datamodel.Result, reason datamodel.NotAnalyzedReason, policy string, failure error) datamodel.Result {
	policied := c.unanalyzedResult(input, reason, policy, failure)
	analyzed.Error = policied.Error
	analyzed.NotAnalyzedReason = policied.NotAnalyzedReason
	if policied.Malware {
		analyzed.Malware = true
		analyzed.Score = policied.Score
		analyzed.MalwareReason = policied.MalwareReason
	}
	return analyzed
}

// abortAnalysis ends an analysis without action nor report, still notifying plugins
// (e.g. session) that the scan started with onStartScanFile is over.
func (c *Connector) abortAnalysis(input fileToAnalyze, result datamodel.Result, err error) {
	result.Error = err
	c.releaseInput(input.location, input.run)
	c.fileScanned(input.location, input.run, input.sha256, result)
	c.finishRun(input.location, input.run)
}

func (c *Connector) addReport(report *datamodel.Report) {
	c.onReport(report)
}

func (c *Connector) workContext() context.Context {
	if c.workCtx == nil {
		return context.Background()
	}
	return c.workCtx
}

// ShutdownSummary is what a stop did.
type ShutdownSummary struct {
	// Abandoned is the number of files whose processing was cut when the drain
	// ended; they stay where they are.
	Abandoned int
	// StillRunning is the number of files not finished when closing ended.
	StillRunning int
	// PluginErrors is the number of plugins whose Close failed.
	PluginErrors int
	// WorkDirRemoved tells whether the work directory was removed.
	WorkDirRemoved bool
}

// Close is Shutdown with no bound on the closing phase.
func (c *Connector) Close(ctx context.Context) {
	c.Shutdown(ctx, context.Background())
}

// Shutdown stops the connector. No new file is accepted. Accepted files may
// finish until drain ends; then running analyses, extractions and actions are
// cancelled and their files are left in place. closing bounds what follows: the
// plugins are closed, the work directory is removed. Plugins always get
// closing, never drain. Only the first call stops the connector; the others
// return an empty summary.
func (c *Connector) Shutdown(drain, closing context.Context) (summary ShutdownSummary) {
	c.closeOnce.Do(func() {
		logger := logger.With(slog.String("operation", "Connector.Shutdown()"))
		logger.Debug("closing scanner")
		close(c.stopIncoming)

		if !waitDone(drain, c.scansWg.Wait) {
			summary.Abandoned = c.countOngoing()
			logger.Warn("drain ended, cutting the files still being processed", slog.Int("files", summary.Abandoned))
			c.cancelWorkContext()
			c.stopWorkers()
			c.interruptPlugins()
			c.waitForWorkers(closing)
			if !waitDone(closing, c.scansWg.Wait) {
				summary.StillRunning = c.countOngoing()
				logger.Error("files still being processed when closing ended", slog.Int("files", summary.StillRunning))
			}
		}

		c.waitForWorkers(closing)
		summary.PluginErrors = closePlugins(closing, c.loadedPlugins)

		closeErr := c.work.close()
		if closeErr != nil {
			logger.Error("failed to remove work directory", slog.String(logErrorKey, closeErr.Error()))
		}
		// A connector without a work directory removed nothing.
		summary.WorkDirRemoved = closeErr == nil && c.work != nil
		c.cancelWorkContext()
	})
	return summary
}

// waitForWorkers stops the workers, waits for them until ctx ends, and ends the
// runs of the files left in the queues.
func (c *Connector) waitForWorkers(ctx context.Context) {
	c.stopWorkers()
	if !waitDone(ctx, c.waitWorkers) {
		logger.Error("workers still running when closing ended")
	}
	c.drainQueues()
}

func (c *Connector) waitWorkers() {
	c.dispatchWg.Wait()
	c.extractWg.Wait()
	c.analysisWg.Wait()
}

// drainQueues ends the runs of the files left in the queues once the workers
// are gone. A worker that is stopping and the stage before it can both be ready
// to go on: a file may be queued behind the last worker, and would hold the
// stop for good.
func (c *Connector) drainQueues() {
	for {
		select {
		case sub := <-c.dispatchChan:
			c.finishRun(sub.location, sub.run)
		case archive := <-c.extractChan:
			c.finishRun(archive.location, archive.run)
		case input := <-c.analysisChan:
			if input.archiveID != "" {
				c.finishRun(input.archiveTopLocation, input.run)
				continue
			}
			c.finishRun(input.location, input.run)
		default:
			return
		}
	}
}

func (c *Connector) stopWorkers() {
	c.stopOnce.Do(func() { close(c.stopWorker) })
}

func (c *Connector) cancelWorkContext() {
	if c.cancelWork != nil {
		c.cancelWork()
	}
}

// interruptPlugins asks the plugins that run work no context can cancel to cut
// it, once.
func (c *Connector) interruptPlugins() {
	for _, plugin := range c.loadedPlugins {
		if i, ok := plugin.(plugins.Interrupter); ok {
			i.Interrupt()
		}
	}
}

func (c *Connector) countOngoing() (n int) {
	c.ongoingAnalysis.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

var errPluginCloseTimeout = errors.New("plugin Close did not return before the end of the closing time")

// closePlugins closes the plugins concurrently, all under ctx, and returns how
// many failed. Once ctx has ended the plugins still closing share one grace;
// those that are not done by then are given up on: a plugin that ignores its
// context must not hold up the stop.
func closePlugins(ctx context.Context, all []plugins.Plugin) (failed int) {
	type outcome struct {
		name string
		err  error
	}
	results := make(chan outcome, len(all))
	for _, plugin := range all {
		go func() { results <- outcome{fmt.Sprintf("%T", plugin), plugin.Close(ctx)} }()
	}
	record := func(o outcome) {
		if o.err != nil {
			failed++
			logger.Error("failed to close plugin", slog.String("plugin", o.name), slog.String(logErrorKey, o.err.Error()))
		}
	}
	pending := len(all)
	ended := ctx.Done()
	var graceOver <-chan time.Time
	for pending > 0 {
		select {
		case o := <-results:
			pending--
			record(o)
		case <-ended:
			ended = nil
			timer := time.NewTimer(plugins.CloseGrace)
			defer timer.Stop()
			graceOver = timer.C
		case <-graceOver:
			// What answered meanwhile is not a timeout.
			for {
				select {
				case o := <-results:
					pending--
					record(o)
					continue
				default:
				}
				break
			}
			for ; pending > 0; pending-- {
				failed++
				logger.Error("failed to close plugin", slog.String(logErrorKey, errPluginCloseTimeout.Error()))
			}
		}
	}
	return failed
}

// waitDone runs wait and tells whether it returned before ctx ended.
func waitDone(ctx context.Context, wait func()) bool {
	done := make(chan struct{})
	go func() {
		wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		// Both may be ready: what finished is not a timeout.
		select {
		case <-done:
			return true
		default:
			return false
		}
	}
}

func (c *Connector) GetLogger() *slog.Logger {
	return logger
}

func (c *Connector) GetConsoleLogger() *slog.Logger {
	return ConsoleLogger
}

// readPath is the path plugins read a file by: the one backed by the verified
// descriptor when descriptors are used (Linux, checked at start), else the path
// the file was deposited at. When descriptors are used and the path cannot be
// built the file is in error: giving the deposit path to the plugins would let
// them read, and waive, another file.
func (c *Connector) readPath(input fileToAnalyze) (string, error) {
	if input.input == nil || !c.fdLinks {
		return input.location, nil
	}
	p, ok := descriptorPath(input.input.f)
	if !ok {
		return "", fmt.Errorf("%w: %s", errNoDescriptorPath, input.location)
	}
	return p, nil
}

var errNoDescriptorPath = errors.New("no usable descriptor path")

// submitContent sends the file to the analysis and checks that the service
// answered about the file that was identified: the SHA256 it reports must be the
// one computed here, whatever the way the content was given.
func (c *Connector) submitContent(ctx context.Context, input fileToAnalyze, opts gdetect.WaitForOptions) (gdetect.Result, error) {
	var res gdetect.Result
	var err error
	if input.input == nil {
		res, err = c.submitter.WaitForFile(ctx, input.location, opts)
	} else {
		res, err = c.waitForDescriptor(ctx, input, opts)
	}
	if err != nil {
		return res, err
	}
	if !strings.EqualFold(res.SHA256, input.sha256) {
		return res, fmt.Errorf("%w: the analyzed content is not the file that was identified (sha256 %q, want %q)", errSubmitContentMismatch, res.SHA256, input.sha256)
	}
	return res, nil
}

// waitForDescriptor is WaitForFile for a file held by a descriptor, with the
// public API of the client: the client's WaitForReader would copy the file to
// the temporary directory first. It looks the SHA256 up (unless the cache is
// bypassed), submits the content read from the descriptor when it is unknown,
// then waits for the result until the timeout.
func (c *Connector) waitForDescriptor(ctx context.Context, input fileToAnalyze, opts gdetect.WaitForOptions) (gdetect.Result, error) {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 180 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	pull := opts.PullTime
	if pull == 0 {
		pull = 2 * time.Second
	}
	id := ""
	if !opts.BypassCache {
		res, err := c.submitter.GetResultBySHA256(ctx, input.sha256)
		var httpErr gdetect.HTTPError
		switch {
		case errors.As(err, &httpErr) && httpErr.Code == http.StatusNotFound:
		case err != nil:
			return res, fmt.Errorf("error getting result from cache: %w", err)
		case res.Done:
			return res, nil
		default:
			id = res.UUID
			if id == "" {
				id = res.ID
			}
		}
	}
	if id == "" {
		var err error
		if id, err = c.submitter.SubmitReader(ctx, input.input.reader(input.size), opts.SubmitOptions); err != nil {
			return gdetect.Result{}, fmt.Errorf("error submitting file: %w", err)
		}
	}
	return c.waitForResult(ctx, id, pull)
}

// waitForResult polls the analysis id until it is done or ctx ends. The server
// holds the connection for up to the time left (Detect), or answers at once
// (SynDetect): then the polls are pull apart.
func (c *Connector) waitForResult(ctx context.Context, id string, pull time.Duration) (gdetect.Result, error) {
	for {
		wait := gdetect.MaxWaitSeconds
		if deadline, ok := ctx.Deadline(); ok {
			wait = min(int(time.Until(deadline).Seconds()), gdetect.MaxWaitSeconds)
		}
		if wait <= 0 || ctx.Err() != nil {
			return gdetect.Result{}, gdetect.ErrTimeout
		}
		start := time.Now()
		res, err := c.submitter.GetResultByUUIDWithWait(ctx, id, wait)
		if err != nil {
			return res, fmt.Errorf("error waiting for result: %w", err)
		}
		if res.Done {
			return res, nil
		}
		if time.Since(start) < pull {
			select {
			case <-ctx.Done():
				return gdetect.Result{}, gdetect.ErrTimeout
			case <-time.After(pull - time.Since(start)):
			}
		}
	}
}

var errSubmitContentMismatch = errors.New("analysis of another content")

// extractSource is the path the extractor reads a deposited archive by: a link
// <folder>/<base name> to the verified descriptor, in a folder of its own beside
// the output folder (the extractor counts what it finds in the output folder),
// so that the archive extracted is the one that was identified. The base name
// keeps the extension the extractor may rely on. cleanup removes the link, it is
// safe to call more than once. Where descriptors have no path (not Linux) it is
// the path the file was deposited at.
func (c *Connector) extractSource(archive fileToAnalyze) (source string, cleanup func(), err error) {
	if archive.input == nil || !c.fdLinks {
		return archive.location, func() {}, nil
	}
	target, ok := descriptorPath(archive.input.f)
	if !ok {
		return "", func() {}, fmt.Errorf("no usable descriptor path for %s", archive.location)
	}
	dir, err := os.MkdirTemp(c.work.extractDir(), "src-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup = func() {
		if e := os.RemoveAll(dir); e != nil {
			logger.Warn("could not remove the source link folder", slog.String("folder", dir), slog.String(logErrorKey, e.Error()))
		}
	}
	link := filepath.Join(dir, filepath.Base(archive.location))
	if err = os.Symlink(target, link); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return link, cleanup, nil
}

// checkDescriptorLinks decides, once, how files are read by their descriptor.
// On Linux /proc must give a path to an open file: without it the guarantee
// that plugins and the extractor read the verified file cannot be given, and
// the connector refuses to start. Elsewhere there is no such path, the deposit
// path is used and the operator is told.
func (c *Connector) checkDescriptorLinks() error {
	if runtime.GOOS != "linux" {
		msg := "descriptors have no path on this system: plugins and the extractor read files by the path they were deposited at, which a user may redirect while they work"
		logger.Warn(msg)
		ConsoleLogger.Warn(msg)
		return nil
	}
	f, err := os.Open(os.DevNull)
	if err != nil {
		return fmt.Errorf("cannot check /proc: %w", err)
	}
	defer func() {
		if e := f.Close(); e != nil {
			logger.Warn("could not close file correctly", slog.String(logErrorKey, e.Error()))
		}
	}()
	if _, ok := descriptorPath(f); !ok {
		return errNoDescriptorLinks
	}
	c.fdLinks = true
	return nil
}

var errNoDescriptorLinks = errors.New("/proc/<pid>/fd cannot be used (is /proc mounted, and not hidden from this process?): without it the connector cannot make sure it reads the file it identified; mount /proc or run on another system")

// defaultAnalysisTimeout is the time given to the analysis of a file when the
// configuration says none: the one of the client.
const defaultAnalysisTimeout = 180 * time.Second

func (c *Connector) analysisTimeout() time.Duration {
	if t := time.Duration(c.config.Timeout); t > 0 {
		return t
	}
	return defaultAnalysisTimeout
}
