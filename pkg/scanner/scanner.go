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

var (
	LogLevel                                = &slog.LevelVar{}
	logger                                  = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: LogLevel}))
	EventHandler    events.EventHandler     = events.NoopEventHandler{}
	ConsoleLogger                           = slog.New(slog.DiscardHandler)
	MetricCollecter metrics.MetricCollecter = metrics.NoopMetricCollecter{}

	errFileTooBig    = errors.New("file is too big to be analyzed")
	errEmptyFile     = errors.New("file is empty")
	errScannerClosed = errors.New("scanner instance is closing and is no longer accepting new files")

	// An archive with a failed extracted file is never moved. These sentinels
	// only tell whether retrying can change the outcome: permanent wins when
	// both apply.
	errInnerTransient = errors.New("an extracted file could not be analyzed, will retry")
	errInnerPermanent = errors.New("an extracted file cannot be analyzed")
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
	FollowSymlinks           bool
	// Roots are the monitored paths: a path is checked for symbolic links from
	// the root that contains it. Without a root, the scan argument is the root.
	Roots []string
	// WorkDir is the base under which the connector creates its private
	// working directory; empty means os.TempDir().
	WorkDir string
}

type fileToAnalyze struct {
	sha256             string
	location           string
	filename           string
	logicalPath        string
	identity           FileIdentity // observed by the monitor, checked before every action
	input              *inputFD     // descriptor of the deposited file, nil for an extracted one
	size               int64
	archiveTopLocation string
	archiveID          string
	archiveLocation    string
	archiveLogicalPath string // logical path of archiveLocation, what plugins are told
	archiveSHA256      string
	archiveSize        int64
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
	size     int64
}

// submission is one file queued by SubmitFile.
type submission struct {
	location string
	want     FileIdentity
}

type Connector struct {
	submitter   gdetect.ControllerExtendedGDetectSubmitter
	quarantiner quarantine.Quarantiner

	closeOnce sync.Once
	// extractorDown is set while the console error of an unavailable extractor is raised.
	extractorDown atomic.Bool

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
	reportMutex            sync.Mutex
	reports                []*datamodel.Report
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

	work, err := newWorkDir(cfg.WorkDir)
	if err != nil {
		return nil, err
	}

	return &Connector{
		work:           work,
		submitter:      submitter,
		quarantiner:    quarantiner,
		dispatchChan:   make(chan submission, cfg.Workers),
		extractChan:    make(chan archiveToAnalyze, cfg.ExtractWorkers),
		analysisChan:   make(chan fileToAnalyze, cfg.Workers),
		config:         cfg,
		archiveStatus:  newArchiveStatusHandler(),
		action:         newAction(cfg, quarantiner),
		generateReport: datamodel.GenerateReport,
		stopIncoming:   make(chan struct{}),
		stopWorker:     make(chan struct{}),
		typesToExtract: extractableTypes(),
	}, nil
}

func newAction(cfg Config, quarantiner quarantine.Quarantiner) *MultiAction {
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
		move, err := NewMoveAction(cfg.MoveTo, cfg.MoveFrom)
		if err == nil {
			action.Actions = append(action.Actions, move)
		} else {
			logger.Error("could not add move legit action", slog.String(logErrorKey, err.Error()))
		}
	}
	if cfg.Actions.Inform {
		action.Actions = append(action.Actions, &PrintAction{Verbose: cfg.Actions.Verbose, Out: cfg.Actions.InformDest})
	}
	action.Actions = append(action.Actions, cfg.CustomActions...)
	return action
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
	input, info, skip, err := c.examineInput(input)
	if skip || err != nil {
		return err
	}
	if info.IsDir() {
		return c.scanDir(ctx, input)
	}
	_, err = c.submit(ctx, input, IdentityOf(info), info)
	return err
}

// examineInput cleans input and decides whether it is to be looked at: not
// when the connector is closing (error), nor for a temporary file, a file of
// the connector work directory or a link not to be followed (skip). It returns
// what the connector will read, and remembers the root of a scan.
func (c *Connector) examineInput(input string) (clean string, info fs.FileInfo, skip bool, err error) {
	select {
	case <-c.stopIncoming:
		return input, nil, true, errScannerClosed
	default:
	}
	clean = filepath.Clean(input)
	inputLogger := logger.With(slog.String("input file", clean))
	if quarantine.IsTempFile(clean) {
		inputLogger.Debug("skip file", slog.String(logReasonKey, "temporary file"))
		return clean, nil, true, nil
	}
	if c.IsInternalPath(clean) {
		inputLogger.Debug("skip file", slog.String(logReasonKey, "connector work directory"))
		return clean, nil, true, nil
	}
	info, err = c.statInput(clean)
	if err != nil {
		if errors.Is(err, errSkippedLink) {
			return clean, nil, true, nil
		}
		return clean, nil, true, err
	}
	c.noteScanRoot(clean)
	return clean, info, false, nil
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
// accepted is false, with a nil error, when the file is refused without
// failure (symbolic link, internal path, temporary file, empty file, already in
// progress). The file is analyzed only if it still has the identity want when
// the pipeline reads it, and acted upon only if it still has it afterwards.
func (c *Connector) SubmitFile(ctx context.Context, input string, want FileIdentity) (accepted bool, err error) {
	input, info, skip, err := c.examineInput(input)
	if skip || err != nil {
		return false, err
	}
	if info.IsDir() {
		return false, nil
	}
	return c.submit(ctx, input, want, info)
}

// submit queues the regular file input, described by info, unless it is empty
// or already being processed.
func (c *Connector) submit(ctx context.Context, input string, want FileIdentity, info fs.FileInfo) (accepted bool, err error) {
	inputLogger := logger.With(slog.String("input file", input))
	if info.Size() == 0 {
		inputLogger.Warn("skip file", slog.String(logReasonKey, "size 0"))
		return false, nil
	}

	if _, loaded := c.ongoingAnalysis.LoadOrStore(input, struct{}{}); loaded {
		inputLogger.Debug("skip file", slog.String(logReasonKey, "ongoing analysis"))
		return false, nil
	}
	c.scansWg.Add(1)

	defer func() {
		if !accepted {
			c.finishAnalysis(input)
		}
	}()

	select {
	case <-ctx.Done():
		return false, context.Canceled
	case <-c.stopIncoming:
		return false, errScannerClosed
	case c.dispatchChan <- submission{location: input, want: want}:
		return true, nil
	}
}

func (c *Connector) handleRestoredFile(location string, sha256 string, size int64, want FileIdentity) (err error) {
	res := datamodel.Result{
		Filename: filepath.Base(location),
		Location: location,
		SHA256:   sha256,
		FileSize: size,
		Restored: true,
	}
	if newres := c.onFileScanned(location, sha256, res); newres != nil {
		res = *newres
	}
	if pathErr := c.checkPath(location); pathErr != nil {
		refusePath(location, pathErr)
		return pathErr
	}
	if idErr := c.checkIdentity(location, want); idErr != nil {
		return idErr
	}
	report := &datamodel.Report{}
	actionCtx, cancel := context.WithTimeout(context.Background(), actionTimeoutForSize(size))
	defer cancel()
	if err = c.action.Handle(actionCtx, location, res, report); err != nil {
		logger.Error("could not handle file action", slog.String("file", location), slog.String(logErrorKey, err.Error()))
		return
	}
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
			for {
				select {
				case sub := <-c.dispatchChan:
					c.finishAnalysis(sub.location)
				default:
					return
				}
			}
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
			for {
				select {
				case archive := <-c.extractChan:
					c.finishAnalysis(archive.location)
				default:
					return
				}
			}
		case archive := <-c.extractChan:
			archiveLogger := logger.With(slog.String("file", archive.location))
			if err := c.tryExtract(archive); err != nil {
				archiveLogger.Error("could not extract file", slog.String(logErrorKey, err.Error()))
				ConsoleLogger.Error(fmt.Sprintf("could not handle file %s, error: %s", archive.location, err.Error()))
				c.finishAnalysis(archive.location)
			}
		}
	}
}

// analysisWorker consumes from analysisChan and performs malware analysis.
func (c *Connector) analysisWorker() {
	for {
		select {
		case <-c.stopWorker:
			for {
				select {
				case input := <-c.analysisChan:
					if input.archiveID != "" {
						c.finishAnalysis(input.archiveTopLocation)
						continue
					}
					c.finishAnalysis(input.location)
				default:
					return
				}
			}
		case input := <-c.analysisChan:
			c.processFile(input)
		}
	}
}

// prepareFile stats the file, computes its SHA256, and checks quarantine restored status.
// Returns the populated fileToAnalyze and whether the file should be skipped.
func (c *Connector) prepareFile(location string, want FileIdentity) (file fileToAnalyze, skip bool) {
	inputLogger := logger.With(slog.String("file", location))

	if err := c.checkPath(location); err != nil {
		refusePath(location, err)
		skip = true
		return
	}

	// One descriptor for the identity, the hash and everything read later:
	// what is read is what was observed, whatever happens to the name meanwhile.
	// It never blocks on a FIFO put there after the stability check.
	f, err := openRegular(location, c.config.FollowSymlinks)
	if err != nil {
		inputLogger.Error("could not open file, stop processing", slog.String("error", err.Error()))
		skip = true
		return
	}
	in := newInputFD(f)
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
		ctx, cancel := context.WithTimeout(context.Background(), restoredCheckTimeout)
		defer cancel()
		restored, err = c.quarantiner.IsRestored(ctx, fileSHA256)
		if err != nil {
			inputLogger.Error("could not check file restored status", slog.String(logErrorKey, err.Error()))
			skip = true
			return
		}
	}
	if restored {
		inputLogger.Debug("consider file as safe, skip it", slog.String(logReasonKey, "restored"))
		skip = true
		// The content was read for the last time: the descriptor is checked,
		// then closed, before the action.
		if err = c.verifyContent(location, in, info.Size(), fileSHA256, identity); err == nil {
			closeInput(in)
			err = c.handleRestoredFile(location, fileSHA256, info.Size(), identity)
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
		size:     info.Size(),
	}
	return
}

// finishAnalysis removes the file from ongoingAnalysis and signals the pipeline
// that this top-level file is fully done. Only files registered via ScanFile
// (LoadOrStore) are present in the map; extracted sub-files are no-ops.
func (c *Connector) finishAnalysis(location string) {
	if v, loaded := c.ongoingAnalysis.LoadAndDelete(location); loaded {
		closeInput(v)
		c.scansWg.Done()
	}
}

// closeInput releases the descriptor held for an ongoing analysis, if any.
func closeInput(v any) {
	if in, ok := v.(*inputFD); ok {
		if err := in.Close(); err != nil {
			logger.Warn("could not close file correctly", slog.String("error", err.Error()))
		}
	}
}

// releaseInput closes the descriptor of the top-level file at location: it
// must be done after the last read of its content and before any action
// (Windows refuses to move or delete a file that is open).
func (c *Connector) releaseInput(location string) {
	if v, ok := c.ongoingAnalysis.Load(location); ok {
		closeInput(v)
	}
}

// finishReading ends the reading of the top-level file input: the content read
// last (the second hash) is the one that was analyzed, the descriptor still is
// the file that was identified, and so is the name; then the descriptor is
// closed. It returns an error when the file must not be acted upon. A file
// without descriptor (tests) is hashed by path.
func (c *Connector) finishReading(input fileToAnalyze) error {
	defer c.releaseInput(input.location)
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

	input, skip := c.prepareFile(location, sub.want)
	if skip {
		c.finishAnalysis(location)
		return
	}
	c.ongoingAnalysis.CompareAndSwap(location, struct{}{}, input.input)

	// Route to extraction if applicable
	if input.size > c.config.ExtractMinThreshold && c.config.Extract {
		archive := archiveToAnalyze{location: location, sha256: input.sha256, identity: input.identity, input: input.input, size: input.size}
		select {
		case <-c.stopWorker:
			c.finishAnalysis(location)
		case c.extractChan <- archive:
			inputLogger.Debug("file sent to extract worker")
		}
		return
	}

	// Route to analysis
	select {
	case <-c.stopWorker:
		c.finishAnalysis(location)
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
	c.onStartScanFile(input.location, input.sha256)
	result := c.analyzeFile(input)
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
	if newres := c.onFileScanned(input.location, input.sha256, result); newres != nil {
		result = *newres
	}
	if pathErr := c.checkPath(input.location); pathErr != nil {
		refusePath(input.location, pathErr)
		c.finishAnalysis(input.location)
		return
	}
	report := &datamodel.Report{}
	actionCtx, actionCancel := context.WithTimeout(context.Background(), actionTimeoutForSize(input.size))
	defer actionCancel()
	if err := c.action.Handle(actionCtx, input.location, result, report); err != nil {
		inputLogger.Error("could not handle file action", slog.String(logErrorKey, err.Error()))
		ConsoleLogger.Error(fmt.Sprintf("could not handle file action for %s: %s", input.location, err.Error()))
	} else {
		inputLogger.Debug("file handled successfully")
	}
	c.addReport(report)
	c.finishAnalysis(input.location)
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

// extractionAnomaly turns an extract-error entry reported by the extractor
// (an anomaly of the archive: data after its end, a mismatch between what was
// listed and what was extracted) into an error.
func extractionAnomaly(e plugins.Extraction) error {
	for _, s := range e.Skipped {
		if s.Reason == datamodel.NotAnalyzedExtractError {
			return fmt.Errorf("the extractor reported an anomaly in %s", s.FileName)
		}
	}
	return nil
}

// tryExtract starts a recursive extraction for archive.
func (c *Connector) tryExtract(archive archiveToAnalyze) (err error) {
	archiveLogger := logger.With(slog.String("input file", archive.location), slog.String("sha256", archive.sha256))
	file := fileToAnalyze{
		location: archive.location,
		sha256:   archive.sha256,
		identity: archive.identity,
		input:    archive.input,
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
	checkErr := c.checkBeforeExtract(archivePath, archive.size, totalExtractedSize, totalExtractedFiles, depth, archiveLogger)
	if checkErr != nil {
		archiveLogger.Debug("file cannot be extracted", slog.String(logReasonKey, checkErr.Error()))
		file := archive
		if file.filename == "" {
			file.filename = file.location
		}
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
		// a plain file: submitting it as is would let its content through.
		archiveLogger.Error("archive extraction failed", slog.String("error", extractErr.Error()))
		err = fmt.Errorf("extract-error: %w", extractErr)
		return
	}
	if extractErr != nil {
		archiveLogger.Debug("error extracting file", slog.String("error", extractErr.Error())) // debug level, because files reaching that point are not necessarily extractable, due to the authorization of type 'application/octet-stream'
		file := archive
		if file.filename == "" {
			file.filename = file.location
		}
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
		input:           archive.input,
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

	if len(extractedFiles) == 0 && extraction.SkippedCount > 0 {
		// Members were left out and none was extracted: submitting the archive
		// whole would let those members through unanalyzed.
		err = fmt.Errorf("extract-error: %d members of the archive were not extracted and none was", extraction.SkippedCount)
		return
	}
	if len(extractedFiles) == 0 {
		file := archive
		if file.filename == "" {
			file.filename = file.location
		}
		err = c.sendForAnalyze(file, archiveLogger)
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
		c.onStartScanFile(archive.location, archive.sha256)
		if archiveResult := c.onScanFile(archive.location, archive.location, archive.sha256, true); archiveResult != nil {
			// Plugin filtered the archive, skip extraction processing and clean up temp folder.
			ok := c.archiveStatus.setArchiveResult(archiveID, *archiveResult)
			if !ok {
				archiveLogger.Warn("could not handle archive, not found in archive handler", slog.String("archive", archive.location))
				return
			}
			if finishErr := c.finishArchiveAnalysis(archiveID); finishErr != nil {
				archiveLogger.Error("could not finish filtered archive analysis", slog.String(logErrorKey, finishErr.Error()))
			}
			return
		}
		archive.archiveTopLocation = archive.location
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
		}
		err = c.recursiveExtract(subFile, depth, totalExtractedSize, totalExtractedFiles, fileLogger)
		if err != nil {
			if errors.Is(err, plugins.ErrExtractorUnavailable) {
				// Not a verdict on this archive: the top archive is left in place
				// without a final result, like on shutdown, instead of ending in
				// definitive error for a passing failure of the extractor.
				fileLogger.Error("recursive extraction abandoned, the extractor is unavailable", slog.String(logErrorKey, err.Error()))
				c.abandonArchive(archiveID, len(extractedFiles)-i, archiveLogger)
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
// result, and its folder goes as soon as the members already sent are done.
func (c *Connector) abandonArchive(archiveID string, unsent int, archiveLogger *slog.Logger) {
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
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
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
//   - size is above minimum extraction threshold
//   - total extracted size/files are below limits
//   - type is an accepted extractable type
//
// returns an error if any of the conditions are not met.
func (c *Connector) checkBeforeExtract(location string, size int64, totalExtractedSize *int64, totalExtractedFiles *int, depth int, logger *slog.Logger) (err error) {
	if depth >= c.config.RecursiveExtractMaxDepth {
		err = fmt.Errorf("max depth reached: %d", depth)
		return
	}

	if size <= c.config.ExtractMinThreshold {
		err = fmt.Errorf("file size (%vB) below extract threshold (%vB)", size, c.config.ExtractMinThreshold)
		return
	}

	if totalExtractedSize == nil {
		err = errors.New("totalExtractedSize is nil")
		return
	}
	// because size is added to totalExtractedSize after extraction completes, the actual
	// total may exceed RecursiveExtractMaxSize by up to one archive's extracted content.
	if *totalExtractedSize > c.config.RecursiveExtractMaxSize {
		err = fmt.Errorf("total extracted size (%vB) reached limit (%vB)", *totalExtractedSize, c.config.RecursiveExtractMaxSize)
		return
	}
	if totalExtractedFiles == nil {
		err = errors.New("totalExtractedFiles is nil")
		return
	}
	if *totalExtractedFiles > c.config.RecursiveExtractMaxFiles {
		err = fmt.Errorf("total extracted files (%v) reached limit (%v)", *totalExtractedFiles, c.config.RecursiveExtractMaxFiles)
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
		return
	}
	if started {
		// No onStartScanFile here: a sub-archive belongs to the scan of its
		// top-level archive and must not start a session of its own.
		if archiveResult := c.onScanFile(input.archiveLogical(), input.archiveLocation, input.archiveSHA256, true); archiveResult != nil {
			archiveResult.Filename = input.archiveLocation
			ok := c.archiveStatus.setArchiveResult(input.archiveID, *archiveResult)
			if !ok {
				archiveLogger.Warn("could not handle archive, not found in archive handler", slog.String("archive", input.archiveLocation))
				return
			}
			if finishErr := c.finishArchiveAnalysis(input.archiveID); finishErr != nil {
				archiveLogger.Error("could not finish archive analysis", slog.String(logErrorKey, finishErr.Error()))
			}
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
		c.finishAnalysis(status.archiveLocation)
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
		c.releaseInput(status.archiveLocation)
	}

	if newResult := c.onFileScanned(status.archiveLocation, status.result.SHA256, status.result); newResult != nil {
		status.result = *newResult
		// don't need to save it in status handler, because it's going to be deleted at func end
	}

	if runAction {
		if pathErr := c.checkPath(status.archiveLocation); pathErr != nil {
			refusePath(status.archiveLocation, pathErr)
			runAction = false
		}
	}

	if runAction {
		report := &datamodel.Report{}
		ctx, cancel := context.WithTimeout(context.Background(), actionTimeoutForSize(status.result.FileSize))
		defer cancel()
		err = c.action.Handle(ctx, status.archiveLocation, status.result, report)
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

func (c *Connector) analyzeFile(input fileToAnalyze) (result datamodel.Result) {
	fileLogger := logger.With(slog.String("file", input.location))

	defer func() {
		fileLogger.Debug("file handled", slog.Any("result", result))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), c.analysisTimeout())
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
		return
	}

	if input.size > c.config.MaxFileSize {
		result = datamodel.Result{
			Filename: input.filename,
			Location: input.location,
			SHA256:   input.sha256,
			FileSize: input.size,
			Error:    errFileTooBig,
		}
		return
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
	}
	return
}

// abortAnalysis ends an analysis without action nor report, still notifying plugins
// (e.g. session) that the scan started with onStartScanFile is over.
func (c *Connector) abortAnalysis(input fileToAnalyze, result datamodel.Result, err error) {
	result.Error = err
	c.releaseInput(input.location)
	c.onFileScanned(input.location, input.sha256, result)
	c.finishAnalysis(input.location)
}

func (c *Connector) addReport(report *datamodel.Report) {
	c.onReport(report)
	c.reportMutex.Lock()
	defer c.reportMutex.Unlock()
	c.reports = append(c.reports, report)
}

// Close stops Connector instance:
//  1. stop accepting new files
//  2. wait for already accepted files to finish
//  3. stop all workers
func (c *Connector) Close(ctx context.Context) {
	c.closeOnce.Do(func() {
		logger := logger.With(slog.String("operation", "Connector.Close()"))
		// Phase 1: stop accepting new files from ScanFile callers.
		logger.Debug("closing scanner")
		close(c.stopIncoming)

		closeWorkers := func() { c.stopOnce.Do(func() { close(c.stopWorker) }) }

		// Phase 2: wait for all accepted files to be fully processed
		// (including extraction and analysis of extracted files).
		// If Close's ctx is cancelled, force-stop workers so channel sends
		// unblock via the <-c.stopWorker select case and call finishAnalysis.
		stop := context.AfterFunc(ctx, closeWorkers)
		logger.Debug("waiting for scans to complete")
		c.scansWg.Wait()
		stop()

		// Phase 3: pipeline drained, stop all worker pools.
		logger.Debug("stopping all workers")
		closeWorkers()
		c.dispatchWg.Wait()
		c.extractWg.Wait()
		c.analysisWg.Wait()

		for _, plugin := range c.loadedPlugins {
			if closeErr := plugin.Close(ctx); closeErr != nil {
				logger.Error("failed to close plugin", slog.String(logErrorKey, closeErr.Error()))
			}
		}

		if closeErr := c.work.close(); closeErr != nil {
			logger.Error("failed to remove work directory", slog.String(logErrorKey, closeErr.Error()))
		}
	})
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
