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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/units"
	"github.com/gabriel-vasile/mimetype"
	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
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
)

// actionTimeoutForSize computes a timeout proportional to file size,
// accounting for I/O-heavy actions like quarantine (read + encrypt + write).
func actionTimeoutForSize(fileSize int64) time.Duration {
	return time.Duration(fileSize/(1024*1024*1024)+1) * actionTimeoutPerGB
}

var (
	LogLevel                          = &slog.LevelVar{}
	logger                            = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: LogLevel}))
	EventHandler  events.EventHandler = events.NoopEventHandler{}
	ConsoleLogger                     = slog.New(slog.DiscardHandler)
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

type Submitter interface {
	gdetect.ControllerGDetectSubmitter
	ExtractExpertViewURL(result *gdetect.Result) (urlExpertView string, err error)
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
	ExtractMinThreshold      int64 // only configurable for unit tests
	RecursiveExtractMaxDepth int
	RecursiveExtractMaxSize  int64
	RecursiveExtractMaxFiles int
	MoveTo                   string
	MoveFrom                 string
	FollowSymlinks           bool
}

type fileToAnalyze struct {
	sha256             string
	location           string
	filename           string
	size               int64
	archiveTopLocation string
	archiveID          string
	archiveLocation    string
	archiveSHA256      string
	archiveSize        int64
}

type archiveToAnalyze struct {
	sha256   string
	location string
	size     int64
}

type Connector struct {
	submitter   Submitter
	quarantiner quarantine.Quarantiner

	closeOnce sync.Once

	stopIncoming chan struct{} // closed first in Close() to reject new inputChan sends
	stopWorker   chan struct{}
	stopOnce     sync.Once

	config Config

	dispatchWg sync.WaitGroup
	extractWg  sync.WaitGroup
	analysisWg sync.WaitGroup

	dispatchChan chan string
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
	onFileScannedCbs       []plugins.OnFileScanned
	onReportCbs            []plugins.OnReport
	generateReport         plugins.GenerateReport
	ongoingAnalysis        sync.Map
	scansWg                sync.WaitGroup // tracks files from ScanFile entry to ongoingAnalysis removal
	typesToExtract         map[string]struct{}
}

const restoredCheckTimeout = 10 * time.Second

func NewConnector(cfg Config, quarantiner quarantine.Quarantiner, submitter Submitter) (*Connector, error) {
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

	return &Connector{
		submitter:      submitter,
		quarantiner:    quarantiner,
		dispatchChan:   make(chan string, cfg.Workers),
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
var ExtractFile = func(archiveLocation, outputDir string) (size int64, files []string, volumes []string, err error) {
	xFile := &xtractr.XFile{
		FilePath:  archiveLocation,
		OutputDir: outputDir,
		FileMode:  0o600,
		DirMode:   0o700,
	}
	return xtractr.ExtractFile(xFile)
}

func (c *Connector) ScanFile(ctx context.Context, input string) (err error) {
	select {
	case <-c.stopIncoming:
		err = errors.New("connector is shutting down")
		return
	default:
	}

	input = filepath.Clean(input)
	inputLogger := logger.With(slog.String("input file", input))

	// Use Lstat to check if it's a symlink without following it
	linfo, err := os.Lstat(input)
	if err != nil {
		return
	}

	// Handle symbolic links
	if linfo.Mode()&os.ModeSymlink != 0 {
		if !c.config.FollowSymlinks {
			inputLogger.Debug("skip file", slog.String(logReasonKey, "symbolic link"))
			return
		}
	}

	// Now get info about the actual file (following symlink if needed)
	info, err := os.Stat(input)
	if err != nil {
		return
	}

	if info.IsDir() {
		return c.scanDir(ctx, input)
	}

	if info.Size() == 0 {
		inputLogger.Warn("skip file", slog.String(logReasonKey, "size 0"))
		return
	}

	if _, loaded := c.ongoingAnalysis.LoadOrStore(input, struct{}{}); loaded {
		inputLogger.Debug("skip file", slog.String(logReasonKey, "ongoing analysis"))
		return
	}
	c.scansWg.Add(1)

	defer func() {
		if err != nil {
			c.finishAnalysis(input)
		}
	}()

	select {
	case <-ctx.Done():
		return context.Canceled
	case <-c.stopIncoming:
		return errors.New("connector is shutting down")
	case c.dispatchChan <- input:
		return
	}
}

func (c *Connector) handleRestoredFile(location string, sha256 string, size int64) (err error) {
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
		err = errors.New("file is empty")
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
		if d.IsDir() {
			return nil
		}

		err := c.ScanFile(ctx, path)
		if err != nil {
			logger.Error("could not scan file", slog.String("file", path), slog.String("err", err.Error()))
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
				case location := <-c.dispatchChan:
					c.finishAnalysis(location)
				default:
					return
				}
			}
		case location := <-c.dispatchChan:
			c.dispatchFile(location)
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
func (c *Connector) prepareFile(location string) (file fileToAnalyze, skip bool) {
	inputLogger := logger.With(slog.String("file", location))

	info, err := os.Stat(location)
	if err != nil {
		inputLogger.Error("could not stat file, stop processing", slog.String("error", err.Error()))
		skip = true
		return
	}

	fileSHA256, err := getFileSHA256(location)
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
		err = c.handleRestoredFile(location, fileSHA256, info.Size())
		if err != nil {
			inputLogger.Error("could not handle restored file", slog.String(logErrorKey, err.Error()))
			return
		}
		return
	}

	file = fileToAnalyze{
		filename: location,
		location: location,
		sha256:   fileSHA256,
		size:     info.Size(),
	}
	return
}

// finishAnalysis removes the file from ongoingAnalysis and signals the pipeline
// that this top-level file is fully done. Only files registered via ScanFile
// (LoadOrStore) are present in the map; extracted sub-files are no-ops.
func (c *Connector) finishAnalysis(location string) {
	if _, loaded := c.ongoingAnalysis.LoadAndDelete(location); loaded {
		c.scansWg.Done()
	}
}

// dispatchFile performs prepareFile (SHA256, size, restored check) and routes the
// file to either extractChan (for extraction) or analysisChan (for analysis).
func (c *Connector) dispatchFile(location string) {
	inputLogger := logger.With(slog.String("file", location))

	input, skip := c.prepareFile(location)
	if skip {
		c.finishAnalysis(location)
		return
	}

	// Route to extraction if applicable
	if input.size > c.config.ExtractMinThreshold && c.config.Extract {
		archive := archiveToAnalyze{location: location, sha256: input.sha256, size: input.size}
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
	actualSHA256, err := getFileSHA256(input.location)
	if err != nil {
		inputLogger.Error("could not compute file SHA256, stop processing", slog.String("error", err.Error()))
		c.finishAnalysis(input.location)
		return
	}
	if actualSHA256 != input.sha256 {
		inputLogger.Error("file SHA256 mismatch: current hash differs from analyzed version, stop processing", slog.String("actual sha256", actualSHA256), slog.String("input sha256", input.sha256))
		ConsoleLogger.Error(fmt.Sprintf("file %s SHA256 mismatch: current hash differs from analyzed version, stop processing", input.location))
		c.finishAnalysis(input.location)
		return
	}

	if result.Error != nil {
		inputLogger.Error("could not handle file properly", slog.Any(logErrorKey, result.Error.Error()))
		ConsoleLogger.Error(fmt.Sprintf("could not handle file %s properly: %s", input.location, result.Error.Error()))
	}
	if newres := c.onFileScanned(input.location, input.sha256, result); newres != nil {
		result = *newres
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

// tryExtract starts a recursive extraction for archive.
func (c *Connector) tryExtract(archive archiveToAnalyze) (err error) {
	archiveLogger := logger.With(slog.String("input file", archive.location), slog.String("sha256", archive.sha256))
	file := fileToAnalyze{
		location: archive.location,
		sha256:   archive.sha256,
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
	checkErr := c.checkBeforeExtract(archive.location, archive.size, totalExtractedSize, totalExtractedFiles, depth, archiveLogger)
	if checkErr != nil {
		archiveLogger.Debug("file cannot be extracted", slog.String(logReasonKey, checkErr.Error()))
		file := archive
		if file.filename == "" {
			file.filename = file.location
		}
		err = c.sendForAnalyze(file, archiveLogger)
		return
	}

	outputDir, outputDirErr := os.MkdirTemp(os.TempDir(), archive.sha256)
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
	extractedSize, extractedFiles, _, extractErr := ExtractFile(archive.location, outputDir)
	if extractErr != nil {
		archiveLogger.Debug("error extracting file", slog.String("error", extractErr.Error())) // debug level, because files reaching that point are not necessarily extractable, due to the authorization of type 'application/octet-stream'
		file := archive
		if file.filename == "" {
			file.filename = file.location
		}
		err = c.sendForAnalyze(file, archiveLogger)
		return
	}
	*totalExtractedSize += extractedSize
	*totalExtractedFiles += len(extractedFiles) // add all extracted files in total, including sub-archives

	archiveLogger.Debug("archive extraction successful", slog.String("extracted files", fmt.Sprintf("%v", extractedFiles)))
	eStatus := archiveStatus{
		archiveLocation: archive.location,
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
			c.archiveStatus.addArchiveResult(archiveID, *archiveResult)
			if finishErr := c.finishArchiveAnalysis(archiveID); finishErr != nil {
				archiveLogger.Error("could not finish filtered archive analysis", slog.String(logErrorKey, finishErr.Error()))
			}
			return
		}
		archive.archiveTopLocation = archive.location
	}

	depth += 1
	// Note: files should be directly streamed to channel and not accumulated in memory
	for _, fileLocation := range extractedFiles {
		fileLogger := archiveLogger.With(slog.Int("depth", depth), slog.String("subfile", fileLocation))

		var fileSHA256 string
		var fileSize int64
		fileSHA256, fileSize, err = c.checkExtractedFile(fileLocation)
		if err != nil {
			fileLogger.Warn("skipping file", slog.String(logReasonKey, err.Error()))
			if removeErr := os.Remove(fileLocation); removeErr != nil {
				fileLogger.Warn("could not remove file")
			}
			finished, ok := c.archiveStatus.decreaseTotal(archiveID)
			if !ok {
				continue
			}
			if finished {
				archiveLogger.Warn("all files from archive skipped")
				err = nil
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
			archiveLocation:    archive.location,
			sha256:             fileSHA256,
			archiveSHA256:      archive.sha256,
			size:               fileSize,
			archiveSize:        archive.size,
			archiveTopLocation: archive.archiveTopLocation,
		}
		err = c.recursiveExtract(subFile, depth, totalExtractedSize, totalExtractedFiles, fileLogger)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				// Shutdown requested. No cleanup needed here:
				// - Temp folder: keep it, files may have been sent to workers
				// - archiveStatus: keep it, workers may still process pending files
				// Resources will be released when process exits or on next startup.
				return
			}
			fileLogger.Error("recursive extraction failed", slog.String(logErrorKey, err.Error()))
			finished, ok := c.archiveStatus.decreaseTotal(archiveID)
			if !ok {
				continue
			}
			if finished {
				err = nil
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
	hash := sha256.New()
	f, err := os.Open(filepath.Clean(location))
	if err != nil {
		return
	}
	defer func() {
		if e := f.Close(); e != nil {
			logger.Warn("could not close file correctly", slog.String("file", location), slog.String("error", e.Error()))
		}
	}()

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

func (c *Connector) analyzeArchiveFile(input fileToAnalyze) (err error) {
	archiveLogger := logger.With(slog.String("archive-id", input.archiveID), slog.String("archive location", input.archiveLocation))
	status, started, ok := c.archiveStatus.getArchiveStatus(input.archiveID, true)
	if status.finished {
		archiveLogger.Debug("archive already analyzed", slog.String("archive-id", input.archiveID))
		return
	}
	if !ok {
		archiveLogger.Warn("could not handle archive, not found in archive handler", slog.String("archive", input.archiveLocation))
		return
	}
	if started {
		c.onStartScanFile(input.archiveLocation, input.archiveSHA256)
		if archiveResult := c.onScanFile(input.archiveLocation, input.archiveLocation, input.archiveSHA256, true); archiveResult != nil {
			ok := c.archiveStatus.addArchiveResult(input.archiveID, *archiveResult)
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

	status, _, ok := c.archiveStatus.getArchiveStatus(archiveID, false)
	if !ok {
		archiveLogger.Warn("could not handle archive, not found in archive handler")
		return
	}
	archiveLogger = logger.With(slog.String("archive location", status.archiveLocation))

	defer func() {
		c.finishAnalysis(status.archiveLocation)
	}()

	isSubArchive := status.parentArchive.statusID != ""

	// SHA256 check, action and report only for top-level archives
	if !isSubArchive {
		currentSHA256, getSHAErr := getFileSHA256(status.archiveLocation)
		if getSHAErr != nil {
			err = fmt.Errorf("could not compute archive sha256, err: %w", getSHAErr)
			return
		}
		if currentSHA256 != status.result.SHA256 {
			archiveLogger.Error("file SHA256 mismatch: current hash differs from analyzed version, stop processing", slog.String("current sha256", currentSHA256), slog.String("input sha256", status.result.SHA256))
			ConsoleLogger.Error(fmt.Sprintf("file %s SHA256 mismatch: current hash differs from analyzed version, stop processing", status.archiveLocation))
			return
		}
	}

	if newResult := c.onFileScanned(status.archiveLocation, status.result.SHA256, status.result); newResult != nil {
		status.result = *newResult
		// don't need to save it in status handler, because it's going to be deleted at func end
	}

	if !isSubArchive {
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.config.Timeout))
	defer cancel()

	opts := c.config.WaitOpts
	opts.Filename = input.location

	fileLogger.Debug("applying onScanFile() from plugins")
	res := c.onScanFile(input.filename, input.location, input.sha256, false)
	if res != nil {
		result = *res
		return
	}

	if input.size > c.config.MaxFileSize {
		result = datamodel.Result{
			Filename: input.filename,
			Location: input.location,
			SHA256:   input.sha256,
			FileSize: input.size,
			Error:    errors.New("file is too big to be analyzed"),
		}
		return
	}
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
	gdetectResult, err := c.submitter.WaitForFile(ctx, input.location, opts)
	httpError := new(gdetect.HTTPError)
	urlError := new(url.Error)
	switch {

	case err == nil:
		if errEvent := EventHandler.NotifyResolution(ctx, "last analysis succeeded", events.GMalwareConfigError, events.GMalwareError); errEvent != nil {
			fileLogger.Error("cannot push resolution event", slog.String("error", errEvent.Error()))
		}

	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, gdetect.ErrTimeout):
		ConsoleLogger.Error(fmt.Sprintf("could not analyze file %s, error: %s", input.location, err.Error()))

	case errors.As(err, httpError):
		err := fmt.Errorf("%d: %s : %s", httpError.Code, httpError.Status, httpError.Body)
		if errEvent := EventHandler.NotifyError(ctx, events.GMalwareError, err); errEvent != nil {
			fileLogger.Error("cannot push error event", slog.String("error", errEvent.Error()))
		}

	case errors.As(err, &urlError):
		err := fmt.Errorf("error %s: %w", urlError.Op, urlError.Err)
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

func (c *Connector) addReport(report *datamodel.Report) {
	c.onReport(report)
	c.reportMutex.Lock()
	defer c.reportMutex.Unlock()
	c.reports = append(c.reports, report)
}

func (c *Connector) Close(ctx context.Context) {
	c.closeOnce.Do(func() {
		// Phase 1: stop accepting new files from ScanFile callers.
		close(c.stopIncoming)

		closeWorkers := func() { c.stopOnce.Do(func() { close(c.stopWorker) }) }

		// Phase 2: wait for all accepted files to be fully processed
		// (including extraction and analysis of extracted files).
		// If Close's ctx is cancelled, force-stop workers so channel sends
		// unblock via the <-c.stopWorker select case and call finishAnalysis.
		stop := context.AfterFunc(ctx, closeWorkers)
		c.scansWg.Wait()
		stop()

		// Phase 3: pipeline drained, stop all worker pools.
		closeWorkers()
		c.dispatchWg.Wait()
		c.extractWg.Wait()
		c.analysisWg.Wait()

		for _, plugin := range c.loadedPlugins {
			if closeErr := plugin.Close(ctx); closeErr != nil {
				logger.Error("failed to close plugin", slog.String(logErrorKey, closeErr.Error()))
			}
		}
	})
}

func (c *Connector) GetLogger() *slog.Logger {
	return logger
}

func (c *Connector) GetConsoleLogger() *slog.Logger {
	return ConsoleLogger
}
