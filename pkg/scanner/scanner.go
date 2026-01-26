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

	"github.com/gabriel-vasile/mimetype"
	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/quarantine"
	"golift.io/xtractr"
)

const (
	logReasonKey = "reason"
	logErrorKey  = "error"

	actionTimeout = 30 * time.Second

	defaultExtractMinThreshold int64 = 8 * 1000 // minimum size to try extraction, in bytes (8KB)
)

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
		"application/x-archive":             {}, // .ar
		"application/x-arj":                 {}, // .arj
		"application/vnd.ms-cab-compressed": {}, // .cab
		"application/x-cpio":                {}, // .cpio
		"application/x-iso9660-image":       {}, // .iso
		"application/x-qemu-disk":           {}, // .qcow, .qcow2
		"application/x-lha":                 {}, // .lha
		"application/x-lzh-compressed":      {}, // .lzh
		"application/vnd.rar":               {}, // .rar
		"application/x-virtualbox-vhd":      {}, // .vhd, .vhdx
		"application/x-7z-compressed":       {}, // .7z
		"application/x-xz":                  {}, // .xz, .tar.xz
		"application/x-bzip2":               {}, // .bz2, .tar.bz2
		"application/gzip":                  {}, // .gz, .tar.gz, .tgz
		"application/x-tar":                 {}, // .tar
		"application/x-lzma":                {}, // .lzma, .tar.lzma
		"application/vnd.ms-htmlhelp":       {}, // .chm
		"application/x-ms-wim":              {}, // .wim
		"application/x-compress":            {}, // .Z
		"application/zip":                   {}, // .zip
		"application/x-rpm":                 {}, // .rpm
		"application/x-apple-diskimage":     {}, // .dmg

		// mimetype fallback, kept to still try extraction (in case identification failed, or for specific raw file formats like flat VMDK)
		"application/octet-stream": {},

		// MIME types absent from default libmagic database
		"application/x-vmdk":           {}, // .vmdk
		"application/x-lzh":            {}, // .lzh
		"application/x-lzh-archive":    {}, // .lzh
		"application/x-rar-compressed": {}, // .rar
		"application/x-vhd":            {}, // .vhd, .vhdx
		"application/x-virtualbox-vdi": {}, // .vdi
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
	ScanPeriod               sdk.Duration
	Extract                  bool
	MaxFileSize              int64
	ExtractMinThreshold      int64 // only configurable for unit tests
	RecursiveExtractMaxDepth int
	RecursiveExtractMaxSize  int64
	RecursiveExtractMaxFiles int
	MoveTo                   string
	MoveFrom                 string
	PluginsConfigPath        string
	FollowSymlinks           bool
}

type fileToAnalyze struct {
	sha256          string
	location        string
	filename        string
	size            int64
	archiveID       string
	archiveLocation string
	archiveSHA256   string
	archiveSize     int64
}

type archiveToAnalyze struct {
	sha256   string
	location string
	size     int64
}

type Connector struct {
	submitter   Submitter
	quarantiner quarantine.Quarantiner

	started bool

	stopExtract chan struct{}
	stopWorker  chan struct{}

	config                 Config
	workerWg               sync.WaitGroup
	extractWg              sync.WaitGroup
	fileChan               chan fileToAnalyze
	archiveChan            chan archiveToAnalyze
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
	ongoingAnalysis        *sync.Map
	typesToExtract         map[string]struct{}
}

const (
	defaultMaxFileSize              int64 = 100 * 1024 * 1024
	defaultWorkers                        = 4
	defaultExtractWorkers                 = 2
	defaultRecursiveExtractMaxDepth       = 10
	defaultRecursiveExtractMaxSize  int64 = 5 * 1000 * 1000 * 1000 // 5GB
	defaultRecursiveExtractMaxFiles       = 10000
)

func NewConnector(config Config, quarantiner quarantine.Quarantiner, submitter Submitter) *Connector {
	if config.Workers < 1 {
		config.Workers = defaultWorkers
	}

	if config.ExtractWorkers < 1 {
		config.ExtractWorkers = defaultExtractWorkers
	}

	if config.MaxFileSize <= 0 {
		config.MaxFileSize = defaultMaxFileSize
	}

	if config.RecursiveExtractMaxDepth < 1 {
		config.RecursiveExtractMaxDepth = defaultRecursiveExtractMaxDepth
		logger.Debug("using default value for recursive_extract_max_depth", slog.Int("value", defaultRecursiveExtractMaxDepth))
	}

	if config.RecursiveExtractMaxSize <= 0 {
		config.RecursiveExtractMaxSize = defaultRecursiveExtractMaxSize
		logger.Debug("using default value for recursive_extract_max_size", slog.Int64("value", defaultRecursiveExtractMaxSize))
	}

	if config.RecursiveExtractMaxFiles < 1 {
		config.RecursiveExtractMaxFiles = defaultRecursiveExtractMaxFiles
		logger.Debug("using default value for recursive_extract_max_files", slog.Int("value", defaultRecursiveExtractMaxFiles))
	}

	if config.ExtractMinThreshold <= 0 {
		config.ExtractMinThreshold = defaultExtractMinThreshold
	}

	return &Connector{
		submitter:       submitter,
		quarantiner:     quarantiner,
		fileChan:        make(chan fileToAnalyze),
		archiveChan:     make(chan archiveToAnalyze),
		config:          config,
		archiveStatus:   newArchiveStatusHandler(),
		action:          newAction(config, quarantiner, EventHandler),
		generateReport:  datamodel.GenerateReport,
		ongoingAnalysis: new(sync.Map),
		stopExtract:     make(chan struct{}),
		stopWorker:      make(chan struct{}),
		typesToExtract:  extractableTypes(),
	}
}

func newAction(config Config, quarantiner quarantine.Quarantiner, eventHandler events.EventHandler) *MultiAction {
	action := NewMultiAction(eventHandler, &ReportAction{})
	if config.Actions.Log {
		action.Actions = append(action.Actions, &LogAction{logger: logger})
	}
	if config.Actions.Quarantine {
		action.Actions = append(action.Actions, NewQuarantineAction(quarantiner))
	}
	if config.Actions.Deleted {
		action.Actions = append(action.Actions, &RemoveFileAction{})
	}
	if config.Actions.Move {
		move, err := NewMoveAction(config.MoveTo, config.MoveFrom)
		if err == nil {
			action.Actions = append(action.Actions, move)
		} else {
			logger.Error("could not add move legit action", slog.String(logErrorKey, err.Error()))
		}
	}
	if config.Actions.Inform {
		action.Actions = append(action.Actions, &PrintAction{Verbose: config.Actions.Verbose, Out: config.Actions.InformDest})
	}
	action.Actions = append(action.Actions, config.CustomActions...)
	return action
}

func (c *Connector) Start() (err error) {
	c.started = true
	for range c.config.Workers {
		c.workerWg.Go(func() { c.worker() })
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
		FileMode:  0o755,
		DirMode:   0o755,
	}
	return xtractr.ExtractFile(xFile)
}

func (c *Connector) ScanFile(ctx context.Context, input string) (err error) {
	if !c.started {
		err = errors.New("connector is stopped")
		return
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

	defer func() {
		if err != nil {
			c.ongoingAnalysis.Delete(input)
		}
	}()

	fileSHA256, err := getFileSHA256(input)
	if err != nil {
		return
	}

	restored, err := c.checkFileRestored(ctx, input, fileSHA256, info.Size())
	if err != nil {
		return
	}
	if restored {
		inputLogger.Debug("consider file as safe, skip it", slog.String(logReasonKey, "restored"))
		return
	}

	// files which size is > ExtractMinThreshold and < c.config.MaxFileSize (usually 100MB) could be directly submitted to Detect,
	// but it has been decided to prefer extraction on host-connector side
	if info.Size() > c.config.ExtractMinThreshold && c.config.Extract {
		inputLogger.Debug("sending file to archive worker ...")
		select {
		case <-ctx.Done():
			return context.Canceled
		case c.archiveChan <- archiveToAnalyze{location: input, sha256: fileSHA256, size: info.Size()}:
			return
		}
	}

	select {
	case <-ctx.Done():
		return context.Canceled
	case c.fileChan <- fileToAnalyze{
		filename: input,
		location: input,
		sha256:   fileSHA256,
		size:     info.Size(),
	}:
		return
	}
}

func (c *Connector) checkFileRestored(ctx context.Context, location string, sha256 string, size int64) (restored bool, err error) {
	if c.quarantiner == nil {
		return
	}
	restored, err = c.quarantiner.IsRestored(ctx, sha256)
	if err != nil {
		return
	}
	if !restored {
		return
	}

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
	if err = c.action.Handle(ctx, location, res, report); err != nil {
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

	err = filepath.WalkDir(input, func(path string, d fs.DirEntry, walkErr error) (err error) {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return
		}

		err = c.ScanFile(ctx, path)
		if err != nil {
			logger.Error("could not scan file", slog.String("file", path), slog.String("err", err.Error()))
			return
		}
		return
	})
	return
}

func (c *Connector) worker() {
	for {
		select {
		case <-c.stopWorker:
			return
		case input := <-c.fileChan:
			inputLogger := logger.With(slog.String("file", input.location))
			if input.archiveID != "" {
				inputLogger.Debug("file has archive_id, handling ...")
				err := c.handleArchive(input)
				if err != nil {
					inputLogger.Error("could not handle file", slog.String("archive-id", input.archiveID), slog.String("archive location", input.archiveLocation), slog.String(logErrorKey, err.Error()))
				}
				continue
			}
			inputLogger.Debug("applying onStartScanFile() from plugins")
			c.onStartScanFile(input.location, input.sha256)
			result := c.handleFile(input)
			c.ongoingAnalysis.Delete(input.location)
			actualSHA256, err := getFileSHA256(input.location)
			if err != nil {
				inputLogger.Error("could not compute file SHA256, stop processing", slog.String("error", err.Error()))
				continue
			}
			if actualSHA256 != input.sha256 {
				inputLogger.Error("file SHA256 mismatch: current hash differs from analyzed version, stop processing", slog.String("actual sha256", actualSHA256), slog.String("input sha256", input.sha256))
				ConsoleLogger.Error(fmt.Sprintf("file %s SHA256 mismatch: current hash differs from analyzed version, stop processing", input.location))
				continue
			}

			if result.Error != nil {
				inputLogger.Error("could not handle file properly", slog.Any(logErrorKey, result.Error.Error()))
				ConsoleLogger.Error(fmt.Sprintf("could not handle file %s properly: %s", input.location, result.Error.Error()))
			}
			if newres := c.onFileScanned(input.location, input.sha256, result); newres != nil {
				result = *newres
			}
			report := &datamodel.Report{}
			ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
			if err := c.action.Handle(ctx, input.location, result, report); err != nil {
				inputLogger.Error("could not handle file action", slog.String(logErrorKey, err.Error()))
				ConsoleLogger.Error(fmt.Sprintf("could not handle file action for %s: %s", input.location, err.Error()))
			} else {
				inputLogger.Debug("file handled successfully")
			}
			cancel()
			c.addReport(report)
		}
	}
}

func (c *Connector) extractWorker() {
	for {
		select {
		case <-c.stopExtract:
			return
		case archive := <-c.archiveChan:
			if err := c.tryExtract(archive); err != nil {
				ConsoleLogger.Error(fmt.Sprintf("could not handle file %s, error: %s", archive.location, err.Error()))
			}
		}
	}
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
				return
			}
			continue
		}
		relPath, relErr := filepath.Rel(outputDir, fileLocation)
		if relErr != nil {
			relPath = fileLocation
		}
		subFile := fileToAnalyze{
			location:        fileLocation,
			archiveID:       archiveID,
			filename:        relPath,
			archiveLocation: archive.location,
			sha256:          fileSHA256,
			archiveSHA256:   archive.sha256,
			size:            fileSize,
			archiveSize:     archive.size,
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
				return
			}
			continue
		}
	}
	return
}

func (c *Connector) sendForAnalyze(file fileToAnalyze, logger *slog.Logger) (err error) {
	logger.Debug("sending file to worker for analyse...")
	select {
	// don't check stopExtract signal here. during shutdown, analysis workers
	// remain active while ongoing extractions complete, so files can still be sent for analysis.
	case <-c.stopWorker:
		err = context.Canceled
	case c.fileChan <- file:
		logger.Debug("file successfully sent to worker")
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
		// Buffer de 128KB (au lieu de 32KB par défaut)
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

func (c *Connector) handleArchive(input fileToAnalyze) (err error) {
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
			return
		}
	}
	result := c.handleFile(input)
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
		c.ongoingAnalysis.Delete(status.archiveLocation)
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
		ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
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

func (c *Connector) handleFile(input fileToAnalyze) (result datamodel.Result) {
	fileLogger := logger.With(slog.String("file", input.location))

	defer func() {
		fileLogger.Debug("file handled", slog.Any("result", result))
	}()

	// GDetect cache
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
		location = input.archiveLocation
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
		Filename:    input.filename,
		FileType:    gdetectResult.FileType,
		Location:    input.location,
		SHA256:      input.sha256,
		Malware:     gdetectResult.Malware,
		Malwares:    gdetectResult.Malwares,
		FileSize:    gdetectResult.FileSize,
		GMalwareURL: urlExpertView,
	}

	for _, f := range gdetectResult.Files {
		result.AnalyzedVolume += f.Size
	}

	switch {
	case gdetectResult.Error != "":
		analysisError := gdetectResult.Error
		if len(gdetectResult.Errors) > 0 {
			errors := make([]string, 0, len(gdetectResult.Errors))
			for k, v := range gdetectResult.Errors {
				errors = append(errors, fmt.Sprintf("%s: %s", k, v))
			}
			analysisError = strings.Join(errors, ",")
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
	if !c.started {
		return
	}
	c.started = false

	close(c.stopExtract)
	c.extractWg.Wait()

	close(c.stopWorker)
	c.workerWg.Wait()

	for _, plugin := range c.loadedPlugins {
		if closeErr := plugin.Close(ctx); closeErr != nil {
			logger.Error("failed to close plugin", slog.String(logErrorKey, closeErr.Error()))
		}
	}
}

func (c *Connector) GetLogger() *slog.Logger {
	return logger
}

func (c *Connector) GetLogLevel() *slog.LevelVar {
	return LogLevel
}

func (c *Connector) GetConsoleLogger() *slog.Logger {
	return ConsoleLogger
}
