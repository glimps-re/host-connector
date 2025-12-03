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

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/quarantine"
	"golift.io/xtractr"
)

const (
	actionTimeout = 30 * time.Second
)

var (
	LogLevel                          = &slog.LevelVar{}
	logger                            = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: LogLevel}))
	EventHandler  events.EventHandler = events.NoopEventHandler{}
	ConsoleLogger                     = slog.New(slog.DiscardHandler)
)

const (
	logReasonKey = "reason"
	logErrorKey  = "error"
)

type Submitter interface {
	gdetect.ControllerGDetectSubmitter
	ExtractExpertViewURL(result *gdetect.Result) (urlExpertView string, err error)
}

type Config struct {
	QuarantineFolder  string
	Workers           int
	ExtractWorkers    int
	Password          string
	Timeout           sdk.Duration
	WaitOpts          gdetect.WaitForOptions
	Actions           Actions
	CustomActions     []Action
	ScanPeriod        sdk.Duration
	Extract           bool
	MaxFileSize       int64
	MoveTo            string
	MoveFrom          string
	PluginsConfigPath string
	FollowSymlinks    bool
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

	// workerCtx     context.Context
	// cancelWorker  context.CancelFunc
	// archiveCtx    context.Context
	// cancelArchive context.CancelFunc

	config             Config
	workerWg           sync.WaitGroup
	extractWg          sync.WaitGroup
	fileChan           chan fileToAnalyze
	archiveChan        chan archiveToAnalyze
	action             Action
	reportMutex        sync.Mutex
	reports            []*datamodel.Report
	archiveStatus      *archiveStatusHandler
	loadedPlugins      []plugins.Plugin
	onStartScanFileCbs []plugins.OnStartScanFile
	onScanFileCbs      []plugins.OnScanFile
	onFileScannedCbs   []plugins.OnFileScanned
	onReportCbs        []plugins.OnReport
	generateReport     plugins.GenerateReport
	ongoingAnalysis    *sync.Map
}

const (
	defaultMaxFileSize    int64 = 100 * 1024 * 1024
	defaultWorkers              = 4
	defaultExtractWorkers       = 2
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

// ExtractFile could be used to override xtract.ExtractFile method
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
		logger.Debug("consider file as safe, skip it", slog.String(logReasonKey, "restored"))
		return
	}

	if info.Size() > c.config.MaxFileSize && c.config.Extract {
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
				err := c.handleArchive(input)
				if err != nil {
					inputLogger.Error("could not handle file", slog.String("archive-id", input.archiveID), slog.String(logErrorKey, err.Error()))
				}
				continue
			}
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

func (c *Connector) tryExtract(archive archiveToAnalyze) (err error) {
	archiveLogger := logger.With(slog.String("input file", archive.location), slog.String("sha256", archive.sha256))

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

	_, files, _, extractErr := ExtractFile(archive.location, outputDir)
	if extractErr != nil {
		select {
		case <-c.stopWorker:
			return context.Canceled
		case c.fileChan <- fileToAnalyze{sha256: archive.sha256, location: archive.location, filename: archive.location, size: archive.size}:
			return
		}
	}

	archiveLogger.Info("extract files from archive", slog.Int("files", len(files)))
	eStatus := archiveStatus{
		archiveName: archive.location,
		result: datamodel.Result{
			SHA256:            archive.sha256,
			MaliciousSubfiles: make(map[string]datamodel.Result),
			Malware:           false,
			Malwares:          []string{},
			FileSize:          archive.size,
		},
		analyzed:  0,
		total:     len(files),
		tmpFolder: outputDir,
	}

	archiveID := c.archiveStatus.addStatus(eStatus)
	needCleanUp = false

	// Stream files directly to channel instead of accumulating in memory
	for _, f := range files {
		fileLogger := archiveLogger.With(slog.String("subfile", f))
		fileSHA256, fileSize, err := c.checkExtractedFile(f)
		if err != nil {
			fileLogger.Warn("skip archive inner file", slog.String("file", f), slog.String(logReasonKey, err.Error()))
			if e := os.Remove(f); e != nil {
				fileLogger.Warn("could not remove archive inner file", slog.String("file", f))
			}
			finished, ok := c.archiveStatus.decreaseTotal(archiveID)
			if !ok {
				continue
			}
			if finished {
				archiveLogger.Warn("all files from archive were skipped")
				return nil
			}
			continue
		}
		relPath, relErr := filepath.Rel(outputDir, f)
		if relErr != nil {
			relPath = f
		}
		fileToSend := fileToAnalyze{
			location:        f,
			archiveID:       archiveID,
			filename:        relPath,
			archiveLocation: archive.location,
			sha256:          fileSHA256,
			archiveSHA256:   archive.sha256,
			size:            fileSize,
			archiveSize:     archive.size,
		}
		select {
		case <-c.stopWorker:
			return context.Canceled
		case c.fileChan <- fileToSend:
			continue
		}
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
	finished, archiveFound := c.archiveStatus.addInnerFileResult(input.archiveID, input.filename, result)
	if !archiveFound {
		archiveLogger.Warn("could not handle archive, not found in archive handler", slog.String("archive", input.archiveLocation))
		return
	}

	if finished {
		err = c.finishArchiveAnalysis(input)
		if err != nil {
			return
		}
	}
	return
}

func (c *Connector) finishArchiveAnalysis(input fileToAnalyze) (err error) {
	archiveLogger := logger.With(slog.String("archive-id", input.archiveID), slog.String("archive location", input.archiveLocation))
	defer func() {
		c.ongoingAnalysis.Delete(input.archiveLocation)
	}()
	status, _, ok := c.archiveStatus.getArchiveStatus(input.archiveID, false)
	if !ok {
		archiveLogger.Warn("could not handle archive, not found in archive handler", slog.String("archive", input.archiveLocation))
		return
	}
	actualSHA256, getSHAErr := getFileSHA256(input.archiveLocation)
	if getSHAErr != nil {
		err = fmt.Errorf("could not compute archive sha256, err: %w", getSHAErr)
		return
	}
	if actualSHA256 != input.archiveSHA256 {
		archiveLogger.Error("file SHA256 mismatch: current hash differs from analyzed version, stop processing", slog.String("actual sha256", actualSHA256), slog.String("input sha256", input.sha256))
		ConsoleLogger.Error(fmt.Sprintf("file %s SHA256 mismatch: current hash differs from analyzed version, stop processing", input.location))
	}
	if newres := c.onFileScanned(input.archiveLocation, input.archiveSHA256, status.result); newres != nil {
		status.result = *newres
	}
	report := &datamodel.Report{}

	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()

	err = c.action.Handle(ctx, status.archiveName, status.result, report)
	if err != nil {
		return
	}

	c.addReport(report)
	removeErr := os.RemoveAll(status.tmpFolder)
	if removeErr != nil {
		archiveLogger.Error("could not remove temp folder",
			slog.String("archive", input.archiveID),
			slog.String("folder", status.tmpFolder),
			slog.String(logErrorKey, removeErr.Error()),
		)
	}
	c.archiveStatus.deleteStatus(input.archiveID)
	return
}

func (c *Connector) handleFile(input fileToAnalyze) (result datamodel.Result) {
	fileLogger := logger.With(slog.String("file", input.location))
	// GDetect cache
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.config.Timeout))
	defer cancel()

	opts := c.config.WaitOpts
	opts.Filename = input.location

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
	case len(gdetectResult.Errors) > 0:
		errors := make([]string, 0, len(gdetectResult.Errors))
		for k, v := range gdetectResult.Errors {
			errors = append(errors, fmt.Sprintf("%s: %s", k, v))
		}
		analysisError := strings.Join(errors, ",")
		ConsoleLogger.Error(fmt.Sprintf("error in %s analysis, error: %s", input.location, analysisError))
		result.AnalysisError = analysisError
	case gdetectResult.Error != "":
		ConsoleLogger.Error(fmt.Sprintf("error in %s analysis, error: %s", input.location, gdetectResult.Error))
		result.AnalysisError = gdetectResult.Error
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
