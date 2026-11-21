// Package main implements a session-based file grouping and reporting plugin.
//
// Groups files by directory structure, tracks their processing, and generates
// consolidated reports per session with optional file cleanup.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/alecthomas/units"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/internal/pathutil"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/quarantine"
)

// SessionPlugin groups files into sessions based on directory structure.
type SessionPlugin struct {
	config        Config
	sessions      map[string]*Session
	mutex         sync.RWMutex
	hcc           plugins.HCContext
	workDir       string
	stop          chan struct{}
	done          chan struct{}
	started       bool
	logger        *slog.Logger
	consoleLogger *slog.Logger

	// cleanupQueue feeds the one goroutine that removes the empty folders of
	// the sessions whose report is written, so that no report ever waits for it;
	// nil when the option is off. cleanupDone is closed when that goroutine ends.
	cleanupQueue   chan string
	cleanupDone    chan struct{}
	cleanupDropped atomic.Bool
	removeDirs     emptyDirsRemover

	// runCtx is cancelled by Close: the attempts of the monitor stop and give
	// their sessions back to the closing list.
	runCtx    context.Context
	cancelRun context.CancelFunc

	// closing holds the sessions whose report is not written yet; closeMu
	// guards it and known.
	closeMu sync.Mutex
	closing []*closingSession
	// held is the batch the monitor is working on, which closing does not hold
	// meanwhile; stopping is set once Close took the sessions, after which the
	// monitor puts nothing back.
	held     *heldBatch
	stopping bool
	// closed is closed by the Close of the run, as the very last thing it does:
	// Init waits for it, so that a Close still running is not overtaken by the next
	// run.
	closed chan struct{}
	// gen counts the runs (Init after Close on the same instance): a monitor of an
	// older run parks nothing in the current one.
	gen uint64
	// onMonitorWait is only set by tests: Close calls it, with no lock held, when
	// it starts to wait for a monitor that has not ended.
	onMonitorWait func()
	known         map[string]string
	fallback      atomic.Bool
	backlog       atomic.Bool

	// maxSpool is max_spool_size in bytes (0: no limit, only in tests that do not
	// go through Init). errBudget is shared by all the sessions. spoolFailing is
	// set while the last write to a spool failed, for the console event.
	maxSpool     int64
	errBudget    errorBudget
	spoolFailing atomic.Bool

	// now and tickEvery are replaced in tests.
	now       func() time.Time
	tickEvery time.Duration
}

// Config defines session behavior and directory monitoring settings.
type Config struct {
	Depth      int           `mapstructure:"depth"`
	Delay      time.Duration `mapstructure:"delay"`
	RootFolder string        `mapstructure:"root_folder"`
	Exports    []string      `mapstructure:"exports"`
	// ReportTimeout bounds each attempt to generate and write the report of one
	// session.
	ReportTimeout time.Duration `mapstructure:"report_timeout"`
	// ReportRetries is how many failed attempts are retried (one per tick)
	// before the JSON fallback is written.
	ReportRetries int `mapstructure:"report_retries"`
	// InflightTimeout is how long files that never end, or files waiting for a
	// worker, can hold a session open since its last activity.
	InflightTimeout time.Duration `mapstructure:"inflight_timeout"`
	// RemoveEmptyDirs removes the empty folders left below a session once its
	// report is written (Linux only).
	RemoveEmptyDirs bool `mapstructure:"remove_empty_dirs"`
	// CleanupTimeout bounds the removal of the empty folders of one session.
	CleanupTimeout time.Duration `mapstructure:"cleanup_timeout"`
	// MaxDuration closes a session that has been open this long, whatever its
	// activity: a regular depositor does not hold one open forever.
	MaxDuration time.Duration `mapstructure:"max_duration"`
	// MaxSpoolSize closes a session whose reports, on disk, reach this size
	// (a size such as "1GiB", at least 1MiB).
	MaxSpoolSize string `mapstructure:"max_spool_size"`
}

const (
	defaultReportTimeout   = 2 * time.Minute
	defaultReportRetries   = 3
	defaultInflightTimeout = 24 * time.Hour
	defaultCleanupTimeout  = 2 * time.Minute
	defaultMaxDuration     = 24 * time.Hour
	defaultMaxSpoolSize    = "1GiB"
	minSpoolSize           = 1 << 20

	// maxClosing bounds the sessions kept waiting for their report after an
	// attempt: past it the oldest get their fallback at once.
	maxClosing = 64

	// maxCleanupQueue bounds the sessions waiting for the removal of their
	// empty folders; past it the removal is skipped for the newest.
	maxCleanupQueue = 64

	// cleanupStopWait is the longest Close waits for a removal of empty folders
	// that does not end when cancelled.
	cleanupStopWait = time.Second
	// maxKnownErrors bounds the files remembered as failed after their session
	// closed.
	maxKnownErrors = 4096
	// fallbackBound bounds the JSON fallbacks written in one go while the
	// connector runs.
	fallbackBound = 10 * time.Second
	// stopReserve is the most of the deadline of Close kept for the JSON
	// fallbacks.
	stopReserve = 10 * time.Second
	// closeMargin is kept between the end of the fallbacks and the end of the
	// grace the connector gives to the plugins, so that the last write is not
	// cut with the process; fallbackFloor is the least time the fallbacks get.
	// The floor may go past the grace when the deadline expired long ago: a
	// fallback is written by an atomic rename, so a process ended meanwhile leaves
	// no half-written report.
	closeMargin   = 300 * time.Millisecond
	fallbackFloor = 250 * time.Millisecond
	// lostEventBound bounds the one notification of the reports lost at stop,
	// whatever their number.
	lostEventBound = 100 * time.Millisecond
	// maxMonitorWait caps the wait of Close for the monitor, so that a slow one
	// does not eat the time of the generators.
	maxMonitorWait = time.Second
	// maxLostIDs bounds the session IDs named in the notification of lost
	// reports; the log names them all.
	maxLostIDs = 10

	// maxReportBase bounds the base name of a report (without its extension) so
	// that the name stays below 255 bytes whatever the folder is called.
	maxReportBase = 200
	// reportMode is the mode of a report: the people it is meant for read it.
	reportMode = 0o644

	// Console events: reports written as JSON because the generator fails, too
	// many sessions waiting for their report, a report lost.
	fallbackEvent = "session-report-fallback"
	backlogEvent  = "session-report-backlog"
	lostEvent     = "session-report-lost"
	// spoolEvent is raised while a spool cannot be written (disk full).
	spoolEvent = "session-spool-error"
	// eventBound bounds the notification of a spool failure, raised from the
	// callbacks of the pipeline.
	eventBound = time.Second
)

// closingSession is a closed session whose report is not written yet. written
// holds the report files already written, by target, so that a new attempt
// writes the missing ones only.
type closingSession struct {
	session  *Session
	attempts int
	written  map[string]struct{}
}

func newClosing(s *Session) *closingSession {
	return &closingSession{session: s, written: make(map[string]struct{})}
}

// Session tracks files and reports for a specific directory. Once closed it no
// longer changes: its reports are written as they are, and what comes next opens
// another session.
type Session struct {
	ID           string
	Paths        []string
	StartTime    time.Time
	LastActivity time.Time
	// InFlight holds the files started and not yet scanned: it is bounded by the
	// parallelism of the pipeline, and by the inflight timeout.
	InFlight map[string]*inflightEntry
	// pending holds the reports in error, by file: a later report of the same
	// file replaces them, so they wait in memory (bounded for the plugin by
	// errBudget); every other report goes to the spool.
	pending map[string]pendingReport
	spool   *spool
	limits  spoolLimits
	// spoolErr is the failure that ended the use of the spool; healthy tells that
	// the last write to it succeeded. forced is why the session must close now.
	spoolErr error
	healthy  bool
	forced   forceReason
	// spilled tells that a report in error went to the spool for lack of memory
	// budget; spillNoted that the plugin said so.
	spilled, spillNoted bool
	// encodeErr is the last failure to encode a report, taken by the status.
	encodeErr error
	released  bool
	closed    bool
	clock     func() time.Time
	mutex     sync.RWMutex
}

// pendingReport is a report in error kept in memory, with its encoded size.
type pendingReport struct {
	report datamodel.Report
	size   int64
}

// spoolLimits is where a session keeps its reports and how much it may hold.
type spoolLimits struct {
	dir     string
	maxSize int64
	budget  *errorBudget
	logger  *slog.Logger
}

// forceReason says why a session closes without waiting for its idle delay.
type forceReason string

const (
	forceSpoolSize  forceReason = "max_spool_size reached"
	forceSpoolError forceReason = "its spool cannot be written"
	forceDuration   forceReason = "max_duration reached"
)

// inflightEntry is a file started in a session. retry marks a new attempt of a
// file that already failed in this session: it does not count as activity.
type inflightEntry struct {
	start time.Time
	retry bool
}

var (
	_ plugins.Plugin    = &SessionPlugin{}
	_ plugins.Validator = &SessionPlugin{}

	// HCPlugin is the exported plugin instance.
	HCPlugin SessionPlugin
)

const (
	sessionIDLogKey = "session_id"
	filepathLogKey  = "file_path"
)

func (p *SessionPlugin) GetDefaultConfig() (config any) {
	config = &Config{
		Depth:           1,
		Delay:           15 * time.Minute,
		ReportTimeout:   defaultReportTimeout,
		ReportRetries:   defaultReportRetries,
		InflightTimeout: defaultInflightTimeout,
		RemoveEmptyDirs: true,
		CleanupTimeout:  defaultCleanupTimeout,
		MaxDuration:     defaultMaxDuration,
		MaxSpoolSize:    defaultMaxSpoolSize,
	}
	return
}

// Validate checks the configuration like Init does and declares the export
// directories, without any effect.
func (p *SessionPlugin) Validate(rawConfig any, vc plugins.ValidationContext) error {
	config, ok := rawConfig.(*Config)
	if !ok {
		return errors.New("bad config passed to session plugin")
	}
	return checkConfig(config, vc, false)
}

// checkConfig is shared by Validate and Init: root_folder must not be the base
// of the work directory, and the export directories are declared to the core,
// which refuses one under a monitored path.
func checkConfig(config *Config, vc plugins.ValidationContext, warn bool) error {
	switch {
	case config.ReportTimeout <= 0:
		return fmt.Errorf("report_timeout %s must be positive", config.ReportTimeout)
	case config.InflightTimeout <= 0:
		return fmt.Errorf("inflight_timeout %s must be positive", config.InflightTimeout)
	case config.ReportRetries < 0:
		return fmt.Errorf("report_retries %d must not be negative", config.ReportRetries)
	case config.RemoveEmptyDirs && config.CleanupTimeout <= 0:
		return fmt.Errorf("cleanup_timeout %s must be positive", config.CleanupTimeout)
	case vc.GetWorkDir() == "":
		return errors.New("the connector has no work directory: the session plugin keeps its reports there")
	case config.MaxDuration <= 0:
		return fmt.Errorf("max_duration %s must be positive", config.MaxDuration)
	}
	if _, err := parseSpoolSize(config.MaxSpoolSize); err != nil {
		return err
	}
	if warn && config.RemoveEmptyDirs && !cleanupSupported {
		msg := "session: remove_empty_dirs is not supported on this system: the empty folders are left"
		vc.GetLogger().Warn(msg)
		vc.GetConsoleLogger().Warn(msg)
	}
	if warn && config.InflightTimeout < config.Delay {
		msg := fmt.Sprintf("session: inflight_timeout %s is shorter than delay %s: files waiting never hold a session open", config.InflightTimeout, config.Delay)
		vc.GetLogger().Warn(msg)
		vc.GetConsoleLogger().Warn(msg)
	}
	workDir := vc.GetWorkDir()
	if workDir != "" && pathutil.Same(filepath.Dir(workDir), config.RootFolder) {
		return fmt.Errorf("root_folder %q is the base of the connector work directory: set work_dir elsewhere", config.RootFolder)
	}

	if warn && workDir != "" && pathutil.Under(config.RootFolder, workDir) {
		msg := fmt.Sprintf("session: the connector work directory %q is under root_folder %q: it is ignored by the sessions, but a work_dir outside root_folder is safer", workDir, config.RootFolder)
		vc.GetLogger().Warn(msg)
		vc.GetConsoleLogger().Warn(msg)
	}
	for _, export := range config.Exports {
		if err := vc.DeclareOutputDir(export); err != nil {
			return fmt.Errorf("exports: %w", err)
		}
	}
	return nil
}

// parseSpoolSize reads max_spool_size, which must be at least minSpoolSize.
func parseSpoolSize(value string) (int64, error) {
	size, err := units.ParseStrictBytes(value)
	if err != nil {
		return 0, fmt.Errorf("max_spool_size %q: %w", value, err)
	}
	if size < minSpoolSize {
		return 0, fmt.Errorf("max_spool_size %q must be at least 1MiB", value)
	}
	return size, nil
}

// Init initializes the plugin, registers callbacks, and starts session monitoring.
func (p *SessionPlugin) Init(rawConfig any, hcc plugins.HCContext) error {
	config, ok := rawConfig.(*Config)
	if !ok {
		return errors.New("bad config passed to session plugin")
	}

	if err := checkConfig(config, hcc, true); err != nil {
		return err
	}
	if err := p.waitPreviousRun(); err != nil {
		return err
	}
	workDir := hcc.GetWorkDir()

	root, err := filepath.Abs(config.RootFolder)
	if err != nil {
		return fmt.Errorf("root_folder %q: %w", config.RootFolder, err)
	}
	if err = hcc.SetTrackingOwners(root, config.Depth); err != nil {
		return fmt.Errorf("session plugin: %w", err)
	}

	maxSpool, err := parseSpoolSize(config.MaxSpoolSize)
	if err != nil {
		return err
	}
	p.config = *config
	p.config.RootFolder = root
	p.workDir = workDir
	p.maxSpool = maxSpool
	p.mutex.Lock()
	p.sessions = make(map[string]*Session)
	p.mutex.Unlock()
	p.hcc = hcc
	p.resetRun()
	p.logger = hcc.GetLogger().With(slog.String("plugin", "session"))
	p.consoleLogger = hcc.GetConsoleLogger()

	hcc.RegisterOnStartScanFile(p.OnStartScanFile)
	hcc.RegisterWithWaitForOptions(p.WaitForOptions)
	hcc.RegisterOnFileScanned(p.OnFileScanned)
	hcc.RegisterOnReport(p.OnReport)

	p.startCleanup()
	go p.sessionMonitor(p.runCtx, p.stop, p.done, p.runGeneration())

	p.logger.Info("plugin initialized",
		slog.Int("depth", config.Depth),
		slog.String("delay", config.Delay.String()),
		slog.String("root_folder", config.RootFolder),
	)
	p.consoleLogger.Info(fmt.Sprintf("session plugin initialized, depth: %d, delay: %s, root_folder: %s",
		config.Depth, config.Delay.String(), config.RootFolder))
	p.started = true
	return nil
}

// Close stops session monitoring, then writes the report of every session, open
// or waiting. The attempts of the monitor are cancelled first and give their
// sessions back; the monitor is waited for half of the time the fallbacks have,
// one second at most. A ctx with no deadline waits for it without bound.
// The sessions of a monitor that does not return in that time are lost, named
// in the log, since only it knows them.
func (p *SessionPlugin) Close(ctx context.Context) error {
	if !p.started {
		return nil
	}
	// Deferred first, so that it runs last: after p.started is false.
	defer close(p.closed)
	if p.cancelRun != nil {
		p.cancelRun()
	}
	close(p.stop)
	fbCtx, cancel := fallbackContext(ctx)
	defer cancel()
	if !p.waitMonitor(ctx, fbCtx) {
		p.logger.Warn("the session monitor did not end in time, the reports are written anyway")
	}
	p.closeAllSessions(ctx, fbCtx)
	p.waitCleanup(ctx)
	p.started = false
	return nil
}

// waitMonitor waits for the monitor to end, up to the midpoint between now and
// the end of fbCtx: the other half is kept for the fallbacks. It tells whether
// the monitor ended.
func (p *SessionPlugin) waitMonitor(ctx, fbCtx context.Context) bool {
	select {
	case <-p.done:
		return true
	default:
	}
	if p.onMonitorWait != nil {
		p.onMonitorWait()
	}
	limit := ctx
	if end, ok := fbCtx.Deadline(); ok {
		var cancel context.CancelFunc
		limit, cancel = context.WithTimeout(context.WithoutCancel(ctx), min(time.Until(end)/2, maxMonitorWait))
		defer cancel()
	}
	select {
	case <-p.done:
		return true
	case <-limit.Done():
		return false
	}
}

// waitCleanup gives the cleanup goroutine, already cancelled, a moment to end:
// a file system call that ignores its context must not hold up the stop.
func (p *SessionPlugin) waitCleanup(ctx context.Context) {
	if p.cleanupDone == nil {
		return
	}
	timer := time.NewTimer(cleanupStopWait)
	defer timer.Stop()
	select {
	case <-p.cleanupDone:
	case <-timer.C:
		p.logger.Warn("a removal of empty folders is still running at stop: it is left behind")
	case <-ctx.Done():
		p.logger.Warn("a removal of empty folders is still running at stop: it is left behind")
	}
}

// attach runs op on the session of file, asking for a new one when the session
// found was closed meanwhile; ensure creates the session when there is none. It
// returns the session op ran on, if any, and whether it was just created.
func (p *SessionPlugin) attach(file string, ensure bool, op func(s *Session, probe bool) (bool, sessionStatus)) (session *Session, created bool) {
	for range 2 {
		session, created = p.getSession(file, ensure)
		if session == nil {
			return session, created
		}
		if ok, st := op(session, p.spoolFailing.Load()); ok {
			p.afterWrite(session, st)
			return session, created
		}
	}
	return nil, false
}

// afterWrite acts on what a write to a session showed: it logs what the
// session could not encode or had to spill, closes the session at once when its
// spool is full or broken, and raises or resolves the console event of the spool
// write failures.
func (p *SessionPlugin) afterWrite(s *Session, st sessionStatus) {
	if st.encodeErr != nil {
		p.logger.Error("a report cannot be encoded, it is kept in memory as it is",
			slog.String(sessionIDLogKey, s.ID), slog.String("error", st.encodeErr.Error()))
	}
	if st.spilled {
		p.logger.Warn("the memory kept for reports in error is spent: they go to the spool, a later success of the same file adds a second line",
			slog.String(sessionIDLogKey, s.ID), slog.Int("budget_bytes", maxPendingErrors))
	}
	if st.forced == "" {
		if st.works && p.spoolFailing.Load() && p.spoolFailing.CompareAndSwap(true, false) && p.hcc != nil {
			ctx, cancel := context.WithTimeout(context.Background(), eventBound)
			defer cancel()
			p.hcc.NotifyResolution(ctx, spoolEvent, "the session reports are written again")
		}
		return
	}
	closed := p.forceClose(s)
	if st.forced != forceSpoolError {
		if closed {
			p.logger.Info("session closed at once, the next deposit opens a new one",
				slog.String(sessionIDLogKey, s.ID), slog.String("reason", string(st.forced)))
		}
		return
	}
	msg := fmt.Sprintf("session %q: its reports cannot be written to the spool (%v): the session is closed and reported with what it holds", s.ID, st.spoolErr)
	p.logger.Error(msg, slog.String(sessionIDLogKey, s.ID))
	p.consoleLogger.Error(msg)
	if p.spoolFailing.CompareAndSwap(false, true) && p.hcc != nil {
		ctx, cancel := context.WithTimeout(context.Background(), eventBound)
		defer cancel()
		p.hcc.NotifyError(ctx, spoolEvent, errors.New(msg))
	}
}

// forceClose takes a session out of the open ones and puts it in the list of
// those waiting for their report, without waiting for the monitor. It tells
// whether it did: the monitor may have taken the session already, and a stop
// that has begun leaves it to closeAllSessions, which still has the time to
// write its report. Lock order: mutex, then closeMu.
func (p *SessionPlugin) forceClose(s *Session) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.sessions[s.ID] != s {
		return false
	}
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	// A guard: a session still in p.sessions means the stop has not taken the lists
	// yet, so this cannot happen while the lock order holds.
	if p.stopping {
		return false
	}
	s.closeSession()
	delete(p.sessions, s.ID)
	p.closing = append(p.closing, newClosing(s))
	return true
}

// OnStartScanFile adds files to their appropriate sessions based on directory path.
// A new attempt at a file that failed, whose session is closed, does not open
// another session: its outcome is reported when it ends well, by OnReport.
func (p *SessionPlugin) OnStartScanFile(file string, sha256 string) {
	session, created := p.attach(file, !p.knownError(file, sha256), func(s *Session, _ bool) (bool, sessionStatus) { return s.addFile(file, sha256), sessionStatus{} })
	if session != nil {
		p.logger.Debug("file added to session",
			slog.String(filepathLogKey, file),
			slog.String(sessionIDLogKey, session.ID),
			slog.String("sha256", sha256),
		)
		if created {
			p.consoleLogger.Info(fmt.Sprintf("session %q started", session.ID))
		}
	}
}

func (p *SessionPlugin) WaitForOptions(opts *gdetect.WaitForOptions, location string) {
	session, _ := p.getSession(location, false)
	if session == nil {
		return
	}
	opts.Tags = append(opts.Tags, fmt.Sprintf("session-%s-%d", session.ID, session.StartTime.Unix()))
}

// OnFileScanned marks files as completed in their sessions. A file that ends in
// error is entered in the session at once, with a minimal report (some end
// without any report, an abandoned archive): in a new session when its own was
// closed, unless it already failed and was reported.
func (p *SessionPlugin) OnFileScanned(file string, sha256 string, result datamodel.Result) (newResult *datamodel.Result) {
	failed := result.Error != nil
	session, _ := p.attach(file, failed && !p.knownError(file, sha256), func(s *Session, probe bool) (bool, sessionStatus) {
		if !s.markFileCompleted(file) {
			return false, sessionStatus{}
		}
		if !failed {
			return true, sessionStatus{}
		}
		return s.addFileError(file, sha256, result.Error.Error(), probe)
	})
	if session == nil {
		return
	}
	if failed {
		p.logger.Warn("file scan completed with error",
			slog.String(filepathLogKey, file),
			slog.String(sessionIDLogKey, session.ID),
			slog.Any("error", result.Error.Error()),
		)
		return
	}
	p.logger.Debug("file scan completed successfully",
		slog.String(filepathLogKey, file),
		slog.String(sessionIDLogKey, session.ID),
	)
	return
}

// OnReport adds scan reports to their sessions for consolidated reporting. A
// report is always attached: when its session was closed meanwhile (a long
// action) a new one is opened and will write a complementary report. Only a
// repeated failure of a file already reported as failed opens nothing.
func (p *SessionPlugin) OnReport(rep *datamodel.Report) {
	session, _ := p.attach(rep.Filename, rep.Error == "" || leftInput(*rep) || !p.knownError(rep.Filename, rep.SHA256), func(s *Session, probe bool) (bool, sessionStatus) { return s.addReport(*rep, probe) })
	if session == nil {
		return
	}
	if rep.Error == "" || leftInput(*rep) {
		p.forgetError(rep.Filename)
	}
	p.logger.Debug("report added to session",
		slog.String(filepathLogKey, rep.Filename),
		slog.String(sessionIDLogKey, session.ID),
		slog.Bool("malicious", rep.Malicious),
		slog.String("sha256", rep.SHA256),
	)
	p.consoleLogger.Debug(fmt.Sprintf("add report for %q to session %q (malicious: %v)", rep.Filename, session.ID, rep.Malicious))
}

func (p *SessionPlugin) knownError(file, sha256 string) bool {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	known, ok := p.known[file]
	return ok && known == sha256
}

func (p *SessionPlugin) forgetError(file string) {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	delete(p.known, file)
}

// leftInput tells that the disposition of the file was done: it was quarantined,
// deleted or moved, so it is not in INPUT any more and will not be tried again.
func leftInput(rep datamodel.Report) bool {
	return rep.Action == datamodel.Quarantined || rep.Deleted || rep.MovedTo != ""
}

// rememberErrors keeps the files of a closed session that ended in error and are
// still in INPUT, to be retried: a retry that fails again opens no new session.
func (p *SessionPlugin) rememberErrors(s *Session) {
	_, held := s.view()
	failed := make(map[string]string, len(held))
	for path, h := range held {
		// Reports kept in memory past the budget after a spool failure are not all
		// failures. A file that left INPUT (quarantined, deleted, moved) is not
		// retried: the same bytes dropped again are a new file and must get their
		// session.
		if h.report.Error != "" && !leftInput(h.report) {
			failed[path] = h.report.SHA256
		}
	}
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	if p.known == nil {
		p.known = make(map[string]string)
	}
	for path, sha := range failed {
		if len(p.known) >= maxKnownErrors {
			for k := range p.known {
				delete(p.known, k)
				break
			}
		}
		p.known[path] = sha
	}
}

func (p *SessionPlugin) getSession(filePath string, ensure bool) (session *Session, created bool) {
	if p.workDir != "" && pathutil.Under(p.workDir, filePath) {
		return
	}
	if !pathutil.Under(p.config.RootFolder, filePath) {
		return
	}
	relPath, err := filepath.Rel(p.config.RootFolder, filePath)
	if err != nil {
		return
	}

	parts := strings.Split(relPath, string(filepath.Separator))
	// Remove the filename (last part) to get only directory parts
	if len(parts) <= p.config.Depth {
		return
	}

	// Build session ID from the first 'depth' directory parts (excluding filename)
	sessionParts := parts[:p.config.Depth]
	sessionID := strings.Join(sessionParts, "/")

	p.mutex.Lock()
	defer p.mutex.Unlock()
	session, exists := p.sessions[sessionID]
	switch {
	case exists:
		return
	case ensure:
		p.closeMu.Lock()
		stopping := p.stopping
		p.closeMu.Unlock()
		if stopping {
			p.logger.Warn("a file arrived after the stop took the sessions: it is in no session report", slog.String(filepathLogKey, filePath))
			return nil, false
		}
		created = true
		sessionPaths := make([]string, 0, len(p.config.Exports))
		for _, v := range p.config.Exports {
			sessionPaths = append(sessionPaths, filepath.Join(v, sessionID))
		}
		session = &Session{
			ID:           sessionID,
			Paths:        sessionPaths,
			StartTime:    p.nowTime(),
			LastActivity: p.nowTime(),
			InFlight:     make(map[string]*inflightEntry),
			pending:      make(map[string]pendingReport),
			limits:       spoolLimits{dir: p.spoolDir(), maxSize: p.maxSpool, budget: &p.errBudget, logger: p.logger},
			clock:        p.nowTime,
		}
		p.sessions[sessionID] = session
		p.logger.Info("new session created",
			slog.String(sessionIDLogKey, sessionID),
			slog.String("export_paths", strings.Join(sessionPaths, ",")),
			slog.String("start_time", session.StartTime.Format(time.RFC3339)),
		)
	default:
		return
	}
	return
}

func (p *SessionPlugin) nowTime() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

func (p *SessionPlugin) tick() time.Duration {
	if p.tickEvery > 0 {
		return p.tickEvery
	}
	return 5 * time.Second
}

// resetRun starts a new run: the lists of sessions waiting and of known errors are
// emptied, the generation moves on, and the channels and the context of the
// monitor are renewed. A monitor of an earlier run keeps the ones it was started
// with.
func (p *SessionPlugin) resetRun() {
	p.closeMu.Lock()
	p.closing, p.known = nil, make(map[string]string)
	p.held, p.stopping = nil, false
	p.gen++
	p.closeMu.Unlock()
	p.stop = make(chan struct{})
	p.done = make(chan struct{})
	p.closed = make(chan struct{})
	p.cleanupQueue, p.cleanupDone = nil, nil
	p.runCtx, p.cancelRun = context.WithCancel(context.Background())
}

// previousRunWait bounds how long Init waits for the goroutines of a previous
// run to end; replaced in tests.
var previousRunWait = 2 * time.Second

// errPreviousRun is what Init returns while goroutines of the previous run are
// still going.
var errPreviousRun = errors.New("the previous run of the session plugin has not ended")

// waitPreviousRun waits, for previousRunWait in all, for the monitor and the
// cleanup goroutine of the previous run to end, and for its Close to return. A new run must not start beside
// them: they would work with the configuration, the sessions and the lists of
// the new one.
func (p *SessionPlugin) waitPreviousRun() error {
	timer := time.NewTimer(previousRunWait)
	defer timer.Stop()
	for _, ended := range []chan struct{}{p.done, p.cleanupDone, p.closed} {
		if ended == nil {
			continue
		}
		select {
		case <-ended:
		case <-timer.C:
			return errPreviousRun
		}
	}
	return nil
}

// spoolDir is the folder of the spool files of the sessions, in the work
// directory: Validate and Init refuse a connector that has none.
func (p *SessionPlugin) spoolDir() string {
	if p.workDir == "" {
		return ""
	}
	return filepath.Join(p.workDir, datamodel.SessionSpoolDir)
}

func (s *Session) nowTime() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

// addFile, markFileCompleted, addFileError and addReport tell false when the
// session is closed: the caller asks for another one.
func (s *Session) addFile(filePath, sha256 string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.closed {
		return false
	}

	now := s.nowTime()
	held, failed := s.pending[filePath]
	retry := failed && held.report.SHA256 == sha256
	s.InFlight[filePath] = &inflightEntry{start: now, retry: retry}
	if !retry {
		s.LastActivity = now
	}
	return true
}

func (s *Session) markFileCompleted(filePath string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.closed {
		return false
	}

	if entry, exists := s.InFlight[filePath]; exists {
		delete(s.InFlight, filePath)
		if !entry.retry {
			s.LastActivity = s.nowTime()
		}
	}
	return true
}

// closeSession freezes the session: nothing is added to it any more.
func (s *Session) closeSession() {
	s.mutex.Lock()
	s.closed = true
	s.mutex.Unlock()
}

// pendingFiles asks the core how many files detected under the folder of the
// session wait for a worker or for their stability.
func (p *SessionPlugin) pendingFiles(s *Session) int {
	if p.hcc == nil {
		return 0
	}
	return p.hcc.PendingFiles(filepath.Join(p.config.RootFolder, filepath.FromSlash(s.ID)))
}

// readyForClosure tells whether the session can be closed: nothing in flight,
// no file detected under its folder waiting, and no activity for the delay. The
// session is closed anyway once it was idle for the inflight timeout, whatever
// holds it. A session that is ready is frozen at once.
func (p *SessionPlugin) readyForClosure(s *Session) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := p.nowTime()
	for path, e := range s.InFlight {
		if now.Sub(e.start) >= p.config.InflightTimeout {
			p.logger.Warn("a file that never ended is dropped from the session",
				slog.String(sessionIDLogKey, s.ID), slog.String(filepathLogKey, path))
			delete(s.InFlight, path)
		}
	}
	if s.forced == "" && p.config.MaxDuration > 0 && now.Sub(s.StartTime) >= p.config.MaxDuration {
		s.forced = forceDuration
	}
	if s.forced != "" {
		p.logger.Info("session closed at once, the next deposit opens a new one",
			slog.String(sessionIDLogKey, s.ID), slog.String("reason", string(s.forced)))
		s.closed = true
		return true
	}
	idle := now.Sub(s.LastActivity)
	if idle >= p.config.InflightTimeout {
		if inFlight, pending := len(s.InFlight), p.pendingFiles(s); inFlight > 0 || pending > 0 {
			p.logger.Warn("session closed with files still unprocessed: they will open a new session",
				slog.String(sessionIDLogKey, s.ID), slog.Int("in_flight", inFlight), slog.Int("pending", pending))
		}
		s.closed = true
		return true
	}
	if len(s.InFlight) > 0 || idle < p.config.Delay || p.pendingFiles(s) > 0 {
		return false
	}
	s.closed = true
	return true
}

// sessionMonitor runs until stop is closed, then closes done. It takes its
// context and channels as parameters: Init may renew the ones of the plugin while
// a monitor of an earlier run, left behind by a Close with a deadline, is still
// ending.
func (p *SessionPlugin) sessionMonitor(ctx context.Context, stop <-chan struct{}, done chan<- struct{}, gen uint64) {
	defer close(done)

	ticker := time.NewTicker(p.tick())
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			p.checkSessions(ctx, gen)
		}
	}
}

// reportSource is what the report of a session is made by.
type reportSource int

const (
	// viaGenerator is the report generator of the connector (a PDF with the
	// report plugin).
	viaGenerator reportSource = iota
	// viaJSON is the plain JSON report, written when the generator fails.
	viaJSON
	// viaRaw is the spool as it is, JSON Lines: the last resort when even the
	// JSON report cannot be made.
	viaRaw
)

// fallbackDeadline is the end of the time the JSON fallbacks of a stop have:
// the grace the connector gives to the plugins past ctxDeadline, less a margin,
// and never less than fallbackFloor after now.
func fallbackDeadline(ctxDeadline, now time.Time) time.Time {
	deadline := ctxDeadline.Add(plugins.CloseGrace - closeMargin)
	return later(deadline, now.Add(fallbackFloor))
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// fallbackContext returns a context, detached from the cancellation of ctx,
// that ends at fallbackDeadline. Without a deadline in ctx there is no end to
// anchor on: it is ctx itself, and the stop is bounded by whoever cancels it.
func fallbackContext(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return ctx, func() {}
	}
	return context.WithDeadline(context.WithoutCancel(ctx), fallbackDeadline(deadline, time.Now()))
}

// closeAllSessions writes the report of every session, open or waiting. The
// generators get the deadline of ctx less a reserve (half of what is left, at
// most stopReserve); the JSON fallbacks, under fbCtx, may use the grace of the
// connector past that deadline. The time is shared by all the sessions: those
// not reached when it is over are lost and counted. The sessions the monitor
// still holds are lost too. It never asks the core for pending files.
func (p *SessionPlugin) closeAllSessions(ctx, fbCtx context.Context) {
	p.mutex.Lock()
	var all []*closingSession
	for id, session := range p.sessions {
		session.closeSession()
		all = append(all, newClosing(session))
		delete(p.sessions, id)
	}
	// The stop is marked before p.mutex is released: a session created after
	// this point is refused (see getSession), so none escapes both lists. Lock
	// order: mutex, then closeMu.
	p.closeMu.Lock()
	all = slices.Concat(p.closing, all)
	p.closing = nil
	var pending []*closingSession
	if held := p.held; held != nil {
		held.taken = true
		pending, held.pending = held.pending, nil
		p.held = nil
	}
	p.stopping = true
	p.closeMu.Unlock()
	p.mutex.Unlock()
	var lostSet lostSessions
	onLost := func(cs *closingSession, cause error) {
		p.logLost(cs, cause)
		lostSet.add(cs.session.ID)
	}
	heldCount := len(pending)
	for _, cs := range pending {
		onLost(cs, errMonitorHeld)
	}

	genCtx := ctx
	if deadline, ok := ctx.Deadline(); ok {
		if left := time.Until(deadline); left > 0 {
			var cancel context.CancelFunc
			genCtx, cancel = context.WithDeadline(ctx, deadline.Add(-min(left/2, stopReserve)))
			defer cancel()
		}
	}
	var written, lost, skipped int
	for _, cs := range all {
		p.logClosing(cs)
		if fbCtx.Err() != nil {
			onLost(cs, fbCtx.Err())
			lost++
			skipped++
			continue
		}
		if p.finish(genCtx, fbCtx, cs, onLost) {
			written++
		} else {
			lost++
		}
	}
	if skipped > 0 {
		p.logger.Warn("the time of the stop is over, sessions not attempted", slog.Int("sessions", skipped))
	}
	p.notifyLost(fbCtx, lostSet)
	p.logger.Info("sessions closed at stop", slog.Int("sessions", len(all)+heldCount), slog.Int("reports_written", written), slog.Int("failures", lost+heldCount))
}

// finish writes the report of a session through the generator, then through the
// JSON fallback if that fails. It tells whether the report was written.
func (p *SessionPlugin) finish(genCtx, fbCtx context.Context, cs *closingSession, onLost lostFunc) bool {
	err := p.tryReport(genCtx, cs)
	if err == nil {
		return true
	}
	return p.fallbackOrLose(fbCtx, cs, err, onLost)
}

// tryReport makes one attempt, bounded by report_timeout, at the report of a
// session through the generator.
func (p *SessionPlugin) tryReport(ctx context.Context, cs *closingSession) error {
	attempt, cancel := context.WithTimeout(ctx, p.config.ReportTimeout)
	defer cancel()
	err := p.writeSessionReport(attempt, cs, viaGenerator)
	if err == nil {
		p.reported(cs.session)
	}
	return err
}

func (p *SessionPlugin) reported(s *Session) {
	p.rememberErrors(s)
	p.freeSession(s)
	p.queueCleanup(s.ID)
}

// freeSession frees the memory and the spool of a session whose report is written
// or lost.
func (p *SessionPlugin) freeSession(s *Session) {
	if err := s.release(); err != nil {
		p.logger.Warn("cannot remove the spool of a session", slog.String(sessionIDLogKey, s.ID), slog.String("error", err.Error()))
	}
}

// startCleanup starts the goroutine that removes empty folders, if the option
// is set and the system supports it.
func (p *SessionPlugin) startCleanup() {
	if !p.config.RemoveEmptyDirs || !cleanupSupported {
		return
	}
	p.removeDirs = removeEmptyDirs
	p.cleanupQueue = make(chan string, maxCleanupQueue)
	p.cleanupDone = make(chan struct{})
	go p.cleanupLoop(p.runCtx, p.cleanupQueue, p.cleanupDone)
}

// queueCleanup asks for the removal of the empty folders of a session. It never
// waits, and does nothing once the plugin is stopping: a report is never held
// back by a cleanup, and a cleanup never runs in the time of Close.
func (p *SessionPlugin) queueCleanup(id string) {
	if p.cleanupQueue == nil || p.runCtx.Err() != nil {
		return
	}
	select {
	case p.cleanupQueue <- id:
	default:
		if p.cleanupDropped.CompareAndSwap(false, true) {
			p.logger.Warn("too many sessions wait for the removal of their empty folders: some are left", slog.Int("queue", maxCleanupQueue))
		}
	}
}

// cleanupLoop takes its context and channels as parameters, for the same reason
// as sessionMonitor.
func (p *SessionPlugin) cleanupLoop(ctx context.Context, queue <-chan string, done chan<- struct{}) {
	defer close(done)
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-queue:
			if len(queue) == 0 {
				p.cleanupDropped.Store(false)
			}
			p.cleanup(ctx, id)
		}
	}
}

// cleanup removes the empty folders below the folder of a session within
// cleanup_timeout. The root folder, the folder of the session and the work
// directory stay.
func (p *SessionPlugin) cleanup(parent context.Context, id string) {
	ctx, cancel := context.WithTimeout(parent, p.config.CleanupTimeout)
	defer cancel()
	stats, err := p.removeDirs(ctx, p.config.RootFolder, filepath.FromSlash(id), p.config.Delay, p.workDir)
	attrs := []any{slog.String(sessionIDLogKey, id), slog.Int("removed", stats.removed), slog.Int("kept", stats.kept), slog.Int("failed", stats.failed)}
	switch {
	case errors.Is(err, errTooDeep):
		p.logger.Warn("the removal of the empty folders of a session is incomplete: part of the tree is too deep", append(attrs, slog.String("error", err.Error()))...)
	case err != nil:
		p.logger.Warn("the removal of the empty folders of a session stopped", append(attrs, slog.String("error", err.Error()))...)
	case stats.failed > 0:
		p.logger.Warn("empty folders of a session could not be removed", append(attrs, slog.String("first_error", stats.firstErr.Error()))...)
	case stats.removed > 0:
		p.logger.Info("empty folders removed", attrs...)
	}
}

// fallbackOrLose writes the JSON report of a session after cause made the normal
// one fail. When that fails too the report is lost: said loudly, never retried.
func (p *SessionPlugin) fallbackOrLose(ctx context.Context, cs *closingSession, cause error, onLost lostFunc) bool {
	p.logger.Error("the session report failed, a JSON fallback is written",
		slog.String(sessionIDLogKey, cs.session.ID), slog.String("error", cause.Error()))
	err := p.writeFallback(ctx, cs)
	if err == nil {
		p.reported(cs.session)
		if p.fallback.CompareAndSwap(false, true) {
			p.hcc.NotifyError(ctx, fallbackEvent, fmt.Errorf("session reports could not be generated, JSON reports are written instead: %w", cause))
		}
		return true
	}
	onLost(cs, err)
	return false
}

// writeFallback writes the JSON report of a session, and when that fails the
// spool as it is: a report is not lost while the spool can still be copied.
func (p *SessionPlugin) writeFallback(ctx context.Context, cs *closingSession) error {
	err := p.writeSessionReport(ctx, cs, viaJSON)
	if err == nil {
		return nil
	}
	p.logger.Error("the JSON report failed, the spool is copied as it is",
		slog.String(sessionIDLogKey, cs.session.ID), slog.String("error", err.Error()))
	if rawErr := p.writeSessionReport(ctx, cs, viaRaw); rawErr != nil {
		return errors.Join(err, rawErr)
	}
	return nil
}

// lostFunc is told of each session whose report could not be written.
type lostFunc = func(cs *closingSession, cause error)

// errMonitorHeld is why the report of a session held by the monitor at stop is
// lost: the monitor did not give it back in time.
var errMonitorHeld = errors.New("held by the session monitor, which did not end in time; the report may have been written meanwhile")

// logLost says, in the logs, that the report of a session could not be written.
func (p *SessionPlugin) logLost(cs *closingSession, cause error) {
	p.freeSession(cs.session)
	msg := fmt.Sprintf("the report of session %q is lost: %v", cs.session.ID, cause)
	p.logger.Error(msg, slog.String(sessionIDLogKey, cs.session.ID))
	p.consoleLogger.Error(msg)
}

// loseReport says that the report of a session could not be written, in the
// logs and with a notification.
func (p *SessionPlugin) loseReport(ctx context.Context, cs *closingSession, cause error) {
	p.logLost(cs, cause)
	var one lostSessions
	one.add(cs.session.ID)
	p.notifyLost(ctx, one)
}

// lostSessions counts the sessions lost, and keeps the IDs of the first
// maxLostIDs for the notification; the log names every one.
type lostSessions struct {
	ids   []string
	count int
}

func (l *lostSessions) add(id string) {
	l.count++
	if len(l.ids) < maxLostIDs {
		l.ids = append(l.ids, id)
	}
}

// notifyLost raises one notification for the sessions lost, under one bound
// whatever their number; the log names each of them.
func (p *SessionPlugin) notifyLost(ctx context.Context, lost lostSessions) {
	if lost.count == 0 {
		return
	}
	msg := fmt.Sprintf("the report of %d session(s) is lost, first: %s", lost.count, strings.Join(lost.ids, ", "))
	notify, cancel := context.WithTimeout(context.WithoutCancel(ctx), lostEventBound)
	defer cancel()
	p.hcc.NotifyError(notify, lostEvent, errors.New(msg))
}

// checkSessions moves the sessions that are ready to the closing list,
// makes one attempt at the report of each session waiting there, and puts back
// those that need another. When more than maxClosing remain, the oldest get
// their JSON fallback at once.
func (p *SessionPlugin) checkSessions(ctx context.Context, gen uint64) {
	if p.runGeneration() != gen {
		return
	}
	p.mutex.Lock()
	var ready []*closingSession
	for sessionID, session := range p.sessions {
		if p.readyForClosure(session) {
			ready = append(ready, newClosing(session))
			delete(p.sessions, sessionID)
		}
	}
	p.mutex.Unlock()
	for _, cs := range ready {
		p.logClosing(cs)
	}

	hb := p.takeBatch(gen, ready)
	if hb == nil {
		p.lateLoss(ctx, ready, errEarlierRun)
		return
	}
	batch := hb.sessions

	var still []*closingSession
	for i, cs := range batch {
		if ctx.Err() != nil {
			still = append(still, batch[i:]...)
			break
		}
		if p.attempt(ctx, cs) {
			p.release(hb, cs)
		} else {
			still = append(still, cs)
		}
	}
	if n := len(still) - maxClosing; n > 0 && ctx.Err() == nil {
		oldest := still[:n]
		left := p.relieve(ctx, oldest)
		for _, cs := range oldest {
			if !slices.Contains(left, cs) {
				p.release(hb, cs)
			}
		}
		still = slices.Concat(left, still[n:])
	}
	left := p.putBack(ctx, hb, still)
	if left <= maxClosing && p.backlog.CompareAndSwap(true, false) {
		p.hcc.NotifyResolution(ctx, backlogEvent, "the sessions no longer wait for their report")
	}
}

// heldBatch is the sessions the monitor works on. sessions is the batch, which
// only the monitor reads; pending is what the monitor still holds, guarded by
// closeMu, and shrinks as the reports are done; taken tells that Close took
// pending, to report it lost.
type heldBatch struct {
	sessions []*closingSession
	pending  []*closingSession
	taken    bool
	gen      uint64
}

// runGeneration is the number of the current run.
func (p *SessionPlugin) runGeneration() uint64 {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	return p.gen
}

// takeBatch takes the waiting sessions and ready for an attempt, and records
// them as held so that Close can name them if the monitor does not return. It
// takes nothing and returns nil for a monitor of an earlier run (gen is not the
// current generation): Init waits for such a monitor to end, this is the second
// line of defence.
func (p *SessionPlugin) takeBatch(gen uint64, ready []*closingSession) *heldBatch {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	if gen != p.gen {
		return nil
	}
	batch := slices.Concat(p.closing, ready)
	hb := &heldBatch{sessions: batch, pending: slices.Clone(batch), gen: gen}
	p.closing = nil
	p.held = hb
	return hb
}

// release says that the report of a session is done, written or lost: Close does
// not count it as held any more. It does nothing once Close took the batch, which
// then owns pending.
func (p *SessionPlugin) release(hb *heldBatch, cs *closingSession) {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	if hb.taken {
		return
	}
	hb.pending = slices.DeleteFunc(hb.pending, func(held *closingSession) bool { return held == cs })
}

// putBack gives back the sessions that need another attempt, and tells how many
// wait. Once Close took the sessions it gives back nothing: those of the batch
// still pending are already reported lost, and none must be parked after the
// stop. A batch taken after Close took the sessions was not seen by Close: its
// sessions are logged lost, counted in a Warn, and notified in one event of
// their own, since they come too late for the summary of Close.
func (p *SessionPlugin) putBack(ctx context.Context, hb *heldBatch, still []*closingSession) int {
	p.closeMu.Lock()
	if p.held == hb {
		p.held = nil
	}
	if !p.stopping && hb.gen == p.gen {
		p.closing = append(still, p.closing...)
		defer p.closeMu.Unlock()
		return len(p.closing)
	}
	waiting := len(p.closing)
	late := !hb.taken
	p.closeMu.Unlock()
	if late {
		p.lateLoss(ctx, still, errMonitorHeld)
	}
	return waiting
}

// errEarlierRun is why the sessions a monitor of an earlier run found are lost.
var errEarlierRun = errors.New("taken by a monitor of an earlier run")

// lateLoss reports lost the sessions that reach the plugin after the stop took
// the others: each is logged, they are counted in a Warn (they are not in the
// summary of Close), and one notification names them. They are never put back:
// the current run may hold a session of the same name.
func (p *SessionPlugin) lateLoss(ctx context.Context, sessions []*closingSession, cause error) {
	if len(sessions) == 0 {
		return
	}
	var lost lostSessions
	for _, cs := range sessions {
		p.logLost(cs, cause)
		lost.add(cs.session.ID)
	}
	p.logger.Warn("sessions arrived after the stop took the others, they are lost and not in its summary", slog.Int("sessions", lost.count))
	p.notifyLost(ctx, lost)
}

// relieve writes the JSON report of sessions that wait too long, in a bound of
// fallbackBound for all, and says that a backlog builds up. It returns the
// sessions it did not finish because ctx ended (the stop): they are not lost,
// Close writes their report.
func (p *SessionPlugin) relieve(parent context.Context, sessions []*closingSession) (left []*closingSession) {
	ctx, cancel := context.WithTimeout(parent, fallbackBound)
	defer cancel()
	if p.backlog.CompareAndSwap(false, true) {
		p.hcc.NotifyError(ctx, backlogEvent, fmt.Errorf("%d session reports wait to be written: the oldest are written as JSON", len(sessions)))
	}
	for _, cs := range sessions {
		err := p.writeFallback(ctx, cs)
		switch {
		case err == nil:
			p.reported(cs.session)
		case parent.Err() != nil:
			left = append(left, cs)
		default:
			p.loseReport(ctx, cs, err)
		}
	}
	return left
}

// attempt tries once to write the report of a closing session; after
// report_retries failures it writes the fallback. It tells whether the session
// is done: written, or lost. An attempt cut by the stop is not counted.
func (p *SessionPlugin) attempt(ctx context.Context, cs *closingSession) bool {
	err := p.tryReport(ctx, cs)
	if err == nil {
		return true
	}
	if ctx.Err() != nil {
		return false
	}
	cs.attempts++
	p.logger.Warn("failed to write the session report, it will be tried again",
		slog.String(sessionIDLogKey, cs.session.ID), slog.Int("attempt", cs.attempts), slog.String("error", err.Error()))
	if cs.attempts <= p.config.ReportRetries {
		return false
	}
	fbCtx, cancel := context.WithTimeout(ctx, fallbackBound)
	defer cancel()
	// A fallback cut by the stop is not a loss: Close writes the report.
	lostHere := false
	written := p.fallbackOrLose(fbCtx, cs, err, func(cs *closingSession, cause error) {
		if ctx.Err() == nil {
			lostHere = true
			p.loseReport(fbCtx, cs, cause)
		}
	})
	return written || lostHere
}

func (p *SessionPlugin) logClosing(cs *closingSession) {
	session := cs.session
	session.mutex.RLock()
	defer session.mutex.RUnlock()

	count := session.countLocked()
	duration := p.nowTime().Sub(session.StartTime).String()
	p.logger.Info("closing session",
		slog.String(sessionIDLogKey, session.ID),
		slog.Int("completed_reports", count),
		slog.Int("in_flight", len(session.InFlight)),
		slog.String("duration", duration))

	p.consoleLogger.Info(fmt.Sprintf("closing session %q (completed reports: %d, duration: %s)", session.ID, count, duration))
}

// reportName is the base name of the report of a session, without extension: a
// name cut, with a short hash of the session, when the folder name is so long
// that the whole would pass the limit of a file name.
func reportName(id string, start time.Time) string {
	flat := strings.ReplaceAll(id, "/", "-")
	full := fmt.Sprintf("%s%s-%d", datamodel.SessionReportPrefix, flat, start.Unix())
	if len(full) <= maxReportBase {
		return full
	}
	sum := sha256.Sum256([]byte(id))
	tail := fmt.Sprintf("-%s-%d", hex.EncodeToString(sum[:4]), start.Unix())
	room := maxReportBase - len(datamodel.SessionReportPrefix) - len(tail)
	for room > 0 && room < len(flat) && !utf8.RuneStart(flat[room]) {
		room--
	}
	return datamodel.SessionReportPrefix + flat[:max(room, 0)] + tail
}

// writeSessionReport generates the report of the session (as JSON by the
// fallback, by the connector's generator otherwise) and writes it to the exports
// that do not hold it yet. Each target that fails is said, with its own error;
// the error returned tells that some is missing. A session with no report or no
// export has nothing to write.
func (p *SessionPlugin) writeSessionReport(ctx context.Context, cs *closingSession, src reportSource) error {
	session := cs.session
	if p.hcc == nil || len(session.Paths) == 0 {
		return nil
	}
	session.mutex.RLock()
	empty := session.countLocked() == 0
	session.mutex.RUnlock()
	if empty {
		return nil
	}
	reports := session.reports(ctx)
	var (
		produce func(io.Writer) error
		ext     = ".json"
	)
	switch src {
	case viaJSON:
		produce = func(w io.Writer) error {
			return datamodel.WriteReportsJSON(ctx, w, reports)
		}
	case viaRaw:
		ext = datamodel.SessionSpoolExt
		produce = func(w io.Writer) error { return session.copyRaw(ctx, w) }
	default:
		generated, err := p.hcc.GenerateReport(ctx, datamodel.ScanContext{
			ScanID: fmt.Sprintf("session-%s-%d", session.ID, session.StartTime.Unix()),
			Start:  session.StartTime,
			End:    p.nowTime(),
		}, reports)
		if err != nil {
			return fmt.Errorf("failed to generate session report: %w", err)
		}
		if generated.Content == nil {
			return errors.New("the report generator gave no content")
		}
		var closeOnce sync.Once
		closeContent := func() {
			closeOnce.Do(func() {
				if e := generated.Content.Close(); e != nil {
					p.logger.Warn("failed to close the session report content", slog.String(sessionIDLogKey, session.ID), slog.String("error", e.Error()))
				}
			})
		}
		// The deadline is kept even when the generator blocks the reader: closing
		// the content ends the copy.
		stop := context.AfterFunc(ctx, closeContent)
		defer func() {
			stop()
			closeContent()
		}()
		if !validExtension(generated.Extension) {
			return fmt.Errorf("the report generator gave an invalid extension %q", generated.Extension)
		}
		ext = generated.Extension
		produce = func(w io.Writer) error {
			if _, err := io.Copy(w, &ctxReader{ctx: ctx, r: generated.Content}); err != nil {
				return err
			}
			return ctx.Err()
		}
	}
	name := reportName(session.ID, session.StartTime) + ext
	var targets []string
	for _, path := range session.Paths {
		if target := filepath.Join(path, name); !cs.has(target) {
			targets = append(targets, target)
		}
	}
	var errs []error
	for _, r := range p.saveReport(produce, targets...) {
		if r.err != nil {
			msg := fmt.Sprintf("failed to save the session report of %q at %q: %v", session.ID, r.target, r.err)
			p.logger.Error(msg, slog.String(sessionIDLogKey, session.ID))
			p.consoleLogger.Error(msg)
			errs = append(errs, r.err)
			continue
		}
		cs.written[r.target] = struct{}{}
		p.hcc.NotifyReportWritten(ctx, session.ID, r.path, r.sha256)
		p.logger.Info("session report saved",
			slog.String(sessionIDLogKey, session.ID),
			slog.String("report_path", r.path),
			slog.String("sha256", r.sha256),
		)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if src == viaGenerator && p.fallback.CompareAndSwap(true, false) {
		p.hcc.NotifyResolution(ctx, fallbackEvent, "session reports are generated again")
	}
	return nil
}

func (cs *closingSession) has(target string) bool {
	_, ok := cs.written[target]
	return ok
}

// ctxReader stops reading once ctx ends.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// validExtension accepts a dot and letters or digits: the generator is a
// plugin, its extension must not be able to name another place.
func validExtension(ext string) bool {
	if len(ext) < 2 || len(ext) > 16 || ext[0] != '.' {
		return false
	}
	for _, c := range ext[1:] {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// closeReportFile closes a report file. Replaced in tests.
var closeReportFile = func(f *os.File) error { return f.Close() }

// maxReportConflicts is how many names a report tries after its own.
const maxReportConflicts = 5

// reportResult is what became of one target of a report.
type reportResult struct {
	target, path, sha256 string
	err                  error
}

// targetWriter writes to one temporary file and keeps its first error without
// failing the others: a failing export must not fail the rest.
type targetWriter struct {
	f   *os.File
	err error
}

func (w *targetWriter) Write(b []byte) (int, error) {
	if w.err == nil {
		_, w.err = w.f.Write(b)
	}
	return len(b), nil
}

// saveReport writes what produce writes to every target, atomically and without
// ever replacing anything: the content goes to a private temporary file of the
// destination folder (created exclusively), is synced, then published under its
// name only if nothing has it. The final name is never opened, truncated or
// removed, whatever fails; only the temporary file is. A report that finds its
// name taken (nobody else may create it) is an anomaly: it is written under a
// conflict name and said loudly. Every target gets a result of its own.
func (p *SessionPlugin) saveReport(produce func(io.Writer) error, targets ...string) []reportResult {
	results := make([]reportResult, len(targets))
	writers := make([]*targetWriter, len(targets))
	var sinks []io.Writer
	for i, target := range targets {
		results[i].target = filepath.Clean(target)
		f, err := createReportTemp(filepath.Dir(results[i].target))
		if err != nil {
			results[i].err = err
			continue
		}
		writers[i] = &targetWriter{f: f}
		sinks = append(sinks, writers[i])
	}
	if len(sinks) == 0 {
		return results
	}
	sum := sha256.New()
	copyErr := produce(io.MultiWriter(append(sinks, sum)...))
	digest := hex.EncodeToString(sum.Sum(nil))
	for i, w := range writers {
		if w == nil {
			continue
		}
		results[i].err = p.publishReport(w, results[i].target, digest, copyErr, &results[i])
	}
	return results
}

// publishReport makes the temporary file of a target durable and gives it its
// name; the temporary file is removed on failure.
func (p *SessionPlugin) publishReport(w *targetWriter, target, digest string, copyErr error, r *reportResult) error {
	err := errors.Join(copyErr, w.err)
	if err == nil {
		err = w.f.Sync()
	}
	// A close that fails after a good copy leaves a truncated report: it is an
	// error like the others and nothing is published.
	if ce := closeReportFile(w.f); ce != nil {
		p.logger.Warn("failed to close report file", slog.String(filepathLogKey, w.f.Name()), slog.String("error", ce.Error()))
		err = errors.Join(err, ce)
	}
	if err == nil {
		var final string
		final, err = quarantine.MoveFileResolvingConflicts(w.f.Name(), target, filepath.Join(filepath.Dir(target), quarantine.StagingDir), time.Now, maxReportConflicts)
		if err == nil {
			if final != target {
				msg := fmt.Sprintf("the session report %q already existed: written as %q", target, final)
				p.logger.Error(msg)
				p.consoleLogger.Error(msg)
			}
			r.path, r.sha256 = final, digest
			return nil
		}
	}
	if e := os.Remove(w.f.Name()); e != nil && !errors.Is(e, os.ErrNotExist) {
		p.logger.Warn("failed to remove a temporary report", slog.String(filepathLogKey, w.f.Name()), slog.String("error", e.Error()))
	}
	return err
}

// createReportTemp creates the temporary file of a report in dir, exclusively,
// with the mode the report will have.
func createReportTemp(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	for range 5 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		name := filepath.Join(dir, quarantine.TempPrefix+"report-"+hex.EncodeToString(b[:]))
		f, err := os.OpenFile(filepath.Clean(name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			if err = f.Chmod(reportMode); err != nil {
				err = errors.Join(err, f.Close(), os.Remove(name))
				return nil, err
			}
			return f, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	return nil, errors.New("no free temporary name")
}

func main() {}
