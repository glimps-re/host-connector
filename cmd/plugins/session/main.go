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

	// runCtx is cancelled by Close: the attempts of the monitor stop and give
	// their sessions back to the closing list.
	runCtx    context.Context
	cancelRun context.CancelFunc

	// closing holds the sessions whose report is not written yet; closeMu
	// guards it and known.
	closeMu  sync.Mutex
	closing  []*closingSession
	known    map[string]string
	fallback atomic.Bool
	backlog  atomic.Bool

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
}

const (
	defaultReportTimeout   = 2 * time.Minute
	defaultReportRetries   = 3
	defaultInflightTimeout = 24 * time.Hour

	// maxClosing bounds the sessions kept waiting for their report after an
	// attempt: past it the oldest get their fallback at once.
	maxClosing = 64
	// maxKnownErrors bounds the files remembered as failed after their session
	// closed.
	maxKnownErrors = 4096
	// fallbackBound bounds the JSON fallbacks written in one go while the
	// connector runs.
	fallbackBound = 10 * time.Second
	// stopReserve is the most of the deadline of Close kept for the JSON
	// fallbacks; expiredBound is all the time they get when the deadline has
	// expired already: the guard of the shutdown kills the process a second
	// after it.
	stopReserve  = 10 * time.Second
	expiredBound = time.Second

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
	// CompletedReports holds one report per file; errorAt indexes the ones that
	// carry an error, which a later report of the same file replaces.
	CompletedReports []datamodel.Report
	errorAt          map[string]int
	closed           bool
	clock            func() time.Time
	mutex            sync.RWMutex
}

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

// Init initializes the plugin, registers callbacks, and starts session monitoring.
func (p *SessionPlugin) Init(rawConfig any, hcc plugins.HCContext) error {
	config, ok := rawConfig.(*Config)
	if !ok {
		return errors.New("bad config passed to session plugin")
	}

	if err := checkConfig(config, hcc, true); err != nil {
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

	p.config = *config
	p.config.RootFolder = root
	p.workDir = workDir
	p.sessions = make(map[string]*Session)
	p.closing, p.known = nil, make(map[string]string)
	p.hcc = hcc
	p.stop = make(chan struct{})
	p.done = make(chan struct{})
	p.runCtx, p.cancelRun = context.WithCancel(context.Background())
	p.logger = hcc.GetLogger().With(slog.String("plugin", "session"))
	p.consoleLogger = hcc.GetConsoleLogger()

	hcc.RegisterOnStartScanFile(p.OnStartScanFile)
	hcc.RegisterWithWaitForOptions(p.WaitForOptions)
	hcc.RegisterOnFileScanned(p.OnFileScanned)
	hcc.RegisterOnReport(p.OnReport)

	go p.sessionMonitor()

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
// sessions back, so none is missed.
func (p *SessionPlugin) Close(ctx context.Context) error {
	if !p.started {
		return nil
	}
	if p.cancelRun != nil {
		p.cancelRun()
	}
	close(p.stop)
	<-p.done
	p.closeAllSessions(ctx)
	p.started = false
	return nil
}

// attach runs op on the session of file, asking for a new one when the session
// found was closed meanwhile; ensure creates the session when there is none. It
// returns the session op ran on, if any, and whether it was just created.
func (p *SessionPlugin) attach(file string, ensure bool, op func(*Session) bool) (session *Session, created bool) {
	for range 2 {
		session, created = p.getSession(file, ensure)
		if session == nil || op(session) {
			return session, created
		}
	}
	return nil, false
}

// OnStartScanFile adds files to their appropriate sessions based on directory path.
// A new attempt at a file that failed, whose session is closed, does not open
// another session: its outcome is reported when it ends well, by OnReport.
func (p *SessionPlugin) OnStartScanFile(file string, sha256 string) {
	session, created := p.attach(file, !p.knownError(file, sha256), func(s *Session) bool { return s.addFile(file, sha256) })
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
	session, _ := p.attach(file, failed && !p.knownError(file, sha256), func(s *Session) bool {
		if !s.markFileCompleted(file) {
			return false
		}
		return !failed || s.addFileError(file, sha256, result.Error.Error())
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
	session, _ := p.attach(rep.Filename, rep.Error == "" || !p.knownError(rep.Filename, rep.SHA256), func(s *Session) bool { return s.addReport(*rep) })
	if session == nil {
		return
	}
	if rep.Error == "" {
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

// rememberErrors keeps the files of a closed session that ended in error.
func (p *SessionPlugin) rememberErrors(s *Session) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	if p.known == nil {
		p.known = make(map[string]string)
	}
	for path, i := range s.errorAt {
		if len(p.known) >= maxKnownErrors {
			for k := range p.known {
				delete(p.known, k)
				break
			}
		}
		p.known[path] = s.CompletedReports[i].SHA256
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
		created = true
		sessionPaths := make([]string, 0, len(p.config.Exports))
		for _, v := range p.config.Exports {
			sessionPaths = append(sessionPaths, filepath.Join(v, sessionID))
		}
		session = &Session{
			ID:               sessionID,
			Paths:            sessionPaths,
			StartTime:        p.nowTime(),
			LastActivity:     p.nowTime(),
			InFlight:         make(map[string]*inflightEntry),
			CompletedReports: make([]datamodel.Report, 0),
			errorAt:          make(map[string]int),
			clock:            p.nowTime,
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

// baseCtx is the context of the attempts of the monitor.
func (p *SessionPlugin) baseCtx() context.Context {
	if p.runCtx != nil {
		return p.runCtx
	}
	return context.Background()
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
	i, failed := s.errorAt[filePath]
	retry := failed && s.CompletedReports[i].SHA256 == sha256
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

// addFileError enters a minimal report for a file that ended in error, unless
// the session already holds one for it.
func (s *Session) addFileError(filePath, sha256, msg string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.closed {
		return false
	}

	if _, ok := s.errorAt[filePath]; ok {
		return true
	}
	s.errorAt[filePath] = len(s.CompletedReports)
	s.CompletedReports = append(s.CompletedReports, datamodel.Report{Filename: filePath, SHA256: sha256, Error: msg})
	s.LastActivity = s.nowTime()
	return true
}

// addReport keeps one report per file that failed: a later report of the same
// file replaces it, and a repeated failure is no activity.
func (s *Session) addReport(rep datamodel.Report) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.closed {
		return false
	}

	if i, ok := s.errorAt[rep.Filename]; ok {
		s.CompletedReports[i] = rep
		if rep.Error == "" {
			delete(s.errorAt, rep.Filename)
			s.LastActivity = s.nowTime()
		}
		return true
	}
	if rep.Error != "" {
		s.errorAt[rep.Filename] = len(s.CompletedReports)
	}
	s.CompletedReports = append(s.CompletedReports, rep)
	s.LastActivity = s.nowTime()
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

func (p *SessionPlugin) sessionMonitor() {
	defer close(p.done)

	ticker := time.NewTicker(p.tick())
	defer ticker.Stop()

	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			p.checkAndCloseSessions()
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
)

// closeAllSessions writes the report of every session, open or waiting. The
// generators get the deadline of ctx less a reserve (half of what is left, at
// most stopReserve) and the JSON fallbacks are written in that reserve; when the
// deadline has expired already they get one second in all. It never asks the
// core for pending files.
func (p *SessionPlugin) closeAllSessions(ctx context.Context) {
	p.mutex.Lock()
	var all []*closingSession
	for id, session := range p.sessions {
		session.closeSession()
		all = append(all, newClosing(session))
		delete(p.sessions, id)
	}
	p.mutex.Unlock()
	p.closeMu.Lock()
	all = slices.Concat(p.closing, all)
	p.closing = nil
	p.closeMu.Unlock()

	genCtx, fbCtx := ctx, ctx
	if deadline, ok := ctx.Deadline(); ok {
		if left := time.Until(deadline); left <= 0 {
			var cancel context.CancelFunc
			fbCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), expiredBound)
			defer cancel()
		} else {
			var cancel context.CancelFunc
			genCtx, cancel = context.WithDeadline(ctx, deadline.Add(-min(left/2, stopReserve)))
			defer cancel()
		}
	}
	var written, lost int
	for _, cs := range all {
		p.logClosing(cs)
		if p.finish(genCtx, fbCtx, cs) {
			written++
		} else {
			lost++
		}
	}
	p.logger.Info("sessions closed at stop", slog.Int("sessions", len(all)), slog.Int("reports_written", written), slog.Int("failures", lost))
}

// finish writes the report of a session through the generator, then through the
// JSON fallback if that fails. It tells whether the report was written.
func (p *SessionPlugin) finish(genCtx, fbCtx context.Context, cs *closingSession) bool {
	err := p.tryReport(genCtx, cs)
	if err == nil {
		return true
	}
	return p.fallbackOrLose(fbCtx, cs, err)
}

// tryReport makes one attempt, bounded by report_timeout, at the report of a
// session through the generator.
func (p *SessionPlugin) tryReport(ctx context.Context, cs *closingSession) error {
	attempt, cancel := context.WithTimeout(ctx, p.config.ReportTimeout)
	defer cancel()
	err := p.writeSessionReport(attempt, cs, viaGenerator)
	if err == nil {
		p.rememberErrors(cs.session)
	}
	return err
}

// fallbackOrLose writes the JSON report of a session after cause made the normal
// one fail. When that fails too the report is lost: said loudly, never retried.
func (p *SessionPlugin) fallbackOrLose(ctx context.Context, cs *closingSession, cause error) bool {
	p.logger.Error("the session report failed, a JSON fallback is written",
		slog.String(sessionIDLogKey, cs.session.ID), slog.String("error", cause.Error()))
	err := p.writeSessionReport(ctx, cs, viaJSON)
	if err == nil {
		p.rememberErrors(cs.session)
		if p.fallback.CompareAndSwap(false, true) {
			p.hcc.NotifyError(ctx, fallbackEvent, fmt.Errorf("session reports could not be generated, JSON reports are written instead: %w", cause))
		}
		return true
	}
	p.loseReport(ctx, cs, err)
	return false
}

// loseReport says that the report of a session could not be written.
func (p *SessionPlugin) loseReport(ctx context.Context, cs *closingSession, cause error) {
	msg := fmt.Sprintf("the report of session %q is lost: %v", cs.session.ID, cause)
	p.logger.Error(msg, slog.String(sessionIDLogKey, cs.session.ID))
	p.consoleLogger.Error(msg)
	p.hcc.NotifyError(context.WithoutCancel(ctx), lostEvent, errors.New(msg))
}

// checkAndCloseSessions moves the sessions that are ready to the closing list,
// makes one attempt at the report of each session waiting there, and puts back
// those that need another. When more than maxClosing remain, the oldest get
// their JSON fallback at once.
func (p *SessionPlugin) checkAndCloseSessions() {
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

	p.closeMu.Lock()
	batch := slices.Concat(p.closing, ready)
	p.closing = nil
	p.closeMu.Unlock()

	ctx := p.baseCtx()
	var still []*closingSession
	for i, cs := range batch {
		if ctx.Err() != nil {
			still = append(still, batch[i:]...)
			break
		}
		if !p.attempt(ctx, cs) {
			still = append(still, cs)
		}
	}
	if n := len(still) - maxClosing; n > 0 && ctx.Err() == nil {
		p.relieve(ctx, still[:n])
		still = still[n:]
	}
	p.closeMu.Lock()
	p.closing = append(still, p.closing...)
	left := len(p.closing)
	p.closeMu.Unlock()
	if left <= maxClosing && p.backlog.CompareAndSwap(true, false) {
		p.hcc.NotifyResolution(ctx, backlogEvent, "the sessions no longer wait for their report")
	}
}

// relieve writes the JSON report of sessions that wait too long, in a bound of
// fallbackBound for all, and says that a backlog builds up.
func (p *SessionPlugin) relieve(ctx context.Context, sessions []*closingSession) {
	ctx, cancel := context.WithTimeout(ctx, fallbackBound)
	defer cancel()
	if p.backlog.CompareAndSwap(false, true) {
		p.hcc.NotifyError(ctx, backlogEvent, fmt.Errorf("%d session reports wait to be written: the oldest are written as JSON", len(sessions)))
	}
	for _, cs := range sessions {
		err := p.writeSessionReport(ctx, cs, viaJSON)
		if err == nil {
			p.rememberErrors(cs.session)
			continue
		}
		p.loseReport(ctx, cs, err)
	}
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
	p.fallbackOrLose(fbCtx, cs, err)
	return ctx.Err() == nil
}

func (p *SessionPlugin) logClosing(cs *closingSession) {
	session := cs.session
	session.mutex.RLock()
	defer session.mutex.RUnlock()

	duration := p.nowTime().Sub(session.StartTime).String()
	p.logger.Info("closing session",
		slog.String(sessionIDLogKey, session.ID),
		slog.Int("completed_reports", len(session.CompletedReports)),
		slog.Int("in_flight", len(session.InFlight)),
		slog.String("duration", duration))

	p.consoleLogger.Info(fmt.Sprintf("closing session %q (completed reports: %d, duration: %s)", session.ID, len(session.CompletedReports), duration))
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
	reports := session.CompletedReports
	session.mutex.RUnlock()
	if len(reports) == 0 {
		return nil
	}
	var (
		produce func(io.Writer) error
		ext     = ".json"
	)
	switch src {
	case viaJSON:
		produce = func(w io.Writer) error {
			return datamodel.WriteReportsJSON(ctx, w, datamodel.ReportsSeq(reports))
		}
	default:
		generated, err := p.hcc.GenerateReport(ctx, datamodel.ScanContext{
			ScanID: fmt.Sprintf("session-%s-%d", session.ID, session.StartTime.Unix()),
			Start:  session.StartTime,
			End:    p.nowTime(),
		}, datamodel.ReportsSeq(reports))
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
