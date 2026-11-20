package handler

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/pkg/scanner"
	"github.com/glimps-re/rfsnotify"
)

type Monitorer interface {
	Start()
	Close() error
	Add(path string) error
}

// OnNewFileFunc receives a file whose identity id was observed stable. It
// reports whether the file was accepted for processing; a refusal without
// failure leaves the file to be found again by the next rescan.
type OnNewFileFunc func(file string, id scanner.FileIdentity) (accepted bool, err error)

type Config struct {
	// DisableWatcher turns off filesystem events: files are only found by
	// the pre-scan and the periodic rescan (network filesystems where watches
	// are not available or reliable). It requires a non-zero Period.
	DisableWatcher bool
	// FollowSymlinks makes the stability check follow links; without it the
	// link itself is examined (a swapped folder must not lend its target's metadata).
	FollowSymlinks bool
	// Skip, when set, tells paths that must never be reported (the connector
	// work directory): it is checked during the rescan walk and on events.
	Skip     func(path string) bool
	PreScan  bool
	Period   sdk.Duration
	ModDelay sdk.Duration
	// MaxTrackedBytes bounds the memory of the table of tracked files; zero
	// means defaultMaxTracked. QuotaPercent is the share above which an owner
	// is visited first when the table is full; zero means defaultQuotaPercent.
	MaxTrackedBytes int64
	QuotaPercent    int
	// Owners groups files into owners as declared by the plugins; Watched are
	// the monitored paths (the default owner is the first folder below one).
	Owners  []scanner.OwnerRule
	Watched []string
	// Context carries the values used to push console events; the monitor
	// outlives its cancellation (nil means context.Background).
	Context context.Context
}

const (
	defaultMaxTracked   = 256 << 20
	defaultQuotaPercent = 25

	// minReportInterval spaces the pressure reports raised outside a rescan.
	minReportInterval = time.Minute

	// Console event types of the monitoring table.
	HostMonitorPressure  events.ErrorEventType = "host-monitor-pressure"
	HostMonitorTableFull events.ErrorEventType = "host-monitor-table-full"
)

type Monitor struct {
	watcher     *rfsnotify.RWatcher
	skip        func(path string) bool
	stat        func(path string) (fs.FileInfo, error)
	wg          sync.WaitGroup
	cb          OnNewFileFunc // callbacks
	preScan     bool
	period      sdk.Duration
	modDelay    sdk.Duration // modification delay
	paths       *sync.Map
	done        chan struct{}
	closeOnce   sync.Once
	table       *fileTable
	wake        chan struct{} // a deadline earlier than the timer may exist
	walkMu      sync.Mutex
	walkPending map[string]struct{} // folders waiting to be walked
	walkWake    chan struct{}
	ctx         context.Context
	repMu       sync.Mutex // guards pressured, tableFull and lastReport
	pressured   bool
	tableFull   bool
	lastReport  time.Time
	started     atomic.Bool
}

func NewMonitor(onNewFile OnNewFileFunc, cfg Config) (*Monitor, error) {
	var watcher *rfsnotify.RWatcher
	if cfg.DisableWatcher {
		if cfg.Period == 0 {
			return nil, config.ErrWatcherNeedsPeriod
		}
	} else {
		var err error
		watcher, err = rfsnotify.NewWatcher()
		if err != nil {
			return nil, err
		}
	}
	watched := make([]string, len(cfg.Watched))
	for i, w := range cfg.Watched {
		abs, err := filepath.Abs(w)
		if err != nil {
			return nil, fmt.Errorf("could not resolve watched path %q: %w", w, err)
		}
		watched[i] = abs
	}
	maxBytes, quota := cfg.MaxTrackedBytes, cfg.QuotaPercent
	if maxBytes <= 0 {
		maxBytes = defaultMaxTracked
	}
	if quota <= 0 {
		quota = defaultQuotaPercent
	}
	base := cfg.Context
	if base == nil {
		base = context.Background()
	}
	return &Monitor{
		ctx:         context.WithoutCancel(base),
		watcher:     watcher,
		cb:          onNewFile,
		skip:        cfg.Skip,
		stat:        statFor(cfg.FollowSymlinks),
		preScan:     cfg.PreScan,
		period:      cfg.Period,
		modDelay:    cfg.ModDelay,
		paths:       new(sync.Map),
		table:       newFileTable(maxBytes, quota, cfg.Owners, watched),
		wake:        make(chan struct{}, 1),
		walkPending: make(map[string]struct{}),
		walkWake:    make(chan struct{}, 1),
		done:        make(chan struct{}),
	}, nil
}

func statFor(followSymlinks bool) func(string) (fs.FileInfo, error) {
	if followSymlinks {
		return os.Stat
	}
	return os.Lstat
}

func (m *Monitor) Close() (err error) {
	m.closeOnce.Do(func() {
		if m.watcher != nil {
			if e := m.watcher.Close(); e != nil {
				logger.Error("cannot close watcher", slog.String("error", e.Error()))
				err = fmt.Errorf("cannot close watcher, error: %w", e)
			}
		}
		close(m.done)
	})
	m.wg.Wait()
	m.started.Store(false)
	return err
}

func (m *Monitor) Start() {
	if m.watcher != nil {
		m.wg.Go(func() {
			m.dispatchEvents()
		})
	}
	if m.period != 0 {
		m.wg.Go(func() {
			m.periodicalScan()
		})
	}
	m.wg.Go(func() {
		m.scanFiles()
	})
	m.wg.Go(func() {
		m.walkQueue()
	})
	m.started.Store(true)
	if m.preScan {
		m.paths.Range(func(key, _ any) bool {
			if root, ok := key.(string); ok {
				m.preScanPath(root)
			}
			return true
		})
	}
}

func (m *Monitor) periodicalScan() {
	ticker := time.NewTicker(time.Duration(m.period))
	defer ticker.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			m.rescan()
		}
	}
}

// rescan walks every root, then purges what was not seen. Only the folders that
// could not be read protect the entries below them.
func (m *Monitor) rescan() {
	m.table.BeginRescan()
	var unreadable []string
	overflow := false
	m.paths.Range(func(key, _ any) bool {
		root, ok := key.(string)
		if !ok {
			m.paths.Delete(key)
			return true
		}
		dirs, over := m.walkRoot(root, maxUnreadableDirs-len(unreadable))
		unreadable = append(unreadable, dirs...)
		overflow = overflow || over
		return true
	})
	m.table.EndRescan(unreadable, overflow)
	if overflow {
		logger.Warn("too many folders could not be read at rescan: every tracked file is protected for this rescan", slog.Int("folders", maxUnreadableDirs))
	}
	m.reportPressure()
}

// maxRescanWarns caps the per-root Warn logs of one rescan: a network
// filesystem can deny access to thousands of directories at every rescan.
const maxRescanWarns = 10

// walkRoot tracks every file under root. An unreadable entry is logged and
// skipped so the other entries are still visited; the folders that could not be
// read are returned, which protects the entries below them from the purge: an
// unreadable entry, a missing root (e.g. unmounted share) or an interrupted
// walk. A subdirectory removed during the walk is not one: its files are
// really gone. At most room folders are listed, whatever the walk meets (a
// hostile tree must not grow the list); overflow tells that more were met.
func (m *Monitor) walkRoot(root string, room int) (unreadable []string, overflow bool) {
	add := func(dir string) {
		if len(unreadable) >= room {
			overflow = true
			return
		}
		unreadable = append(unreadable, dir)
	}
	root = filepath.Clean(root)
	// The trailing separator makes WalkDir follow a root that is a symlink.
	walkPath := withSeparator(root)
	warns, skipped := 0, 0
	err := filepath.WalkDir(walkPath, func(path string, d fs.DirEntry, walkErr error) error {
		select {
		case <-m.done:
			add(root)
			return fs.SkipAll
		default:
		}
		if walkErr != nil {
			isRoot := path == root || path == walkPath
			if !isRoot && errors.Is(walkErr, fs.ErrNotExist) {
				logger.Debug("path removed during rescan", slog.String("path", path))
			} else {
				dir := path
				if d == nil || !d.IsDir() {
					dir = filepath.Dir(path)
				}
				add(filepath.Clean(dir))
				if warns < maxRescanWarns {
					warns++
					logger.Warn("cannot access path at rescan", slog.String("path", path), slog.String("error", walkErr.Error()))
				} else {
					skipped++
					logger.Debug("cannot access path at rescan", slog.String("path", path), slog.String("error", walkErr.Error()))
				}
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if m.skip != nil && m.skip(path) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() || quarantine.IsTempFile(path) {
			return nil
		}
		m.discover(path, false)
		return nil
	})
	if err != nil {
		add(root)
		logger.Error("cannot walk dir at rescan", slog.String("path", root), slog.String("error", err.Error()))
	}
	if skipped > 0 {
		logger.Warn("more paths could not be accessed at rescan", slog.String("root", root), slog.Int("more", skipped))
	}
	return unreadable, overflow
}

// discover starts tracking path. A rescan only marks the files it already
// tracks (no stat); an event always examines the file, so that a change pushes
// its deadline back.
func (m *Monitor) discover(path string, examine bool) {
	if !examine && m.table.Touch(path) {
		return
	}
	info, err := m.stat(path)
	if err != nil {
		m.table.Forget(path)
		return
	}
	if info.IsDir() {
		// A folder created or moved in: its files may predate the watch placed
		// on it, so they are walked like at a rescan. A link to a folder is never
		// walked: it would lead out of the monitored tree (the work directory,
		// /etc, a parent), or loop.
		if scanner.IsLinkToFolder(path) {
			logger.Warn("link to a folder ignored", slog.String("path", path))
			return
		}
		m.preScanPath(path)
		return
	}
	now := time.Now()
	if m.table.Track(path, scanner.IdentityOf(info), now, now.Add(time.Duration(m.modDelay))) {
		select {
		case m.wake <- struct{}{}:
		default:
		}
	}
	if m.period == 0 {
		m.reportPressureIfDue(now)
	}
}

// reportPressureIfDue serves the event-only mode, where no rescan ends to
// report: a refusal or an eviction is raised as soon as it happens, then at
// most once a minute, and the end of the pressure is raised once a minute has
// passed without any.
func (m *Monitor) reportPressureIfDue(now time.Time) {
	m.repMu.Lock()
	if now.Sub(m.lastReport) < minReportInterval || !m.table.HasPressure() && !m.pressured && !m.tableFull {
		m.repMu.Unlock()
		return
	}
	notes := m.collectPressure(now)
	m.repMu.Unlock()
	m.push(m.ctx, notes)
}

func withSeparator(path string) string {
	if strings.HasSuffix(path, string(filepath.Separator)) {
		return path
	}
	return path + string(filepath.Separator)
}

// dispatchEvents reads filesystem events from the watcher and queue these files for scanning.
// Returns when m.done or a watcher channel is closed.
func (m *Monitor) dispatchEvents() {
	for {
		select {
		case <-m.done:
			return
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			if m.skip != nil && m.skip(event.Name) {
				continue
			}
			if (event.Has(fsnotify.Create) || event.Has(fsnotify.Write)) && !quarantine.IsTempFile(event.Name) {
				m.discover(event.Name, true)
			}
		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			logger.Error("watcher error", slog.String("error", err.Error()))
		}
	}
}

// scanFiles is the only goroutine that owns the deadlines: one timer, set to the
// earliest of them, whatever the number of tracked files.
func (m *Monitor) scanFiles() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		if next, ok := m.table.NextDeadline(); ok {
			timer.Reset(max(time.Until(next), 0))
		} else {
			timer.Reset(time.Hour)
		}
		select {
		case <-m.done:
			return
		case <-m.wake:
		case <-timer.C:
			m.processDue()
		}
	}
}

// processDue hands to the callback the files whose deadline has passed and
// whose metadata did not change meanwhile; a changed one waits again. No lock
// is held while stat or the callback run.
func (m *Monitor) processDue() {
	if m.period == 0 {
		m.reportPressureIfDue(time.Now())
	}
	for {
		select {
		case <-m.done:
			return
		default:
		}
		path, stamp, ok := m.table.PopDue(time.Now())
		if !ok {
			return
		}
		info, err := m.stat(path)
		if err != nil {
			m.table.Forget(path)
			continue
		}
		if cur := scanner.IdentityOf(info); !cur.Equal(stamp) {
			m.table.Forget(path)
			now := time.Now()
			m.table.Track(path, cur, now, now.Add(time.Duration(m.modDelay)))
			continue
		}
		if _, err := m.cb(path, stamp); err != nil {
			logger.Error("could not scan file", slog.String("path", path), slog.String("err", err.Error()), slog.String(datamodel.LogSourceKey, "monitor"))
		}
		m.table.Forget(path)
	}
}

// reportPressure tells the operator what the rescan took from whom, and when
// it stopped. The first event names the owners that were refused or evicted;
// the second one is raised when files left in INPUT fill the table.
func (m *Monitor) reportPressure() {
	m.repMu.Lock()
	notes := m.collectPressure(time.Now())
	m.repMu.Unlock()
	m.push(m.ctx, notes)
}

// pressureNote is one event to push: an error, or the resolution of one.
type pressureNote struct {
	resolution bool
	key        events.ErrorEventType
	msg        string
}

// notifyTimeout bounds one push to the console: the table must never wait on it.
const notifyTimeout = 5 * time.Second

// collectPressure takes the pressure of the table and decides what to tell. It
// runs under repMu; the events are pushed after the lock is released.
func (m *Monitor) collectPressure(now time.Time) (notes []pressureNote) {
	rep := m.table.TakePressure()
	if rep.Refused > 0 || len(rep.Owners) > 0 || rep.Others > 0 {
		notes = append(notes, pressureNote{key: HostMonitorPressure, msg: describePressure(rep)})
		m.pressured = true
		m.lastReport = now
	} else if m.pressured {
		m.pressured = false
		m.lastReport = now
		notes = append(notes, pressureNote{resolution: true, key: HostMonitorPressure, msg: "monitoring table pressure ended"})
	}
	full := ""
	for _, p := range rep.Owners {
		if p.DoneBytesOverHalf {
			full = fmt.Sprintf("the monitoring table is full of files left in INPUT by %q, admission is slowed down: remove those files from INPUT", p.Owner)
			break
		}
	}
	switch {
	case full != "":
		notes = append(notes, pressureNote{key: HostMonitorTableFull, msg: full})
		m.tableFull = true
		m.lastReport = now
	case m.tableFull:
		m.tableFull = false
		m.lastReport = now
		notes = append(notes, pressureNote{resolution: true, key: HostMonitorTableFull, msg: "monitoring table no longer full of files left in INPUT"})
	}
	return notes
}

func (m *Monitor) push(parent context.Context, notes []pressureNote) {
	for _, n := range notes {
		ctx, cancel := context.WithTimeout(parent, notifyTimeout)
		var err error
		switch {
		case n.resolution:
			logger.Info(n.msg)
			err = eventHandler.NotifyResolution(ctx, n.msg, n.key)
		case n.key == HostMonitorTableFull:
			logger.Error(n.msg)
			consoleLogger.Error(n.msg)
			err = eventHandler.NotifyError(ctx, n.key, errors.New(n.msg))
		default:
			logger.Warn(n.msg)
			consoleLogger.Warn(n.msg)
			err = eventHandler.NotifyError(ctx, n.key, errors.New(n.msg))
		}
		cancel()
		if err != nil {
			logger.Warn("could not push console event", slog.String("type", string(n.key)), slog.String("error", err.Error()))
		}
	}
}

func describePressure(rep pressureReport) string {
	owners := slices.SortedFunc(maps.Values(rep.Owners), func(a, b *ownerPressure) int { return cmp.Compare(a.Owner, b.Owner) })
	var b strings.Builder
	fmt.Fprintf(&b, "monitoring table under pressure: %d file(s) refused", rep.Refused)
	for _, p := range owners {
		fmt.Fprintf(&b, "; %q holds %d bytes, evicted %d waiting, %d to retry, %d final, %d refused (they are rescanned)", p.Owner, p.Share, p.Waiting, p.Retry, p.Final, p.RefusedFiles)
	}
	if rep.Others > 0 {
		fmt.Fprintf(&b, "; %d more file(s) of other owners", rep.Others)
	}
	return b.String()
}

func (m *Monitor) Add(path string) error {
	// Absolute, like the watched paths of the table: the walk yields paths of
	// the same form, or a user would be split into one owner per sub-folder.
	path, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("error watching %s: %w", path, err)
	}
	if _, ok := m.paths.Load(path); ok {
		return nil
	}
	if m.watcher != nil {
		if err := m.watcher.AddRecursive(path); err != nil {
			return fmt.Errorf("error watching %s: %w", path, err)
		}
	} else if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("error watching %s: %w", path, err)
	}
	m.paths.Store(path, struct{}{})
	if m.preScan && m.started.Load() {
		m.preScanPath(path)
	}
	return nil
}

// preScanPath asks for the files already under root to be tracked (at start,
// when a path is added, or when a folder appears). A single goroutine walks, one
// folder at a time; a folder whose walk is already waiting, or whose parent's
// is, is not queued again: `mkdir -p` of depth N asks for one walk, not N.
func (m *Monitor) preScanPath(root string) {
	root = filepath.Clean(root)
	m.walkMu.Lock()
	for dir := root; ; {
		if _, covered := m.walkPending[dir]; covered {
			m.walkMu.Unlock()
			return
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	m.dropBelow(root)
	m.walkPending[root] = struct{}{}
	m.walkMu.Unlock()
	select {
	case m.walkWake <- struct{}{}:
	default:
	}
}

// walkQueue is the only consumer of the folders to walk. The unreadable
// folders it meets are not reported: only a rescan purges, and only a rescan
// needs them.
func (m *Monitor) walkQueue() {
	for {
		select {
		case <-m.done:
			return
		case <-m.walkWake:
		}
		for {
			root, ok := m.nextWalk()
			if !ok {
				break
			}
			m.walkRoot(root, 0)
		}
	}
}

// dropBelow removes from the queue the folders below root: its walk covers
// them. The caller holds walkMu.
func (m *Monitor) dropBelow(root string) {
	prefix := withSeparator(root)
	for other := range m.walkPending {
		if strings.HasPrefix(other, prefix) {
			delete(m.walkPending, other)
		}
	}
}

// nextWalk takes a folder to walk.
func (m *Monitor) nextWalk() (string, bool) {
	m.walkMu.Lock()
	defer m.walkMu.Unlock()
	for root := range m.walkPending {
		delete(m.walkPending, root)
		return root, true
	}
	return "", false
}
