package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/alecthomas/units"
	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

const (
	// HostConfigRejected stays raised until a Configure succeeds: the console
	// and the connector disagree on the configuration while it lasts.
	HostConfigRejected events.ErrorEventType = "host-config-rejected"
	// HostConfigUnknownKeys is raised when the console sends keys this version
	// does not know, and resolved by the next Configure without such keys.
	HostConfigUnknownKeys events.ErrorEventType = "host-config-unknown-keys"
)

const (
	rejectedNotApplied  = "the previous configuration stays in service; the requested configuration is NOT applied; after a restart the connector will receive the rejected configuration and will not start"
	rejectedInterrupted = "processing was interrupted and resumed with the previous configuration; the requested configuration is NOT applied; after a restart the connector will receive the rejected configuration and will not start"
	rejectedNoConfig    = "no configuration is in service and the connector is not running; the requested configuration is NOT applied; fix it and send it again"
	rejectedStoppedConn = "the connector is stopped; the previous configuration will be used at the next Start; the requested configuration is NOT applied; after a restart the connector will receive the rejected configuration and will not start"
	rejectedStopped     = "the rollback failed too: processing is STOPPED; the requested configuration is NOT applied and the previous one could not be restored; fix the configuration and send it again"
	unknownKeysNoEffect = "these keys have NO effect on this connector; update the connector for them to apply"
)

// rejectReminderEvery is the period of the reminder logged while a rejected
// configuration is still pending. A variable so tests can shorten it.
var rejectReminderEvery = time.Hour

var errGMalwareConfig = errors.New("gmalware client configuration")

// prepared holds what the validation step computed, so the apply steps do not
// parse the configuration again.
type prepared struct {
	maxFileSize             int64
	extractMinSize          int64
	recursiveExtractMaxSize int64
	pluginsConfig           []scanner.PluginConfig
}

// prepare validates conf without any effect on what is running or on disk.
func (h *Handler) prepare(conf *config.Config) (p *prepared, err error) {
	if err = errors.Join(config.Validate(conf), config.CheckImplemented(conf)); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	p = new(prepared)
	if p.maxFileSize, err = units.ParseStrictBytes(conf.MaxFileSize); err != nil {
		return nil, fmt.Errorf("could not parse max-file-size: %w", err)
	}
	if conf.ExtractMinSize != "" {
		if p.extractMinSize, err = units.ParseStrictBytes(conf.ExtractMinSize); err != nil {
			return nil, fmt.Errorf("could not parse extract-min-size: %w", err)
		}
	}
	if conf.RecursiveExtractMaxSize != "" {
		if p.recursiveExtractMaxSize, err = units.ParseStrictBytes(conf.RecursiveExtractMaxSize); err != nil {
			return nil, fmt.Errorf("could not parse recursive-extract-max-size: %w", err)
		}
	}
	switch {
	case p.maxFileSize > maxFileSizeDetect && !conf.GMalwareSyndetect:
		logger.Warn("max file size can't exceed 100MiB, set the value to 100MiB", slog.String("max-file-size", conf.MaxFileSize))
		p.maxFileSize = maxFileSizeDetect
	case p.maxFileSize > maxFileSizeSynDetect:
		logger.Warn("max file size can't exceed 2GiB, set the value to 2GiB", slog.String("max-file-size", conf.MaxFileSize))
		p.maxFileSize = maxFileSizeSynDetect
	case p.maxFileSize <= 0:
		logger.Warn("max file size must be greater than 0, set the value to 100MiB", slog.String("max-file-size", conf.MaxFileSize))
		p.maxFileSize = maxFileSizeDetect
	}
	if err = checkWorkDir(conf); err != nil {
		return nil, err
	}
	if err = checkReportLocation(conf.Print.Location); err != nil {
		return nil, err
	}
	if _, err = gdetect.NewClientFromConfig(gmalwareClientConfig(conf)); err != nil {
		return nil, fmt.Errorf("%w: %w", errGMalwareConfig, err)
	}
	if p.pluginsConfig, err = readPluginsConfig(conf.PluginsConfig); err != nil {
		return nil, err
	}
	return p, nil
}

func readPluginsConfig(path string) ([]scanner.PluginConfig, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("could not open plugins config file %q: %w", path, err)
	}
	defer func() {
		if e := f.Close(); e != nil {
			logger.Warn("error closing plugin config file", slog.String("file", path), slog.String("error", e.Error()))
		}
	}()
	pluginsConfig, err := decodePluginsConfig(f)
	if err != nil {
		return nil, fmt.Errorf("could not decode plugins config file, error: %w", err)
	}
	return pluginsConfig, nil
}

// apply validates conf, then applies it. A configuration that fails validation
// touches nothing. One that fails while being applied is rolled back to the
// previous configuration; without any previous valid configuration, or when
// the rollback fails too, the connector stops completely.
func (h *Handler) apply(ctx context.Context, conf *config.Config, start bool) (err error) {
	p, err := h.prepare(conf)
	if err != nil {
		return h.refuse(ctx, conf, err)
	}
	if err = h.install(ctx, conf, p, start); err == nil {
		h.commit(ctx, conf)
		return nil
	}
	if !h.configured || conf == h.conf {
		h.conf = conf
		h.failSetup(ctx, err)
		return err
	}

	rerr := h.replay(ctx, h.conf, start)
	if rerr != nil {
		err = errors.Join(err, fmt.Errorf("rollback failed: %w", rerr))
		h.failSetup(ctx, err)
		h.notifyRejected(ctx, err, rejectedStopped)
		return err
	}
	h.notifyRejected(ctx, err, rejectedInterrupted)
	return err
}

// replay applies the previous configuration again after a failed application.
func (h *Handler) replay(ctx context.Context, old *config.Config, start bool) error {
	p, err := h.prepare(old)
	if err != nil {
		return err
	}
	if err = h.install(ctx, old, p, start); err != nil {
		return err
	}
	h.commit(ctx, old)
	return nil
}

// refuse handles a configuration that failed validation.
func (h *Handler) refuse(ctx context.Context, conf *config.Config, err error) error {
	if !h.configured || conf == h.conf {
		h.conf = conf
		h.failSetup(ctx, err)
		return err
	}
	h.notifyRejected(ctx, err, h.consequence())
	return err
}

// consequence tells what a rejection means in the real state of the connector.
func (h *Handler) consequence() string {
	switch {
	case !h.configured:
		return rejectedNoConfig
	case h.stopped:
		return rejectedStoppedConn
	default:
		return rejectedNotApplied
	}
}

func (h *Handler) commit(ctx context.Context, conf *config.Config) {
	h.conf = conf
	h.configured = true
	h.needSetup = false
	if conf.Actions.Quarantine && conf.Quarantine.Format == string(quarantine.FormatZip) {
		warnZipPasswordPublic()
	}
	warnFollowSymlinks(conf)
	if e := eventHandler.NotifyResolution(ctx, "config setup succeeded", HostConfigError, events.GMalwareConfigError); e != nil {
		logger.Warn("could not push resolution event to connector manager", slog.String("error", e.Error()))
	}
}

// failSetup stops everything and arms the next Start to apply the
// configuration again.
func (h *Handler) failSetup(ctx context.Context, err error) {
	h.closeRunning(ctx)
	h.stopped = true
	h.needSetup = true
	key := HostConfigError
	if errors.Is(err, errGMalwareConfig) {
		key = events.GMalwareConfigError
	}
	logger.Error("configuration cannot be applied, connector stopped", slog.String("error", err.Error()))
	if e := eventHandler.NotifyError(ctx, key, err); e != nil {
		logger.Warn("could not push console error", slog.String("error", e.Error()))
	}
}

// closeRunning closes what is running: the monitor first, so it stops feeding
// a closing Connector, then the Connector, then the report destination, which
// ongoing analyses write to until Connector.Close returns.
func (h *Handler) closeRunning(ctx context.Context) {
	if h.monitor != nil {
		if e := h.monitor.Close(); e != nil {
			logger.Error("could not close monitor", slog.String("error", e.Error()))
		}
		h.monitor = nil
	}
	if h.Conn != nil {
		h.Conn.Close(ctx)
		h.Conn = nil
	}
	if h.informDest != nil {
		if e := h.informDest.Close(); e != nil {
			logger.Warn("could not close inform destination", slog.String("error", e.Error()))
		}
		h.informDest = nil
	}
}

// install runs the applying steps. 2: stop what runs, rebuild the Connector,
// load the plugins, prepare the monitor. 3: reconfigure the quarantine, last
// because it moves files. 4: start the workers and the monitor.
func (h *Handler) install(ctx context.Context, conf *config.Config, p *prepared, start bool) (err error) {
	setLogLevel(conf)
	var reportFile io.WriteCloser
	informDest := io.WriteCloser(os.Stdout)
	if conf.Print.Location != "" {
		dir := filepath.Dir(conf.Print.Location)
		if err = os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("could not create report directory %q: %w", dir, err)
		}
		reportFile, err = os.OpenFile(filepath.Clean(conf.Print.Location), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			return fmt.Errorf("could not open report location, error: %w", err)
		}
		informDest = reportFile
	}

	h.closeRunning(ctx)
	h.informDest = reportFile

	var (
		conn *scanner.Connector
		mon  *Monitor
		done bool
	)
	defer func() {
		if done {
			return
		}
		if mon != nil {
			if e := mon.Close(); e != nil {
				logger.Error("could not close monitor", slog.String("error", e.Error()))
			}
		}
		if conn != nil {
			conn.Close(ctx)
		}
		h.closeRunning(ctx)
	}()

	if err = h.setupGMalwareClient(ctx, conf); err != nil {
		return fmt.Errorf("%w: %w", errGMalwareConfig, err)
	}

	quarantineCreated := false
	if conf.Actions.Quarantine && h.Quarantiner == nil {
		if err = h.setupQuarantiner(ctx, conf); err != nil {
			return fmt.Errorf("error init quarantine: %w", err)
		}
		quarantineCreated = true
	}

	conn, err = h.newConnector(conf, p, informDest)
	if err != nil {
		return err
	}
	if err = conn.LoadPlugins(p.pluginsConfig); err != nil {
		return fmt.Errorf("could not load plugins, error: %w", err)
	}
	h.Conn = conn

	mon, err = NewMonitor(h.OnNewFile(ctx), Config{
		DisableWatcher: conf.Monitoring.DisableFSWatcher,
		Skip:           conn.IsInternalPath,
		PreScan:        conf.Monitoring.PreScan,
		Period:         conf.Monitoring.Period,
		ModDelay:       conf.Monitoring.ModificationDelay,
		FollowSymlinks: conf.FollowSymlinks,
	})
	if err != nil {
		mon = nil
		return fmt.Errorf("could not init monitoring: %w", err)
	}
	h.monitor = mon
	if start {
		if err = addWatches(mon, conf.Paths); err != nil {
			return err
		}
	} else if err = checkPathsExist(conf.Paths); err != nil {
		return err
	}

	if !quarantineCreated {
		if err = h.reconfigureQuarantine(ctx, conf); err != nil {
			return fmt.Errorf("error init quarantine: %w", err)
		}
	}

	if start {
		if err = startConnector(conn); err != nil {
			return fmt.Errorf("could not start host connector workers, error: %w", err)
		}
		mon.Start()
		h.stopped = false
	}
	done = true
	return nil
}

// startConnector starts the workers of conn. A variable so tests can inject a
// failure at the last step of an application.
var startConnector = func(conn *scanner.Connector) error { return conn.Start() }

func addWatches(mon Monitorer, paths []string) error {
	logger.Info("setting up directory monitoring, this may take a while for large directories ...", slog.Int("paths", len(paths)))
	for _, path := range paths {
		if err := mon.Add(path); err != nil {
			return fmt.Errorf("error adding path %s to monitoring: %w", path, err)
		}
	}
	return nil
}

// checkPathsExist is addWatches for a connector that does not start: the
// monitored paths must exist, or the configuration would fail at the next Start.
func checkPathsExist(paths []string) error {
	for _, path := range paths {
		if _, err := os.Stat(filepath.Clean(path)); err != nil {
			return fmt.Errorf("monitored path %s: %w", path, err)
		}
	}
	return nil
}

// reconfigureQuarantine applies the quarantine settings of conf to the running
// Quarantiner; unchanged settings are left alone.
func (h *Handler) reconfigureQuarantine(ctx context.Context, conf *config.Config) error {
	if !conf.Actions.Quarantine {
		return h.setupQuarantiner(ctx, conf)
	}
	if h.Quarantiner != nil && reflect.DeepEqual(h.qConf, quarantineConfig(conf)) {
		return nil
	}
	return h.setupQuarantiner(ctx, conf)
}

func (h *Handler) newConnector(conf *config.Config, p *prepared, informDest io.WriteCloser) (*scanner.Connector, error) {
	customAction := make([]scanner.Action, 0)
	if conf.Gui {
		customAction = append(customAction, new(GuiHandleResult))
	}
	quarantiner := h.Quarantiner
	if !conf.Actions.Quarantine {
		quarantiner = nil
	}
	return scanner.NewConnector(scanner.Config{
		QuarantineFolder:    conf.Quarantine.Location,
		MaxFileSize:         p.maxFileSize,
		ExtractMinThreshold: p.extractMinSize,
		Workers:             conf.Workers,
		ExtractWorkers:      conf.ExtractWorkers,
		Password:            conf.Quarantine.Password,
		Timeout:             conf.GMalwareTimeout,
		FollowSymlinks:      conf.FollowSymlinks,
		WorkDir:             conf.WorkDir,
		Roots:               conf.Paths,
		Actions: scanner.Actions{
			Log:        conf.Actions.Log,
			Quarantine: conf.Actions.Quarantine,
			Inform:     conf.Actions.Print,
			Verbose:    conf.Print.Verbose,
			Move:       conf.Actions.Move,
			Deleted:    conf.Actions.Delete || conf.Actions.Quarantine,
			InformDest: informDest,
		},
		WaitOpts: gdetect.WaitForOptions{
			SubmitOptions: gdetect.SubmitOptions{
				Tags:        append(conf.GMalwareUserTags, "GMHost"),
				BypassCache: conf.GMalwareBypassCache,
			},
			Timeout:  time.Duration(conf.GMalwareTimeout),
			PullTime: time.Millisecond * 500,
		},
		CustomActions:            customAction,
		Extract:                  conf.Extract,
		RecursiveExtractMaxDepth: conf.RecursiveExtractMaxDepth,
		RecursiveExtractMaxSize:  p.recursiveExtractMaxSize,
		RecursiveExtractMaxFiles: conf.RecursiveExtractMaxFiles,
		MoveTo:                   conf.Move.Destination,
		MoveFrom:                 conf.Move.Source,
	}, quarantiner, h.submitter)
}

// notifyRejected raises the durable event telling that conf was not applied.
func (h *Handler) notifyRejected(ctx context.Context, err error, consequence string) {
	msg := fmt.Errorf("configuration rejected: %w; %s", err, consequence)
	logger.Error("configuration rejected", slog.String("error", msg.Error()))
	if e := eventHandler.NotifyError(ctx, HostConfigRejected, msg); e != nil {
		logger.Warn("could not push console error", slog.String("error", e.Error()))
	}
	h.startRejectReminder(msg.Error())
}

func (h *Handler) resolveRejected(ctx context.Context) {
	h.stopRejectReminder()
	if e := eventHandler.NotifyResolution(ctx, "configuration applied", HostConfigRejected); e != nil {
		logger.Warn("could not push resolution event to connector manager", slog.String("error", e.Error()))
	}
}

func (h *Handler) startRejectReminder(message string) {
	h.remindMu.Lock()
	defer h.remindMu.Unlock()
	h.lastRejected = message
	if h.remindStop != nil {
		return
	}
	stop := make(chan struct{})
	h.remindStop = stop
	every := rejectReminderEvery
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				h.remindMu.Lock()
				last := h.lastRejected
				h.remindMu.Unlock()
				logger.Warn("a rejected configuration is still pending: " + last)
			}
		}
	}()
}

func (h *Handler) stopRejectReminder() {
	h.remindMu.Lock()
	defer h.remindMu.Unlock()
	if h.remindStop != nil {
		close(h.remindStop)
		h.remindStop = nil
	}
}

// reportUnknownKeys keeps the unknown keys of the last Configure visible: they
// are applied without effect, which must never pass for applied.
func (h *Handler) reportUnknownKeys(ctx context.Context, keys []string) {
	if len(keys) == 0 {
		if e := eventHandler.NotifyResolution(ctx, "no unknown configuration key", HostConfigUnknownKeys); e != nil {
			logger.Warn("could not push resolution event to connector manager", slog.String("error", e.Error()))
		}
		return
	}
	msg := fmt.Sprintf("unknown configuration keys: %v; %s", capKeys(keys), unknownKeysNoEffect)
	logger.Warn(msg)
	if e := eventHandler.NotifyError(ctx, HostConfigUnknownKeys, errors.New(msg)); e != nil {
		logger.Warn("could not push console error", slog.String("error", e.Error()))
	}
}

func setLogLevel(conf *config.Config) {
	level := slog.LevelInfo
	if conf.Debug {
		level = slog.LevelDebug
	}
	scanner.LogLevel.Set(level)
	datamodel.LogLevel.Set(level)
	LogLevel.Set(level)
	logger.Debug("log level set to debug")
}

func gmalwareClientConfig(conf *config.Config) gdetect.ClientConfig {
	// The default idle pool keeps only 2 connections per host, which fits occasional requests but not a worker pool.
	// Sizing the idle pool to the worker count lets connections be reused across requests instead of paying a TCP+TLS handshake on nearly every one.
	nbAnalysisWorkers := conf.Workers
	if nbAnalysisWorkers < 1 {
		nbAnalysisWorkers = config.DefaultWorkers
	}
	return gdetect.ClientConfig{
		Endpoint:            conf.GMalwareAPIURL,
		ExpertURL:           conf.GMalwareExpertURL,
		Token:               conf.GMalwareAPIToken,
		Insecure:            conf.GMalwareNoCertCheck,
		Syndetect:           conf.GMalwareSyndetect,
		MaxIdleConnsPerHost: nbAnalysisWorkers,
	}
}

func quarantineConfig(conf *config.Config) quarantine.Config {
	return quarantine.Config{
		Location:         conf.Quarantine.Location,
		RegistryLocation: conf.Quarantine.Registry,
		LockPassword:     conf.Quarantine.Password,
		Format:           quarantine.Format(conf.Quarantine.Format),
		WatchedPaths:     conf.Paths,
	}
}

// checkReportLocation checks, without creating anything, that print.location
// can be written: an existing file must open for appending, a missing one needs
// an existing, writable ancestor directory.
func checkReportLocation(location string) error {
	if location == "" {
		return nil
	}
	location = filepath.Clean(location)
	info, err := os.Stat(location)
	if err == nil {
		if info.IsDir() {
			return fmt.Errorf("print.location %q is a directory", location)
		}
		f, openErr := os.OpenFile(location, os.O_WRONLY|os.O_APPEND, 0)
		if openErr != nil {
			return fmt.Errorf("print.location %q cannot be written: %w", location, openErr)
		}
		return f.Close()
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("print.location %q: %w", location, err)
	}
	for dir := filepath.Dir(location); ; dir = filepath.Dir(dir) {
		di, statErr := os.Stat(dir)
		if statErr == nil {
			if !di.IsDir() {
				return fmt.Errorf("print.location %q: %q is not a directory", location, dir)
			}
			if di.Mode().Perm()&0o200 == 0 {
				return fmt.Errorf("print.location %q: directory %q is not writable", location, dir)
			}
			return nil
		}
		if !errors.Is(statErr, os.ErrNotExist) || dir == filepath.Dir(dir) {
			return fmt.Errorf("print.location %q: %w", location, statErr)
		}
	}
}

const (
	maxReportedKeys   = 50
	maxReportedKeyLen = 256
)

// capKeys bounds what is reported: the keys come from the network.
func capKeys(keys []string) []string {
	out := make([]string, 0, min(len(keys), maxReportedKeys)+1)
	for i, k := range keys {
		if i == maxReportedKeys {
			out = append(out, fmt.Sprintf("... and %d more", len(keys)-maxReportedKeys))
			break
		}
		if len(k) > maxReportedKeyLen {
			k = k[:maxReportedKeyLen] + "..."
		}
		out = append(out, k)
	}
	return out
}
