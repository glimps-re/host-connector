package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/config"
	quarantine "github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

var LogLevel = &slog.LevelVar{}

var logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
	Level: LogLevel,
}))

var (
	consoleLogger                     = slog.New(slog.DiscardHandler)
	eventHandler  events.EventHandler = events.NoopEventHandler{}
)

type Handler struct {
	Conn        *scanner.Connector
	submitter   gdetect.ControllerExtendedGDetectSubmitter
	monitor     Monitorer
	Quarantiner quarantine.Quarantiner
	informDest  io.WriteCloser

	mu          sync.RWMutex
	stopped     bool
	wantStopped bool
	needSetup   bool
	// configured is true once a configuration has been applied: from then on a
	// refused one leaves the running configuration in place.
	configured bool
	conf       *config.Config
	qConf      quarantine.Config

	remindMu     sync.Mutex
	remindStop   chan struct{}
	remindDone   chan struct{}
	lastRejected string

	// validatePlugins replaces scanner.ValidatePlugins when set (tests).
	validatePlugins func([]scanner.PluginConfig, *scanner.ValidationContext) error
}

const (
	HostConfigError events.ErrorEventType = "host-bad-config"
	HostStartError  events.ErrorEventType = "host-start"
)

const (
	maxFileSizeDetect    = 100 * 1024 * 1024  // 100 MiB
	maxFileSizeSynDetect = 2048 * 1024 * 1024 // 2 GiB
)

var _ sdk.Connector = &Handler{}

func NewHandler(ctx context.Context, config *config.Config, consoleClient *sdk.ConnectorManagerClient, unresolvedErrors map[events.ErrorEventType]string) (h *Handler, err error) {
	h = new(Handler)
	h.stopped = true
	if consoleClient != nil {
		eventHandler = consoleClient.NewConsoleEventHandler(LogLevel, unresolvedErrors)
		consoleLogger = slog.New(eventHandler.GetLogHandler())
		scanner.ConsoleLogger = consoleLogger
		scanner.EventHandler = eventHandler
	}
	err = h.setup(ctx, config)
	if err != nil {
		return
	}
	if consoleClient != nil {
		scanner.MetricCollecter = consoleClient.NewMetricCollecter(h.submitter)
	}
	return
}

func (h *Handler) setup(ctx context.Context, conf *config.Config) error {
	h.conf = conf
	return h.apply(ctx, conf, false)
}

func (h *Handler) setupGMalwareClient(ctx context.Context, conf *config.Config) (err error) {
	detectConfig := gmalwareClientConfig(conf)
	if h.submitter == nil {
		client, err := gdetect.NewClientFromConfig(detectConfig)
		if err != nil {
			return fmt.Errorf("init glimps malware client error: %w", err)
		}
		h.submitter = client
		return nil
	}
	if err = h.submitter.Reconfigure(ctx, detectConfig); err != nil {
		return fmt.Errorf("reconfigure gdetect client error: %w", err)
	}
	return nil
}

func (h *Handler) setupQuarantiner(ctx context.Context, config *config.Config) (err error) {
	if !config.Actions.Quarantine {
		if h.Quarantiner != nil {
			if err = h.Quarantiner.Close(); err != nil {
				return
			}
			h.Quarantiner = nil
			h.qConf = quarantine.Config{}
		}
		return
	}

	qConfig := quarantineConfig(config)
	if h.Quarantiner != nil {
		if err = h.Quarantiner.Reconfigure(ctx, qConfig); err != nil {
			return
		}
	} else {
		quarantiner, newErr := quarantine.NewQuarantineHandler(ctx, qConfig)
		if newErr != nil {
			return newErr
		}
		h.Quarantiner = quarantiner
	}
	h.qConf = qConfig
	return
}

// warnZipPasswordPublic warns that the quarantine password is recoverable from
// ZipCrypto files: whoever deposited a file knows its plaintext.
func warnZipPasswordPublic() {
	const msg = "with the zip quarantine format, the quarantine password must be considered public: do not reuse it elsewhere, existing tar quarantine files of this directory are no longer confidential either"
	logger.Warn(msg)
	consoleLogger.Warn(msg)
}

func (h *Handler) OnNewFile(ctx context.Context) OnNewFileFunc {
	return func(file string, id scanner.FileIdentity) (bool, error) {
		return h.Conn.SubmitFile(ctx, file, id)
	}
}

func (h *Handler) Start(ctx context.Context) (err error) {
	logger.Debug("received Start action from connector-manager")
	defer func() {
		if err != nil {
			logger.Error("Start action failed", slog.String("error", err.Error()))
			return
		}
		logger.Debug("Start action completed")
	}()
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.startLocked(ctx, "starting")
}

func (h *Handler) startLocked(ctx context.Context, phase string) (err error) {
	logger := logger.With(slog.String("phase", phase))

	h.wantStopped = false
	if !h.stopped {
		return nil
	}
	if h.needSetup || h.Conn == nil || h.monitor == nil {
		logger.Info("setting up connector configuration ...") // info level because start is an important phase and not frequent
		if err = h.apply(ctx, h.conf, true); err != nil {
			return
		}
		logger.Info("connector configuration completed successfully")
	} else if err = h.activate(ctx); err != nil {
		return
	}
	if e := eventHandler.NotifyResolution(ctx, "host connector started successfully", HostConfigError, HostStartError, events.GMalwareConfigError); e != nil {
		logger.Error("could not push console error", slog.String("error", e.Error()))
	}
	logger.Info("monitoring successfully completed. phase successful")
	return
}

// activate starts a connector that is built but not running.
func (h *Handler) activate(ctx context.Context) (err error) {
	if err = addWatches(h.monitor, h.conf.Paths); err != nil {
		h.failSetup(ctx, err)
		return
	}
	if err = startConnector(h.Conn); err != nil {
		err = fmt.Errorf("could not start host connector workers, error: %w", err)
		if e := eventHandler.NotifyError(ctx, HostStartError, err); e != nil {
			logger.Warn("could not push console error", slog.String("error", e.Error()))
		}
		h.failSetup(ctx, err)
		return
	}
	h.monitor.Start()
	h.stopped = false
	return
}

func (h *Handler) Stop(ctx context.Context) (err error) {
	logger := logger.With(slog.String("phase", "stopping"))

	logger.Debug("received Stop action from connector-manager")
	defer func() {
		if err != nil {
			logger.Error("Stop action failed", slog.String("error", err.Error()))
			return
		}
		logger.Debug("Stop action completed")
	}()
	h.mu.Lock()
	defer h.mu.Unlock()

	h.wantStopped = true
	if h.stopped && h.Quarantiner == nil {
		return
	}
	h.stopped = true
	h.needSetup = true
	logger.Info("stopping, waiting for ongoing analyses to complete, this may take a while ...") // info level because stop is an important phase and not frequent
	h.closeRunning(ctx)
	if h.Quarantiner != nil {
		err = h.Quarantiner.Close()
		if err != nil {
			return
		}
		h.Quarantiner = nil
		h.qConf = quarantine.Config{}
	}
	logger.Info("connector stopped")
	return
}

func (h *Handler) Configure(ctx context.Context, rawConfig json.RawMessage) (err error) {
	logger.Debug("received Configure action from connector-manager")
	defer func() {
		if err != nil {
			logger.Error("Configure action failed", slog.String("error", err.Error()))
			return
		}
		logger.Debug("Configure action completed")
	}()
	h.mu.Lock()
	defer h.mu.Unlock()

	conf := new(config.Config)
	if err = json.Unmarshal(rawConfig, conf); err != nil {
		h.notifyRejected(ctx, fmt.Errorf("undecodable configuration: %w", err), h.consequence())
		return
	}

	if err = h.apply(ctx, conf, !h.wantStopped); err != nil {
		err = fmt.Errorf("failed to setup host connector: %w", err)
		return
	}
	h.resolveRejected(ctx)
	h.reportUnknownKeys(ctx, unknownKeys(rawConfig))
	h.reportMoveMode(ctx, conf)
	return
}

func (h *Handler) Restore(ctx context.Context, restoreInfo sdk.RestoreActionContent) (err error) {
	logger.Debug("received Restore action from connector-manager")
	defer func() {
		if err != nil {
			logger.Error("Restore action failed", slog.String("error", err.Error()))
			return
		}
		logger.Debug("Restore action completed")
	}()
	h.mu.RLock()
	quarantiner := h.Quarantiner
	h.mu.RUnlock()
	if quarantiner == nil {
		err = errors.New("quarantine is disabled, cannot restore files")
		return
	}
	err = quarantiner.Restore(ctx, restoreInfo.ID)
	if err != nil {
		return
	}
	return
}

func (h *Handler) Status() (status sdk.ConnectorStatus) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.stopped {
		return sdk.Stopped
	}
	return sdk.Started
}

// Close ends what outlives Stop: the reminder of a rejected configuration.
func (h *Handler) Close() { h.stopRejectReminder() }
