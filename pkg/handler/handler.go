package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/alecthomas/units"
	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	quarantine "github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/pkg/scanner"
	"go.yaml.in/yaml/v3"
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
	submitter   scanner.Submitter
	monitor     Monitorer
	Quarantiner quarantine.Quarantiner

	stopped     bool
	wantStopped bool
	needSetup   bool
	conf        *config.Config
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
	return
}

func (h *Handler) setup(ctx context.Context, config *config.Config) (err error) {
	err = h.setupGMalwareClient(ctx, config)
	if err != nil {
		err = fmt.Errorf("setup gmalware client error: %w", err)
		if e := eventHandler.NotifyError(ctx, events.GMalwareConfigError, err); e != nil {
			logger.Warn("could not push console error", slog.String("error", e.Error()))
		}
		return
	}
	err = h.setupHostConnector(ctx, config)
	if err != nil {
		if e := eventHandler.NotifyError(ctx, HostConfigError, err); e != nil {
			logger.Warn("could not push console error", slog.String("error", e.Error()))
		}
		return
	}
	if e := eventHandler.NotifyResolution(ctx, "config setup succeeded", HostConfigError, events.GMalwareConfigError); e != nil {
		logger.Warn("could not push resolution event to connector manager", slog.String("error", e.Error()))
	}
	h.needSetup = false
	return
}

func (h *Handler) setupGMalwareClient(ctx context.Context, config *config.Config) (err error) {
	detectConfig := gdetect.ClientConfig{
		Endpoint:  config.GMalwareAPIURL,
		ExpertURL: config.GMalwareExpertURL,
		Token:     config.GMalwareAPIToken,
		Insecure:  config.GMalwareNoCertCheck,
		Syndetect: config.GMalwareSyndetect,
	}

	if h.submitter == nil {
		client, err := gdetect.NewClientFromConfig(detectConfig)
		if err != nil {
			err = fmt.Errorf("init glimps malware client error: %w", err)
			return err
		}
		h.submitter = client
	} else {
		err = h.submitter.Reconfigure(ctx, detectConfig)
		if err != nil {
			err = fmt.Errorf("reconfigure gdetect client error: %w", err)
			return
		}
	}
	return
}

func (h *Handler) setupQuarantiner(ctx context.Context, config *config.Config) (err error) {
	if !config.Actions.Quarantine {
		if h.Quarantiner != nil {
			if err = h.Quarantiner.Close(); err != nil {
				return
			}
			h.Quarantiner = nil
		}
		return
	}

	qConfig := quarantine.Config{
		Location:         config.Quarantine.Location,
		RegistryLocation: config.Quarantine.Registry,
		LockPassword:     config.Quarantine.Password,
	}

	if h.Quarantiner != nil {
		err = h.Quarantiner.Reconfigure(ctx, qConfig)
		if err != nil {
			return
		}
		return
	}

	quarantiner, err := quarantine.NewQuarantineHandler(ctx, qConfig)
	if err != nil {
		return
	}
	h.Quarantiner = quarantiner
	return
}

func (h *Handler) setupHostConnector(ctx context.Context, config *config.Config) (err error) {
	if config.Workers == 0 {
		config.Workers = 4
	}

	if config.ExtractWorkers == 0 {
		config.ExtractWorkers = 2
	}

	if config.Debug {
		scanner.LogLevel.Set(slog.LevelDebug)
		datamodel.LogLevel.Set(slog.LevelDebug)
		LogLevel.Set(slog.LevelDebug)
		logger.Debug("log level set to debug")
	} else {
		scanner.LogLevel.Set(slog.LevelInfo)
		datamodel.LogLevel.Set(slog.LevelInfo)
		LogLevel.Set(slog.LevelInfo)
		logger.Info("log level set to info")
	}

	err = h.setupQuarantiner(ctx, config)
	if err != nil {
		err = fmt.Errorf("error init quarantine: %w", err)
		return
	}

	customAction := make([]scanner.Action, 0)
	if config.Gui {
		customAction = append(customAction, new(GuiHandleResult))
	}

	maxFileSize, err := units.ParseStrictBytes(config.MaxFileSize)
	if err != nil {
		err = fmt.Errorf("could not parse max-file-size: %w", err)
		return
	}

	switch {
	case maxFileSize > maxFileSizeDetect && !config.GMalwareSyndetect:
		logger.Warn("max file size can't exceed 100MiB, set the value to 100MiB", slog.String("max-file-size", config.MaxFileSize))
		maxFileSize = maxFileSizeDetect
	case maxFileSize > maxFileSizeSynDetect:
		logger.Warn("max file size can't exceed 2GiB, set the value to 2GiB", slog.String("max-file-size", config.MaxFileSize))
		maxFileSize = maxFileSizeSynDetect
	case maxFileSize <= 0:
		logger.Warn("max file size must be greater than 0, set the value to 100MiB", slog.String("max-file-size", config.MaxFileSize))
		maxFileSize = maxFileSizeDetect
	}

	var informDest io.Writer = os.Stdout
	if config.Print.Location != "" {
		informFile, createErr := os.Create(config.Print.Location)
		if createErr != nil {
			err = fmt.Errorf("could not open report location, error: %w", createErr)
			return
		}
		informDest = informFile
	}

	if h.Conn != nil {
		h.Conn.Close(ctx)
	}

	h.Conn = scanner.NewConnector(scanner.Config{
		QuarantineFolder: config.Quarantine.Location,
		MaxFileSize:      maxFileSize,
		Workers:          config.Workers,
		ExtractWorkers:   config.ExtractWorkers,
		Password:         config.Quarantine.Password,
		Timeout:          config.GMalwareTimeout,
		FollowSymlinks:   config.FollowSymlinks,
		Actions: scanner.Actions{
			Log:        config.Actions.Log,
			Quarantine: config.Actions.Quarantine,
			Inform:     config.Actions.Print,
			Verbose:    config.Print.Verbose,
			Move:       config.Actions.Move,
			Deleted:    config.Actions.Delete || config.Actions.Quarantine,
			InformDest: informDest,
		},
		WaitOpts: gdetect.WaitForOptions{
			Tags:        append(config.GMalwareUserTags, "GMHost"),
			Timeout:     time.Duration(config.GMalwareTimeout),
			PullTime:    time.Millisecond * 500,
			BypassCache: config.GMalwareBypassCache,
		},
		ScanPeriod:    config.Monitoring.Period,
		CustomActions: customAction,
		Extract:       config.Extract,
		MoveTo:        config.Move.Destination,
		MoveFrom:      config.Move.Source,
	}, h.Quarantiner, h.submitter)

	if config.PluginsConfig != "" {
		configFile, openErr := os.Open(filepath.Clean(config.PluginsConfig))
		if openErr != nil {
			err = openErr
			return
		}
		defer func() {
			if e := configFile.Close(); e != nil {
				logger.Warn("error closing plugin config file", slog.String("file", config.PluginsConfig), slog.String("error", e.Error()))
			}
		}()

		pluginsConfig := make(map[string]scanner.PluginConfig)
		err = yaml.NewDecoder(configFile).Decode(pluginsConfig)
		if err != nil {
			return fmt.Errorf("could not decode plugins config file, error: %w", err)
		}
		err = h.Conn.LoadPlugins(pluginsConfig)
		if err != nil {
			return fmt.Errorf("could not load plugins, error: %w", err)
		}
	}

	if h.monitor != nil {
		if e := h.monitor.Close(); e != nil {
			logger.Error("could not close monitor for reconfiguring", slog.String("error", e.Error()))
		}
		h.monitor = nil
	}

	mon, monErr := NewMonitor(
		h.OnNewFile(ctx),
		Config{
			PreScan:  config.Monitoring.PreScan,
			ReScan:   config.Monitoring.ReScan,
			Period:   config.Monitoring.Period,
			ModDelay: config.Monitoring.ModificationDelay,
		},
	)
	if monErr != nil {
		err = monErr
		return
	}
	h.monitor = mon
	h.conf = config
	return
}

func (h *Handler) OnNewFile(ctx context.Context) OnNewFileFunc {
	return func(file string) error {
		return h.Conn.ScanFile(ctx, file)
	}
}

func (h *Handler) Start(ctx context.Context) (err error) {
	h.wantStopped = false
	if h.needSetup {
		err = h.setup(ctx, h.conf)
		if err != nil {
			return
		}
	}

	err = h.Conn.Start() //nolint:contextcheck // no ctx to pass, workers are launched goroutine
	if err != nil {
		err = fmt.Errorf("could not start host connector workers, error: %w", err)
		if e := eventHandler.NotifyError(ctx, HostStartError, err); e != nil {
			logger.Warn("could not push console error", slog.String("error", e.Error()))
		}
		return
	}
	h.monitor.Start()
	for _, path := range h.conf.Paths {
		if err = h.monitor.Add(path); err != nil {
			err = fmt.Errorf("could not start host connector workers, error monitoring path %s: %w", path, err)
			if e := eventHandler.NotifyError(ctx, HostConfigError, err); e != nil {
				logger.Warn("could not push console error", slog.String("error", e.Error()))
			}
			if e := h.monitor.Close(); e != nil {
				logger.Error("could not close monitor", slog.String("error", e.Error()))
			}
			h.Conn.Close(ctx)
			return
		}
	}
	h.stopped = false
	if e := eventHandler.NotifyResolution(ctx, "host connector started successfully", HostConfigError, HostStartError, events.GMalwareConfigError); e != nil {
		logger.Error("could not push console error", slog.String("error", e.Error()))
	}
	logger.Info("connector started")
	return
}

func (h *Handler) Stop(ctx context.Context) (err error) {
	h.wantStopped = true
	if h.stopped {
		return
	}
	h.stopped = true
	h.needSetup = true
	if h.monitor != nil {
		err = h.monitor.Close()
		if err != nil {
			return
		}
		h.monitor = nil
	}
	if h.Conn != nil {
		h.Conn.Close(ctx)
		h.Conn = nil
	}
	if h.Quarantiner != nil {
		err = h.Quarantiner.Close()
		if err != nil {
			return
		}
		h.Quarantiner = nil
	}
	logger.Info("connector stopped")
	return
}

func (h *Handler) Configure(ctx context.Context, rawConfig json.RawMessage) (err error) {
	conf := new(config.Config)
	err = json.Unmarshal(rawConfig, conf)
	if err != nil {
		return
	}
	err = h.setup(ctx, conf)
	if err != nil {
		logger.Error("failed to setup host connector", slog.String("error", err.Error()))
		return
	}
	if !h.wantStopped {
		err = h.Start(ctx)
		if err != nil {
			return
		}
	}
	return
}

func (h *Handler) Restore(ctx context.Context, restoreInfo sdk.RestoreActionContent) (err error) {
	if h.Quarantiner == nil {
		err = errors.New("quarantine is disabled, cannot restore files")
		return
	}
	err = h.Quarantiner.Restore(ctx, restoreInfo.ID)
	if err != nil {
		return
	}
	return
}

func (h *Handler) Status() (status sdk.ConnectorStatus) {
	if h.stopped {
		return sdk.Stopped
	}
	return sdk.Started
}
