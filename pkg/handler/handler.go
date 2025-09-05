package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/alecthomas/units"
	"github.com/glimps-re/connector-manager/pkg/shared"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/cache"
	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/monitor"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

var Logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))

type Handler struct {
	Conn    *scanner.Connector
	Client  scanner.Submitter
	Lock    scanner.Locker
	Cache   cache.Cacher
	Monitor *monitor.Monitor
	events  chan any
	stopped bool
	conf    *config.Config
}

var _ shared.Connector = &Handler{}

func NewHandler(ctx context.Context, config *config.Config) (h *Handler, err error) {
	h = &Handler{
		conf: config,
	}
	err = h.setup(ctx, config)
	if err != nil {
		return
	}
	return
}

// only used with new or stopped handler
func (h *Handler) setup(ctx context.Context, config *config.Config) (err error) {
	if h.Cache == nil {
		h.Cache, err = cache.NewCache(ctx, config.Cache.Location)
		if err != nil {
			return
		}
	}
	if h.Client == nil {
		client, err := gdetect.NewClient(config.GMalwareAPIURL, config.GMalwareAPIToken, config.GMalwareNoCertCheck, nil)
		if err != nil {
			err = fmt.Errorf("init gdetect client error: %w", err)
			return err
		}

		if config.Syndetect {
			client.SetSyndetect()
		}
		h.Client = client
	} else {
		err = h.Client.Reconfigure(config.GMalwareAPIURL, config.GMalwareAPIToken, config.GMalwareNoCertCheck, config.Syndetect, nil)
		if err != nil {
			err = fmt.Errorf("reconfigure gdetect client error: %w", err)
			return
		}
	}
	if config.Console.URL != "" && h.events == nil {
		h.events = make(chan any, 100)
	}
	customAction := make([]scanner.Action, 0)
	if config.Gui {
		customAction = append(customAction, &GuiHandleResult{})
	}

	maxFileSize, err := units.ParseStrictBytes(config.MaxFileSize)
	if err != nil {
		err = fmt.Errorf("could not parse max-file-size: %w", err)
		return
	}
	if maxFileSize > 100*1024*1024 && !config.Syndetect {
		Logger.Warn("max file size can't exceed 100MiB, set the value to 100MiB", slog.String("max-file-size", config.MaxFileSize))
		maxFileSize = 100 * 1024 * 1024
	}
	if maxFileSize > 2048*1024*1024 {
		Logger.Warn("max file size can't exceed 2GiB, set the value to 2GiB", slog.String("max-file-size", config.MaxFileSize))
		maxFileSize = 2048 * 1024 * 1024
	}
	if maxFileSize <= 0 {
		Logger.Warn("max file size must be greater than 0, set the value to 100MiB", slog.String("max-file-size", config.MaxFileSize))
		maxFileSize = 100 * 1024 * 1024
	}

	var informDest io.Writer = os.Stdout
	if config.Print.Location != "" {
		informDest, err = os.Create(config.Print.Location)
		if err != nil {
			err = fmt.Errorf("could not open report location: %w", err)
			return
		}
	}

	h.Conn = scanner.NewConnector(scanner.Config{
		QuarantineFolder: config.Quarantine.Location,
		MaxFileSize:      maxFileSize,
		Workers:          config.Workers,
		Password:         config.Quarantine.Password,
		Cache:            h.Cache,
		Submitter:        h.Client,
		Timeout:          config.Timeout,
		Actions: scanner.Actions{
			Log:        config.Actions.Log,
			Quarantine: config.Actions.Quarantine,
			Inform:     config.Actions.Print,
			Verbose:    config.Verbose,
			Move:       config.Actions.Move,
			Deleted:    config.Actions.Delete || config.Actions.Quarantine,
			InformDest: informDest,
		},
		WaitOpts: gdetect.WaitForOptions{
			Tags:     append(config.GMalwareUserTags, "GMHost"),
			Timeout:  config.Timeout,
			PullTime: time.Millisecond * 500,
		},
		ScanPeriod:    config.Monitoring.Period,
		CustomActions: customAction,
		Extract:       config.Extract,
		MoveTo:        config.Move.Destination,
		MoveFrom:      config.Move.Source,
		ConsoleEvents: h.events,
	})

	if err := h.Conn.LoadPlugins(scanner.Config{
		PluginsDir: config.PluginConfig.Location,
		Plugins:    config.PluginConfig.Plugins,
	}); err != nil {
		return err
	}
	h.Lock = &scanner.Lock{Password: config.Quarantine.Password}
	return
}

func (h *Handler) OnNewFile(ctx context.Context) monitor.OnNewFileFunc {
	return func(file string) error {
		return h.Conn.ScanFile(ctx, file)
	}
}

func (h *Handler) Launch(ctx context.Context) (events <-chan any, errs <-chan error) {
	events = h.events
	return
}

func (h *Handler) Start(ctx context.Context) (err error) {
	err = h.Conn.Start(ctx)
	if err != nil {
		return
	}
	mon, err := monitor.NewMonitor(
		h.OnNewFile(ctx),
		h.conf.Monitoring.PreScan,
		h.conf.Monitoring.Period,
		h.conf.Monitoring.ModificationDelay,
	)
	if err != nil {
		return
	}
	h.Monitor = mon
	h.Monitor.Start()
	for _, path := range h.conf.Paths {
		if err = h.Monitor.Add(path); err != nil {
			return
		}
	}
	h.stopped = false
	return
}

func (h *Handler) Stop(ctx context.Context) (err error) {
	h.stop()
	h.stopped = true
	return
}

func (h *Handler) stop() {
	if h.stopped {
		return
	}
	h.Monitor.Close()
	h.Conn.Close()
}

func (h *Handler) Configure(ctx context.Context, config json.RawMessage) (err error) {
	err = json.Unmarshal(config, h.conf)
	if err != nil {
		return
	}
	h.stop()
	err = h.setup(ctx, h.conf)
	if err != nil {
		return
	}
	if !h.stopped {
		err = h.Start(ctx)
		if err != nil {
			return
		}
	}
	return
}

func (h *Handler) Restore(ctx context.Context, restoreInfo shared.RestoreActionContent) (err error) {
	qa := scanner.NewQuarantineAction(h.Cache, h.conf.Quarantine.Location, h.Lock, h.events)
	err = qa.Restore(ctx, restoreInfo.ID)
	if err != nil {
		return
	}
	return
}

func (h *Handler) Status() (status shared.ConnectorStatus) {
	if h.stopped {
		return shared.Stopped
	}
	return shared.Started
}

func (h *Handler) Close() {
	close(h.events)
}
