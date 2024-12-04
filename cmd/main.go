package cmd

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/alecthomas/units"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/cache"
	"github.com/glimps-re/host-connector/pkg/scanner"
	"github.com/spf13/cobra"
)

var Logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))

type GContext struct {
	conn   *scanner.Connector
	client scanner.Submitter
	lock   scanner.Locker
	cache  cache.Cacher
}

var gctx = GContext{}

func initGCtx() (err error) {
	cache, err := cache.NewCache(conf.Cache.Location)
	if err != nil {
		return
	}
	client, err := gdetect.NewClient(conf.GDetect.URL, conf.GDetect.Token, conf.GDetect.Insecure, nil)
	if err != nil {
		return fmt.Errorf("init gdetect client error: %w", err)
	}
	if conf.GDetect.Syndetect {
		client.SetSyndetect()
	}
	customAction := make([]scanner.Action, 0)
	if conf.Gui {
		customAction = append(customAction, &GuiHandleResult{})
	}

	maxFileSize, err := units.ParseStrictBytes(conf.MaxFileSize)
	if err != nil {
		return fmt.Errorf("could not parse max-file-size: %w", err)
	}
	if maxFileSize > 100*1024*1024 && !conf.GDetect.Syndetect {
		Logger.Warn("max file size can't exceed 100MiB, set the value to 100MiB", slog.String("max-file-size", conf.MaxFileSize))
		maxFileSize = 100 * 1024 * 1024
	}
	if maxFileSize > 2048*1024*1024 {
		Logger.Warn("max file size can't exceed 2GiB, set the value to 2GiB", slog.String("max-file-size", conf.MaxFileSize))
		maxFileSize = 2048 * 1024 * 1024
	}
	if maxFileSize <= 0 {
		Logger.Warn("max file size must be greater than 0, set the value to 100MiB", slog.String("max-file-size", conf.MaxFileSize))
		maxFileSize = 100 * 1024 * 1024
	}

	var informDest io.Writer = os.Stdout
	if conf.Print.Location != "" {
		informDest, err = os.Create(conf.Print.Location)
		if err != nil {
			return fmt.Errorf("could not open report location: %w", err)
		}
	}

	connector := scanner.NewConnector(scanner.Config{
		QuarantineFolder: conf.Quarantine.Location,
		MaxFileSize:      maxFileSize,
		Workers:          conf.Workers,
		Password:         conf.Quarantine.Password,
		Cache:            cache,
		Submitter:        client,
		Timeout:          conf.GDetect.Timeout,
		Actions: scanner.Actions{
			Log:        conf.Actions.Log,
			Quarantine: conf.Actions.Quarantine,
			Inform:     conf.Actions.Print,
			Verbose:    conf.Verbose,
			Move:       conf.Actions.Move,
			Deleted:    conf.Actions.Delete || conf.Actions.Quarantine,
			InformDest: informDest,
		},
		WaitOpts: gdetect.WaitForOptions{
			Tags:     append(conf.GDetect.Tags, "GMHost"),
			Timeout:  conf.GDetect.Timeout,
			PullTime: time.Millisecond * 500,
		},
		ScanPeriod:    conf.Monitoring.Period,
		CustomActions: customAction,
		Extract:       conf.Extract,
		MoveTo:        conf.Move.Destination,
		MoveFrom:      conf.Move.Source,
	})
	lock := &scanner.Lock{Password: conf.Quarantine.Password}
	gctx = GContext{
		conn:   connector,
		client: client,
		lock:   lock,
		cache:  cache,
	}
	return
}

func Main() {
	initRoot(rootCmd)
	rootCmd.AddCommand(scanCmd)
	quarantineCmd.AddCommand(quarantineListCmd)
	quarantineCmd.AddCommand(quarantineRestoreCmd)
	rootCmd.AddCommand(quarantineCmd)
	rootCmd.AddCommand(monitoringCmd)
	defer func() {
		if gctx.cache != nil {
			gctx.cache.Close()
		}
	}()
	if err := rootCmd.Execute(); err != nil {
		Logger.Error("could not execute GMHost", slog.String("error", err.Error()))
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// mandatory tricks for windowsgui app
	cobra.MousetrapHelpText = ""
}
