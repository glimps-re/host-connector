package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"time"

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

func initGCtx() error {
	cache, err := cache.NewCache(conf.Cache.Location)
	if err != nil {
		return err
	}
	client, err := gdetect.NewClient(conf.GDetect.URL, conf.GDetect.Token, conf.GDetect.Insecure, nil)
	if err != nil {
		return fmt.Errorf("init gdetect client error: %s", err)
	}
	customAction := make([]scanner.Action, 0)
	if conf.Gui {
		customAction = append(customAction, &GuiHandleResult{})
	}
	connector := scanner.NewConnector(scanner.Config{
		QuarantineFolder: conf.Quarantine.Location,
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
			Deleted:    conf.Actions.Delete || conf.Actions.Quarantine,
		},
		WaitOpts: gdetect.WaitForOptions{
			Tags:     append(conf.GDetect.Tags, "GMHost"),
			Timeout:  conf.GDetect.Timeout,
			PullTime: time.Millisecond * 500,
		},
		ScanPeriod:    conf.Monitoring.Period,
		CustomActions: customAction,
	})
	lock := &scanner.Lock{Password: conf.Quarantine.Password}
	gctx = GContext{
		conn:   connector,
		client: client,
		lock:   lock,
		cache:  cache,
	}
	return nil
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
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// mandatory tricks for windowsgui app
	cobra.MousetrapHelpText = ""
}
