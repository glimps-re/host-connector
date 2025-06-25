package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/alecthomas/units"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/cache"
	"github.com/glimps-re/host-connector/pkg/filesystem"
	"github.com/glimps-re/host-connector/pkg/scanner"
	"github.com/spf13/cobra"
)

var Logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))

type GContext struct {
	fs     filesystem.FileSystem
	conn   *scanner.Connector
	client scanner.Submitter
	lock   scanner.Locker
	cache  cache.Cacher
}

var gctx = GContext{}

const (
	maxFileSizeDetect    = 100 * 1024 * 1024
	maxFileSizeSyndetect = 2048 * 1024 * 1024
)

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
	if maxFileSize > maxFileSizeDetect && !conf.GDetect.Syndetect {
		Logger.Warn("max file size can't exceed 100MiB, set the value to 100MiB", slog.String("max-file-size", conf.MaxFileSize))
		maxFileSize = maxFileSizeDetect
	}
	if maxFileSize > maxFileSizeSyndetect {
		Logger.Warn("max file size can't exceed 2GiB, set the value to 2GiB", slog.String("max-file-size", conf.MaxFileSize))
		maxFileSize = maxFileSizeSyndetect
	}
	if maxFileSize <= 0 {
		Logger.Warn("max file size must be greater than 0, set the value to 100MiB", slog.String("max-file-size", conf.MaxFileSize))
		maxFileSize = maxFileSizeDetect
	}

	var informDest io.Writer = os.Stdout
	if conf.Print.Location != "" {
		informDest, err = os.Create(conf.Print.Location)
		if err != nil {
			return fmt.Errorf("could not open report location: %w", err)
		}
	}

	var fs filesystem.FileSystem
	if conf.S3Config != nil {
		fsCtx, cancel := context.WithTimeout(context.Background(), time.Second*30)
		defer cancel()
		fs, err = filesystem.NewS3FileSystem(fsCtx, filesystem.S3Config{
			Endpoint:        conf.S3Config.Endpoint,
			AccessKeyID:     conf.S3Config.AccessKey,
			SecretAccessKey: conf.S3Config.SecretKey,
			Insecure:        conf.S3Config.Insecure,
			Region:          conf.S3Config.Region,
			UsePathStyle:    conf.S3Config.UsePathStyle,
		})
	} else {
		fs = filesystem.NewLocalFileSystem()
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
			Move:       conf.Actions.MoveLegit,
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
	}, fs)
	lock := &scanner.Lock{Password: conf.Quarantine.Password}
	gctx = GContext{
		fs:     fs,
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
			if e := gctx.cache.Close(); e != nil {
				Logger.Warn("could not close cache", slog.String("error", e.Error()))
			}
		}
	}()
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		exitErrorCode()
	}
}

func exitErrorCode() {
	os.Exit(1)
}

func init() {
	// mandatory tricks for windowsgui app
	cobra.MousetrapHelpText = ""
}
