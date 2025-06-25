package cmd

import (
	"errors"
	"log/slog"
	"os"

	"github.com/glimps-re/host-connector/pkg/cache"
	"github.com/glimps-re/host-connector/pkg/scanner"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func initRoot(rootCmd *cobra.Command) {
	initConfig := func() {
		if conf.Config == "" {
			conf.Config = getConfigFile()
		}
		viper.SetConfigFile(conf.Config)
		viper.SetConfigType("yaml")

		if err := viper.ReadInConfig(); err != nil {
			Logger.Error("Can't read config", slog.String("error", err.Error()))
			return
		}
		if err := viper.Unmarshal(conf); err != nil {
			Logger.Error("Can't unmarshal config", slog.String("error", err.Error()))
		}
	}
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&conf.Config, "config", DefaultConfigPath, "config file")
	rootCmd.PersistentFlags().StringVar(&conf.GDetect.Token, "gdetect-token", os.Getenv("GDETECT_TOKEN"), "GLIMPS Malware Detect token")
	rootCmd.PersistentFlags().StringVar(&conf.GDetect.URL, "gdetect-url", os.Getenv("GDETECT_URL"), "GLIMPS Malware Detect url (E.g https://gmalware.ggp.glimps.re)")
	rootCmd.PersistentFlags().BoolVar(&conf.GDetect.Syndetect, "gdetect-syndetect", conf.GDetect.Syndetect, "Use syndetect API to analyze files")
	rootCmd.PersistentFlags().DurationVar(&conf.GDetect.Timeout, "timeout", DefaultTimeout, "Time allowed to analyze each file")
	rootCmd.PersistentFlags().DurationVar(&conf.Cache.ScanValidity, "scan-validity", DefaultScanValidity, "Validity duration for each scan result")
	rootCmd.PersistentFlags().IntVar(&conf.Workers, "workers", DefaultWorkers, "number of files analyzed at the same time")
	rootCmd.PersistentFlags().StringVar(&conf.Cache.Location, "cache", DefaultCacheLocation, "location of the cache DB")
	rootCmd.PersistentFlags().StringVar(&conf.Quarantine.Location, "quarantine", DefaultQuarantineLocation, "location of the quarantine folder")
	rootCmd.PersistentFlags().StringVar(&conf.MaxFileSize, "max-file-size", DefaultMaxFileSize, "max file size to push to GLIMPS Malware")
	rootCmd.PersistentFlags().BoolVar(&conf.Debug, "debug", conf.Debug, "print debug strings")
	rootCmd.PersistentFlags().BoolVar(&conf.Verbose, "verbose", conf.Verbose, "print more information")
	rootCmd.PersistentFlags().BoolVar(&conf.Quiet, "quiet", conf.Quiet, "print no information")
	rootCmd.PersistentFlags().BoolVar(&conf.Extract, "extract", conf.Extract, "extract archive and scan inner files")
	rootCmd.PersistentFlags().BoolVar(&conf.GDetect.Insecure, "insecure", conf.GDetect.Insecure, "do not check certificates")
	rootCmd.PersistentFlags().StringVar(&conf.Move.Source, "move-source", "", "root folder from where to move files")
	rootCmd.PersistentFlags().StringVar(&conf.Move.Destination, "move-destination", "", "folder where legit files will be moved")
	rootCmd.PersistentFlags().StringVar(&conf.Print.Location, "print-location", "", "destination file for report logs")

	initMonitoring(monitoringCmd)
	scanCmd.PersistentFlags().BoolVar(&conf.Gui, "gui", conf.Gui, "gui")
}

var rootCmd = &cobra.Command{
	Use:   "GMHost",
	Short: "GLIMPS Malware Host connector is a tool to scan files with GLIMPS Malware Detect",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		err = yaml.NewEncoder(os.Stdout).Encode(conf)
		if err != nil {
			Logger.Error("error encode yaml conf", slog.String("err", err.Error()))
			return
		}
		if err = cmd.Usage(); err != nil {
			return
		}
		return
	},
}

func GlobalInit(cmd *cobra.Command, args []string) error {
	if conf.Debug {
		Logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
		scanner.Logger = Logger
		cache.Logger = Logger
	}
	if conf.Workers == 0 {
		conf.Workers = 1
	}
	if conf.Quarantine.Location != "" && conf.Actions.Quarantine {
		_, err := os.Stat(conf.Quarantine.Location)
		if errors.Is(err, os.ErrNotExist) {
			if err = os.MkdirAll(conf.Quarantine.Location, 0o755); err != nil {
				return err
			}
		}
	}
	Logger.Debug("debug activated")
	if err := initGCtx(); err != nil {
		Logger.Error("could not init context", slog.String("error", err.Error()))
		return err
	}
	return nil
}
