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
			Logger.Debug("Can't read config", "error", err)
			return
		}
		if err := viper.Unmarshal(conf); err != nil {
			Logger.Error("Can't unmarshal config", "error", err)
		}
	}
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&conf.Config, "config", DefaultConfigPath, "config file")
	rootCmd.PersistentFlags().StringVar(&conf.GDetect.Token, "gdetect-token", os.Getenv("GDETECT_TOKEN"), "GMalware Detect token")
	rootCmd.PersistentFlags().StringVar(&conf.GDetect.URL, "gdetect-url", os.Getenv("GDETECT_URL"), "GMalware Detect url (E.g https://gmalware.ggp.glimps.re)")
	rootCmd.PersistentFlags().DurationVar(&conf.GDetect.Timeout, "timeout", DefaultTimeout, "Time allowed to analyze each files")
	rootCmd.PersistentFlags().DurationVar(&conf.Cache.ScanValidity, "scan-validity", DefaultScanValidity, "Validity duration for each scan result")
	rootCmd.PersistentFlags().UintVar(&conf.Workers, "workers", DefaultWorkers, "number of files analyzed at the same time")
	rootCmd.PersistentFlags().StringVar(&conf.Cache.Location, "cache", DefaultCacheLocation, "location of the cache DB")
	rootCmd.PersistentFlags().StringVar(&conf.Quarantine.Location, "quarantine", DefaultQuarantineLocation, "location of the quarantine folder")
	// rootCmd.PersistentFlags().StringVar(&conf.ExportLocation, "export", DefaultExportLocation, "location of the quarantine folder")
	rootCmd.PersistentFlags().BoolVar(&conf.Debug, "debug", conf.Debug, "print debug strings")
	rootCmd.PersistentFlags().BoolVar(&conf.Verbose, "verbose", conf.Verbose, "print more information")
	rootCmd.PersistentFlags().BoolVar(&conf.Quiet, "quiet", conf.Quiet, "print no information")
	rootCmd.PersistentFlags().BoolVar(&conf.GDetect.Insecure, "insecure", conf.GDetect.Insecure, "do not check certificates")

	initMonitoring(monitoringCmd)
	scanCmd.PersistentFlags().BoolVar(&conf.Gui, "gui", conf.Gui, "gui")
}

var rootCmd = &cobra.Command{
	Use:   "GMHost",
	Short: "GMalware Host connector is a tool to scan files with GMalware Detect",
	Run: func(cmd *cobra.Command, args []string) {
		yaml.NewEncoder(os.Stdout).Encode(conf)
		cmd.Usage()
	},
	// PersistentPreRunE: GlobalInit,
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
		Logger.Error("could not init context", "error", err)
		return err
	}
	return nil
}
