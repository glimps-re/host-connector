package cli

import (
	"log/slog"
	"os"

	"github.com/glimps-re/connector-manager/pkg/shared"
	"github.com/glimps-re/host-connector/pkg/cache"
	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/handler"
	"github.com/glimps-re/host-connector/pkg/scanner"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var Conf = &config.Config{
	Config: config.DefaultConfigPath,
	HostConfig: shared.HostConfig{
		Workers:     config.DefaultWorkers,
		MaxFileSize: config.DefaultMaxFileSize,
		Actions: shared.HostActionsConfig{
			Delete:     true,
			Quarantine: true,
			Print:      true,
			Log:        true,
		},
		Quarantine: shared.HostQuarantineConfig{
			Password: "infected",
		},
		Cache: shared.HostCacheConfig{
			ScanValidity: config.DefaultScanValidity,
			Location:     ":file::memory",
		},
		Timeout: config.DefaultTimeout,
	},
}

func initRoot(rootCmd *cobra.Command) {
	initConfig := func() {
		if Conf.Config == "" {
			conf, err := config.GetConfigFile()
			if err != nil {
				Logger.Error("could not create config file", slog.String("location", conf))
			}
			Conf.Config = conf
		}
		viper.SetConfigFile(Conf.Config)
		viper.SetConfigType("yaml")

		if err := viper.ReadInConfig(); err != nil {
			Logger.Error("Can't read config", slog.String("error", err.Error()))
			return
		}
		if err := viper.Unmarshal(Conf); err != nil {
			Logger.Error("Can't unmarshal config", slog.String("error", err.Error()))
		}
	}
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&Conf.Config, "config", config.DefaultConfigPath, "config file")
	rootCmd.PersistentFlags().StringVar(&Conf.GMalwareAPIToken, "gdetect-token", os.Getenv("GDETECT_TOKEN"), "GLIMPS Malware Detect token")
	rootCmd.PersistentFlags().StringVar(&Conf.GMalwareAPIURL, "gdetect-url", os.Getenv("GDETECT_URL"), "GLIMPS Malware Detect url (E.g https://gmalware.ggp.glimps.re)")
	rootCmd.PersistentFlags().BoolVar(&Conf.Syndetect, "gdetect-syndetect", Conf.Syndetect, "Use syndetect API to analyze files")
	rootCmd.PersistentFlags().DurationVar(&Conf.Timeout, "timeout", config.DefaultTimeout, "Time allowed to analyze each file")
	rootCmd.PersistentFlags().DurationVar(&Conf.Cache.ScanValidity, "scan-validity", config.DefaultScanValidity, "Validity duration for each scan result")
	rootCmd.PersistentFlags().IntVar(&Conf.Workers, "workers", config.DefaultWorkers, "number of files analyzed at the same time")
	rootCmd.PersistentFlags().StringVar(&Conf.Cache.Location, "cache", config.DefaultCacheLocation, "location of the cache DB")
	rootCmd.PersistentFlags().StringVar(&Conf.Quarantine.Location, "quarantine", config.DefaultQuarantineLocation, "location of the quarantine folder")
	rootCmd.PersistentFlags().StringVar(&Conf.MaxFileSize, "max-file-size", config.DefaultMaxFileSize, "max file size to push to GLIMPS Malware")
	rootCmd.PersistentFlags().BoolVarP(&Conf.Debug, "debug", "d", Conf.Debug, "print debug strings")
	rootCmd.PersistentFlags().BoolVarP(&Conf.Verbose, "verbose", "v", Conf.Verbose, "print more information")
	rootCmd.PersistentFlags().BoolVarP(&Conf.Quiet, "quiet", "q", Conf.Quiet, "print no information")
	rootCmd.PersistentFlags().BoolVar(&Conf.Extract, "extract", Conf.Extract, "extract archive and scan inner files")
	rootCmd.PersistentFlags().BoolVar(&Conf.GMalwareNoCertCheck, "insecure", Conf.GMalwareNoCertCheck, "do not check certificates")
	rootCmd.PersistentFlags().StringVar(&Conf.Move.Source, "move-source", "", "root folder from where to move files")
	rootCmd.PersistentFlags().StringVar(&Conf.Move.Destination, "move-destination", "", "folder where legit files will be moved")
	rootCmd.PersistentFlags().StringVar(&Conf.Print.Location, "print-location", "", "destination file for report logs")

	initMonitoring(monitoringCmd)
	initAgent(agentCmd)
	scanCmd.PersistentFlags().BoolVar(&Conf.Gui, "gui", Conf.Gui, "gui")
}

var rootCmd = &cobra.Command{
	Use:   "GMHost",
	Short: "GLIMPS Malware Host connector is a tool to scan files with GLIMPS Malware Detect",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		err = yaml.NewEncoder(os.Stdout).Encode(Conf)
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

func GlobalInit(cmd *cobra.Command, args []string) (err error) {
	if Conf.Debug {
		Logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
		scanner.Logger = Logger
		cache.Logger = Logger
		handler.Logger = Logger
	}

	Logger.Debug("debug activated")
	gctx, err = handler.NewHandler(cmd.Context(), Conf)
	if err != nil {
		Logger.Error("could not init context", slog.String("error", err.Error()))
		return
	}
	return nil
}
