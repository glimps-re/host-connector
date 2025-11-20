package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/handler"
	"github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/pkg/scanner"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var hostConfig = &config.Config{
	Config: config.DefaultConfigPath,
	HostConfig: sdk.HostConfig{
		CommonConnectorConfig: sdk.CommonConnectorConfig{
			GMalwareTimeout: config.DefaultTimeout,
		},
		Workers:     config.DefaultWorkers,
		MaxFileSize: config.DefaultMaxFileSize,
		Actions: sdk.HostActionsConfig{
			Delete:     true,
			Quarantine: true,
			Print:      true,
			Log:        true,
		},
		Monitoring: sdk.HostMonitoringConfig{
			ModificationDelay: config.DefaultModificationDelay,
		},
		Quarantine: sdk.HostQuarantineConfig{
			Password: "infected",
			Registry: ":file::memory",
		},
	},
}

func initConfig() {
	if hostConfig.Config == "" {
		conf, err := config.GetConfigFile()
		if err != nil {
			logger.Error("could not create config file", slog.String("location", conf))
		}
		hostConfig.Config = conf
	}
	viper.SetConfigFile(hostConfig.Config)
	viper.SetConfigType("yaml")
	if err := viper.ReadInConfig(); err != nil {
		logger.Error("can't read config", slog.String("error", err.Error()))
		return
	}
	if err := viper.Unmarshal(hostConfig, viper.DecodeHook(sdk.DurationMapstructureHook())); err != nil {
		logger.Error("can't unmarshal config", slog.String("error", err.Error()))
	}
}

func initRoot(rootCmd *cobra.Command) {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&hostConfig.Config, "config", config.DefaultConfigPath, "config file")
	rootCmd.PersistentFlags().StringVar(&hostConfig.GMalwareAPIToken, "gmalware-token", os.Getenv("GMALWARE_TOKEN"), "GLIMPS Malware Detect token")
	rootCmd.PersistentFlags().StringVar(&hostConfig.GMalwareAPIURL, "gmalware-url", os.Getenv("GMALWARE_URL"), "GLIMPS Malware Detect url (E.g https://gmalware.ggp.glimps.re)")
	rootCmd.PersistentFlags().BoolVar(&hostConfig.GMalwareSyndetect, "gmalware-syndetect", hostConfig.GMalwareSyndetect, "Use syndetect API to analyze files")

	rootCmd.PersistentFlags().Var(&hostConfig.GMalwareTimeout, "timeout", "Time allowed to analyze each file")
	rootCmd.PersistentFlags().IntVar(&hostConfig.Workers, "workers", config.DefaultWorkers, "Number of concurrent workers for file analysis (default: 4, affects CPU usage)")
	rootCmd.PersistentFlags().IntVar(&hostConfig.ExtractWorkers, "extract-workers", config.DefaultExtractWorkers, "Number of concurrent workers for archive extraction (default: 2, used when extract is enabled)")
	rootCmd.PersistentFlags().StringVar(&hostConfig.Quarantine.Registry, "quarantine-registry", hostConfig.Quarantine.Registry, "Path to the database that store quarantined and restored file entry (leave empty for in-memory store, lost on restart)")
	rootCmd.PersistentFlags().StringVar(&hostConfig.Quarantine.Location, "quarantine", config.DefaultQuarantineLocation, "Directory path where quarantined files are stored (files are encrypted with .lock extension)")
	rootCmd.PersistentFlags().StringVar(&hostConfig.MaxFileSize, "max-file-size", config.DefaultMaxFileSize, "Maximum file size to scan directly (e.g., '100MB'). Files exceeding this are extracted if 'extract' is enabled, otherwise rejected")
	rootCmd.PersistentFlags().BoolVarP(&hostConfig.Debug, "debug", "d", hostConfig.Debug, "print debug strings")
	rootCmd.PersistentFlags().BoolVarP(&hostConfig.Print.Verbose, "verbose", "v", hostConfig.Print.Verbose, "Report all scanned files, including clean files (not just malware detections)")
	rootCmd.PersistentFlags().BoolVar(&hostConfig.Extract, "extract", hostConfig.Extract, "Enable archive extraction for files exceeding max_file_size (archives are unpacked and contents scanned)")
	rootCmd.PersistentFlags().BoolVar(&hostConfig.GMalwareNoCertCheck, "insecure", hostConfig.GMalwareNoCertCheck, "do not check certificates")
	rootCmd.PersistentFlags().StringVar(&hostConfig.Move.Source, "move-source", "", "Source directory filter (only clean files within this path are moved to destination)")
	rootCmd.PersistentFlags().StringVar(&hostConfig.Move.Destination, "move-destination", "", "Target directory for moving clean files (preserves subdirectory structure)")
	rootCmd.PersistentFlags().StringVar(&hostConfig.Print.Location, "print-location", "", "File path for scan reports (leave empty to print to stdout)")
	rootCmd.PersistentFlags().BoolVar(&hostConfig.FollowSymlinks, "follow-symlinks", false, "Follow symbolic links when scanning directories (if disabled, symlinks are skipped)")

	monitoringCmd.PersistentFlags().BoolVar(&hostConfig.Monitoring.PreScan, "pre-scan", false, "Immediately scan all existing files in monitored paths when monitoring starts")
	monitoringCmd.PersistentFlags().Var(&hostConfig.Monitoring.Period, "scan-period", "Time interval between periodic re-scans (e.g., '1h', '30m', requires rescan enabled)")
	monitoringCmd.PersistentFlags().Var(&hostConfig.Monitoring.ModificationDelay, "mod-delay", "Wait time after file modification before scanning (e.g., '30s', prevents scanning incomplete writes)")

	agentCmd.PersistentFlags().StringVar(&hostConfig.Console.URL, "console-url", "", "connector manager url")
	agentCmd.PersistentFlags().StringVar(&hostConfig.Console.APIKey, "console-api-key", "", "connector manager API key")
	agentCmd.PersistentFlags().BoolVar(&hostConfig.Console.Insecure, "console-insecure", false, "if set, skip certificate check")

	scanCmd.PersistentFlags().BoolVar(&hostConfig.Gui, "gui", hostConfig.Gui, "gui")
}

var rootCmd = &cobra.Command{
	Use:   "GMHost",
	Short: "GLIMPS Malware Host connector is a tool to scan files with GLIMPS Malware Detect",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		err = yaml.NewEncoder(os.Stdout).Encode(hostConfig)
		if err != nil {
			logger.Error("error encode yaml conf", slog.String("err", err.Error()))
			return
		}
		if err = cmd.Usage(); err != nil {
			return
		}
		return
	},
}

func initHandlerNoConsole(cmd *cobra.Command, _ []string) (err error) {
	if hostConfig.Debug {
		LogLevel.Set(slog.LevelDebug)
		scanner.LogLevel.Set(slog.LevelDebug)
		quarantine.LogLevel.Set(slog.LevelDebug)
		handler.LogLevel.Set(slog.LevelDebug)
		datamodel.LogLevel.Set(slog.LevelDebug)
		logger.Debug("debug activated")
	}
	hostHandler, err = handler.NewHandler(cmd.Context(), hostConfig, nil, nil)
	if err != nil {
		logger.Error("could not init host connector properly", slog.String("error", err.Error()))
		return
	}
	return nil
}

func initHandler(cmd *cobra.Command, _ []string, consoleClient *sdk.ConnectorManagerClient, unresolvedErrors map[events.ErrorEventType]string) (err error) {
	if hostConfig.Debug {
		LogLevel.Set(slog.LevelDebug)
		scanner.LogLevel.Set(slog.LevelDebug)
		quarantine.LogLevel.Set(slog.LevelDebug)
		handler.LogLevel.Set(slog.LevelDebug)
		datamodel.LogLevel.Set(slog.LevelDebug)
		logger.Debug("debug activated")
	}
	hostHandler, err = handler.NewHandler(cmd.Context(), hostConfig, consoleClient, unresolvedErrors)
	if err != nil {
		logger.Error("could not init host connector properly", slog.String("error", err.Error()))
		return
	}
	return nil
}

func checkFiles(cmd *cobra.Command, args []string) error {
	pathsToScan := args
	pathsToScan = append(pathsToScan, hostConfig.Paths...)
	if len(pathsToScan) < 1 {
		return errors.New("at least one file is mandatory")
	}
	for _, path := range pathsToScan {
		if _, err := os.Stat(filepath.Clean(path)); err != nil {
			return fmt.Errorf("could not check file %s: %w", path, err)
		}
	}
	return nil
}
