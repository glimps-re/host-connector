package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/monitor"
	"github.com/spf13/cobra"
)

var monitoringCmd = &cobra.Command{
	Use:               "monitoring",
	Short:             "Start monitoring location with GLIMPS Malware host",
	PersistentPreRunE: GlobalInit,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		logger.Debug("config", slog.Any("config", Conf))
		if len(args) == 0 {
			args = Conf.Paths
		}
		if err = gctx.Conn.Start(context.Background()); err != nil {
			return
		}
		defer gctx.Conn.Close()
		mon, err := monitor.NewMonitor(func(file string) error {
			return gctx.Conn.ScanFile(cmd.Context(), file)
		}, Conf.Monitoring.PreScan, Conf.Monitoring.Period, Conf.Monitoring.ModificationDelay)
		if err != nil {
			return
		}
		mon.Start()
		defer mon.Close()
		for _, arg := range args {
			if err = mon.Add(arg); err != nil {
				return
			}
		}
		// wait forever
		<-cmd.Context().Done()
		return
	},
	Args: func(cmd *cobra.Command, args []string) error {
		// append paths from conf
		args = append(args, Conf.Paths...)
		if len(args) < 1 {
			return errors.New("at least one file is mandatory")
		}
		for _, arg := range args {
			if _, err := os.Stat(arg); err != nil {
				return fmt.Errorf("could not check file %s", arg)
			}
		}
		return nil
	},
}

func initMonitoring(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(&Conf.Monitoring.PreScan, "pre-scan", false, "start monitoring with a scan")
	cmd.PersistentFlags().DurationVar(&Conf.Monitoring.Period, "scan-period", Conf.Monitoring.Period, "re-scan files every scan-period")
	cmd.PersistentFlags().DurationVar(&Conf.Monitoring.ModificationDelay, "mod-delay", config.DefaultModificationDelay, "Time waited between two modifications of a file before submitting it")
}
