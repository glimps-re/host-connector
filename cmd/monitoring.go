package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/glimps-re/host-connector/pkg/monitor"
	"github.com/spf13/cobra"
)

var monitoringCmd = &cobra.Command{
	Use:               "monitoring",
	Short:             "start monitoring location with GMalware host",
	PersistentPreRunE: GlobalInit,
	RunE: func(cmd *cobra.Command, args []string) error {
		Logger.Debug("config", "conf", conf)
		if len(args) == 0 {
			args = conf.Paths
		}
		gctx.conn.Start()
		defer gctx.conn.Close()
		mon, err := monitor.NewMonitor(func(file string) error {
			return gctx.conn.ScanFile(cmd.Context(), file)
		}, conf.Monitoring.PreScan, conf.Monitoring.Period, conf.Monitoring.ModificationDelay)
		if err != nil {
			return err
		}
		mon.Start()
		defer mon.Close()
		for _, arg := range args {
			if err := mon.Add(arg); err != nil {
				return err
			}
		}
		// wait forever
		select {}
	},
	Args: func(cmd *cobra.Command, args []string) error {
		// append paths from conf
		args = append(args, conf.Paths...)
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
	cmd.PersistentFlags().BoolVar(&conf.Monitoring.PreScan, "pre-scan", false, "scan monitoring with a scan")
	cmd.PersistentFlags().DurationVar(&conf.Monitoring.Period, "scan-period", conf.Monitoring.Period, "re-scan files every scan-period")
	cmd.PersistentFlags().DurationVar(&conf.Monitoring.ModificationDelay, "mod-delay", DefaultModificationDelay, "Time waited between two modifications of a file before submitting it")
}
