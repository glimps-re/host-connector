package cli

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
)

var monitoringCmd = &cobra.Command{
	Use:   "monitoring",
	Short: "Start monitoring location with GLIMPS Malware host",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		logger.Debug("config", slog.Any("config", hostConfig))
		hostConfig.Paths = append(hostConfig.Paths, args...)
		err = initHandlerNoConsole(cmd, args)
		if err != nil {
			logger.Error("error setting up host connector, wait for a reconfigure from connector manager...", slog.String("error", err.Error()))
			return
		}
		err = hostHandler.Start(cmd.Context())
		if err != nil {
			return fmt.Errorf("could not start host connector, err: %w", err)
		}
		defer runStop(cmd.Context(), stopHandler)
		<-cmd.Context().Done()
		return
	},
	Args: checkFiles,
}
