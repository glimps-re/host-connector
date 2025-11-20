package cli

import (
	"context"
	"log/slog"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/spf13/cobra"
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Start monitoring location with GLIMPS Malware host under Connector manager control\n Global config will not be used.",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		logger.Debug("config", slog.Any("config", hostConfig))
		console := sdk.NewConnectorManagerClient(context.Background(), hostConfig.Console)
		managedConfig := &sdk.HostConfig{}
		info := &sdk.RegistrationInfo{
			Config: managedConfig,
		}

		registerCtx, registerCancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer registerCancel()
		err = console.Register(registerCtx, "v1.0.0", info)
		if err != nil {
			return
		}
		hostConfig.HostConfig = *managedConfig

		if hostConfig.Debug {
			LogLevel.Set(slog.LevelDebug)
		}
		err = initHandler(cmd, args, &console, info.UnresolvedErrors)
		if err != nil {
			logger.Error("error setting up host connector, wait for a reconfigure from connector manager...", slog.String("error", err.Error()))
		}

		if !info.Stopped {
			err = hostHandler.Start(cmd.Context())
			if err != nil {
				logger.Error("error starting host connector, wait for a reconfigure from connector manager...", slog.String("error", err.Error()))
			}
		}
		defer func() {
			stopCtx, stopCancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer stopCancel()
			if e := hostHandler.Stop(stopCtx); e != nil {
				logger.Error("error stopping connector", slog.String("error", e.Error()))
			}
		}()
		go console.Start(cmd.Context(), hostHandler)
		<-cmd.Context().Done()
		return
	},
}
