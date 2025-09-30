package cli

import (
	"context"
	"log/slog"
	"time"

	"github.com/glimps-re/connector-manager/pkg/shared"
	"github.com/glimps-re/host-connector/pkg/handler"
	"github.com/spf13/cobra"
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Start monitoring location with GLIMPS Malware host under Connector manager control\n Global config will not be used.",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		logger.Debug("config", slog.Any("config", Conf))
		console := shared.NewConnectorManagerClient(context.Background(), Conf.Console)
		managedConfig := &shared.HostConfig{}
		info := &shared.RegistrationInfo{
			Config: managedConfig,
		}

		registerCtx, registerCancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer registerCancel()
		err = console.Register(registerCtx, "v1.0.0", info)
		if err != nil {
			return
		}
		Conf.HostConfig = *managedConfig
		gctx, err = handler.NewHandler(cmd.Context(), Conf)
		if err != nil {
			return
		}
		if Conf.Debug {
			LogLevel.Set(slog.LevelDebug)
		}
		defer gctx.Close()
		if !info.Stopped {
			err = gctx.Start(context.Background())
			if err != nil {
				return
			}
		}
		go console.Start(context.Background(), gctx)
		<-context.Background().Done()
		return
	},
}

func initAgent(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&Conf.Console.URL, "console-url", "", "connector manager url")
	cmd.PersistentFlags().StringVar(&Conf.Console.APIKey, "console-api-key", "", "connector manager API key")
	cmd.PersistentFlags().BoolVar(&Conf.Console.Insecure, "console-insecure", false, "if set, skip certificate check")
}
