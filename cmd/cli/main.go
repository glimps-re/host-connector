package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/glimps-re/host-connector/pkg/handler"
	"github.com/spf13/cobra"
)

var LogLevel = &slog.LevelVar{}

var logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
	Level: LogLevel,
}))

var gctx = &handler.Handler{}

func Main() {
	if err := main_(); err != nil {
		os.Exit(1)
	}
}

func main_() (err error) {
	initRoot(rootCmd)
	rootCmd.AddCommand(scanCmd)
	quarantineCmd.AddCommand(quarantineListCmd)
	quarantineCmd.AddCommand(quarantineRestoreCmd)
	rootCmd.AddCommand(quarantineCmd)
	rootCmd.AddCommand(monitoringCmd)
	rootCmd.AddCommand(agentCmd)
	defer func() {
		if gctx.Cache != nil {
			if err := gctx.Cache.Close(); err != nil {
				logger.Error("cannot close cache", slog.String("error", err.Error()))
			}
		}
	}()
	err = rootCmd.Execute()
	if err != nil {
		fmt.Println(err)
		return err
	}
	return
}

func init() {
	// mandatory tricks for windowsgui app
	cobra.MousetrapHelpText = ""
}
