package cli

import (
	"errors"
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

var hostHandler = &handler.Handler{}

func Main() {
	if err := main_(); err != nil {
		os.Exit(1)
	}
}

func main_() (err error) {
	initRoot(rootCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
	quarantineCmd.AddCommand(quarantineListCmd)
	quarantineCmd.AddCommand(quarantineRestoreCmd)
	rootCmd.AddCommand(quarantineCmd)
	rootCmd.AddCommand(monitoringCmd)
	rootCmd.AddCommand(agentCmd)
	ctx, cancel := signalContext()
	defer cancel()
	err = rootCmd.ExecuteContext(ctx)
	if err != nil {
		fmt.Println(err)
		return err
	}
	if overran.Load() {
		return errors.New("the stop did not finish within shutdown_timeout")
	}
	return
}

func init() {
	// mandatory tricks for windowsgui app
	cobra.MousetrapHelpText = ""
}
