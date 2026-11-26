package cli

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/glimps-re/host-connector/internal/displaytext"
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
		printError(os.Stderr, err)
		return err
	}
	if overran.Load() {
		return errors.New("the stop did not finish within shutdown_timeout")
	}
	return
}

// printError writes the error of a command on w, once: cobra's own print is off
// (rootCmd.SilenceErrors), since it would echo a name of the depositor as it is.
func printError(w io.Writer, err error) {
	if _, werr := fmt.Fprintf(w, "Error: %s\n", displaytext.Sanitize(err.Error())); werr != nil {
		logger.Error("cannot print the error", slog.String("error", werr.Error()))
	}
}

func init() {
	// mandatory tricks for windowsgui app
	cobra.MousetrapHelpText = ""
}
