package cli

import (
	"context"
	_ "embed" // embed file
	"log/slog"

	"github.com/glimps-re/host-connector/pkg/handler"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan folders",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		if err = initHandler(cmd, args, nil, nil); err != nil {
			return
		}
		if err = hostHandler.Conn.Start(); err != nil {
			return
		}
		if len(args) == 0 {
			args = hostConfig.Paths
		}
		var done context.Context
		if hostConfig.Gui {
			done = handler.Gui("", 0)
		}
		for _, arg := range args {
			if err = hostHandler.Conn.ScanFile(cmd.Context(), arg); err != nil {
				logger.Error("error during scan", slog.String("file", arg), slog.String("error", err.Error()))
				hostHandler.Conn.Close(cmd.Context())
				return
			}
		}
		hostHandler.Conn.Close(cmd.Context())
		handler.HandleScanFinished()
		if hostConfig.Gui {
			<-done.Done()
		}
		return
	},
	Args: checkFiles,
}
