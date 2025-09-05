package cli

import (
	"context"
	_ "embed" // embed file
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/glimps-re/host-connector/pkg/handler"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:     "scan",
	Short:   "Scan folders",
	PreRunE: GlobalInit,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		if err = gctx.Conn.Start(context.Background()); err != nil {
			return
		}
		if len(args) == 0 {
			args = Conf.Paths
		}
		var done context.Context
		if Conf.Gui {
			done = handler.Gui("", 0)
		}
		for _, arg := range args {
			if err = gctx.Conn.ScanFile(cmd.Context(), arg); err != nil {
				Logger.Error("error during scan", slog.String("file", arg), slog.String("error", err.Error()))
				gctx.Conn.Close()
				return
			}
		}
		gctx.Conn.Close()
		handler.HandleScanFinished()
		if Conf.Gui {
			<-done.Done()
		}
		return
	},
	Args: func(cmd *cobra.Command, args []string) error {
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
