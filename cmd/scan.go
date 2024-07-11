package cmd

import (
	"context"
	_ "embed" // embed file
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:     "scan",
	Short:   "Scan folders",
	PreRunE: GlobalInit,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		if err = gctx.conn.Start(); err != nil {
			return
		}
		if len(args) == 0 {
			args = conf.Paths
		}
		var done context.Context
		if conf.Gui {
			done = Gui("", 0)
		}
		for _, arg := range args {
			if err = gctx.conn.ScanFile(cmd.Context(), arg); err != nil {
				Logger.Error("error during scan", slog.String("file", arg), slog.String("error", err.Error()))
				gctx.conn.Close()
				return
			}
		}
		gctx.conn.Close()
		HandleScanFinished()
		if conf.Gui {
			<-done.Done()
		}
		return
	},
	Args: func(cmd *cobra.Command, args []string) error {
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

type GuiHandleResult struct{}

var HandleScanFinished = func() {}
