package cmd

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:     "scan",
	Short:   "Scan folders",
	PreRunE: GlobalInit,
	Run: func(cmd *cobra.Command, args []string) {
		gctx.conn.Start()
		if len(args) == 0 {
			args = conf.Paths
		}
		var done context.Context
		if conf.Gui {
			done = Gui("", 0)
		}
		for _, arg := range args {
			if err := gctx.conn.ScanFile(cmd.Context(), arg); err != nil {
				Logger.Error("error during scan", "file", arg, "error", err)
				gctx.conn.Close()
				return
			}
		}
		gctx.conn.Close()
		HandleScanFinished()
		if conf.Gui {
			<-done.Done()
		}
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
