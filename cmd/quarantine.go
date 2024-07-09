package cmd

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/glimps-re/host-connector/pkg/scanner"
	"github.com/spf13/cobra"
)

var quarantineCmd = &cobra.Command{
	Use:   "quarantine",
	Short: "Handler GMalware host quarantined files",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		if err = cmd.Usage(); err != nil {
			return
		}
		return
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := GlobalInit(cmd, args); err != nil {
			return err
		}
		if conf.Quarantine.Location == "" {
			return fmt.Errorf("quarantine location is mandatory")
		}
		return nil
	},
}

var quarantineListCmd = &cobra.Command{
	Use:   "list",
	Short: "List GMalware host quarantined files",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("|%-64s|%-64s|%-64s|\n", "ID", "Reason", "File")
		qa := scanner.NewQuarantineAction(nil, conf.Quarantine.Location, gctx.lock)
		files, err := qa.ListQuarantinedFiles(cmd.Context())
		if err != nil {
			return err
		}
		for file := range files {
			fmt.Printf("|%-64s|%-64s|%-64s|\n", file.ID, file.Reason, filepath.Base(file.Filepath))
		}
		return nil
	},
}

var restorePattern = regexp.MustCompile(".*([0-9a-f]{64}).lock")

var quarantineRestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore quarantined files",
	RunE: func(cmd *cobra.Command, args []string) error {
		qa := scanner.NewQuarantineAction(gctx.cache, conf.Quarantine.Location, gctx.lock)
		for _, sha := range args {
			if strings.HasSuffix(sha, ".lock") {
				ts := restorePattern.FindStringSubmatch(sha)
				if len(ts) == 2 {
					sha = ts[1]
				}
			}
			if err := qa.Restore(sha); err != nil {
				return err
			}
		}
		return nil
	},
}
