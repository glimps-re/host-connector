package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/spf13/cobra"
)

var quarantineCmd = &cobra.Command{
	Use:   "quarantine",
	Short: "Handle GLIMPS Malware host quarantined files",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		if err = cmd.Usage(); err != nil {
			return
		}
		return
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := initHandler(cmd, args, nil, nil); err != nil {
			return err
		}
		if hostConfig.Quarantine.Location == "" {
			return errors.New("quarantine location is mandatory")
		}
		return nil
	},
}

var quarantineListCmd = &cobra.Command{
	Use:   "list",
	Short: "List GLIMPS Malware host quarantined files",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("|%-64s|%-64s|%-64s|\n", "ID", "Reason", "File")
		for f, err := range hostHandler.Quarantiner.ListQuarantinedFiles(cmd.Context()) {
			if err != nil {
				return err
			}
			fmt.Printf("|%-64s|%-64s|%-64s|\n", f.ID, f.Reason, filepath.Base(f.Filepath))
		}
		return nil
	},
}

var restorePattern = regexp.MustCompile(".*([0-9a-f]{64}).lock")

var quarantineRestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore quarantined files",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, id := range args {
			if strings.HasSuffix(id, ".lock") {
				ts := restorePattern.FindStringSubmatch(id)
				if len(ts) == 2 {
					id = ts[1]
				}
			}
			if err := hostHandler.Restore(cmd.Context(), sdk.RestoreActionContent{
				ID: id,
			}); err != nil {
				return err
			}
		}
		return nil
	},
}
