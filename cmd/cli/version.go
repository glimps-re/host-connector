package cli

import (
	"fmt"

	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print host connector version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("host connector version: %s", config.Version)
	},
}
