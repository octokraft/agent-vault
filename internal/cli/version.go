package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	// Set by ldflags at build time
	Version = "dev"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("agent-vault %s\n", Version)
	},
}
