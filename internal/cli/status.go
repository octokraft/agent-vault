package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show vault status",
	RunE: func(cmd *cobra.Command, args []string) error {
		path := resolveVaultPath()

		if _, err := os.Stat(path); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "No vault found at %s\n", path)
			fmt.Fprintln(os.Stderr, "Run 'agent-vault init' to create one.")
			return nil
		}

		v, err := openVault()
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "Vault:   %s\n", path)
		fmt.Fprintf(os.Stderr, "Secrets: %d\n", v.Count())

		names := v.List()
		if len(names) > 0 {
			fmt.Fprintln(os.Stderr, "Names:")
			for _, name := range names {
				fmt.Fprintf(os.Stderr, "  - %s\n", name)
			}
		}

		return nil
	},
}
