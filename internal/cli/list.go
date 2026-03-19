package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List secret names in the vault",
	Long:  `Lists all secret names stored in the vault. Only names are shown — never values.`,
	Aliases: []string{"ls"},
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := openVault()
		if err != nil {
			return err
		}

		names := v.List()
		if len(names) == 0 {
			fmt.Fprintln(os.Stderr, "No secrets stored.")
			return nil
		}

		for _, name := range names {
			fmt.Println(name)
		}
		return nil
	},
}
