package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rmCmd = &cobra.Command{
	Use:   "rm <name>",
	Short: "Delete a secret from the vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		v, lock, err := openVaultLocked()
		if err != nil {
			return err
		}
		defer lock.Unlock()

		if !v.Delete(name) {
			return fmt.Errorf("secret %q not found", name)
		}

		if err := v.Save(); err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "Secret %q deleted\n", name)
		return nil
	},
}
