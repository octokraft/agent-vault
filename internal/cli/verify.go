package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify vault integrity and report expired secrets",
	Long:  `Decrypts the vault and checks that all secrets are valid and not expired.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := openVault()
		if err != nil {
			return fmt.Errorf("vault integrity check failed: %w", err)
		}

		names := v.List()
		expired := 0
		for _, name := range names {
			if v.IsExpired(name) {
				fmt.Fprintf(os.Stderr, "  EXPIRED: %s\n", name)
				expired++
			}
		}

		total := v.Count()
		active := total - expired

		fmt.Fprintf(os.Stderr, "Vault OK: %d secret(s), %d active, %d expired\n", total, active, expired)

		if expired > 0 {
			fmt.Fprintln(os.Stderr, "Tip: use 'agent-vault rm <name>' to remove expired secrets.")
		}

		return nil
	},
}
