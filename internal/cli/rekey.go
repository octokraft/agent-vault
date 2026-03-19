package cli

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/octokraft/agent-vault/internal/vault"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var rekeyCmd = &cobra.Command{
	Use:   "rekey",
	Short: "Change the vault passphrase",
	Long: `Re-encrypts the vault with a new passphrase. All secrets are preserved.
The old passphrase is required to decrypt, then a new passphrase is used to re-encrypt.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		path := resolveVaultPath()

		// Open with current passphrase
		v, lock, err := openVaultLocked()
		if err != nil {
			return err
		}
		defer lock.Unlock()

		// Get new passphrase
		var newPass string
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return fmt.Errorf("rekey requires an interactive terminal for safety")
		}

		fmt.Fprint(os.Stderr, "Enter NEW passphrase: ")
		newBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return fmt.Errorf("reading new passphrase: %w", err)
		}

		fmt.Fprint(os.Stderr, "Confirm NEW passphrase: ")
		confirmBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return fmt.Errorf("reading confirmation: %w", err)
		}

		if string(newBytes) != string(confirmBytes) {
			return fmt.Errorf("passphrases do not match")
		}
		newPass = string(newBytes)

		if newPass == "" {
			return fmt.Errorf("passphrase cannot be empty")
		}

		// Generate new salt for the new key
		salt, err := vault.GenerateSalt()
		if err != nil {
			return fmt.Errorf("generating salt: %w", err)
		}

		// Re-encrypt with the new passphrase and new salt
		v.SetPassphrase(newPass, base64.StdEncoding.EncodeToString(salt))

		if err := v.Save(); err != nil {
			return err
		}

		fmt.Fprintln(os.Stderr, "Vault re-encrypted with new passphrase.")
		fmt.Fprintf(os.Stderr, "Vault: %s\n", path)
		return nil
	},
}
