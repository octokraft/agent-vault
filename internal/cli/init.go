package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/octokraft/agent-vault/internal/vault"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new vault",
	Long:  `Creates a new encrypted vault. You'll be prompted for a passphrase that encrypts the vault at rest.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		path := resolveVaultPath()

		passphrase, err := getOrPromptPassphrase("Enter vault passphrase: ")
		if err != nil {
			return err
		}

		if passphrase == "" {
			return fmt.Errorf("passphrase cannot be empty")
		}

		// If interactive, confirm passphrase
		if os.Getenv("AGENT_VAULT_PASSPHRASE") == "" && term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprint(os.Stderr, "Confirm passphrase: ")
			confirm, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return fmt.Errorf("reading confirmation: %w", err)
			}
			if string(confirm) != passphrase {
				return fmt.Errorf("passphrases do not match")
			}
		}

		v, err := vault.Create(path, passphrase)
		if err != nil {
			return err
		}
		_ = v

		fmt.Fprintf(os.Stderr, "Vault created at %s\n", path)
		fmt.Fprintln(os.Stderr, "Set AGENT_VAULT_PASSPHRASE to unlock without prompting.")
		return nil
	},
}

func getOrPromptPassphrase(prompt string) (string, error) {
	// Priority 1: --passphrase-fd flag (most secure — not visible in /proc)
	if passphraseFd >= 0 {
		f := os.NewFile(uintptr(passphraseFd), "passphrase-fd")
		if f == nil {
			return "", fmt.Errorf("invalid file descriptor: %d", passphraseFd)
		}
		defer f.Close()
		data := make([]byte, 4096)
		n, err := f.Read(data)
		if err != nil && n == 0 {
			return "", fmt.Errorf("reading from fd %d: %w", passphraseFd, err)
		}
		return strings.TrimSpace(string(data[:n])), nil
	}

	// Priority 2: environment variable
	if p := os.Getenv("AGENT_VAULT_PASSPHRASE"); p != "" {
		return p, nil
	}

	// Priority 3: interactive terminal prompt
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("no TTY available and AGENT_VAULT_PASSPHRASE not set\n  Tip: use --passphrase-fd or set AGENT_VAULT_PASSPHRASE")
	}

	fmt.Fprint(os.Stderr, prompt)
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading passphrase: %w", err)
	}

	return strings.TrimSpace(string(passBytes)), nil
}

func openVault() (*vault.Vault, error) {
	path := resolveVaultPath()
	passphrase, err := getOrPromptPassphrase("Vault passphrase: ")
	if err != nil {
		return nil, err
	}
	return vault.Open(path, passphrase)
}

// openVaultLocked opens the vault with an exclusive file lock for write operations.
func openVaultLocked() (*vault.Vault, *vault.FileLock, error) {
	path := resolveVaultPath()

	lock, err := vault.Lock(path)
	if err != nil {
		return nil, nil, err
	}

	passphrase, err := getOrPromptPassphrase("Vault passphrase: ")
	if err != nil {
		lock.Unlock()
		return nil, nil, err
	}

	v, err := vault.Open(path, passphrase)
	if err != nil {
		lock.Unlock()
		return nil, nil, err
	}

	return v, lock, nil
}
