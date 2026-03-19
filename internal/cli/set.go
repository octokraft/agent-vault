package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var setFromStdin bool

var setCmd = &cobra.Command{
	Use:   "set <name>",
	Short: "Store a secret in the vault",
	Long: `Stores a secret value under the given name. The value is read from the
terminal (hidden input) or from stdin with --stdin flag.

The secret value is never echoed or logged.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		v, err := openVault()
		if err != nil {
			return err
		}

		var value string

		if setFromStdin || !term.IsTerminal(int(os.Stdin.Fd())) {
			// Read from stdin
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				value = scanner.Text()
			}
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("reading stdin: %w", err)
			}
		} else {
			// Read from terminal (hidden)
			fmt.Fprintf(os.Stderr, "Enter value for %q: ", name)
			valBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return fmt.Errorf("reading secret: %w", err)
			}
			value = string(valBytes)
		}

		value = strings.TrimRight(value, "\n\r")
		if value == "" {
			return fmt.Errorf("secret value cannot be empty")
		}

		existed := v.Has(name)
		v.Set(name, value)

		if err := v.Save(); err != nil {
			return err
		}

		if existed {
			fmt.Fprintf(os.Stderr, "Secret %q updated\n", name)
		} else {
			fmt.Fprintf(os.Stderr, "Secret %q stored\n", name)
		}
		return nil
	},
}

func init() {
	setCmd.Flags().BoolVar(&setFromStdin, "stdin", false, "read secret value from stdin")
}
