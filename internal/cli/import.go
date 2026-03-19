package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/octokraft/agent-vault/internal/vault"
	"github.com/spf13/cobra"
)

var (
	importPrefix string
	importTTL    string
)

var importCmd = &cobra.Command{
	Use:   "import <env-file>",
	Short: "Import secrets from a .env file",
	Long: `Reads KEY=VALUE pairs from a .env file and stores each as a secret.
Lines starting with # are ignored. Secret names are lowercased and
dots replace underscores by default. Use --prefix to namespace imports.

The .env file is read but its contents are never logged.

Example:
  agent-vault import .env
  agent-vault import --prefix prod. secrets.env`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		file, err := os.Open(args[0])
		if err != nil {
			return fmt.Errorf("opening file: %w", err)
		}
		defer file.Close()

		// Parse env file
		type entry struct {
			name, value string
		}
		var entries []entry

		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())

			// Skip empty lines and comments
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("line %d: invalid format (expected KEY=VALUE)", lineNum)
			}

			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			// Remove surrounding quotes from value
			if len(value) >= 2 {
				if (value[0] == '"' && value[len(value)-1] == '"') ||
					(value[0] == '\'' && value[len(value)-1] == '\'') {
					value = value[1 : len(value)-1]
				}
			}

			name := importPrefix + strings.ToLower(strings.ReplaceAll(key, "_", "."))

			if err := vault.ValidateSecretName(name); err != nil {
				return fmt.Errorf("line %d: %w", lineNum, err)
			}

			entries = append(entries, entry{name: name, value: value})
		}

		if err := scanner.Err(); err != nil {
			return fmt.Errorf("reading file: %w", err)
		}

		if len(entries) == 0 {
			return fmt.Errorf("no secrets found in %s", args[0])
		}

		// Open vault and import
		v, lock, err := openVaultLocked()
		if err != nil {
			return err
		}
		defer lock.Unlock()

		var ttl time.Duration
		if importTTL != "" {
			ttl, err = time.ParseDuration(importTTL)
			if err != nil {
				return fmt.Errorf("invalid TTL: %w", err)
			}
		}

		for _, e := range entries {
			v.Set(e.name, e.value, ttl)
		}

		if err := v.Save(); err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "Imported %d secret(s) from %s\n", len(entries), args[0])
		return nil
	},
}

func init() {
	importCmd.Flags().StringVar(&importPrefix, "prefix", "", "prefix for imported secret names")
	importCmd.Flags().StringVar(&importTTL, "ttl", "", "TTL for all imported secrets")
}
