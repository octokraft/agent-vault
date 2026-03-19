package cli

import (
	"github.com/octokraft/agent-vault/internal/vault"
	"github.com/spf13/cobra"
)

var vaultPath string

var rootCmd = &cobra.Command{
	Use:   "agent-vault",
	Short: "Zero-knowledge secret injection for AI agents",
	Long: `Agent Vault is a secrets manager designed for AI agents.

Secrets are injected into commands via environment variables or stdin pipes.
There is no command to retrieve secrets in plaintext — by design.

Your secrets flow through pipes, not prompts.`,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&vaultPath, "vault", "", "vault file path (default: ~/.agent-vault/vault.enc)")
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(setCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(rmCmd)
	rootCmd.AddCommand(execCmd)
	rootCmd.AddCommand(pipeCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(verifyCmd)
}

func Execute() error {
	return rootCmd.Execute()
}

func resolveVaultPath() string {
	if vaultPath != "" {
		return vaultPath
	}
	return vault.GetPath()
}
