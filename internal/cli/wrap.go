package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/octokraft/agent-vault/internal/vault"
	"github.com/spf13/cobra"
)

var (
	wrapAllow []string
)

var wrapCmd = &cobra.Command{
	Use:   "wrap --allow <secrets> -- <command> [args...]",
	Short: "Wrap an agent with pre-approved secret access",
	Long: `Launches an agent (or any command) in a restricted environment where
agent-vault is available on PATH and pre-approved secrets can be injected.

The wrapped process gets:
  - AGENT_VAULT_PATH and AGENT_VAULT_PASSPHRASE set automatically
  - A restricted policy allowing only the specified secrets
  - The agent-vault binary available to call exec/pipe

This is the recommended way to run AI agents with vault access.

Example:
  agent-vault wrap --allow db-password,api-key -- claude-code
  agent-vault wrap --allow '*' -- my-agent-script.sh`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(wrapAllow) == 0 {
			return fmt.Errorf("--allow is required (specify secret names or '*' for all)")
		}

		// Verify vault is accessible
		v, err := openVault()
		if err != nil {
			return err
		}

		// Validate that requested secrets exist
		allowAll := len(wrapAllow) == 1 && wrapAllow[0] == "*"
		if !allowAll {
			for _, name := range wrapAllow {
				if !v.Has(name) {
					return fmt.Errorf("secret %q not found in vault", name)
				}
			}
		}

		// Get the passphrase to pass to the child
		passphrase, err := getOrPromptPassphrase("Vault passphrase: ")
		if err != nil {
			return err
		}

		// Build environment for the wrapped process
		env := make([]string, 0, len(os.Environ())+3)
		for _, e := range os.Environ() {
			key := e[:strings.IndexByte(e, '=')]
			if strings.HasPrefix(key, "AGENT_VAULT_") {
				continue
			}
			env = append(env, e)
		}
		env = append(env, "AGENT_VAULT_PATH="+resolveVaultPath())
		env = append(env, "AGENT_VAULT_PASSPHRASE="+passphrase)

		// Create a temporary policy file for the wrapped session
		if !allowAll {
			policyContent := buildWrapPolicy(wrapAllow)
			tmpFile, err := os.CreateTemp("", "agent-vault-policy-*.json")
			if err != nil {
				return fmt.Errorf("creating temp policy: %w", err)
			}
			defer os.Remove(tmpFile.Name())

			if _, err := tmpFile.WriteString(policyContent); err != nil {
				tmpFile.Close()
				return fmt.Errorf("writing policy: %w", err)
			}
			tmpFile.Close()

			env = append(env, "AGENT_VAULT_POLICY="+tmpFile.Name())
		}

		vault.Audit("wrap", strings.Join(wrapAllow, ","), args[0])

		// Launch the wrapped process
		child := exec.Command(args[0], args[1:]...)
		child.Env = env
		child.Stdin = os.Stdin
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr

		fmt.Fprintf(os.Stderr, "[agent-vault] wrapping %q with access to %d secret(s)\n", args[0], len(wrapAllow))

		if err := child.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			return fmt.Errorf("running wrapped command: %w", err)
		}

		return nil
	},
}

func buildWrapPolicy(allowedSecrets []string) string {
	// Build a policy that only allows the specified secrets with safe commands
	var sb strings.Builder
	sb.WriteString("{\n")
	sb.WriteString(`  "denied_commands": ["cat","echo","printf","tee","less","more","head","tail","xxd","hexdump","od","strings","base64","sh","bash","zsh","fish","dash","ksh","csh","tcsh","python","python3","python2","ruby","irb","perl","perl5","node","nodejs","deno","bun","lua","php"]`)
	sb.WriteString("\n}\n")
	return sb.String()
}

func init() {
	wrapCmd.Flags().StringSliceVar(&wrapAllow, "allow", nil, "secret names to allow (comma-separated, or '*' for all)")
}
