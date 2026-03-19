package cli

import (
	"fmt"
	"os"

	"github.com/octokraft/agent-vault/internal/policy"
	"github.com/spf13/cobra"
)

var (
	pipePolicyFile string
	pipeNoPolicy   bool
	pipeNewline    bool
)

var pipeCmd = &cobra.Command{
	Use:   "pipe <secret-name> -- <command> [args...]",
	Short: "Pipe a secret into a command's stdin",
	Long: `Writes a secret value to a command's standard input via a pipe.
The secret never touches the filesystem or command-line arguments.

Use -- to separate the secret name from the command.

Examples:
  agent-vault pipe db-password -- psql -U admin mydb
  agent-vault pipe github-token -- gh auth login --with-token
  agent-vault pipe signing-key -- gpg --import`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		secretName := args[0]
		command := args[1]
		cmdArgs := args[2:]

		// Load policy
		var pol *policy.Policy
		if !pipeNoPolicy {
			if pipePolicyFile != "" {
				var err error
				pol, err = policy.LoadPolicy(pipePolicyFile)
				if err != nil {
					return fmt.Errorf("loading policy: %w", err)
				}
			} else if pf := policy.FindPolicyFile(); pf != "" {
				var err error
				pol, err = policy.LoadPolicy(pf)
				if err != nil {
					return fmt.Errorf("loading policy: %w", err)
				}
			} else {
				pol = policy.DefaultPolicy()
			}
		}

		// Check policy
		if pol != nil {
			if err := pol.CheckSecretCommand(secretName, command); err != nil {
				return err
			}
		}

		v, err := openVault()
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "[agent-vault] piping secret %q into %q\n", secretName, command)

		return v.Pipe(secretName, pipeNewline, command, cmdArgs)
	},
}

func init() {
	pipeCmd.Flags().StringVar(&pipePolicyFile, "policy", "", "path to policy file")
	pipeCmd.Flags().BoolVar(&pipeNoPolicy, "no-policy", false, "disable policy checks (use with caution)")
	pipeCmd.Flags().BoolVar(&pipeNewline, "newline", false, "append newline to piped value")
}
