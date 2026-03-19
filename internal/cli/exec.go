package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/octokraft/agent-vault/internal/policy"
	"github.com/spf13/cobra"
)

var (
	execEnvFlags  []string
	execPolicyFile string
	execNoPolicy   bool
)

var execCmd = &cobra.Command{
	Use:   "exec [--env NAME=secret] -- <command> [args...]",
	Short: "Run a command with secrets injected as environment variables",
	Long: `Executes a command with specified secrets injected as environment variables.
The current process is replaced by the command — secrets exist only in the
new process's environment and are never written to disk or logs.

Use -- to separate agent-vault flags from the command.

Examples:
  agent-vault exec --env DB_PASS=db-password -- psql -U admin mydb
  agent-vault exec --env AWS_SECRET_ACCESS_KEY=aws-key --env AWS_ACCESS_KEY_ID=aws-id -- aws s3 ls`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(execEnvFlags) == 0 {
			return fmt.Errorf("at least one --env NAME=secret mapping is required")
		}

		// Parse env mappings
		envMap := make(map[string]string)
		for _, mapping := range execEnvFlags {
			parts := strings.SplitN(mapping, "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid --env format %q (expected NAME=secret-name)", mapping)
			}
			envMap[parts[0]] = parts[1]
		}

		// Load policy
		var pol *policy.Policy
		if !execNoPolicy {
			if execPolicyFile != "" {
				var err error
				pol, err = policy.LoadPolicy(execPolicyFile)
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
			if err := pol.CheckCommand(args[0]); err != nil {
				return err
			}
			if err := pol.CheckArgs(args[0], args[1:]); err != nil {
				return err
			}
			for _, secretName := range envMap {
				if err := pol.CheckSecretCommand(secretName, args[0]); err != nil {
					return err
				}
			}
		}

		v, err := openVault()
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "[agent-vault] injecting %d secret(s) into %q\n", len(envMap), args[0])

		// This replaces the current process — does not return on success
		return v.Exec(envMap, args[0], args[1:])
	},
}

func init() {
	execCmd.Flags().StringArrayVarP(&execEnvFlags, "env", "e", nil, "map ENV_VAR=secret-name (repeatable)")
	execCmd.Flags().StringVar(&execPolicyFile, "policy", "", "path to policy file")
	execCmd.Flags().BoolVar(&execNoPolicy, "no-policy", false, "disable policy checks (use with caution)")
}
