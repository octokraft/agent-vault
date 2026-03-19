package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Policy defines access controls for secret injection.
type Policy struct {
	AllowedCommands []string               `json:"allowed_commands,omitempty"`
	DeniedCommands  []string               `json:"denied_commands,omitempty"`
	SecretRules     map[string]*SecretRule  `json:"secrets,omitempty"`
}

// SecretRule defines per-secret access controls.
type SecretRule struct {
	AllowedCommands []string `json:"allowed_commands,omitempty"`
}

// DangerousCommands are commands that could expose secrets to stdout/network.
var DangerousCommands = []string{
	"cat", "echo", "printf", "tee", "less", "more", "head", "tail",
	"xxd", "hexdump", "od", "strings", "base64",
}

// LoadPolicy reads a policy file from disk.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}

	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy: %w", err)
	}

	return &p, nil
}

// DefaultPolicy returns a secure default policy that blocks dangerous commands.
func DefaultPolicy() *Policy {
	return &Policy{
		DeniedCommands: DangerousCommands,
	}
}

// CheckCommand validates that a command is allowed by the policy.
func (p *Policy) CheckCommand(command string) error {
	base := filepath.Base(command)

	// Check denied list first
	for _, denied := range p.DeniedCommands {
		if base == denied || command == denied {
			return fmt.Errorf("command %q is denied by policy (could expose secrets)", base)
		}
	}

	// If allowed list exists, command must be in it
	if len(p.AllowedCommands) > 0 {
		for _, allowed := range p.AllowedCommands {
			if base == allowed || command == allowed {
				return nil
			}
		}
		return fmt.Errorf("command %q is not in the allowed commands list", base)
	}

	return nil
}

// CheckSecretCommand validates that a specific secret can be used with a command.
func (p *Policy) CheckSecretCommand(secretName, command string) error {
	if err := p.CheckCommand(command); err != nil {
		return err
	}

	rule, ok := p.SecretRules[secretName]
	if !ok {
		return nil
	}

	base := filepath.Base(command)
	if len(rule.AllowedCommands) > 0 {
		for _, allowed := range rule.AllowedCommands {
			if base == allowed || command == allowed {
				return nil
			}
		}
		return fmt.Errorf("secret %q cannot be used with command %q", secretName, base)
	}

	return nil
}

// FindPolicyFile looks for a policy file in standard locations.
func FindPolicyFile() string {
	// Check current directory
	if _, err := os.Stat(".agent-vault-policy.json"); err == nil {
		return ".agent-vault-policy.json"
	}

	// Check home directory
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	path := filepath.Join(home, ".agent-vault", "policy.json")
	if _, err := os.Stat(path); err == nil {
		return path
	}

	return ""
}
