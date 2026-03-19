package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultPolicyBlocksDangerousCommands(t *testing.T) {
	pol := DefaultPolicy()

	for _, cmd := range DangerousCommands {
		if err := pol.CheckCommand(cmd); err == nil {
			t.Errorf("expected %q to be blocked by default policy", cmd)
		}
	}
}

func TestDefaultPolicyAllowsSafeCommands(t *testing.T) {
	pol := DefaultPolicy()

	safe := []string{"psql", "mysql", "aws", "gh", "docker", "kubectl", "curl"}
	for _, cmd := range safe {
		if err := pol.CheckCommand(cmd); err != nil {
			t.Errorf("expected %q to be allowed, got: %v", cmd, err)
		}
	}
}

func TestAllowedCommandsList(t *testing.T) {
	pol := &Policy{
		AllowedCommands: []string{"psql", "mysql"},
	}

	if err := pol.CheckCommand("psql"); err != nil {
		t.Errorf("psql should be allowed: %v", err)
	}
	if err := pol.CheckCommand("curl"); err == nil {
		t.Error("curl should not be allowed when allowlist is set")
	}
}

func TestDeniedOverridesAllowed(t *testing.T) {
	pol := &Policy{
		DeniedCommands: []string{"cat"},
	}

	if err := pol.CheckCommand("cat"); err == nil {
		t.Error("cat should be denied")
	}
}

func TestSecretSpecificRules(t *testing.T) {
	pol := &Policy{
		SecretRules: map[string]*SecretRule{
			"db-password": {
				AllowedCommands: []string{"psql", "mysql"},
			},
		},
	}

	if err := pol.CheckSecretCommand("db-password", "psql"); err != nil {
		t.Errorf("psql should be allowed for db-password: %v", err)
	}
	if err := pol.CheckSecretCommand("db-password", "curl"); err == nil {
		t.Error("curl should not be allowed for db-password")
	}
	// Unrestricted secret should work with any non-denied command
	if err := pol.CheckSecretCommand("other-secret", "curl"); err != nil {
		t.Errorf("curl should be allowed for unrestricted secret: %v", err)
	}
}

func TestLoadPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	content := `{
		"allowed_commands": ["psql"],
		"denied_commands": ["cat"],
		"secrets": {
			"db-pass": {
				"allowed_commands": ["psql"]
			}
		}
	}`

	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writing policy file: %v", err)
	}

	pol, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	if len(pol.AllowedCommands) != 1 {
		t.Fatalf("expected 1 allowed command, got %d", len(pol.AllowedCommands))
	}
	if len(pol.DeniedCommands) != 1 {
		t.Fatalf("expected 1 denied command, got %d", len(pol.DeniedCommands))
	}
}

func TestCheckCommandWithPath(t *testing.T) {
	pol := DefaultPolicy()

	// Should check basename, not full path
	if err := pol.CheckCommand("/usr/bin/cat"); err == nil {
		t.Error("/usr/bin/cat should be blocked (basename is cat)")
	}
	if err := pol.CheckCommand("/usr/bin/psql"); err != nil {
		t.Errorf("/usr/bin/psql should be allowed: %v", err)
	}
}
