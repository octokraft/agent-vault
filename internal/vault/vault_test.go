package vault

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tempVaultPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "vault.enc")
}

func TestCreateAndOpen(t *testing.T) {
	path := tempVaultPath(t)
	pass := "test-passphrase"

	v, err := Create(path, pass)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if v.Count() != 0 {
		t.Fatalf("new vault should have 0 secrets, got %d", v.Count())
	}

	v2, err := Open(path, pass)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if v2.Count() != 0 {
		t.Fatalf("reopened vault should have 0 secrets, got %d", v2.Count())
	}
}

func TestCreateAlreadyExists(t *testing.T) {
	path := tempVaultPath(t)
	_, err := Create(path, "pass")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err = Create(path, "pass")
	if err == nil {
		t.Fatal("expected error when vault already exists")
	}
}

func TestOpenWrongPassphrase(t *testing.T) {
	path := tempVaultPath(t)
	_, err := Create(path, "correct")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err = Open(path, "wrong")
	if err == nil {
		t.Fatal("expected error when opening with wrong passphrase")
	}
}

func TestSetAndList(t *testing.T) {
	path := tempVaultPath(t)
	v, _ := Create(path, "pass")

	v.Set("beta", "val-b", 0)
	v.Set("alpha", "val-a", 0)
	v.Set("gamma", "val-c", 0)

	names := v.List()
	if len(names) != 3 {
		t.Fatalf("expected 3 secrets, got %d", len(names))
	}

	// Should be sorted
	if names[0] != "alpha" || names[1] != "beta" || names[2] != "gamma" {
		t.Fatalf("expected sorted names, got %v", names)
	}
}

func TestSetPersists(t *testing.T) {
	path := tempVaultPath(t)
	pass := "pass"

	v, _ := Create(path, pass)
	v.Set("api-key", "sk-12345", 0)
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	v2, err := Open(path, pass)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if v2.Count() != 1 {
		t.Fatalf("expected 1 secret, got %d", v2.Count())
	}

	if !v2.Has("api-key") {
		t.Fatal("expected to find api-key")
	}
}

func TestSetUpdate(t *testing.T) {
	path := tempVaultPath(t)
	v, _ := Create(path, "pass")

	v.Set("key", "old-value", 0)
	v.Set("key", "new-value", 0)

	if v.Count() != 1 {
		t.Fatalf("updating should not create duplicate, got count=%d", v.Count())
	}
}

func TestDelete(t *testing.T) {
	path := tempVaultPath(t)
	v, _ := Create(path, "pass")

	v.Set("to-delete", "val", 0)
	if !v.Delete("to-delete") {
		t.Fatal("Delete should return true for existing secret")
	}

	if v.Delete("to-delete") {
		t.Fatal("Delete should return false for non-existent secret")
	}

	if v.Count() != 0 {
		t.Fatalf("expected 0 secrets after delete, got %d", v.Count())
	}
}

func TestHas(t *testing.T) {
	path := tempVaultPath(t)
	v, _ := Create(path, "pass")

	v.Set("exists", "val", 0)

	if !v.Has("exists") {
		t.Fatal("Has should return true for existing secret")
	}
	if v.Has("missing") {
		t.Fatal("Has should return false for non-existent secret")
	}
}

func TestVaultFilePermissions(t *testing.T) {
	path := tempVaultPath(t)
	_, err := Create(path, "pass")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Fatalf("vault file should be 0600, got %o", perm)
	}
}

func TestValidateSecretName(t *testing.T) {
	valid := []string{"api-key", "db.password", "AWS_SECRET", "a", "a1", "my-secret-123"}
	for _, name := range valid {
		if err := ValidateSecretName(name); err != nil {
			t.Errorf("expected %q to be valid, got: %v", name, err)
		}
	}

	invalid := []string{"", "-bad", ".bad", "bad-", "has space", "has/slash", "a@b", string(make([]byte, 256))}
	for _, name := range invalid {
		if err := ValidateSecretName(name); err == nil {
			t.Errorf("expected %q to be invalid", name)
		}
	}
}

func TestZeroize(t *testing.T) {
	data := []byte("sensitive-data")
	Zeroize(data)
	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte %d not zeroed: %d", i, b)
		}
	}
}

func TestSecretExpiry(t *testing.T) {
	path := tempVaultPath(t)
	v, _ := Create(path, "pass")

	// Secret with past expiry
	v.Set("expired", "val", 0)
	v.data.Secrets["expired"].ExpiresAt = time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)

	_, err := v.getSecret("expired")
	if err == nil {
		t.Fatal("expected error for expired secret")
	}

	// Secret with future expiry
	v.Set("valid", "val", 24*time.Hour)

	_, err = v.getSecret("valid")
	if err != nil {
		t.Fatalf("expected valid secret, got: %v", err)
	}

	// Secret with no expiry
	v.Set("forever", "val", 0)

	_, err = v.getSecret("forever")
	if err != nil {
		t.Fatalf("expected valid secret, got: %v", err)
	}
}

func TestScrubEnv(t *testing.T) {
	environ := []string{
		"HOME=/home/user",
		"AGENT_VAULT_PASSPHRASE=secret",
		"AGENT_VAULT_PATH=/tmp/vault",
		"AGENT_VAULT_CUSTOM=foo",
		"PATH=/usr/bin",
	}

	clean := scrubEnv(environ)
	if len(clean) != 2 {
		t.Fatalf("expected 2 env vars after scrub, got %d: %v", len(clean), clean)
	}
	for _, e := range clean {
		if e == "AGENT_VAULT_PASSPHRASE=secret" || e == "AGENT_VAULT_PATH=/tmp/vault" || e == "AGENT_VAULT_CUSTOM=foo" {
			t.Fatalf("vault env var not scrubbed: %s", e)
		}
	}
}
