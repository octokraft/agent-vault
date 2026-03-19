package vault

import (
	"os"
	"path/filepath"
	"testing"
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

	v.Set("beta", "val-b")
	v.Set("alpha", "val-a")
	v.Set("gamma", "val-c")

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
	v.Set("api-key", "sk-12345")
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

	v.Set("key", "old-value")
	v.Set("key", "new-value")

	if v.Count() != 1 {
		t.Fatalf("updating should not create duplicate, got count=%d", v.Count())
	}
}

func TestDelete(t *testing.T) {
	path := tempVaultPath(t)
	v, _ := Create(path, "pass")

	v.Set("to-delete", "val")
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

	v.Set("exists", "val")

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
