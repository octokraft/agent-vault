package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Secret holds a secret value and metadata.
type Secret struct {
	Value     string `json:"value"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// IsExpired returns true if the secret has a TTL and it has passed.
func (s *Secret) IsExpired() bool {
	if s.ExpiresAt == "" {
		return false
	}
	expires, err := time.Parse(time.RFC3339, s.ExpiresAt)
	if err != nil {
		return false
	}
	return time.Now().UTC().After(expires)
}

// VaultData is the decrypted inner data of the vault.
type VaultData struct {
	Secrets map[string]*Secret `json:"secrets"`
}

// Vault provides operations on the secret store.
type Vault struct {
	path       string
	passphrase string
	file       *VaultFile
	data       *VaultData
}

// Create initializes a new vault at the given path.
func Create(path, passphrase string) (*Vault, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("vault already exists at %s", path)
	}

	salt, err := GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	data := &VaultData{
		Secrets: make(map[string]*Secret),
	}

	vf := &VaultFile{
		Version: 1,
		Salt:    base64.StdEncoding.EncodeToString(salt),
	}

	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	if err := vf.EncryptPayload(passphrase, plaintext); err != nil {
		return nil, err
	}

	if err := Save(path, vf); err != nil {
		return nil, err
	}

	return &Vault{
		path:       path,
		passphrase: passphrase,
		file:       vf,
		data:       data,
	}, nil
}

// Open decrypts and loads an existing vault.
func Open(path, passphrase string) (*Vault, error) {
	vf, err := Load(path)
	if err != nil {
		return nil, err
	}

	plaintext, err := vf.DecryptPayload(passphrase)
	if err != nil {
		return nil, err
	}
	defer Zeroize(plaintext)

	var data VaultData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, fmt.Errorf("parsing vault data: %w", err)
	}

	if data.Secrets == nil {
		data.Secrets = make(map[string]*Secret)
	}

	return &Vault{
		path:       path,
		passphrase: passphrase,
		file:       vf,
		data:       &data,
	}, nil
}

// Set stores or updates a secret. TTL of 0 means no expiry.
func (v *Vault) Set(name, value string, ttl time.Duration) {
	now := time.Now().UTC().Format(time.RFC3339)
	var expiresAt string
	if ttl > 0 {
		expiresAt = time.Now().UTC().Add(ttl).Format(time.RFC3339)
	}

	if existing, ok := v.data.Secrets[name]; ok {
		existing.Value = value
		existing.UpdatedAt = now
		existing.ExpiresAt = expiresAt
	} else {
		v.data.Secrets[name] = &Secret{
			Value:     value,
			CreatedAt: now,
			UpdatedAt: now,
			ExpiresAt: expiresAt,
		}
	}
}

// getSecret retrieves a secret, checking expiry. Returns error if expired.
func (v *Vault) getSecret(name string) (*Secret, error) {
	secret, ok := v.data.Secrets[name]
	if !ok {
		return nil, fmt.Errorf("secret not found: %s", name)
	}
	if secret.IsExpired() {
		return nil, fmt.Errorf("secret %q has expired (was valid until %s)", name, secret.ExpiresAt)
	}
	return secret, nil
}

// List returns sorted secret names.
func (v *Vault) List() []string {
	names := make([]string, 0, len(v.data.Secrets))
	for name := range v.data.Secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Has returns true if a secret with the given name exists.
func (v *Vault) Has(name string) bool {
	_, ok := v.data.Secrets[name]
	return ok
}

// Delete removes a secret. Returns false if it didn't exist.
func (v *Vault) Delete(name string) bool {
	if _, ok := v.data.Secrets[name]; !ok {
		return false
	}
	delete(v.data.Secrets, name)
	return true
}

// Count returns the number of stored secrets.
func (v *Vault) Count() int {
	return len(v.data.Secrets)
}

// IsExpired returns true if the named secret exists and has expired.
func (v *Vault) IsExpired(name string) bool {
	secret, ok := v.data.Secrets[name]
	if !ok {
		return false
	}
	return secret.IsExpired()
}

// Save encrypts and writes the vault to disk.
func (v *Vault) Save() error {
	plaintext, err := json.Marshal(v.data)
	if err != nil {
		return err
	}
	defer Zeroize(plaintext)

	if err := v.file.EncryptPayload(v.passphrase, plaintext); err != nil {
		return err
	}

	return Save(v.path, v.file)
}

// Exec runs a command with secrets injected as environment variables.
// envMap maps ENV_VAR_NAME -> secret_name.
func (v *Vault) Exec(envMap map[string]string, command string, args []string) error {
	// Build clean environment — scrub ALL vault-related vars to prevent leakage
	env := scrubEnv(os.Environ())
	for envName, secretName := range envMap {
		secret, err := v.getSecret(secretName)
		if err != nil {
			return err
		}
		env = append(env, envName+"="+secret.Value)
	}

	// Find the command binary
	binary, err := exec.LookPath(command)
	if err != nil {
		return fmt.Errorf("command not found: %s", command)
	}

	// Audit log
	secretNames := make([]string, 0, len(envMap))
	for _, sn := range envMap {
		secretNames = append(secretNames, sn)
	}
	AuditExec(secretNames, command)

	// Replace the current process with the command.
	// Secrets exist only in the new process's environment.
	argv := append([]string{command}, args...)
	return syscall.Exec(binary, argv, env)
}

// Pipe writes a secret to a command's stdin.
func (v *Vault) Pipe(secretName string, newline bool, command string, args []string) error {
	secret, err := v.getSecret(secretName)
	if err != nil {
		return err
	}

	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Scrub vault env vars from piped command too
	cmd.Env = scrubEnv(os.Environ())

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("creating stdin pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting command: %w", err)
	}

	AuditPipe(secretName, command)

	value := secret.Value
	if newline {
		value += "\n"
	}

	if _, err := io.WriteString(stdin, value); err != nil {
		stdin.Close()
		cmd.Wait()
		return fmt.Errorf("writing to stdin: %w", err)
	}
	stdin.Close()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("command failed: %w", err)
	}

	return nil
}

// scrubEnv removes all AGENT_VAULT_* variables from an environment slice.
func scrubEnv(environ []string) []string {
	clean := make([]string, 0, len(environ))
	for _, e := range environ {
		key := e[:strings.IndexByte(e, '=')]
		if strings.HasPrefix(key, "AGENT_VAULT_") {
			continue
		}
		clean = append(clean, e)
	}
	return clean
}

// GetPassphrase reads the vault passphrase from the environment or returns an error.
func GetPassphrase() (string, error) {
	if p := os.Getenv("AGENT_VAULT_PASSPHRASE"); p != "" {
		return p, nil
	}
	return "", fmt.Errorf("AGENT_VAULT_PASSPHRASE not set (set it or use 'agent-vault init' interactively)")
}

// GetPath returns the vault path from the environment or the default.
func GetPath() string {
	if p := os.Getenv("AGENT_VAULT_PATH"); p != "" {
		return p
	}
	return DefaultPath()
}
