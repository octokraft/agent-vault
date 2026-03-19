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

// Set stores or updates a secret.
func (v *Vault) Set(name, value string) {
	now := time.Now().UTC().Format(time.RFC3339)
	if existing, ok := v.data.Secrets[name]; ok {
		existing.Value = value
		existing.UpdatedAt = now
	} else {
		v.data.Secrets[name] = &Secret{
			Value:     value,
			CreatedAt: now,
			UpdatedAt: now,
		}
	}
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
	// Build clean environment — scrub vault-related vars to prevent leakage
	env := make([]string, 0, len(os.Environ()))
	for _, e := range os.Environ() {
		key := e[:strings.IndexByte(e, '=')]
		switch key {
		case "AGENT_VAULT_PASSPHRASE", "AGENT_VAULT_PATH":
			continue // scrub sensitive vault config from child process
		}
		env = append(env, e)
	}
	for envName, secretName := range envMap {
		secret, ok := v.data.Secrets[secretName]
		if !ok {
			return fmt.Errorf("secret not found: %s", secretName)
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
	secret, ok := v.data.Secrets[secretName]
	if !ok {
		return fmt.Errorf("secret not found: %s", secretName)
	}

	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

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
