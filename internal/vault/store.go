package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// VaultFile represents the encrypted vault on disk.
type VaultFile struct {
	Version   int    `json:"version"`
	Salt      string `json:"salt"`
	Encrypted string `json:"encrypted"`
}

// DefaultPath returns the default vault file path (~/.agent-vault/vault.enc).
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".agent-vault/vault.enc"
	}
	return filepath.Join(home, ".agent-vault", "vault.enc")
}

// Load reads a vault file from disk.
func Load(path string) (*VaultFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading vault file: %w", err)
	}

	var vf VaultFile
	if err := json.Unmarshal(data, &vf); err != nil {
		return nil, fmt.Errorf("parsing vault file: %w", err)
	}

	if vf.Version != 1 {
		return nil, fmt.Errorf("unsupported vault version: %d", vf.Version)
	}

	return &vf, nil
}

// Save writes a vault file to disk with secure permissions.
func Save(path string, vf *VaultFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("creating vault directory: %w", err)
	}

	data, err := json.MarshalIndent(vf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling vault: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing vault file: %w", err)
	}

	return nil
}

// DecryptPayload decrypts the vault file's encrypted payload.
func (vf *VaultFile) DecryptPayload(passphrase string) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(vf.Salt)
	if err != nil {
		return nil, fmt.Errorf("decoding salt: %w", err)
	}

	encrypted, err := base64.StdEncoding.DecodeString(vf.Encrypted)
	if err != nil {
		return nil, fmt.Errorf("decoding encrypted data: %w", err)
	}

	key := DeriveKey(passphrase, salt)
	return Decrypt(key, encrypted)
}

// EncryptPayload encrypts data and updates the vault file.
func (vf *VaultFile) EncryptPayload(passphrase string, data []byte) error {
	salt, err := base64.StdEncoding.DecodeString(vf.Salt)
	if err != nil {
		return fmt.Errorf("decoding salt: %w", err)
	}

	key := DeriveKey(passphrase, salt)
	encrypted, err := Encrypt(key, data)
	if err != nil {
		return err
	}

	vf.Encrypted = base64.StdEncoding.EncodeToString(encrypted)
	return nil
}
