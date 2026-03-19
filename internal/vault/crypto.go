package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	SaltSize     = 16
	KeySize      = 32
	NonceSize    = 12
	ArgonTime    = 3
	ArgonMemory  = 64 * 1024
	ArgonThreads = 4
)

// GenerateSalt creates a cryptographically random salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	_, err := rand.Read(salt)
	return salt, err
}

// DeriveKey derives an encryption key from a passphrase and salt using Argon2id.
func DeriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)
}

// Encrypt encrypts plaintext using AES-256-GCM. Returns nonce prepended to ciphertext.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts ciphertext that was encrypted with Encrypt.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := ciphertext[:NonceSize]
	encrypted := ciphertext[NonceSize:]

	plaintext, err := aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong passphrase?): %w", err)
	}

	return plaintext, nil
}
