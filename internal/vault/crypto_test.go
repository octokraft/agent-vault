package vault

import (
	"bytes"
	"testing"
)

func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	if len(salt1) != SaltSize {
		t.Fatalf("expected %d bytes, got %d", SaltSize, len(salt1))
	}

	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	if bytes.Equal(salt1, salt2) {
		t.Fatal("two salts should not be equal")
	}
}

func TestDeriveKey(t *testing.T) {
	salt, _ := GenerateSalt()

	key1 := DeriveKey("password1", salt)
	key2 := DeriveKey("password2", salt)
	key3 := DeriveKey("password1", salt)

	if len(key1) != KeySize {
		t.Fatalf("expected %d bytes, got %d", KeySize, len(key1))
	}
	if bytes.Equal(key1, key2) {
		t.Fatal("different passwords should produce different keys")
	}
	if !bytes.Equal(key1, key3) {
		t.Fatal("same password and salt should produce same key")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := DeriveKey("test-passphrase", make([]byte, SaltSize))
	plaintext := []byte("super secret value")

	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext should not equal plaintext")
	}

	decrypted, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := DeriveKey("correct", make([]byte, SaltSize))
	key2 := DeriveKey("wrong", make([]byte, SaltSize))

	ciphertext, _ := Encrypt(key1, []byte("secret"))

	_, err := Decrypt(key2, ciphertext)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

func TestDecryptTooShort(t *testing.T) {
	key := DeriveKey("test", make([]byte, SaltSize))
	_, err := Decrypt(key, []byte("short"))
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}
}

func TestEncryptNondeterministic(t *testing.T) {
	key := DeriveKey("test", make([]byte, SaltSize))
	plaintext := []byte("same data")

	ct1, _ := Encrypt(key, plaintext)
	ct2, _ := Encrypt(key, plaintext)

	if bytes.Equal(ct1, ct2) {
		t.Fatal("encrypting same data twice should produce different ciphertext (random nonce)")
	}
}
