package vault

import (
	"fmt"
	"regexp"
	"unsafe"
)

// Zeroize overwrites a byte slice with zeros to clear sensitive data from memory.
// This is a best-effort defense — the Go GC may have already copied the data.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ZeroizeString overwrites a string's backing memory with zeros.
// WARNING: This violates Go's string immutability contract and should only
// be used for sensitive data (passphrases, secret values) that must not linger.
func ZeroizeString(s *string) {
	if len(*s) == 0 {
		return
	}
	b := unsafe.Slice(unsafe.StringData(*s), len(*s))
	for i := range b {
		b[i] = 0
	}
	*s = ""
}

var validSecretName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,253}[a-zA-Z0-9]$`)

// ValidateSecretName checks that a secret name is safe and well-formed.
func ValidateSecretName(name string) error {
	if len(name) < 1 || len(name) > 255 {
		return fmt.Errorf("secret name must be 1-255 characters")
	}
	if len(name) == 1 {
		if matched, _ := regexp.MatchString(`^[a-zA-Z0-9]$`, name); !matched {
			return fmt.Errorf("single-character secret name must be alphanumeric")
		}
		return nil
	}
	if !validSecretName.MatchString(name) {
		return fmt.Errorf("secret name must be alphanumeric with dots, dashes, or underscores (got %q)", name)
	}
	return nil
}
