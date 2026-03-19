package vault

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// AuditEvent represents a logged vault operation.
type AuditEvent struct {
	Timestamp string
	Operation string
	Target    string
	Command   string
}

// Audit logs a vault operation to stderr. Secret values are never included.
func Audit(op, target, command string) {
	ts := time.Now().UTC().Format(time.RFC3339)
	parts := []string{
		fmt.Sprintf("[agent-vault] %s", ts),
		fmt.Sprintf("op=%s", op),
	}
	if target != "" {
		parts = append(parts, fmt.Sprintf("secret=%s", target))
	}
	if command != "" {
		parts = append(parts, fmt.Sprintf("cmd=%s", command))
	}
	fmt.Fprintln(os.Stderr, strings.Join(parts, " "))
}

// AuditExec logs an exec operation with multiple secret injections.
func AuditExec(secretNames []string, command string) {
	ts := time.Now().UTC().Format(time.RFC3339)
	fmt.Fprintf(os.Stderr, "[agent-vault] %s op=exec secrets=[%s] cmd=%s\n",
		ts, strings.Join(secretNames, ","), command)
}

// AuditPipe logs a pipe operation.
func AuditPipe(secretName, command string) {
	Audit("pipe", secretName, command)
}

// AuditAccess logs when a secret is accessed (set, delete, etc).
func AuditAccess(op, secretName string) {
	Audit(op, secretName, "")
}
