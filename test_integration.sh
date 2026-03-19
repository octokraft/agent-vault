#!/usr/bin/env bash
# Integration test for agent-vault
# Verifies the security model end-to-end
set -euo pipefail

VAULT="/tmp/agent-vault-test-$$"
PASS="test-passphrase-$$"
BIN="./agent-vault"
FAILURES=0

cleanup() { rm -f "$VAULT" "${VAULT}.lock"; }
trap cleanup EXIT

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILURES=$((FAILURES + 1)); }

echo "=== Agent Vault Integration Tests ==="

# Build
echo "Building..."
go build -o "$BIN" ./cmd/agent-vault

# 1. Init
echo "--- Test: init ---"
AGENT_VAULT_PASSPHRASE="$PASS" AGENT_VAULT_PATH="$VAULT" $BIN init 2>/dev/null && pass "vault created" || fail "init failed"

# 2. Set secrets
echo "--- Test: set ---"
echo "db-secret-value" | AGENT_VAULT_PASSPHRASE="$PASS" AGENT_VAULT_PATH="$VAULT" $BIN set db-password --stdin 2>/dev/null && pass "set db-password" || fail "set failed"
echo "api-key-value" | AGENT_VAULT_PASSPHRASE="$PASS" AGENT_VAULT_PATH="$VAULT" $BIN set api-key --stdin 2>/dev/null && pass "set api-key" || fail "set failed"

# 3. List (should show names only)
echo "--- Test: list ---"
OUTPUT=$(AGENT_VAULT_PASSPHRASE="$PASS" AGENT_VAULT_PATH="$VAULT" $BIN list 2>/dev/null)
echo "$OUTPUT" | grep -q "db-password" && pass "list shows db-password" || fail "list missing db-password"
echo "$OUTPUT" | grep -q "api-key" && pass "list shows api-key" || fail "list missing api-key"
echo "$OUTPUT" | grep -q "secret-value" && fail "list leaks secret values!" || pass "list does not leak values"

# 4. Exec (secret injected as env var)
echo "--- Test: exec ---"
OUTPUT=$(AGENT_VAULT_PASSPHRASE="$PASS" AGENT_VAULT_PATH="$VAULT" $BIN exec --no-policy --env DB_PASS=db-password -- printenv DB_PASS 2>/dev/null)
[ "$OUTPUT" = "db-secret-value" ] && pass "exec injects correct value" || fail "exec wrong value: $OUTPUT"

# 5. Exec env scrubbing (vault passphrase must NOT be in child env)
echo "--- Test: env scrubbing ---"
OUTPUT=$(AGENT_VAULT_PASSPHRASE="$PASS" AGENT_VAULT_PATH="$VAULT" $BIN exec --no-policy --env DB_PASS=db-password -- env 2>/dev/null)
echo "$OUTPUT" | grep -q "AGENT_VAULT_PASSPHRASE" && fail "passphrase leaked to child!" || pass "passphrase scrubbed from child"
echo "$OUTPUT" | grep -q "AGENT_VAULT_PATH" && fail "vault path leaked to child!" || pass "vault path scrubbed from child"

# 6. Policy blocks cat
echo "--- Test: policy blocks cat ---"
AGENT_VAULT_PASSPHRASE="$PASS" AGENT_VAULT_PATH="$VAULT" $BIN pipe db-password -- cat 2>/dev/null && fail "cat should be blocked!" || pass "cat blocked by policy"

# 7. Policy blocks bash
echo "--- Test: policy blocks bash ---"
AGENT_VAULT_PASSPHRASE="$PASS" AGENT_VAULT_PATH="$VAULT" $BIN exec --env S=db-password -- bash -c 'echo $S' 2>/dev/null && fail "bash should be blocked!" || pass "bash blocked by policy"

# 8. Policy blocks python
echo "--- Test: policy blocks python ---"
AGENT_VAULT_PASSPHRASE="$PASS" AGENT_VAULT_PATH="$VAULT" $BIN exec --env S=db-password -- python3 -c 'pass' 2>/dev/null && fail "python should be blocked!" || pass "python3 blocked by policy"

# 9. Pipe (secret piped to stdin)
echo "--- Test: pipe ---"
OUTPUT=$(AGENT_VAULT_PASSPHRASE="$PASS" AGENT_VAULT_PATH="$VAULT" $BIN pipe db-password --no-policy -- wc -c 2>/dev/null)
[ "$OUTPUT" = "15" ] && pass "pipe sends correct byte count" || fail "pipe wrong count: $OUTPUT"

# 10. TTL expiry
echo "--- Test: TTL expiry ---"
echo "temp" | AGENT_VAULT_PASSPHRASE="$PASS" AGENT_VAULT_PATH="$VAULT" $BIN set temp-key --stdin --ttl 1s 2>/dev/null
sleep 2
AGENT_VAULT_PASSPHRASE="$PASS" AGENT_VAULT_PATH="$VAULT" $BIN exec --no-policy --env T=temp-key -- printenv T 2>/dev/null && fail "expired secret should be rejected!" || pass "expired secret rejected"

# 11. Wrong passphrase
echo "--- Test: wrong passphrase ---"
AGENT_VAULT_PASSPHRASE="wrong" AGENT_VAULT_PATH="$VAULT" $BIN list 2>/dev/null && fail "wrong passphrase should fail!" || pass "wrong passphrase rejected"

# 12. Verify
echo "--- Test: verify ---"
AGENT_VAULT_PASSPHRASE="$PASS" AGENT_VAULT_PATH="$VAULT" $BIN verify 2>/dev/null && pass "verify succeeds" || fail "verify failed"

# 13. Delete
echo "--- Test: rm ---"
AGENT_VAULT_PASSPHRASE="$PASS" AGENT_VAULT_PATH="$VAULT" $BIN rm temp-key 2>/dev/null && pass "rm temp-key" || fail "rm failed"

# 14. File permissions
echo "--- Test: file permissions ---"
PERMS=$(stat -c %a "$VAULT")
[ "$PERMS" = "600" ] && pass "vault file is 0600" || fail "vault file is $PERMS"

# 15. Passphrase-fd
echo "--- Test: passphrase-fd ---"
OUTPUT=$(AGENT_VAULT_PATH="$VAULT" $BIN --passphrase-fd 3 list 3<<<"$PASS" 2>/dev/null)
echo "$OUTPUT" | grep -q "api-key" && pass "passphrase-fd works" || fail "passphrase-fd failed"

# Summary
echo ""
echo "=== Results: $((15 - FAILURES))/15 passed, $FAILURES failures ==="
[ "$FAILURES" -eq 0 ] && echo "All tests passed!" || echo "SOME TESTS FAILED"
exit "$FAILURES"
