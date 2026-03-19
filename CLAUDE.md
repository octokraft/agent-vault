# Agent Vault

Zero-knowledge secret injection CLI. Secrets are injected into commands via env vars or stdin pipes — never output as plaintext.

## Build & Test

```bash
go build -o agent-vault ./cmd/agent-vault    # build
go test -race ./...                          # unit tests
bash test_integration.sh                     # integration tests (15 tests)
```

## Architecture

- `cmd/agent-vault/main.go` — entry point
- `internal/vault/` — core: crypto (AES-256-GCM + Argon2id), store (atomic file I/O), vault (secret operations), lock (flock), audit, secure (memory zeroing)
- `internal/cli/` — cobra commands: init, set, list, rm, exec, pipe, import, rekey, verify, wrap, status, version
- `internal/policy/` — command allowlisting and shell blocking
- `docs/` — GitHub Pages site

## Using Secrets (for AI agents)

You are an AI agent. You MUST NOT retrieve secret values. Instead, inject them:

```bash
# Inject as environment variable
agent-vault exec --env DB_PASS=db-password -- psql -U admin mydb

# Pipe to stdin
agent-vault pipe github-token -- gh auth login --with-token

# List available secrets (names only)
agent-vault list
```

**Never use** `--no-policy` unless the human operator explicitly approves it.

## Security Design

- No `get`/`read`/`show` command exists — no code path outputs secrets
- Default policy blocks shells (bash, python, node) and exfiltration commands (cat, echo, curl)
- `AGENT_VAULT_*` env vars are scrubbed from child processes
- Vault files: AES-256-GCM, Argon2id, 0600 permissions, atomic writes, flock
- Prefer `--passphrase-fd` over env var for passphrase delivery
