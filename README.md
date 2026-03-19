# Agent Vault

**Zero-knowledge secret injection for AI agents.**

Agents reference secrets by name. The vault injects them into commands via environment variables or stdin pipes. There is no command to retrieve secrets in plaintext — by design.

## Why

When an AI agent needs to use an API key or database password, the typical approach is: agent reads the secret, then passes it to a command. The secret is now in the agent's context window, logs, and memory.

Agent Vault eliminates this attack surface. Secrets flow from the vault directly into commands. The agent orchestrates but never observes.

## Install

```bash
go install github.com/octokraft/agent-vault/cmd/agent-vault@latest
```

## Quick Start

```bash
# Human initializes the vault (interactive passphrase)
agent-vault init

# Human stores secrets
agent-vault set db-password
agent-vault set github-token

# Agent injects secrets into commands — never sees values
agent-vault exec --env PGPASSWORD=db-password -- psql -U admin mydb
agent-vault pipe github-token -- gh auth login --with-token

# Safe operations
agent-vault list     # names only, never values
agent-vault status   # vault metadata
agent-vault rm old-key
```

## Security Model

| Layer | Protection |
|-------|-----------|
| **No read primitive** | No `get`, `cat`, or `show` command exists. Secrets can only be injected. |
| **Policy engine** | Commands like `cat`, `echo`, `tee` are blocked by default. Per-secret command allowlists supported. |
| **Env scrubbing** | `AGENT_VAULT_PASSPHRASE` is stripped from the child process environment during `exec`. |
| **Encryption at rest** | AES-256-GCM with Argon2id key derivation (64MB memory, 3 iterations). |
| **File permissions** | Vault files are created with `0600`. |
| **Memory zeroing** | Decrypted plaintext is zeroed after use (best-effort in Go). |
| **File locking** | Exclusive `flock` prevents concurrent vault corruption. |
| **Audit logging** | All secret access is logged to stderr with timestamps. |

## How Agents Use It

Set `AGENT_VAULT_PASSPHRASE` in the agent's session environment (the human does this once). The agent then uses the CLI normally — it can inject secrets into commands but has no way to extract them.

```
Human → sets passphrase → Agent session
                              ↓
                    agent-vault exec/pipe
                              ↓
                    Vault decrypts → injects into command
                              ↓
                    Secret reaches command, not agent
```

## Policy Files

Create `.agent-vault-policy.json` to restrict secret access:

```json
{
  "allowed_commands": ["psql", "mysql", "aws", "gh"],
  "denied_commands": ["cat", "echo", "curl"],
  "secrets": {
    "db-password": {
      "allowed_commands": ["psql", "mysql"]
    }
  }
}
```

## License

MIT
