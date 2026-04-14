# LASSO — Secrets Management Patterns

**Document version:** 1.0
**Last updated:** 2026-03-24
**Audience:** DevOps engineers, security teams, developers configuring LASSO profiles

---

## Overview

LASSO profiles are TOML configuration files that define sandbox behavior: allowed commands, network rules, environment variables, and webhook integrations. Some of these fields naturally involve secrets (API keys, webhook signing secrets, authentication tokens). This document describes recommended patterns for handling secrets safely in LASSO deployments.

**Core principle:** Never store plaintext secrets in TOML config files. Use environment variable references instead.

---

## 1. Fields That May Contain Secrets

The following profile and configuration fields are sensitive:

| Field | Location | Risk |
|---|---|---|
| `webhook.secret` | Profile TOML `[webhook]` section | HMAC signing key for webhook payloads. Exposure allows forging audit events. |
| `extra_env` values | Profile TOML `[sandbox]` section | Environment variables passed into the sandbox. May contain API keys, database credentials, or service tokens. |
| Agent auth environment variables | Profile TOML `[agent]` section or agent-specific config | Tokens for AI agent providers (e.g., `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`). |
| `auth.token` | `~/.lasso/auth.json` | GitHub OAuth token from `lasso auth login`. |
| HMAC signing keys | `~/.lasso/.audit_key`, `~/.lasso/.checkpoint_key` | Audit log signing keys. Exposure allows forging audit entries. See [key-management.md](./key-management.md). |

---

## 2. Recommended Pattern: Environment Variable References

### 2.1 The Pattern

Store secret values as environment variables on the host. In TOML configuration, reference the variable name — not the value.

**Correct** — reference the env var name:
```toml
[webhook]
url = "https://siem.internal/lasso-events"
secret_env = "LASSO_WEBHOOK_SECRET"    # LASSO reads this env var at runtime

[sandbox]
extra_env = [
    "DATABASE_URL",       # passed through from host environment
    "API_KEY",            # passed through from host environment
]
```

**Incorrect** — hardcoded secret:
```toml
[webhook]
url = "https://siem.internal/lasso-events"
secret = "sk-wh-a1b2c3d4e5f6"         # DO NOT DO THIS

[sandbox]
extra_env = [
    "DATABASE_URL=postgres://user:p@ssw0rd@db:5432/prod",  # DO NOT DO THIS
]
```

### 2.2 Setting Environment Variables

Set secrets in the host environment before launching LASSO:

```bash
# Option 1: Export in shell session
export LASSO_WEBHOOK_SECRET="sk-wh-a1b2c3d4e5f6"
export DATABASE_URL="postgres://user:password@db:5432/prod"
lasso create strict --dir .

# Option 2: Use a .env file (NOT checked into version control)
# .env
LASSO_WEBHOOK_SECRET=sk-wh-a1b2c3d4e5f6
DATABASE_URL=postgres://user:password@db:5432/prod

# Load and run
set -a; source .env; set +a
lasso create strict --dir .

# Option 3: systemd service (EnvironmentFile)
# /etc/lasso/secrets.env  (mode 0600, owned by lasso service user)
LASSO_WEBHOOK_SECRET=sk-wh-a1b2c3d4e5f6
```

---

## 3. The `extra_env` Field

The `extra_env` profile field passes host environment variables into the sandbox container. This is the primary mechanism for giving sandboxed agents access to secrets they need (database connections, API keys, etc.) without embedding those secrets in configuration files.

### 3.1 Passthrough Mode (Name Only)

When `extra_env` contains just a variable name, LASSO reads the current value from the host environment and passes it into the container:

```toml
[sandbox]
extra_env = [
    "ANTHROPIC_API_KEY",
    "DATABASE_URL",
    "REDIS_URL",
]
```

The agent inside the sandbox sees these variables with the values from the host environment. If a variable is not set on the host, it is not passed through (no error, the variable simply does not exist inside the sandbox).

### 3.2 Explicit Value Mode

When `extra_env` contains `NAME=VALUE`, the value is set directly. Use this only for non-secret configuration:

```toml
[sandbox]
extra_env = [
    "LOG_LEVEL=INFO",           # not a secret — safe to hardcode
    "APP_ENV=staging",          # not a secret — safe to hardcode
    "API_KEY",                  # secret — passthrough from host
]
```

---

## 4. The `--pass-env` CLI Flag

The `--pass-env` flag on `lasso create` and `lasso exec` passes additional host environment variables into the sandbox at runtime, supplementing what is defined in the profile:

```bash
# Pass a secret that's not in the profile
lasso create development --dir . --pass-env AWS_SESSION_TOKEN

# Pass multiple variables
lasso create development --dir . \
    --pass-env AWS_ACCESS_KEY_ID \
    --pass-env AWS_SECRET_ACCESS_KEY \
    --pass-env AWS_SESSION_TOKEN

# Combine with profile extra_env
# Profile already defines DATABASE_URL passthrough;
# --pass-env adds temporary credentials
lasso create strict --dir . --pass-env TEMP_AUDIT_TOKEN
```

**When to use `--pass-env` vs. `extra_env`:**

| Scenario | Use |
|---|---|
| Variable is always needed by this profile | `extra_env` in the profile TOML |
| Variable is needed only for this session | `--pass-env` on the command line |
| Variable is user-specific (different per developer) | `--pass-env` on the command line |
| Short-lived credentials (STS tokens, rotating keys) | `--pass-env` on the command line |

---

## 5. Integration with External Key Vaults

LASSO does not directly integrate with key vault services, but its environment-variable-based secrets model works seamlessly with vault agents that populate the host environment.

### 5.1 HashiCorp Vault

```bash
# Vault agent populates environment, then LASSO reads it
eval $(vault kv get -format=json secret/lasso | jq -r '.data.data | to_entries | .[] | "export \(.key)=\(.value)"')
lasso create strict --dir .
```

Or with Vault Agent auto-auth and env template:

```hcl
# vault-agent.hcl
template {
  contents = <<-EOF
    LASSO_WEBHOOK_SECRET={{ with secret "secret/lasso" }}{{ .Data.data.webhook_secret }}{{ end }}
    DATABASE_URL={{ with secret "secret/lasso" }}{{ .Data.data.database_url }}{{ end }}
  EOF
  destination = "/run/lasso/secrets.env"
  perms = 0600
}
```

### 5.2 AWS Secrets Manager

```bash
# Fetch secrets and export as env vars
eval $(aws secretsmanager get-secret-value \
    --secret-id lasso/production \
    --query 'SecretString' \
    --output text | jq -r 'to_entries | .[] | "export \(.key)=\(.value)"')
lasso create strict --dir .
```

### 5.3 Azure Key Vault

```bash
export LASSO_WEBHOOK_SECRET=$(az keyvault secret show \
    --vault-name lasso-prod --name webhook-secret \
    --query value -o tsv)
lasso create strict --dir .
```

### 5.4 Kubernetes Secrets

When LASSO runs inside Kubernetes, secrets can be mounted as environment variables via the pod spec:

```yaml
env:
  - name: LASSO_WEBHOOK_SECRET
    valueFrom:
      secretKeyRef:
        name: lasso-secrets
        key: webhook-secret
```

The LASSO profile references these variables normally via `extra_env` passthrough.

---

## 6. Anti-Patterns

### 6.1 Hardcoded API Keys in TOML

```toml
# NEVER DO THIS
[sandbox]
extra_env = [
    "OPENAI_API_KEY=sk-proj-abc123def456",
]
```

**Risk:** If the TOML file is committed to version control, the key is exposed in git history permanently. Even if removed later, it remains in prior commits.

### 6.2 Webhook Secrets in Checked-In Config

```toml
# NEVER DO THIS
[webhook]
secret = "whsec_live_a1b2c3d4"
```

**Risk:** Anyone with repository read access can forge webhook payloads, potentially injecting false audit events into downstream SIEM systems.

### 6.3 Secrets in Profile Export Files

When sharing profiles via `lasso profile export`, be aware that exported TOML files may contain `extra_env` entries. Review exported profiles before sharing:

```bash
# Export a profile
lasso profile export strict > shared-profile.toml

# Review for secrets before sharing
grep -i "key\|secret\|password\|token" shared-profile.toml
```

### 6.4 Secrets in Command Arguments

```bash
# NEVER DO THIS — the secret appears in the audit log
lasso exec <id> -- curl -H "Authorization: Bearer sk-secret123" https://api.example.com
```

**Risk:** Command arguments are captured in the audit trail. Use environment variables inside the sandbox instead:

```bash
# Correct: pass secret as env var, reference it in the command
lasso create dev --dir . --pass-env API_TOKEN
lasso exec <id> -- sh -c 'curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com'
```

### 6.5 Logging Secret Values

LASSO audit logs capture command text and environment variable **names** (not values) passed via `extra_env`. However, if a command prints secret values to stdout/stderr and output capture is enabled, those values will appear in the audit log.

**Mitigation:** Ensure scripts inside the sandbox do not print credentials. Use `--no-capture-output` if output capture is enabled and commands may emit sensitive data.

---

## 7. Checklist for Secure Deployments

- [ ] No plaintext secrets in any `.toml` config file
- [ ] All secrets referenced via environment variable names only
- [ ] `.env` files are in `.gitignore`
- [ ] HMAC signing keys (`~/.lasso/.audit_key`, `~/.lasso/.checkpoint_key`) have `0600` permissions
- [ ] `~/.lasso/auth.json` has `0600` permissions
- [ ] Webhook secrets are set via environment variables, not in profile TOML
- [ ] Exported profiles are reviewed for secrets before sharing
- [ ] CI/CD pipelines use secrets management (GitHub Secrets, Vault, etc.) to populate env vars
- [ ] `--pass-env` is used for session-specific or short-lived credentials
- [ ] Scripts inside sandboxes do not print credential values to stdout/stderr

---

## Related Documents

- [Key Management](./key-management.md) — HMAC signing key lifecycle
- [Hardening Guide](./hardening-guide.md) — Full security hardening for regulated environments
- [Threat Model](./threat-model.md) — Attack surfaces and mitigations
- [Environment Variables](../env-vars.md) — All LASSO environment variables
