# Network Egress Inventory

This document enumerates every outbound network connection that LASSO makes, under what conditions, and how to disable each one. LASSO is designed for security-conscious environments; the default installation makes **zero** outbound network calls during normal sandbox operation.

## Summary Table

| Connection | Destination | When | User-initiated | Can disable |
|------------|-------------|------|----------------|-------------|
| GitHub OAuth Device Flow | `github.com`, `api.github.com` | `lasso auth login` | Yes | Don't run the command |
| Webhook dispatch | User-configured URL | Audit events fire | Yes (configured in profile) | Remove webhooks from profile |
| Syslog forwarding | User-configured address | Audit events fire | Yes (configured in profile) | Remove `syslog_address` from config |
| Checkpoint manifest fetch | (not active) | Never | N/A | Already disabled |
| Dashboard HTTP server | Binds `127.0.0.1:8080` | `lasso dashboard` | Yes | Don't run the command |

## Detailed Breakdown

### 1. GitHub OAuth Device Flow

**Source:** `lasso/auth/github.py`

**Endpoints contacted:**
- `POST https://github.com/login/device/code` -- request a device code
- `POST https://github.com/login/oauth/access_token` -- poll for token
- `GET https://api.github.com/user` -- fetch user info after login

**When it runs:** Only when the user explicitly invokes `lasso auth login`. This is an interactive command that opens a browser for the user to authorize. It is never triggered automatically.

**Scopes requested:** `read:user read:org` (read-only; no write access to repos).

**How to avoid:** Simply do not run `lasso auth login`. LASSO operates fully without GitHub authentication. The auth flow exists for teams that use GitHub-based authentication.

**Environment override:** If `GITHUB_TOKEN` is already set in the environment, the device flow is skipped entirely -- the existing token is stored locally and no network calls to GitHub are made (except optionally `GET /user` when calling `get_user_info()`).

---

### 2. Webhook Dispatch

**Source:** `lasso/core/webhooks.py`

**Destination:** Whatever URL(s) the user configures in their sandbox profile's `webhooks` section.

**When it runs:** After each audit event (command execution, lifecycle change, violation, file access, network access), if one or more webhook endpoints are configured and the event type matches the webhook's event filter.

**Protocol details:**
- HTTP POST with JSON payload
- Custom headers: `X-Lasso-Event`, `X-Lasso-Delivery` (unique ID), `X-Lasso-Timestamp`
- User-Agent: `LASSO-Webhook/1.0`
- Optional HMAC-SHA256 signature in `X-Lasso-Signature` header (format: `t=<timestamp>,sha256=<hex>`) when a webhook secret is configured
- Retries with exponential backoff (0.5s, 1s, 2s, ...) on failure
- Dispatch is asynchronous via background daemon threads -- never blocks sandbox operations
- Uses stdlib `urllib.request` only (no third-party HTTP libraries)

**How to disable:** Do not configure any webhooks in your profile. By default, no webhooks are configured. The dispatcher is a no-op when the webhook list is empty.

---

### 3. Syslog Forwarding

**Source:** `lasso/core/audit.py` (`_setup_syslog`, `_forward_to_syslog`)

**Destination:** User-configured syslog address. Supports:
- Unix domain sockets (e.g., `/dev/log`)
- UDP: `udp://host:port`
- TCP: `tcp://host:port`

**When it runs:** After each audit event, if `syslog_address` is configured in the audit config.

**How to disable:** Do not set `syslog_address` in your audit configuration. It is empty by default.

---

### 4. Checkpoint Manifest URL

**Source:** `lasso/core/checkpoint.py`

**Current state:** The `CHECKPOINT_MANIFEST_URL` constant is defined as an **empty string**:

```python
CHECKPOINT_MANIFEST_URL: str = ""
```

This means LASSO does **not** fetch any remote checkpoint manifest. The checkpoint system operates entirely from the local file `~/.lasso/checkpoints.json`. There is no phone-home, no update check, and no remote manifest fetch.

The constant exists as a placeholder for a future feature where teams could optionally point to an internal manifest endpoint. It has no default value and no code path currently uses it for network access.

---

### 5. Dashboard HTTP Server

**Source:** `lasso/cli/main.py`, `lasso/dashboard/app.py`

**Binding:** `127.0.0.1:8080` by default (localhost only, not externally accessible).

**When it runs:** Only when the user explicitly runs `lasso dashboard`.

**Flags:**
- `--host` overrides the bind address (default: `127.0.0.1`)
- `--port` / `-p` overrides the port (default: `8080`)
- `LASSO_DASHBOARD_PUBLIC=1` disables authentication and CSRF protection (development only; never use in production)

The dashboard is a local management UI. It does not make any outbound connections itself.

---

## Explicit Non-Connections

LASSO does **not** perform any of the following:

- **No telemetry.** No usage data, crash reports, or feature flags are sent anywhere.
- **No analytics.** No tracking pixels, no event collection, no third-party analytics SDKs.
- **No auto-update phone-home.** LASSO does not check for updates, download binaries, or contact any update server. The checkpoint system is purely local.
- **No license validation.** No license server calls. LASSO is not gated by any remote license check.
- **No DNS or IP lookups** beyond what the user explicitly configures (webhooks, syslog).

---

## Air-Gapped / Offline Operation

LASSO is designed to work fully offline. To run in an air-gapped environment:

1. **Install** LASSO and its dependencies (Python, Docker/Podman) via your organization's package mirror or sneakernet.

2. **Skip GitHub auth.** Do not run `lasso auth login`. If you need a GitHub token, set `GITHUB_TOKEN` in the environment from your internal secrets manager.

3. **Use offline or strict profiles:**
   ```bash
   lasso create offline --dir /path/to/project
   ```
   The `offline` and `strict` built-in profiles disable all network access inside the sandbox by default.

4. **Do not configure webhooks.** Leave the webhooks section empty in your profile. Audit logs are written locally to JSONL files.

5. **Syslog forwarding** to a local Unix socket (`/dev/log`) works without any external network access if you want centralized logging on the same host.

6. **Dashboard** binds to localhost by default and requires no external connectivity.

All core functionality -- sandbox creation, command gating, audit logging, HMAC signing, and profile management -- works with zero network access.
