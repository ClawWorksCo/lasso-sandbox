# LASSO Security Hardening Guide

**Document version:** 1.0
**Last updated:** 2026-03-16
**Audience:** Security engineers, DevOps teams, compliance officers deploying LASSO in regulated environments
**Companion document:** [Threat Model](./threat-model.md)

---

## 1. Overview

This guide describes how to configure LASSO for maximum security in banking and financial services environments. It covers profile configuration, network isolation, audit log management, key rotation, infrastructure hardening, and operational monitoring.

All recommendations assume compliance with DORA (EU 2022/2554) and ISO 27001. Where LASSO provides a configuration option, the recommended setting is given explicitly. Where LASSO depends on infrastructure-level controls, the required host configuration is described.

---

## 2. Profile Configuration for Banking Environments

### 2.1 Start from the strict Profile

The built-in `strict` profile (`lasso/config/defaults.py` L63-106) is the recommended starting point for regulated environments. It provides:

- Whitelist-only command execution (no shell operators)
- Zero network access
- Full audit trail with HMAC signing and command output capture
- Hidden sensitive paths (`/etc/ssh`, `/etc/ssl/private`)
- Guardrail enforcement enabled

To bootstrap a project:

```bash
lasso init --profile strict
```

### 2.2 Recommended Profile Settings

The following TOML configuration represents the maximum-security profile. Each setting is annotated with its security rationale.

```toml
[commands]
# CRITICAL: Always use whitelist mode in production.
# Blacklist mode permits everything not explicitly blocked,
# which means new attack tools are allowed by default.
mode = "whitelist"

# Minimal command set: only what the agent actually needs.
# Review this list quarterly and remove unused commands.
whitelist = [
    "python3", "python", "pip", "pip3",
    "Rscript", "R",
    "ls", "cat", "head", "tail", "grep", "find", "wc",
    "sort", "uniq", "diff", "mkdir", "cp", "mv", "touch",
]

# CRITICAL: Shell operators enable command chaining, redirection,
# and subshell execution. Disable for all regulated workloads.
allow_shell_operators = false

# Wall-clock timeout prevents runaway processes.
# 600 seconds (10 minutes) is generous for data analysis;
# reduce for interactive workflows.
max_execution_seconds = 600

# Block dangerous argument patterns even for whitelisted commands.
[commands.blocked_args]
pip = ["install --user", "install -e", "install --target"]
git = ["push", "push --force", "remote add", "remote set-url"]
python3 = ["-c"]    # Block inline code execution via -c flag
python = ["-c"]
find = ["-delete"]  # Redundant with DANGEROUS_ARGS but explicit
```

```toml
[filesystem]
working_dir = "/path/to/project"

# Default read-only paths protect system binaries.
# Add any additional paths that must not be writable.
read_only_paths = ["/usr", "/lib", "/lib64", "/bin", "/sbin"]

# Hide sensitive files from the agent entirely.
# These paths are not mounted in the container.
hidden_paths = [
    "/etc/shadow", "/etc/gshadow", "/root",
    "/etc/ssh", "/etc/ssl/private",
    "/etc/lasso",   # LASSO's own configuration
    "/home/*/.ssh",  # SSH keys
    "/home/*/.gnupg", # GPG keys
    "/home/*/.aws",   # AWS credentials
    "/home/*/.azure", # Azure credentials
]

# Disk quota prevents storage exhaustion attacks.
max_disk_mb = 20480   # 20 GB
temp_dir_mb = 256     # Restrict /tmp to 256 MB
```

```toml
[network]
# CRITICAL: Use "none" for any workload that does not
# strictly require network access. This is the strongest
# network isolation available.
mode = "none"

# If network access is required (e.g., package installation),
# use "restricted" with the minimum necessary allowlist.
# allowed_domains = ["pypi.org", "files.pythonhosted.org"]
# allowed_ports = [443]

# Always block cloud metadata and private ranges,
# even in "full" mode (these are the defaults).
blocked_cidrs = [
    "169.254.169.254/32",  # Cloud metadata (AWS, GCP, Azure)
    "10.0.0.0/8",          # RFC 1918 private
    "172.16.0.0/12",       # RFC 1918 private
    "192.168.0.0/16",      # RFC 1918 private
    "100.64.0.0/10",       # Carrier-grade NAT
    "198.18.0.0/15",       # Benchmark testing
]

# Use internal DNS servers when network is restricted.
# Public DNS (1.1.1.1, 8.8.8.8) may leak query data.
# dns_servers = ["10.0.0.53"]
```

```toml
[resources]
# Memory limit: prevents OOM conditions affecting the host.
max_memory_mb = 8192

# CPU limit: prevents CPU starvation of host services.
# 50% is conservative; adjust based on dedicated vs. shared host.
max_cpu_percent = 50

# PID limit: prevents fork bombs.
# 150 is sufficient for Python/R data analysis workloads.
max_pids = 150

# Open file limit: prevents file descriptor exhaustion.
max_open_files = 1024

# Single file size limit: prevents large file creation.
max_file_size_mb = 100
```

```toml
[guardrails]
# CRITICAL: enforce = true means violations block execution.
# Set to false only for initial testing/debugging.
enforce = true

# Default rules are recommended for all deployments.
[[guardrails.rules]]
id = "no-escape"
description = "Agent must not access paths outside working_dir."
severity = "critical"
enabled = true

[[guardrails.rules]]
id = "no-exfiltration"
description = "Agent must not transmit file contents to external hosts."
severity = "critical"
enabled = true

[[guardrails.rules]]
id = "log-modifications"
description = "All file modifications must be logged in audit trail."
severity = "error"
enabled = true
```

```toml
[audit]
# CRITICAL: All five settings below must be enabled for
# DORA compliance (Articles 10, 12, 17).
enabled = true
sign_entries = true
include_command_output = true
include_file_diffs = true
log_format = "jsonl"

# Log rotation settings.
max_log_size_mb = 100
rotation_count = 10

# RECOMMENDED: Store signing key on separate mount.
# See Section 6 for key management recommendations.
signing_key_path = "/mnt/secure/lasso-audit.key"

# Alternative: Network-mounted secure storage
# signing_key_path = "/secure-nfs/lasso/audit.key"
```

> **WARNING: Co-located signing keys provide weak tamper evidence.**
> If `signing_key_path` is not configured, LASSO stores the HMAC key inside `log_dir`
> (as `.audit_key`). An attacker with write access to the log directory can read the
> key, modify entries, and recompute valid signatures. Always store the signing key
> on a separate filesystem, mount, or key management system so that compromising the
> log directory alone is not sufficient to forge audit entries.

**Syslog forwarding.** For real-time log delivery to a SIEM or central syslog collector,
configure `syslog_address`. Each audit entry is forwarded as a JSON payload via syslog
in addition to being written to local disk.

```toml
[audit]
# Forward audit entries to a central SIEM via syslog.
syslog_address = "udp://siem.company.com:514"
syslog_facility = "local0"
```

Supported address formats:
- **Unix socket:** `/dev/log` (local syslog daemon)
- **UDP:** `udp://siem.company.com:514`
- **TCP:** `tcp://siem.company.com:514`

Syslog forwarding is non-blocking -- errors are logged but never crash the sandbox.

### 2.3 Profile Integrity Verification

Every sandbox profile has a deterministic SHA-256 hash computed by `SandboxProfile.config_hash()` (`lasso/config/schema.py` L303-306). This hash is logged in the audit trail at sandbox startup.

To verify that the profile in use matches the approved configuration:

1. Compute the expected hash from the approved TOML file
2. Compare against the `config_hash` field in the audit log's `lifecycle:start` event
3. Alert on mismatch -- this indicates the profile was modified between approval and use

```bash
# Verify audit log integrity
lasso audit verify ./audit/log.jsonl

# View the startup event to check config_hash
lasso audit view ./audit/log.jsonl --type lifecycle
```

### 2.4 Version Control for Profiles

Store all sandbox profiles in version control alongside the project code. This provides:

- Change history: who modified the profile, when, and why
- Code review: profile changes should require security team approval
- Reproducibility: `profile_version` counter (`schema.py` L276-280) tracks incremental changes
- Audit trail linkage: `config_hash` in the audit log can be matched to a specific git commit

---

## 3. Network Isolation Best Practices

### 3.1 Default to No Network

The strongest network isolation is `mode = "none"`. In this mode:

- Docker sets `--network none`, removing all network interfaces except loopback
- LASSO additionally applies iptables rules as defense-in-depth (DROP all, ACCEPT loopback)
- DNS resolution is impossible -- no DNS servers are configured
- Even shell-level network techniques (e.g., `/dev/tcp`) fail because no route exists

Use this mode for all workloads that do not strictly require network access: data analysis, code generation, report writing, testing.

### 3.2 Restricted Mode Configuration

When network access is required (e.g., `pip install` during environment setup), use `restricted` mode with the minimum necessary allowlist.

**Domain allowlisting:**

```toml
[network]
mode = "restricted"

# Only the specific domains needed. Be precise:
# "pypi.org" allows the index; "files.pythonhosted.org" allows package downloads.
# Do not use wildcards or broad domains like "*.amazonaws.com".
allowed_domains = [
    "pypi.org",
    "files.pythonhosted.org",
]

# Only HTTPS. Never allow HTTP (port 80) in production.
allowed_ports = [443]
```

**CIDR allowlisting (for internal services):**

```toml
# If the agent needs to reach an internal package mirror:
allowed_cidrs = ["10.100.50.0/24"]
# This permits ONLY the specific subnet, on allowed_ports only.
```

**DNS server hardening:**

```toml
# Use internal DNS servers to prevent DNS query leakage.
# Public DNS (1.1.1.1, 8.8.8.8) sends queries to external resolvers.
dns_servers = ["10.0.0.53", "10.0.0.54"]
```

### 3.3 Blocking Cloud Metadata Endpoints

Cloud metadata services (AWS IMDSv1 at `169.254.169.254`, GCP metadata at `metadata.google.internal`, Azure IMDS at `169.254.169.254`) are blocked by default via `blocked_cidrs`. This prevents Server-Side Request Forgery (SSRF) attacks where an agent attempts to read cloud credentials from the metadata service.

Ensure the default blocked CIDRs are never removed:

```toml
blocked_cidrs = [
    "169.254.169.254/32",   # Cloud metadata (AWS, GCP, Azure)
    "169.254.0.0/16",       # Link-local (broader protection)
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]
```

### 3.4 Network Policy Verification

After a sandbox starts, verify that network rules were applied successfully:

```bash
# Check the audit log for network_policy_applied event
lasso audit view ./audit/log.jsonl --type lifecycle
```

Look for the `network_policy_applied` event with `rules_failed: 0`. If any rules failed, the sandbox may have weaker network isolation than intended. Common failure causes:

- iptables not installed in the container image (add `iptables` to the Dockerfile)
- Insufficient capabilities (`NET_ADMIN` not granted -- check `converter.py` L123-131)
- Container network namespace not yet ready at rule application time

### 3.5 Proxy Configuration

For environments that require traffic inspection, LASSO supports proxying via `NetworkConfig`:

```toml
[network]
enable_proxy = true
proxy_address = "10.0.0.100:8080"
```

This routes all container traffic through an inspection proxy where TLS can be terminated, content inspected, and connections logged. The proxy provides an additional layer of network visibility beyond what iptables rules offer.

---

## 4. Audit Log Management

### 4.1 Log Storage Architecture

```
Production Deployment:

  [LASSO Sandbox]
       |
       | (writes JSONL to local disk)
       v
  [Local audit/*.jsonl]
       |
       | (forward in real-time via log shipper)
       v
  [Central Log Aggregation]  (Splunk, ELK, Azure Sentinel)
       |
       v
  [Immutable Archive]  (S3 with Object Lock, WORM storage)
```

**Local storage.** Audit logs are written as append-only JSONL files in the configured `log_dir` (default: `./audit/`). Each sandbox session creates a new file named `{sandbox_id}_{timestamp}.jsonl`.

**Central forwarding.** Forward logs in real-time to a central aggregation platform. Use a log shipper (Filebeat, Fluentd, Vector) configured to watch `log_dir` for new files. This ensures logs are preserved even if the local host is compromised.

**Immutable archive.** For DORA Article 12 compliance, archive audit logs to immutable storage (S3 with Object Lock, Azure Blob with immutability policies, or dedicated WORM storage). Retain for the period required by your retention policy (typically 5-7 years for financial services).

### 4.2 Log Verification Procedures

**Routine verification (automated, daily):**

```bash
# Verify all audit logs in a directory
for f in ./audit/*.jsonl; do
    lasso audit verify "$f"
done
```

Integrate this into a CI/CD pipeline or cron job. Alert on any verification failure.

**Incident verification (manual, on-demand):**

```bash
# Verify a specific log file with explicit key path
lasso audit verify ./audit/sandbox_a1b2c3_20260316T140000Z.jsonl \
    --key /etc/lasso/keys/audit.key

# Filter to violations for incident investigation
lasso audit view ./audit/log.jsonl --type violation

# Filter to blocked commands
lasso audit view ./audit/log.jsonl --type command
# (then grep for "blocked" in the output)
```

**Verification result interpretation:**

| Result | Meaning | Action |
|---|---|---|
| `valid: true`, `verified == total` | Log integrity intact | No action needed |
| `valid: false`, `first_break_at: N` | Chain broken at line N | Investigate: was the log file truncated, edited, or corrupted? |
| `errors: "no signature found"` | Entry was written without signing | Check if `sign_entries` was disabled during that session |
| `errors: "signature mismatch"` | Entry content was modified after writing | Treat as potential tampering -- escalate to incident response |

### 4.3 Log Retention

| Environment | Retention Period | Rationale |
|---|---|---|
| Development | 30 days | Debugging and iteration |
| Staging | 90 days | Pre-production validation |
| Production (banking) | 7 years | DORA Article 12, national banking regulations |
| Incident-related | Indefinite | Legal hold, forensic evidence |

Configure log rotation to prevent disk exhaustion:

```toml
[audit]
max_log_size_mb = 100   # Rotate at 100 MB
rotation_count = 10      # Keep 10 rotated files locally
```

Forward to central storage before local rotation deletes old files.

### 4.4 Sensitive Data in Logs

When `include_command_output = true`, audit logs may contain:

- Command stdout/stderr (first 2000 bytes)
- File paths and names
- Error messages that may reveal internal structure

When `include_file_diffs = true`, audit logs may contain file content.

**Recommendations:**

- Classify audit logs at the same data sensitivity level as the data the agent processes
- Apply the same access controls to audit logs as to the production data
- If logs contain PII, ensure they comply with GDPR data subject access and erasure requirements
- Consider redacting sensitive fields before forwarding to central logging (or use a log processing pipeline)

---

## 5. Dashboard and API Hardening

### 5.1 Dashboard Authentication

**Never run the dashboard in public mode in production.** The environment variable `LASSO_DASHBOARD_PUBLIC=1` disables all authentication and CSRF protection.

**Token management:**

- The dashboard token is stored at `~/.lasso/dashboard_token` with `0o600` permissions
- Rotate the token periodically by deleting the file and restarting the dashboard
- Use a strong, unique `LASSO_SECRET_KEY` environment variable for Flask session signing:

```bash
export LASSO_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

If `LASSO_SECRET_KEY` is not set, Flask generates a random key on each process restart, which invalidates all active sessions. In production, set a stable key and rotate it periodically.

### 5.2 API Key Management

**Generate API keys before production deployment:**

```python
from lasso.api.auth import APIKeyStore

store = APIKeyStore()
key = store.generate_key()  # Returns "lasso_<random>"
store.save_key(key, name="monitoring-integration", scopes=["read"])
store.save_key(store.generate_key(), name="ci-automation", scopes=["read", "write"])
store.save_key(store.generate_key(), name="admin-operator", scopes=["admin"])
```

**Scope assignments:**

| Scope | Permitted Operations | Recommended For |
|---|---|---|
| `read` | List sandboxes, view status, read audit logs | Monitoring dashboards, SIEM integrations |
| `write` | Create/stop sandboxes, execute commands | CI/CD automation, agent orchestrators |
| `admin` | All operations (implies read + write) | Manual administration only |

**Key storage.** API keys are stored in `~/.lasso/api_keys.json`. Protect this file:

```bash
chmod 600 ~/.lasso/api_keys.json
```

### 5.3 Network Binding

The dashboard should bind to `127.0.0.1` (localhost) in production, not `0.0.0.0`:

```bash
lasso dashboard --host 127.0.0.1 --port 8080
```

If remote access is required, place the dashboard behind a reverse proxy (nginx, Caddy, Traefik) with:

- TLS termination (HTTPS only)
- Client certificate authentication (mTLS) for additional security
- IP allowlisting for the management network
- Additional security headers (CSP, HSTS, Permissions-Policy)

### 5.4 Security Headers

LASSO sets `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` on all responses (`dashboard/app.py` L577-579). When deploying behind a reverse proxy, add additional headers:

```nginx
# Reverse proxy security headers
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
```

---

## 6. Key Rotation Procedures

### 6.1 Audit Signing Key Rotation

The HMAC signing key is the trust root for audit log integrity. Rotation procedure:

1. **Stop all running sandboxes** (each sandbox has its own `AuditLogger` instance with the key loaded in memory)

2. **Back up the current key:**
   ```bash
   cp ~/.lasso/audit/.audit_key ~/.lasso/audit/.audit_key.backup.$(date +%Y%m%d)
   ```

3. **Verify all existing logs** before rotation (you need the old key to verify old logs):
   ```bash
   for f in ./audit/*.jsonl; do
       lasso audit verify "$f" --key ~/.lasso/audit/.audit_key
   done
   ```

4. **Delete the current key:**
   ```bash
   rm ~/.lasso/audit/.audit_key
   ```

5. **Start new sandboxes** -- LASSO auto-generates a new key on first use (`audit.py` L95-110)

6. **Store the old key** in a secure archive alongside the logs it signed. Old logs can only be verified with the key that signed them.

**Rotation frequency.** Rotate the signing key:
- Every 90 days as a baseline
- Immediately if key compromise is suspected
- When personnel with key access leave the organization

**Per-session keys.** Each sandbox session creates a new log file. For maximum security, configure `signing_key_path` to point to a unique key per session, managed by an external key management system.

### 6.2 Dashboard Token Rotation

```bash
# Delete the existing token
rm ~/.lasso/dashboard_token

# Restart the dashboard -- a new token is generated and printed
lasso dashboard
```

Distribute the new token to authorized operators through a secure channel (not email, not chat). Consider integrating with SSO/OIDC in future LASSO versions.

### 6.3 API Key Rotation

1. Generate a new key with the same scopes as the old one
2. Update all integrations to use the new key
3. Remove the old key from `api_keys.json`
4. Verify no requests are using the old key (check for 401 responses in logs)

```python
from lasso.api.auth import APIKeyStore

store = APIKeyStore()
new_key = store.generate_key()
store.save_key(new_key, name="monitoring-v2", scopes=["read"])
# After migration, manually edit api_keys.json to remove the old key
```

### 6.4 Flask Secret Key Rotation

The `LASSO_SECRET_KEY` environment variable signs Flask sessions. Rotation invalidates all active dashboard sessions (users must re-authenticate).

```bash
export LASSO_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
# Restart the dashboard
```

---

## 7. Infrastructure Hardening

### 7.1 Dedicated Host Configuration

Run LASSO on a dedicated host (physical or VM) with:

- **Minimal OS installation** -- no desktop environment, no unnecessary services
- **Hardened kernel** -- disable unused modules, enable `kernel.unprivileged_userns_clone=0` if not needed
- **Automatic security updates** -- `unattended-upgrades` on Debian/Ubuntu
- **No outbound internet access from host** (unless required for container image pulls)
- **Encrypted disk** -- LUKS full-disk encryption at rest
- **SSH key-only access** -- disable password authentication

### 7.2 Container Runtime Hardening

**Docker-specific:**

```json
// /etc/docker/daemon.json
{
    "userns-remap": "default",
    "no-new-privileges": true,
    "live-restore": true,
    "userland-proxy": false,
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    }
}
```

- `userns-remap`: maps container root to an unprivileged host UID, adding defense against container escapes
- `no-new-privileges`: prevents processes from gaining additional privileges via setuid binaries
- `userland-proxy: false`: uses iptables for port forwarding instead of a userland proxy (reduces attack surface)

**Podman-specific:**

Podman runs rootless by default, which provides stronger isolation than Docker's default rootful mode. Ensure rootless mode is used:

```bash
# Verify rootless mode
podman info --format '{{.Host.Security.Rootless}}'
# Should output: true
```

### 7.3 Seccomp Profiles (Future)

LASSO's roadmap includes seccomp profile support. In the interim, apply the Docker default seccomp profile (which blocks ~44 syscalls) or a custom restrictive profile:

```bash
docker run --security-opt seccomp=./lasso-seccomp.json ...
```

A recommended seccomp profile for LASSO sandboxes should block: `mount`, `umount`, `pivot_root`, `sethostname`, `setdomainname`, `reboot`, `kexec_load`, `init_module`, `delete_module`, `iopl`, `ioperm`, `swapon`, `swapoff`, `mknode`, and other dangerous syscalls.

### 7.4 SELinux / AppArmor

If the host runs SELinux or AppArmor, create a custom policy for LASSO containers:

**AppArmor (Ubuntu/Debian):**

```
# /etc/apparmor.d/lasso-sandbox
profile lasso-sandbox flags=(attach_disconnected) {
    # Deny all by default
    deny /** w,

    # Allow read access to container filesystem
    /workspace/** rw,
    /tmp/** rw,

    # Deny network (enforced additionally by iptables)
    deny network,

    # Deny mount operations
    deny mount,
    deny umount,
    deny pivot_root,
}
```

### 7.5 Monitoring and Alerting

Deploy host-level monitoring alongside LASSO's audit logging:

| Monitor | Tool | Alert Condition |
|---|---|---|
| Container escapes | Falco | `syscall.type = execve` from container PID namespace accessing host paths |
| Unexpected network traffic | tcpdump / Suricata | Any traffic from LASSO container interfaces when mode is `none` |
| Resource exhaustion | Prometheus + node_exporter | Host CPU > 90%, memory > 90%, disk > 80% |
| LASSO process health | systemd watchdog | LASSO process exits, dashboard unreachable |
| Audit log gaps | Custom script | No new audit entries for > 5 minutes during active sandbox |
| Configuration drift | AIDE / OSSEC | Changes to LASSO config files, profiles, or key material |

---

## 8. Operational Security Checklist

Use this checklist before promoting a LASSO deployment to production.

### Pre-Deployment

- [ ] Sandbox profile uses `commands.mode = "whitelist"`
- [ ] `allow_shell_operators = false`
- [ ] Network mode is `none` or `restricted` with explicit allowlist
- [ ] Cloud metadata CIDR `169.254.169.254/32` is in `blocked_cidrs`
- [ ] Private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are in `blocked_cidrs`
- [ ] `guardrails.enforce = true`
- [ ] `audit.enabled = true` and `audit.sign_entries = true`
- [ ] `include_command_output = true` and `include_file_diffs = true`
- [ ] Profile is stored in version control with security team approval
- [ ] `config_hash` of approved profile is recorded

### Authentication

- [ ] `LASSO_DASHBOARD_PUBLIC` is NOT set (or not equal to `"1"`)
- [ ] Dashboard token file exists with `0o600` permissions
- [ ] At least one API key is configured in `api_keys.json`
- [ ] API key scopes follow least-privilege principle
- [ ] `LASSO_SECRET_KEY` is set to a strong, stable value
- [ ] Dashboard binds to `127.0.0.1` (or behind a reverse proxy with TLS)

### Key Management

- [ ] Audit signing key stored separately from audit logs (`signing_key_path` configured)
- [ ] Signing key file has `0o600` permissions
- [ ] Key rotation schedule is documented and followed
- [ ] Old keys are archived alongside the logs they signed

### Infrastructure

- [ ] LASSO runs on dedicated infrastructure (not developer workstations)
- [ ] Host OS is patched and automatically updated
- [ ] Docker/Podman runtime is current version
- [ ] Container images are rebuilt regularly with latest base
- [ ] Host disk is encrypted at rest
- [ ] SSH access is key-only

### Monitoring

- [ ] Audit logs forwarded to central aggregation platform
- [ ] Automated daily log verification (`lasso audit verify`)
- [ ] Alerts configured for: blocked commands, guardrail violations, config hash mismatches
- [ ] Host resource monitoring active
- [ ] Incident response runbook exists for sandbox security events

---

## 9. Incident Response Playbook

### Scenario: High Rate of Blocked Commands

**Indicator.** Audit logs show repeated `outcome: "blocked"` events from a single sandbox, especially with varying command names or escalating patterns.

**Interpretation.** The AI agent may be probing the sandbox boundary, attempting to discover allowed commands or bypass the command gate.

**Response:**

1. Stop the sandbox immediately: `lasso stop <sandbox_id>`
2. Export the complete audit log for analysis
3. Verify audit log integrity: `lasso audit verify`
4. Analyze the blocked commands: what was the agent trying to do?
5. If the pattern suggests adversarial behavior, investigate the agent's instruction source (was the CLAUDE.md modified? Was an MCP server compromised?)
6. If the pattern is benign (agent needs a command not in the whitelist), update the profile through the standard change process

### Scenario: Guardrail Violation (Path Escape)

**Indicator.** Audit log contains `type: "violation"`, `rule_id: "no-escape"`.

**Interpretation.** The agent attempted to access a file outside the working directory. This may be prompt injection causing the agent to seek sensitive files.

**Response:**

1. Stop the sandbox
2. Review the violation context: what path was the agent trying to access?
3. Check if the agent's recent commands include any that could have been influenced by prompt injection (look for commands immediately following file reads)
4. Examine the files the agent read before the violation -- do they contain injected instructions?
5. If prompt injection is confirmed, quarantine the affected files and report to the security team

### Scenario: Audit Log Verification Failure

**Indicator.** `lasso audit verify` reports `valid: false` with a `first_break_at` line number.

**Interpretation.** The audit log has been tampered with, corrupted, or the signing key changed mid-session.

**Response:**

1. Treat as a potential security incident until proven otherwise
2. Preserve the log file and signing key as evidence (do not modify)
3. Compare the local log against the central log aggregation copy (if forwarded)
4. If the central copy is intact and the local copy is different, the local host may be compromised
5. If both copies match and show the break, investigate whether a process crash or disk error caused corruption
6. Escalate to incident response if tampering is confirmed

### Scenario: Unauthorized Dashboard or API Access

**Indicator.** Dashboard logs show authentication failures, or API returns 401 errors for previously valid keys.

**Response:**

1. Check if the dashboard token or API keys were rotated (planned change?)
2. If not planned, rotate all credentials immediately
3. Review access logs for the source IP of failed attempts
4. If brute-force is detected, implement IP-based rate limiting at the reverse proxy level
5. Verify `LASSO_DASHBOARD_PUBLIC` is not set

---

## 10. Compliance Mapping Quick Reference

| Control | DORA Article | ISO 27001 Control | LASSO Feature |
|---|---|---|---|
| Access control | Art. 9 | A.9.1, A.9.2 | Command whitelist, API keys, dashboard auth |
| Network segmentation | Art. 9 | A.13.1 | Network modes (none/restricted), iptables rules |
| Cryptographic controls | Art. 9 | A.10.1 | HMAC-SHA256 audit signing, SHA-256 config hashing |
| Event logging | Art. 10 | A.12.4 | JSONL audit trail, lifecycle events, violation logging |
| Tamper detection | Art. 10 | A.12.4.2 | HMAC hash chain, independent verification |
| Backup and recovery | Art. 12 | A.12.3 | Log rotation, profile versioning, state persistence |
| Incident reporting | Art. 17 | A.16.1 | Timestamped audit entries, violation events, log export |
| Third-party risk | Art. 28-30 | A.15.1, A.15.2 | Agent sandboxing, profile presets, multi-agent isolation |
| Change management | Art. 9 | A.12.1.2 | Profile versioning, config_hash, audit of config changes |

See [DORA Compliance Mapping](../compliance/DORA-mapping.md) for the full detailed mapping.
