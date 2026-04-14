# LASSO — DORA Compliance Mapping

**Document version:** 1.0
**Last updated:** 2026-03-16
**Applicable regulation:** Regulation (EU) 2022/2554 — Digital Operational Resilience Act
**DORA effective date:** January 17, 2025
**Applicable to:** Financial entities and their ICT third-party service providers operating in the EU

---

## Purpose

This document maps LASSO's technical controls to the requirements of the Digital Operational Resilience Act (DORA). It is intended for compliance officers, security architects, and auditors evaluating how LASSO contributes to an organization's DORA compliance posture.

DORA does not specifically mention "AI agents," but its ICT risk management, incident reporting, and third-party oversight requirements clearly encompass AI coding agents used in software development. AI agents are ICT systems that execute code, access files, and make network requests — all activities that DORA requires financial entities to govern.

---

## Mapping Summary

| DORA Article | Requirement | LASSO Feature | Compliance Status |
|---|---|---|---|
| Art. 5-6 | ICT risk management framework | Command whitelisting, network isolation, profiles | Supported |
| Art. 9 | Protection and prevention | Container isolation, command gate, blocked arguments | Supported |
| Art. 10 | Detection | Audit logging, violation detection, guardrail engine | Supported |
| Art. 11 | Response and recovery | Sandbox stop/cleanup, state persistence, registry | Supported |
| Art. 12 | Backup policies | Audit log export, profile versioning, config hashing | Supported |
| Art. 15 | Further harmonisation of ICT risk management tools | Guardrails, network policy, resource limits | Supported |
| Art. 17 | ICT-related incident reporting | Tamper-evident audit trail with timestamps | Supported |
| Art. 28-30 | Third-party ICT risk management | Agent sandboxing, policy presets, multi-agent support | Supported |

---

## Detailed Mapping

### Article 5-6: ICT Risk Management Framework

**Requirement:** Financial entities shall have in place an internal governance and control framework that ensures an effective and prudent management of all ICT risks, including identification, protection, detection, response, and recovery.

**How LASSO satisfies this:**

LASSO provides a policy-as-code framework for managing ICT risks introduced by AI coding agents. Each sandbox is governed by a `SandboxProfile` — a versioned, deterministic configuration that defines exactly what an agent is permitted to do.

**Command policy enforcement.** Every command an AI agent attempts to execute passes through the `CommandGate` before reaching the container. The gate operates in two modes:

- **Whitelist mode** (`commands.mode = "whitelist"`): only explicitly listed commands are permitted. The `strict` profile, for example, restricts agents to `python3`, `pip`, `Rscript`, `ls`, `cat`, `grep`, and a small set of file utilities. Everything else is blocked.
- **Blacklist mode** (`commands.mode = "blacklist"`): all commands are permitted except those explicitly blocked. This mode is available but not recommended for regulated environments.

```toml
# Example: strict profile command policy
[commands]
mode = "whitelist"
whitelist = [
    "python3", "python", "pip", "pip3",
    "Rscript", "R", "jupyter", "jupyter-lab",
    "ls", "cat", "head", "tail", "grep", "find", "wc",
    "sort", "uniq", "diff", "mkdir", "cp", "mv", "touch",
]
allow_shell_operators = false
max_execution_seconds = 600
```

**Network isolation.** The `NetworkConfig` defines three modes: `none` (no network access), `restricted` (explicit domain allowlisting), and `full` (unrestricted). For banking use cases, `none` is the default — the agent cannot make any network requests.

```toml
# Example: complete network isolation for banking
[network]
mode = "none"
```

**Profile versioning.** Each profile carries a `profile_version` counter and a deterministic `config_hash()` (SHA-256 of the configuration, excluding timestamps). This allows auditors to verify that the policy in effect at a given time matches the approved policy.

---

### Article 9: Protection and Prevention

**Requirement:** Financial entities shall use and maintain updated ICT systems, protocols, and tools that are appropriate to the scale and complexity of their operations and that implement adequate measures to protect ICT assets.

**How LASSO satisfies this:**

LASSO implements defense-in-depth with multiple independent protection layers.

**Layer 1: Command gate.** Before a command reaches the container, the `CommandGate` validates it against:

- Whitelist/blacklist policy
- Blocked argument patterns (e.g., `git push` is blocked even though `git` is whitelisted)
- Dangerous argument detection (hardcoded rules for commands like `find -exec`, `tar --to-command`, `curl -o` that can be used for sandbox escape)
- Shell operator restrictions (pipes, redirects, subshells blocked by default)
- Path traversal detection (including URL-encoded traversal like `%2e%2e%2f` and double-encoding)
- Null byte stripping and control character rejection
- Symlink resolution to prevent path escape via symbolic links

```toml
# Example: blocking dangerous argument patterns
[commands.blocked_args]
pip = ["install --user", "install -e"]
git = ["push", "remote add"]
```

**Layer 2: Container isolation.** Each sandbox runs inside a Docker or Podman container with:

- Filesystem isolation: only the configured `working_dir` is mounted read-write
- Read-only system paths: `/usr`, `/lib`, `/bin`, `/sbin` are mounted read-only
- Hidden paths: sensitive files like `/etc/shadow`, `/etc/ssh`, `/etc/ssl/private` are not visible inside the container
- Resource limits via cgroups v2: memory cap (`max_memory_mb`), CPU throttle (`max_cpu_percent`), PID limit (`max_pids`), file size limit (`max_file_size_mb`)
- Custom images per profile: only the tools specified in the whitelist are installed in the container image

**Layer 3: Network rules.** When network access is restricted, LASSO generates and applies iptables rules inside the container's network namespace. In `restricted` mode:

- Default policy is DROP for both INPUT and OUTPUT
- Only explicitly allowed domains (resolved to IPs) on allowed ports are permitted
- Cloud metadata endpoints (169.254.169.254) and private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are blocked by default
- DNS is restricted to configured servers

**Layer 4: Guardrail engine.** The `GuardrailEngine` enforces behavioral rules on agent actions:

- `no-escape` (critical): blocks access to paths outside the working directory
- `no-exfiltration` (critical): detects suspiciously large data payloads being sent to external hosts
- `log-modifications` (error): ensures all file modifications are captured in the audit trail

---

### Article 10: Detection

**Requirement:** Financial entities shall have in place mechanisms to promptly detect anomalous activities, including ICT network performance issues and ICT-related incidents.

**How LASSO satisfies this:**

**Audit logging.** Every action inside a LASSO sandbox is recorded in a structured JSONL audit log. Events include:

| Event Type | What Is Logged | Example |
|---|---|---|
| `command` | Every command execution (allowed or blocked) | `python3 analysis.py` executed, exit code 0 |
| `command` (blocked) | Every blocked command with reason | `curl http://evil.com` blocked: not in whitelist |
| `lifecycle` | Sandbox start, stop, configuration changes | Sandbox started with profile hash `a3f2b1...` |
| `violation` | Guardrail violations | Path escape attempt to `/etc/passwd` |
| `file` | File access operations | Write to `./output/results.csv` |
| `network` | Network connection attempts | Connection to `pypi.org:443` |

**Tamper detection.** When `audit.sign_entries = true` (the default for banking profiles), each log entry is HMAC-SHA256 signed with a hash chain:

1. The chain starts with a seed value (`"0" * 64`).
2. Each entry is signed as `HMAC(key, f"{previous_chain_hash}:{json_payload}")`.
3. The signature of entry N becomes the chain input for entry N+1.

This means that if any entry is modified, deleted, or reordered, the chain breaks and `lasso audit verify` will detect it.

```bash
# Verify the integrity of an audit trail
lasso audit verify ./audit/log.jsonl

# Output:
# Verification result:
#   Total entries: 1,247
#   Verified: 1,247
#   Chain integrity: VALID
```

**Violation detection.** Blocked commands and guardrail violations are logged with the event type `violation` or outcome `blocked`, along with the reason for blocking. These entries can be filtered and forwarded to a SIEM for alerting.

---

### Article 11: Response and Recovery

**Requirement:** Financial entities shall put in place a comprehensive ICT business continuity policy, including response and recovery plans.

**How LASSO satisfies this:**

**Controlled shutdown.** The `Sandbox.stop()` method performs a clean shutdown sequence:

1. Logs the stop event to the audit trail (including total execution count and blocked count)
2. Stops the container via the backend
3. Removes the container
4. Updates state to `STOPPED`

**State persistence.** The `SandboxRegistry` persists sandbox metadata to disk via the `StateStore`. If LASSO crashes, the `reconcile()` method on restart checks which containers from previous runs still exist and updates state accordingly. Each sandbox is classified as `alive`, `stopped`, or `gone`.

**Lifecycle tracking.** Every state transition is logged to the audit trail:

```json
{"type": "lifecycle", "action": "start", "detail": {"profile": "strict", "config_hash": "a3f2b1c8...", "backend": "DockerBackend"}}
{"type": "lifecycle", "action": "running"}
{"type": "lifecycle", "action": "stopped", "detail": {"prev_state": "running", "total_execs": 347, "total_blocked": 12}}
```

**Context manager support.** Sandboxes support Python's `with` statement, ensuring cleanup runs even if an exception occurs:

```python
with Sandbox(profile, backend=docker) as sb:
    result = sb.exec("python3 analysis.py")
# Container is stopped and removed automatically
```

---

### Article 12: Backup Policies

**Requirement:** Financial entities shall have in place policies and procedures for backup, restoration, and recovery that ensure data can be recovered and systems can be restarted.

**How LASSO satisfies this:**

**Audit log preservation.** Audit logs are written as append-only JSONL files. Each sandbox session produces a separate log file named `{sandbox_id}_{timestamp}.jsonl`, ensuring logs are preserved across sessions. Configuration options:

```toml
[audit]
enabled = true
log_dir = "./audit"
log_format = "jsonl"
sign_entries = true
max_log_size_mb = 100
rotation_count = 10
```

**Profile versioning.** Sandbox profiles are stored as TOML files with version tracking:

- `version`: schema version for forward/backward compatibility
- `profile_version`: auto-incrementing counter for change tracking
- `config_hash()`: deterministic SHA-256 hash for integrity verification

**Configuration integrity.** The `config_hash()` method produces a deterministic SHA-256 hash of the profile configuration (excluding timestamps). This hash is logged in the audit trail at sandbox startup, creating a verifiable link between the policy in effect and the audit evidence.

---

### Article 15: Further Harmonisation of ICT Risk Management Tools

**Requirement:** ESAs shall develop regulatory technical standards specifying common ICT risk management tools, methods, processes, and policies.

**How LASSO satisfies this:**

LASSO's configurable policy model aligns with the principle of standardized, reproducible ICT risk management:

**Guardrail rules.** Each guardrail rule has a structured definition:

```toml
[[guardrails.rules]]
id = "no-escape"
description = "Agent must not attempt to access paths outside working_dir."
severity = "critical"
enabled = true

[[guardrails.rules]]
id = "no-exfiltration"
description = "Agent must not transmit file contents to external hosts."
severity = "critical"
enabled = true
```

**Resource limits.** Resource constraints are enforced via cgroups v2 inside containers:

| Config Option | Default (strict) | Purpose |
|---|---|---|
| `resources.max_memory_mb` | 8192 | Prevents memory exhaustion |
| `resources.max_cpu_percent` | 50 | Prevents CPU starvation of host |
| `resources.max_pids` | 150 | Prevents fork bombs |
| `resources.max_open_files` | 1024 | Prevents file descriptor exhaustion |
| `resources.max_file_size_mb` | 100 | Prevents disk filling attacks |

**Network policy.** The `NetworkPolicy` class generates iptables rules from declarative configuration. In `restricted` mode, the default deny policy with explicit allowlisting follows the principle of least privilege.

---

### Article 17: ICT-Related Incident Reporting

**Requirement:** Financial entities shall report major ICT-related incidents to competent authorities. Reports must include the nature of the incident, its impact, and the measures taken.

**How LASSO satisfies this:**

LASSO's audit trail provides the raw evidence needed for incident reporting.

**Complete action history.** Every command execution, blocked attempt, and guardrail violation is timestamped in UTC with:

- `event_id`: unique identifier for each event
- `ts`: ISO 8601 timestamp in UTC
- `sandbox_id`: which sandbox the event occurred in
- `type`: event category (command, lifecycle, violation, file, network)
- `actor`: who or what initiated the action (agent, system)
- `action`: what was attempted
- `outcome`: result (success, error, blocked)
- `detail`: additional context (duration, exit code, block reason)
- `sig`: HMAC-SHA256 signature (when signing is enabled)

**Incident reconstruction.** To reconstruct what an agent did during a specific time window:

```bash
# View all events from a sandbox session
lasso audit view ./audit/sandbox_a1b2c3_20260316T140000Z.jsonl

# Filter to violations only
lasso audit view ./audit/log.jsonl --type violation

# Verify log integrity before submitting as evidence
lasso audit verify ./audit/log.jsonl
```

**Evidence chain.** The HMAC hash chain provides cryptographic proof that the audit log has not been tampered with after the fact. An auditor can independently verify the chain using the `verify_audit_log()` function with access to the signing key.

---

### Articles 28-30: Third-Party ICT Risk Management

**Requirement:** Financial entities shall manage ICT third-party risk as an integral component of ICT risk. This includes assessing risks from ICT third-party service providers, including sub-outsourcing chains.

**How LASSO satisfies this:**

AI coding agents (Claude Code, OpenCode) are third-party ICT tools that execute arbitrary code on financial institution infrastructure. DORA requires governance of these tools.

**Agent sandboxing.** LASSO wraps third-party AI agents in sandboxes with enforced policies. The agent operates inside the sandbox; LASSO controls what the agent can do from outside the sandbox.

**Multi-agent support.** LASSO supports multiple agent providers through a pluggable architecture:

- **Claude Code**: CLAUDE.md guardrails injected automatically, sandbox wraps all tool execution
- **OpenCode**: plugin-based integration via `opencode-lasso-plugin.js`, `opencode.json` configuration
- **Extensible**: `AgentProvider` abstract base class for adding new agent types

**Policy presets for financial services.** The built-in `strict` profile provides a compliance-ready configuration:

- Whitelist-only commands (no shell operators)
- Zero network access
- Full audit trail with HMAC signing
- Command output logging for forensic analysis
- Hidden sensitive paths (`/etc/ssh`, `/etc/ssl/private`)
- Guardrail enforcement enabled

**Real-world threat context.** The need for third-party agent governance is demonstrated by:

- **CVE-2025-59536**: Claude Code remote code execution via malicious `.mcp.json` configuration files. A compromised MCP server configuration could execute arbitrary commands on developer workstations. LASSO's command gate blocks unapproved commands regardless of how they are triggered.
- **CVE-2026-22708**: Cursor sandbox bypass via shell builtins. Demonstrates that agent-native sandboxing is insufficient without external enforcement. LASSO's container-level isolation is independent of the agent's own security model.

---

## Generating DORA Evidence from LASSO

To produce compliance evidence for a DORA audit:

1. **Policy documentation**: Export the active sandbox profile as TOML. The `config_hash()` provides a fingerprint for the approved policy.

2. **Audit trail**: Collect the JSONL audit logs for the relevant time period. Verify integrity with `lasso audit verify`.

3. **Incident report**: Filter audit logs for `type: violation` and `outcome: blocked` entries. Each entry includes the timestamp, what was attempted, and why it was blocked.

4. **Configuration integrity**: Compare the `config_hash` logged at sandbox startup against the approved profile hash to verify that the correct policy was in effect.

5. **Third-party agent inventory**: Use the `agent` field in audit events to identify which AI agents were active and what actions they performed.

---

## Limitations

LASSO assists with DORA compliance but does not guarantee it. Specifically:

- LASSO governs AI agent behavior within its sandboxes. It does not govern agent behavior outside of LASSO (e.g., agents running on developer laptops without LASSO).
- DORA requires an organization-wide ICT risk management framework. LASSO is one control within that framework, not a substitute for it.
- LASSO does not currently provide automated DORA reporting templates. Audit logs must be manually correlated with DORA reporting requirements.
- Network policy enforcement depends on iptables availability inside the container. Minimal container images may lack iptables.
- The audit signing key must be protected separately. If the signing key is compromised, an attacker could forge audit entries.
