# LASSO Compliance Documentation

**Last updated:** 2026-03-16

---

## Overview

LASSO provides technical controls that help financial institutions meet regulatory requirements for governing AI coding agents. This directory contains mappings between LASSO's features and specific regulatory frameworks.

LASSO is not a compliance product. It is an infrastructure tool that produces the audit evidence and enforces the policies that compliance programs require. The distinction matters: compliance is an organizational outcome, not a software feature. LASSO provides the technical foundation.

---

## Regulatory Coverage

| Regulation | Jurisdiction | Effective | LASSO Mapping Document |
|---|---|---|---|
| **DORA** (Digital Operational Resilience Act) | EU | January 17, 2025 | [DORA-mapping.md](DORA-mapping.md) |
| **EU AI Act** (high-risk provisions) | EU | August 2, 2026 | [EU-AI-Act-mapping.md](EU-AI-Act-mapping.md) |

These two regulations are the primary drivers for EU financial institutions. They overlap in their requirements for risk management, record-keeping, and third-party governance — and LASSO addresses both from a single set of technical controls.

### Why These Regulations Matter for AI Agents

AI coding agents are ICT systems that execute arbitrary code on financial institution infrastructure. They read files, write code, run commands, and (if permitted) make network requests. Under DORA, they are ICT tools that must be governed. Under the EU AI Act, they participate in the development lifecycle of systems that may be classified as high-risk.

Until recently, this was theoretical. Two vulnerabilities made it concrete:

- **CVE-2025-59536** (Claude Code): Remote code execution via malicious `.mcp.json` configuration files. A compromised MCP server configuration could execute arbitrary commands on developer workstations without the developer's knowledge.
- **CVE-2026-22708** (Cursor): Sandbox bypass via shell builtins, demonstrating that agent-native sandboxing alone is insufficient.

These are not hypothetical risks. They are assigned CVEs with demonstrated exploits.

---

## How LASSO Produces Compliance Evidence

LASSO generates four categories of evidence that map to regulatory requirements.

### 1. Policy Documentation (Profiles)

Every LASSO sandbox runs under a `SandboxProfile` — a TOML configuration file that defines the complete security policy. The profile specifies:

- Which commands the agent can execute (whitelist or blacklist)
- Which argument patterns are blocked
- What network access is permitted
- Which filesystem paths are visible, read-only, or writable
- What resource limits apply (memory, CPU, PIDs, disk)
- Which guardrail rules are enforced
- How audit logging is configured

To export the active profile for compliance documentation:

```bash
# Profiles are stored as TOML files in .lasso/profiles/
cat .lasso/profiles/strict.toml
```

Each profile includes a deterministic `config_hash` (SHA-256) that uniquely identifies the configuration. This hash is logged in the audit trail when a sandbox starts, creating a verifiable chain from policy to execution.

### 2. Audit Trails (Automatic Logging)

LASSO's `AuditLogger` records every action an AI agent takes inside a sandbox. Logs are written as JSONL (one JSON object per line) with optional HMAC-SHA256 signatures.

**What is recorded:**

- Every command execution (command, arguments, exit code, duration)
- Every blocked command (with the specific reason for blocking)
- Sandbox lifecycle events (start, stop, configuration)
- Guardrail violations (path escape attempts, exfiltration attempts)
- File access events
- Network connection attempts

**Where logs are stored:**

```
./audit/
  sandbox_a1b2c3_20260316T140000Z.jsonl
  sandbox_d4e5f6_20260316T153000Z.jsonl
  .audit_key                              # HMAC signing key (protect this)
```

Each sandbox session produces a separate, timestamped log file.

### 3. Integrity Verification (Tamper Evidence)

When `audit.sign_entries = true` (the default for the `strict` profile), LASSO creates a cryptographic hash chain across all audit entries:

1. Each entry is serialized as compact JSON (sorted keys, no whitespace)
2. Signed as `HMAC-SHA256(key, previous_chain_hash + ":" + json_payload)`
3. The signature becomes the chain input for the next entry

To verify the integrity of an audit log:

```bash
lasso audit verify ./audit/sandbox_a1b2c3_20260316T140000Z.jsonl
```

The verification replays the entire chain and reports:

```
Verification result:
  Total entries: 1,247
  Verified: 1,247
  Chain integrity: VALID
  First break: None
```

If any entry has been modified, deleted, reordered, or inserted, the verification will report the exact line number where the chain breaks.

**Regulatory relevance:**
- DORA Art. 10 (detection): tamper-evident logs detect post-hoc manipulation
- DORA Art. 17 (incident reporting): verified logs provide trustworthy evidence
- EU AI Act Art. 12 (record-keeping): automatic, integrity-protected logging

### 4. Policy Enforcement Records (Blocked Actions)

Every time LASSO blocks an action, it records a detailed entry explaining what was attempted and why it was blocked. This creates a record of the security controls actively preventing unauthorized behavior.

Example blocked action log entry:

```json
{
    "event_id": "b3c4d5e6f7a89012",
    "ts": "2026-03-16T14:25:33.123456+00:00",
    "sandbox_id": "f8a2c1b3e4d5",
    "type": "command",
    "actor": "agent",
    "action": "curl https://external-server.com/upload",
    "outcome": "blocked",
    "detail": {
        "reason": "Command 'curl' is not in the whitelist."
    },
    "sig": "..."
}
```

---

## Example: Generating a DORA Audit Report

The following procedure produces evidence suitable for a DORA compliance audit of AI agent usage.

### Step 1: Collect Active Profiles

```bash
# List all profiles in use
ls .lasso/profiles/

# Export the strict profile
cat .lasso/profiles/strict.toml > evidence/profiles/strict.toml

# Record the config hash
python3 -c "
from lasso.config.profile import load_profile
p = load_profile('.lasso/profiles/strict.toml')
print(f'Config hash: {p.config_hash()}')
print(f'Profile version: {p.profile_version}')
"
```

### Step 2: Verify Audit Log Integrity

```bash
# Verify all audit logs for the reporting period
for log in ./audit/*.jsonl; do
    echo "--- Verifying: $log ---"
    lasso audit verify "$log"
done
```

### Step 3: Extract Policy Violations

```bash
# View all blocked commands and violations
lasso audit view ./audit/sandbox_*.jsonl --type violation
lasso audit view ./audit/sandbox_*.jsonl --type command | grep '"outcome":"blocked"'
```

### Step 4: Generate Summary Statistics

```python
from lasso.core.audit_verify import read_audit_entries

entries = read_audit_entries("./audit/sandbox_a1b2c3_20260316T140000Z.jsonl")

total_commands = sum(1 for e in entries if e["type"] == "command")
blocked = sum(1 for e in entries if e.get("outcome") == "blocked")
violations = sum(1 for e in entries if e["type"] == "violation")

print(f"Total commands executed: {total_commands}")
print(f"Commands blocked: {blocked}")
print(f"Guardrail violations: {violations}")
```

### Step 5: Assemble Evidence Package

The evidence package for a DORA audit should include:

| Artifact | DORA Article | Purpose |
|---|---|---|
| Active sandbox profiles (TOML) | Art. 5-6 | Documents the ICT risk management policy |
| Config hash records | Art. 9 | Proves the correct policy was in effect |
| Audit log files (JSONL) | Art. 10, 17 | Complete action history with timestamps |
| Verification results | Art. 10 | Proves logs have not been tampered with |
| Violation summaries | Art. 9, 17 | Documents policy enforcement and incidents |
| Profile version history | Art. 12 | Documents policy changes over time |

---

## Protecting Audit Evidence

The signing key (`.audit_key`) is critical to the integrity of the audit trail. Protect it:

1. **Restrict file permissions.** LASSO sets the key file to `0600` (owner read/write only) on creation.
2. **Back up the key separately.** If the key is lost, existing logs cannot be verified (though they remain readable).
3. **Do not store the key in the same directory as the logs** in production. Use `audit.signing_key_path` to specify a separate, access-controlled location.
4. **Rotate the key periodically.** Each sandbox session can use a different key by configuring `signing_key_path`.

```toml
[audit]
sign_entries = true
signing_key_path = "/secure/keys/lasso-audit.key"
```

---

## Disclaimer

LASSO provides technical controls and audit evidence that support regulatory compliance. It does not guarantee compliance with any regulation. Compliance is an organizational responsibility that requires policies, procedures, training, and technical controls working together.

This documentation describes LASSO's current capabilities. It is not legal advice. Organizations should work with legal counsel and compliance professionals to determine how LASSO fits within their specific compliance programs.

The regulatory landscape for AI governance is evolving. DORA implementing technical standards (ITS/RTS) and EU AI Act harmonized standards are still being finalized. This documentation will be updated as regulatory guidance is published.
