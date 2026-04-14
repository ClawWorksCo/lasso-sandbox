# LASSO — EU AI Act Compliance Mapping

**Document version:** 1.0
**Last updated:** 2026-03-16
**Applicable regulation:** Regulation (EU) 2024/1689 — Artificial Intelligence Act
**High-risk provisions effective:** August 2, 2026
**Maximum penalties:** EUR 35M or 7% of global annual turnover (whichever is higher)

---

## Purpose

This document maps LASSO's technical controls to the requirements of the EU Artificial Intelligence Act, with a focus on the high-risk system provisions that apply to financial services. It is intended for compliance officers, legal teams, and technology leaders at EU financial institutions preparing for the August 2, 2026 high-risk deadline.

---

## Applicability to Financial Services

The EU AI Act classifies certain AI systems used in financial services as **high-risk** (Annex III, paragraph 5). These include AI systems used for:

- Creditworthiness assessment and credit scoring
- Risk assessment and pricing in life and health insurance
- Customer-facing financial decisions

AI coding agents (Claude Code, OpenCode) used to develop, test, or analyze financial models and data fall under organizational governance requirements even when the agent itself is not the high-risk system. The rationale: an AI agent that writes or modifies code for a credit scoring model is part of the development lifecycle of a high-risk system and must be governed accordingly.

---

## Mapping Summary

| AI Act Article | Requirement | LASSO Feature | Compliance Status |
|---|---|---|---|
| Art. 9 | Risk management system | Profile-based risk policies, defense-in-depth layers | Supported |
| Art. 10 | Data and data governance | Filesystem isolation, hidden paths, read-only mounts | Supported |
| Art. 11 | Technical documentation | Profile TOML export, config hashing, audit trails | Supported |
| Art. 12 | Record-keeping | HMAC-signed, hash-chained JSONL audit logs | Supported |
| Art. 13 | Transparency | Policy explanation, audit viewer, dashboard | Supported |
| Art. 14 | Human oversight | Command gating, approval workflows, sandbox REPL | Supported |
| Art. 15 | Accuracy, robustness, cybersecurity | Container isolation, seccomp, resource limits | Supported |

---

## Detailed Mapping

### Article 9: Risk Management System

**Requirement:** Providers of high-risk AI systems shall establish, implement, document, and maintain a risk management system. This system shall be a continuous iterative process planned and run throughout the entire lifecycle of the high-risk AI system.

**How LASSO contributes:**

LASSO implements risk management for AI agent execution through a layered policy model. Each sandbox profile represents a documented, versioned risk policy.

**Profile-based risk tiers.** LASSO ships with three built-in profiles that represent increasing levels of trust:

| Profile | Risk Level | Network | Commands | Audit | Use Case |
|---|---|---|---|---|---|
| `standard` | Moderate | Restricted (package registries only) | 30+ dev tools, shell operators allowed | Standard | General software development |
| `strict` | Regulated | None | Data tools only (Python, R, Jupyter) | Full (signed, with output logging) | Banking risk model development |
| `offline` | Restricted | None | Standard dev tools, no network | Standard | Air-gapped environments |

**Configurable risk controls.** Organizations can create custom profiles that match their risk appetite:

```toml
[commands]
mode = "whitelist"
whitelist = ["python3", "pip", "ls", "cat", "grep"]  # Only these commands
allow_shell_operators = false                          # No pipes or redirects
max_execution_seconds = 600                            # 10-minute timeout

[network]
mode = "none"  # Complete network isolation

[guardrails]
enforce = true  # Violations block execution, not just log
```

**Defense-in-depth.** LASSO does not rely on any single control. Four independent layers operate simultaneously:

1. **Command gate** — validates every command before it reaches the container
2. **Container isolation** — Docker/Podman process and filesystem isolation
3. **Network rules** — iptables enforcement inside the container namespace
4. **Audit logging** — tamper-evident record of all activity

If any single layer fails, the remaining layers continue to provide protection.

---

### Article 10: Data and Data Governance

**Requirement:** High-risk AI systems which make use of techniques involving the training of AI models with data shall be developed on the basis of training, validation, and testing data sets that meet quality criteria. Data governance and management practices shall address data collection, relevant data preparation, labelling, and cleaning.

**How LASSO contributes:**

While LASSO does not manage training data directly, it governs how AI agents access and manipulate data within sandboxed environments.

**Filesystem isolation.** Each sandbox has a defined filesystem boundary:

```toml
[filesystem]
working_dir = "/workspace/risk-models"
read_only_paths = ["/usr", "/lib", "/lib64", "/bin", "/sbin"]
hidden_paths = ["/etc/shadow", "/etc/gshadow", "/root", "/etc/ssh", "/etc/ssl/private"]
max_disk_mb = 20480
```

- **`working_dir`**: the only directory where the agent has read-write access
- **`read_only_paths`**: system directories mounted read-only (agent cannot modify system binaries)
- **`hidden_paths`**: sensitive files that do not exist from the agent's perspective (credentials, SSH keys, TLS private keys)

**Data boundary enforcement.** The `no-escape` guardrail rule prevents agents from accessing files outside the designated working directory. Path traversal attempts (including URL-encoded variants like `%2e%2e%2f`) are detected and blocked by the command gate.

**No data exfiltration.** When network mode is `none`, the agent cannot transmit data to any external endpoint. The `no-exfiltration` guardrail provides an additional software-level check for large data payloads.

---

### Article 11: Technical Documentation

**Requirement:** The technical documentation of a high-risk AI system shall be drawn up before that system is placed on the market or put into service. It shall contain, at a minimum, a general description of the system, detailed information about the elements of the system and the process for its development, and information about the monitoring, functioning, and control of the system.

**How LASSO contributes:**

**Profile-as-documentation.** Each LASSO sandbox profile is a TOML document that fully describes the security and operational parameters of the agent's execution environment. The profile serves as technical documentation of the controls in effect.

**Configuration hashing.** The `config_hash()` method produces a deterministic SHA-256 hash of the profile (excluding timestamps). This hash is logged in the audit trail at sandbox startup, creating a verifiable link between the technical documentation (profile) and the operational evidence (audit log).

**Policy explanation.** Both the `CommandGate` and `NetworkPolicy` classes expose `explain_policy()` methods that produce human-readable summaries of the active policy:

```python
gate.explain_policy()
# {
#     "mode": "whitelist",
#     "allowed_commands": ["cat", "grep", "ls", "python3", ...],
#     "blocked_args": {"git": ["push", "remote add"], "pip": ["install --user"]},
#     "shell_operators": false,
#     "max_seconds": 600
# }
```

---

### Article 12: Record-Keeping

**Requirement:** High-risk AI systems shall technically allow for the automatic recording of events (logs) over the lifetime of the system. The logging capabilities shall ensure a level of traceability of the AI system's functioning throughout its lifecycle that is appropriate to the intended purpose of the system.

**How LASSO satisfies this:**

This is LASSO's strongest compliance alignment. The `AuditLogger` provides automatic, tamper-evident recording of every action an AI agent takes.

**What is logged:**

| Event Type | Fields Recorded | Purpose |
|---|---|---|
| `command` | command, args, exit code, duration, stdout/stderr (optional) | Track every command execution |
| `command` (blocked) | command, block reason | Track policy enforcement |
| `lifecycle` | action (start/stop/error), profile hash, backend type | Track sandbox state changes |
| `violation` | rule ID, description, severity | Track guardrail enforcement |
| `file` | path, operation (read/write/delete) | Track file system access |
| `network` | host, port, outcome | Track network requests |

**Log entry structure:**

```json
{
    "event_id": "a1b2c3d4e5f67890",
    "ts": "2026-03-16T14:23:01.456789+00:00",
    "sandbox_id": "f8a2c1b3e4d5",
    "type": "command",
    "actor": "agent",
    "action": "python3",
    "target": "risk_model.py --scenario stress_test",
    "outcome": "success",
    "detail": {
        "duration_ms": 4523,
        "exit_code": 0,
        "stdout_head": "Model run complete. VaR(95%): 12.3M EUR\n",
        "stderr_head": ""
    },
    "sig": "e8b4f2a1c3d567890abcdef1234567890abcdef1234567890abcdef12345678"
}
```

**Tamper evidence.** The HMAC-SHA256 hash chain ensures that:

- Modifying any entry breaks the chain from that point forward
- Deleting an entry breaks the chain
- Reordering entries breaks the chain
- Inserting a forged entry breaks the chain

**Independent verification.** The `verify_audit_log()` function replays the entire hash chain and reports:

- Total number of entries
- Number of successfully verified entries
- Line number of the first chain break (if any)
- Specific error messages for each invalid entry

```bash
lasso audit verify ./audit/sandbox_f8a2c1b3e4d5_20260316T140000Z.jsonl
```

**Log retention.** Configurable via `audit.max_log_size_mb` (default: 100 MB) and `audit.rotation_count` (default: 10 rotations). Each sandbox session produces a separate, timestamped log file for clean archival.

---

### Article 13: Transparency

**Requirement:** High-risk AI systems shall be designed and developed in such a way as to ensure that their operation is sufficiently transparent to enable deployers to interpret the system's output and use it appropriately.

**How LASSO contributes:**

**Policy transparency.** Agents operating inside a LASSO sandbox can inspect the active policy. The `explain_policy()` methods on `CommandGate` and `NetworkPolicy` produce structured summaries of what is allowed and what is blocked.

**Clear block messages.** When a command is blocked, the agent receives a specific, actionable error message:

```
BLOCKED: Command 'curl' is not in the whitelist.
BLOCKED: Blocked argument pattern for 'pip': 'install --user'
BLOCKED: Shell operators (pipes, redirects, subshells) are not allowed.
BLOCKED: Path traversal detected in argument: '../../etc/passwd'
BLOCKED: Dangerous argument '-exec' detected for command 'find'.
```

**Audit viewer.** The `lasso audit view` command and the web dashboard provide human-readable views of the audit trail, allowing operators to inspect what an agent did and why certain actions were blocked.

**Guardrail injection.** The `GuardrailEngine.inject_guardrail_instructions()` method appends the active guardrail rules to the agent's instruction file (e.g., CLAUDE.md), making the constraints visible to the agent itself.

---

### Article 14: Human Oversight

**Requirement:** High-risk AI systems shall be designed and developed in such a way as to be effectively overseen by natural persons during the period in which they are used. Human oversight shall aim to prevent or minimize the risks to health, safety, or fundamental rights that may emerge.

**How LASSO contributes:**

**Command gating as human oversight proxy.** The command gate acts as a pre-approved policy set by human administrators. Rather than requiring a human to approve every action (which is impractical for AI coding agents executing hundreds of commands per session), the gate enforces a policy that a human defined in advance.

**Interactive shell mode.** The `lasso shell` command provides a supervised execution mode where a human operator can observe and control agent execution in real time:

```bash
lasso shell --agent claude-code --dir /workspace/risk-models
```

**Sandbox lifecycle control.** Human operators can start, pause, stop, and remove sandboxes at any time via the CLI or dashboard. The `SandboxRegistry` provides `stop()` and `stop_all()` methods for immediate intervention.

**Post-hoc review.** The audit trail enables human reviewers to examine everything an agent did after the fact. The tamper-evident log ensures the review is based on an accurate record.

---

### Article 15: Accuracy, Robustness, and Cybersecurity

**Requirement:** High-risk AI systems shall be designed and developed in such a way that they achieve an appropriate level of accuracy, robustness, and cybersecurity, and that they perform consistently in those respects throughout their lifecycle.

**How LASSO contributes:**

**Container isolation.** Each sandbox runs in a dedicated Docker or Podman container with:

- Process isolation (separate PID namespace)
- Filesystem isolation (bind mounts with explicit permissions)
- User isolation (non-root execution inside the container)
- Custom images with only whitelisted tools installed

**Resource limits.** Cgroups v2 enforcement prevents resource exhaustion:

```toml
[resources]
max_memory_mb = 8192     # Prevent memory exhaustion
max_cpu_percent = 50     # Prevent CPU starvation
max_pids = 150           # Prevent fork bombs
max_open_files = 1024    # Prevent file descriptor exhaustion
max_file_size_mb = 100   # Prevent disk filling
```

**Security hardening.** The command gate includes hardened input validation:

- Null byte stripping on all input
- Control character rejection (newlines, carriage returns, escape sequences)
- URL-encoded path traversal detection (single and double encoding)
- Symlink resolution before path validation
- Dangerous argument patterns blocked for 25+ common commands

**Network security.** Default configuration blocks access to:

- Cloud metadata endpoints (169.254.169.254/32) — prevents SSRF against cloud infrastructure
- Private network ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) — prevents lateral movement
- All network access (when mode is `none`)

---

## Compliance Timeline

| Date | Milestone | LASSO Relevance |
|---|---|---|
| August 1, 2024 | AI Act enters into force | Planning phase |
| February 2, 2025 | Prohibited practices apply | LASSO does not facilitate prohibited practices |
| August 2, 2025 | Governance and general-purpose AI rules apply | Profile-based governance framework |
| **August 2, 2026** | **High-risk system requirements apply** | **Full mapping documented here** |
| August 2, 2027 | Certain high-risk systems in Annex I | Continued compliance support |

---

## Generating EU AI Act Evidence from LASSO

For organizations preparing for the August 2, 2026 deadline:

1. **Document your risk policy.** Export the active LASSO profile(s) as TOML files. These serve as technical documentation of the controls applied to AI agent execution (Article 11).

2. **Enable full audit logging.** Set `audit.sign_entries = true` and `audit.include_command_output = true` for all sandboxes involved in high-risk system development. This satisfies the automatic logging requirement (Article 12).

3. **Preserve audit logs.** Archive audit log files with their corresponding signing keys. Verify chain integrity before archival with `lasso audit verify`.

4. **Document the human oversight process.** Record who approved the sandbox profile, when, and what review process was followed (Article 14). LASSO profiles include `created_at` and `updated_at` timestamps, and `config_hash()` for integrity verification.

5. **Maintain a third-party agent inventory.** Document which AI agents are in use, which LASSO profiles govern them, and what risk assessment was performed for each.

---

## Limitations

LASSO assists with EU AI Act compliance but does not guarantee it. Specifically:

- The EU AI Act applies to AI systems, not just their execution environments. LASSO governs how agents execute code, not the AI models themselves.
- Article 10 (data governance) requirements for training data are outside LASSO's scope. LASSO governs data access, not data quality or provenance.
- Article 13 (transparency) requirements for AI system outputs are outside LASSO's scope. LASSO provides transparency about agent actions, not about AI model decision-making.
- Compliance requires organizational measures (policies, procedures, training) beyond technical controls. LASSO is one component of a compliance program.
- The EU AI Act implementing regulations and harmonized standards are still being finalized. This mapping may need to be updated as guidance is published.
