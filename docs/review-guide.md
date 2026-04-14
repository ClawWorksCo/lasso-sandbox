# How to Review LASSO

A guided reading order for first-time reviewers evaluating LASSO's security claims.
Total code surface: ~3,500 lines of Python across the security-critical modules listed below.

---

## Reading Order

### 1. Command Gate (primary security boundary)

**File:** `lasso/core/commands.py`

This is the single chokepoint every agent command passes through. Start here.

Key things to verify:
- `CommandGate.check()` is the sole entry point for command validation
- Null bytes are stripped before any parsing (`_strip_null_bytes`)
- Control characters (newlines, carriage returns, escape sequences) are rejected
- URL-encoded path traversal is detected pre- and post-decode (double-encoding covered)
- Unicode dot-like characters (fullwidth periods, dot leaders) are caught in path arguments
- Symlinks are resolved via `os.path.realpath` before traversal checks
- `DANGEROUS_ARGS` dict blocks inherently dangerous commands (database clients, debuggers) and dangerous argument patterns (find -exec, sed -e, tar --to-command)
- Shell operators (pipes, redirects, subshells) are blocked unless explicitly enabled
- Whitelist/blacklist enforcement respects the active `ProfileMode` (observe/assist/autonomous)
- `shlex.split` parsing errors result in a block verdict, not a pass-through
- `ntpath.basename` handles Windows-style path prefixes on any platform

### 2. Audit Trail (tamper-evident logging)

**Files:** `lasso/core/audit.py`, `lasso/core/audit_verify.py`

Every sandbox action is logged to an append-only JSONL file with HMAC-SHA256 signatures chained entry-to-entry.

Key things to verify:
- `AuditLogger._sign()` chains signatures: `HMAC(key, f"{prev_chain_hash}:{payload}")` where `prev_chain_hash` starts at `"0" * 64`
- Signing key is auto-generated (32 bytes from `secrets.token_bytes`) and stored with `0o600` permissions
- A warning is emitted when the key is stored alongside the logs (production guidance: use `signing_key_path` for external storage)
- Log rotation preserves chain continuity via `rotation_marker` entries that record `previous_chain_hash`
- `verify_audit_log()` independently replays the chain and reports the first break point
- `verify_chain()` validates across rotated files by checking rotation markers link adjacent files
- Syslog forwarding supports Unix socket, UDP, and TCP transports
- Webhook dispatch is non-blocking (background threads) and failures never crash the logger

### 3. Container Hardening (image builder + converter)

**Files:** `lasso/backends/image_builder.py`, `lasso/backends/converter.py`

These translate a `SandboxProfile` into a locked-down container.

Key things to verify:
- `generate_dockerfile()` installs only packages for whitelisted commands (via `TOOL_TO_PACKAGE` mapping)
- `profile_to_container_config()` sets:
  - `cap_drop=["ALL"]` — all Linux capabilities dropped
  - `security_opt=["no-new-privileges"]` — prevents privilege escalation via setuid/setgid
  - `user="1000:1000"` — runs as unprivileged user, never root
  - `read_only_root=True` — root filesystem is read-only
  - `pids_limit`, `mem_limit`, `cpu_quota` — resource limits from profile
- Windows path translation: `C:\Users\me\project` becomes `/c/Users/me/project` for Docker Desktop mounts
- `_resolve_runtime()` maps isolation levels: `gvisor` -> `runsc`, `kata` -> `io.containerd.kata.v2`
- `needs_network_rules()` determines when iptables rules are applied inside the container
- `NET_ADMIN` capability is added only when network policy enforcement requires it

### 4. Configuration Schema (security-relevant fields)

**File:** `lasso/config/schema.py`

Pydantic models that define and validate all security-sensitive settings.

Key things to verify:
- `FilesystemConfig.validate_writable_paths()` rejects:
  - Path traversal (`..`)
  - System-critical prefixes (`/etc`, `/root`, `/bin`, `/usr`, `/proc`, `/sys`, `/dev`, `/boot`)
  - Bare `/home` (too broad — requires subdirectory)
  - Relative paths targeting system directories (`etc`, `proc`, etc.)
- `NetworkConfig.blocked_ports` defaults include all common database ports (1433, 1434, 3306, 5432, 27017, 6379, 9042, 8123, 9000, 1521, 5984)
- `NetworkConfig.blocked_cidrs` defaults block cloud metadata (`169.254.169.254/32`) and all RFC 1918 private ranges
- `CommandConfig.mode` defaults to `WHITELIST` (deny-by-default)
- `ProfileMode` controls gradual authorization: observe (read-only) -> assist (curated dev) -> autonomous (full)
- `GitRepoAccessConfig.block_git_history_content` defaults to `True` — prevents PII exposure from commit diffs

### 5. Network Policy (iptables rules)

**File:** `lasso/core/network.py`

Translates `NetworkConfig` into iptables rules applied inside the container's network namespace.

Key things to verify:
- `NONE` mode: default policy DROP on both INPUT and OUTPUT, only loopback allowed
- `RESTRICTED` mode: default DROP, then explicit allows for DNS, resolved domain IPs on allowed ports, and allowed CIDRs
- `FULL` mode: only blocked CIDRs are dropped (plus blocked ports)
- Database ports are blocked in ALL modes (FULL and RESTRICTED) via `blocked_ports` loop
- `check_destination()` provides a software-level pre-flight check (iptables is the real enforcement)
- DNS is explicitly allowed in RESTRICTED mode (required to resolve allowed domains)
- Blocked CIDRs are applied before allow rules (takes precedence)
- Established connections are allowed on INPUT (stateful tracking)

---

## What to Skip

- **`lasso/dashboard/`** — Flask + HTMX web UI. Not security-critical; it's a monitoring interface behind its own auth layer.
- **`presentation/`** — Slide deck build scripts. Not part of the runtime.

---

## Test Structure

Tests are in `tests/` and organized by security layer:

| Test file | What it covers |
|-----------|---------------|
| `tests/test_commands.py` | Command gate whitelist/blacklist, blocked args, shell operators |
| `tests/unit/test_command_security.py` | Null bytes, control chars, URL-encoded traversal, unicode lookalikes, symlink resolution, dangerous args |
| `tests/unit/test_network.py` | Network policy generation, iptables rules for all modes |
| `tests/unit/test_network_enforcement.py` | `check_destination()` pre-flight checks, database port blocking |
| `tests/unit/test_database_blocking.py` | Database port and client tool blocking (ports + command gate) |
| `tests/unit/test_audit_verify.py` | HMAC chain verification, tamper detection, rotation linkage |
| `tests/unit/test_audit_rotation.py` | Log rotation mechanics, chain continuity across files |
| `tests/unit/test_image_builder.py` | Dockerfile generation, tool-to-package mapping |
| `tests/unit/test_guardrails.py` | Agent instruction guardrails enforcement |
| `tests/unit/test_crypto.py` | HMAC signing, file hashing utilities |
| `tests/unit/test_windows_compat.py` | Windows path conversion, ntpath handling |
| `tests/integration/test_container_security.py` | End-to-end container hardening verification (requires Docker) |
| `tests/integration/test_docker_backend.py` | Docker backend lifecycle (requires Docker) |

Run unit tests (no Docker required):
```bash
python3 -m pytest tests/ -m "not integration" -q
```

---

## Known Limitations

1. **Interpreter escape via `python -c`**: The command gate blocks `python3 -c` and `python -c` via `DANGEROUS_ARGS`, but if `python3` is whitelisted and the agent writes a `.py` file then executes it with `python3 script.py`, the script has full access to the Python standard library inside the container. Mitigation: container isolation (no-new-privileges, dropped capabilities, read-only root) limits what the script can do.

2. **Symlink TOCTOU (Time-of-Check-Time-of-Use)**: The command gate resolves symlinks at check time via `os.path.realpath`, but a race exists between the check and the actual command execution. A symlink could be created or modified between `CommandGate.check()` and the command running inside the container. Mitigation: the container's filesystem mounts limit what symlinks can point to.

3. **Shell operator bypass in BLACKLIST mode**: If `allow_shell_operators` is enabled, complex shell pipelines may combine safe individual commands in unsafe ways. Mitigation: `allow_shell_operators` defaults to `False`; profiles that enable it accept this risk.

4. **DNS rebinding**: In RESTRICTED mode, domains are resolved to IPs for iptables rules. A DNS rebinding attack could cause a domain to resolve to a different IP after the rules are applied. Mitigation: iptables rules are applied at sandbox creation time; re-resolution would require a sandbox restart.

---

## Reviewer Checklist

Before signing off, confirm:

- [ ] **LICENSE**: Apache-2.0 license file is present and matches `pyproject.toml`
- [ ] **Dependencies audited**: Only 7 runtime deps (typer, rich, pydantic, tomli, tomli_w, docker, flask) — all widely used, actively maintained
- [ ] **No network egress without user action**: Default network mode is `restricted`; `none` and `full` require explicit profile configuration
- [ ] **Command gate covers known bypasses**: Null bytes, control chars, URL-encoded traversal (single and double), unicode lookalikes, symlink resolution, dangerous args for 30+ commands, database client tools blocked entirely
- [ ] **Audit chain is sound**: HMAC-SHA256 chain with independent verification; rotation markers link files; syslog forwarding available for SIEM integration
- [ ] **Container drops all capabilities**: `cap_drop=["ALL"]`, `no-new-privileges`, unprivileged user (1000:1000), read-only root filesystem
- [ ] **Database access blocked at two layers**: Network ports (iptables) AND command gate (client tools like psql, mysql, mongo, redis-cli blocked entirely)
- [ ] **Writable path validation**: System-critical paths rejected, bare `/home` rejected, relative system paths rejected, path traversal rejected
- [ ] **Git history content blocked by default**: `block_git_history_content=True` prevents PII exposure from commit diffs
