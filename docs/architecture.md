# LASSO Architecture

> Last updated: 2026-03-17 | Covers LASSO v1.6.3

---

## 1. System Overview

LASSO (Layered Agent Sandbox Security Orchestrator) is a security-first
execution environment for AI coding agents. It wraps agent workloads in
container-based sandboxes with five defense-in-depth layers: command gating,
container isolation, network policy enforcement, behavioral guardrails, and
tamper-evident audit logging. LASSO targets regulated environments (banking,
healthcare, government) where DORA, ISO 27001, and EU AI Act compliance
require provable control over what AI agents can do, access, and transmit.

```
                          +-------------------+
                          |   Entry Points    |
                          |                   |
                  +-------+-------------------+---------+
                  |                            |         |
                  v                            v         v
               +-----+                  +---------+
               | CLI |                  |Dashboard|
               +--+--+                  +----+----+
                  |                          |
                  v                          v
            +---------------------------------------------+
            |          SandboxRegistry                     |
            |   (in-memory index + StateStore on disk)     |
            +----------------------+----------------------+
                                   |
                                   v
            +---------------------------------------------+
            |              Sandbox                        |
            |  CommandGate | AuditLogger | NetworkPolicy  |
            +----------------------+----------------------+
                                   |
                     +-------------+-------------+
                     |                           |
                     v                           v
            +-----------------+         +-----------------+
            | ContainerBackend|         |  Native (subproc)|
            | (Docker/Podman) |         |  fallback mode   |
            +-----------------+         +-----------------+
```

---

## 2. Request Flow

### 2.1 `lasso create development --dir .`

```
User                CLI                  Registry            Sandbox              Backend
 |                   |                      |                   |                    |
 |-- create cmd ---->|                      |                   |                    |
 |                   |-- resolve profile -->|                   |                    |
 |                   |   (BUILTIN_PROFILES) |                   |                    |
 |                   |                      |                   |                    |
 |                   |-- registry.create()->|                   |                    |
 |                   |                      |-- new Sandbox --->|                    |
 |                   |                      |                   |-- CommandGate()    |
 |                   |                      |                   |-- AuditLogger()   |
 |                   |                      |                   |                    |
 |                   |                      |-- store.record_create()               |
 |                   |                      |   (persist to ~/.lasso/state.json)    |
 |                   |                      |                   |                    |
 |                   |-- sandbox.start() -->|                   |                    |
 |                   |                      |                   |-- state=CONFIGURING|
 |                   |                      |                   |-- audit: "start"   |
 |                   |                      |                   |                    |
 |                   |                      |       [cold path] |                    |
 |                   |                      |                   |-- ensure_image --->|
 |                   |                      |                   |   (build if needed)|
 |                   |                      |                   |                    |
 |                   |                      |                   |-- profile_to_      |
 |                   |                      |                   |   container_config |
 |                   |                      |                   |                    |
 |                   |                      |                   |-- backend.create ->|
 |                   |                      |                   |-- backend.start  ->|
 |                   |                      |                   |                    |
 |                   |                      |                   |-- apply iptables   |
 |                   |                      |                   |   network rules -->|
 |                   |                      |                   |                    |
 |                   |                      |                   |-- state=RUNNING    |
 |                   |                      |                   |-- audit: "running" |
 |                   |                      |                   |                    |
 |<-- sandbox_id ----|                      |                   |                    |
```

**Key files:**
- `lasso/cli/main.py` -- Typer CLI entry point
- `lasso/config/defaults.py` -- `BUILTIN_PROFILES` dict (factory functions)
- `lasso/core/sandbox.py` -- `SandboxRegistry.create()`, `Sandbox.start()`
- `lasso/backends/converter.py` -- `profile_to_container_config()`
- `lasso/backends/image_builder.py` -- `ensure_image()`
- `lasso/backends/docker_backend.py` -- `DockerBackend.create()`, `.start()`

### 2.2 `lasso exec <id> -- python3 script.py`

```
User               CLI              Sandbox           CommandGate        Backend          AuditLogger
 |                  |                  |                  |                 |                  |
 |-- exec cmd ----->|                  |                  |                 |                  |
 |                  |-- sb.exec() ---->|                  |                 |                  |
 |                  |                  |-- gate.check() ->|                 |                  |
 |                  |                  |                  |                 |                  |
 |                  |                  |  [validation pipeline]             |                  |
 |                  |                  |  1. strip null bytes               |                  |
 |                  |                  |  2. reject control chars           |                  |
 |                  |                  |  3. block shell operators          |                  |
 |                  |                  |  4. shlex.split + extract cmd      |                  |
 |                  |                  |  5. whitelist/blacklist check      |                  |
 |                  |                  |  6. user blocked_args check        |                  |
 |                  |                  |  7. DANGEROUS_ARGS check           |                  |
 |                  |                  |  8. path traversal detection       |                  |
 |                  |                  |     (URL-decode, unicode, symlink) |                  |
 |                  |                  |                  |                 |                  |
 |                  |                  |<-- verdict ------|                 |                  |
 |                  |                  |                  |                 |                  |
 |                  |                  |  [if BLOCKED]    |                 |                  |
 |                  |                  |-- audit.log_command_blocked() ---->|----------------->|
 |                  |                  |<-- ExecResult(blocked=True) -------|                  |
 |                  |                  |                  |                 |                  |
 |                  |                  |  [if ALLOWED]    |                 |                  |
 |                  |                  |-- backend.exec(container_id, cmd)->|                  |
 |                  |                  |<-- ExecResult ---|-----------------|                  |
 |                  |                  |                  |                 |                  |
 |                  |                  |-- audit.log_command(cmd, result) ->|----------------->|
 |                  |                  |   (duration, exit_code, output)    |                  |
 |                  |                  |                  |                 |                  |
 |<-- stdout/err ---|<-- ExecResult ---|                  |                 |                  |
```

**Key files:**
- `lasso/core/sandbox.py` -- `Sandbox.exec()`, `_exec_with_backend()`
- `lasso/core/commands.py` -- `CommandGate.check()`, `DANGEROUS_ARGS`
- `lasso/core/audit.py` -- `AuditLogger.log_command()`, `.log_command_blocked()`
- `lasso/backends/docker_backend.py` -- `DockerBackend.exec()`

---

## 3. Defense-in-Depth Layers

```
+=====================================================================+
|  Layer 5: AUDIT LOGGING                                             |
|  AuditLogger (lasso/core/audit.py)                                  |
|  - HMAC-SHA256 signed entries with hash chaining                    |
|  - JSONL append-only log per sandbox                                |
|  - Log rotation (max_log_size_mb, rotation_count)                   |
|  - Webhook dispatch to SIEM/SOAR (lasso/core/webhooks.py)           |
|  - Independent verification (lasso/core/audit_verify.py)            |
|  +================================================================+ |
|  | Layer 4: GUARDRAILS ENGINE                                     | |
|  | GuardrailEngine (lasso/core/guardrails.py)                     | |
|  | - no-escape: block access outside working_dir                  | |
|  | - no-exfiltration: detect large data payloads to external hosts| |
|  | - log-modifications: ensure all file changes are audited       | |
|  | - Agent MD injection: append rules to CLAUDE.md / AGENTS.md    | |
|  | +============================================================+| |
|  | | Layer 3: NETWORK POLICY                                    || |
|  | | NetworkPolicy (lasso/core/network.py)                      || |
|  | | - mode: none | restricted | full                           || |
|  | | - iptables rules inside container namespace                || |
|  | | - DNS server control (resolv.conf generation)              || |
|  | | - Domain allowlist/blocklist, CIDR rules, port filtering   || |
|  | | - Cloud metadata endpoint blocked (169.254.169.254)        || |
|  | | +========================================================+|| |
|  | | | Layer 2: CONTAINER ISOLATION                            ||| |
|  | | | ContainerBackend (lasso/backends/base.py)               ||| |
|  | | | - Docker/Podman via Docker SDK                          ||| |
|  | | | - Read-only root filesystem                             ||| |
|  | | | - All capabilities dropped (cap_drop=ALL)               ||| |
|  | | | - Non-root user (1000:1000)                             ||| |
|  | | | - Memory/CPU/PID cgroup limits                          ||| |
|  | | | - tmpfs for /tmp with size limits                       ||| |
|  | | | - Custom image per profile (only allowed tools)         ||| |
|  | | | +====================================================+||| |
|  | | | | Layer 1: COMMAND GATE                               |||| |
|  | | | | CommandGate (lasso/core/commands.py)                 |||| |
|  | | | | - Whitelist or blacklist mode per profile            |||| |
|  | | | | - Shell operator blocking (|, ;, &, `, $())         |||| |
|  | | | | - Dangerous argument detection (find -exec, etc.)   |||| |
|  | | | | - Path traversal detection (URL-encode, unicode,    |||| |
|  | | | |   symlink resolution, double encoding)              |||| |
|  | | | | - Control character rejection                       |||| |
|  | | | | - Null byte stripping                               |||| |
|  | | | +====================================================+||| |
|  | | +========================================================+|| |
|  | +============================================================+| |
|  +================================================================+ |
+=====================================================================+
```

**Enforcement order for every command execution:**

1. **CommandGate** validates the raw command string (Layer 1)
2. If allowed, the command runs inside a **container** with restricted
   capabilities, filesystem, and resource limits (Layer 2)
3. The container's **iptables rules** enforce network policy at the
   kernel level (Layer 3)
4. **GuardrailEngine** checks behavioral rules (path escape,
   exfiltration) and can block actions (Layer 4)
5. **AuditLogger** records every action with HMAC signatures and
   hash chaining for tamper detection (Layer 5)

---

## 4. Component Architecture

```
+---------------------------+     +---------------------------+
|         CLI               |     |        Dashboard          |
| lasso/cli/main.py         |     | lasso/dashboard/app.py    |
| (Typer + Rich)            |     | (Flask + HTMX + Pico CSS) |
| Commands: create, exec,   |     | Routes: /, /sandbox/<id>, |
|   stop, interactive,      |     |   /profiles, /audit,      |
|   profile, audit, agent,  |     |   /check, /partials/*     |
|   auth, dashboard         |     | lasso/dashboard/auth.py   |
+------------+--------------+     | (token login, CSRF)       |
             |                    +------------+--------------+
             |                                 |
             v                                 v
+------------------------------------------------------------+
|                 SandboxRegistry                             |
| lasso/core/sandbox.py :: SandboxRegistry                   |
| - In-memory dict[str, Sandbox]                             |
| - StateStore (persistent to ~/.lasso/state.json)           |
| - Reconcile: compare persisted state vs live containers    |
| - Graceful shutdown: stop all + save state + log events    |
+----------------------------+-------------------------------+
                             |
         +-------------------+-------------------+
         |                                       |
         v                                       v
+--------------------+                +---------------------+
|     Sandbox        |                |    Agent Providers   |
| lasso/core/        |                | lasso/agents/        |
| sandbox.py         |                | base.py: AgentProvider|
| - CommandGate      |                |   ABC, AgentConfig   |
| - AuditLogger      |                | registry.py: detect, |
| - NetworkPolicy    |                |   list, get_provider |
| - WebhookDispatcher|                | claude_code.py       |
| - Lifecycle:       |                | opencode.py          |
|   CREATED ->       |                +---------------------+
|   CONFIGURING ->   |
|   RUNNING ->       |
|   STOPPED          |
+---------+----------+
          |
+---------+---------------------------------------------------+
|                   ContainerBackend ABC                        |
| lasso/backends/base.py                                       |
| 15-method interface:                                         |
|   is_available, get_info, create, start, stop, remove, exec, |
|   inspect, logs, list_containers, create_network,            |
|   remove_network, build_image, image_exists                  |
+---+-----------------------------+---------------------------+
    |                             |
    v                             v
+---------------------+   +---------------------+
| DockerBackend       |   | FakeBackend         |
| lasso/backends/     |   | (tests only)        |
| docker_backend.py   |   | In-memory container |
| - Docker SDK        |   | simulation for fast |
| - Works with Podman |   | unit tests          |
|   via DOCKER_HOST   |   +---------------------+
+---------------------+

+------------------------------------------------------------+
|                     Config System                           |
| lasso/config/schema.py   -- Pydantic models (10 sections)  |
|   SandboxProfile > FilesystemConfig, CommandConfig,         |
|   NetworkConfig, ResourceConfig, GuardrailsConfig,          |
|   AuditConfig, AgentAuthConfig, WebhookConfig,              |
|   GuardrailRule                                             |
| lasso/config/defaults.py -- 5 builtin profiles             |
|   standard, open, offline, strict, evaluation               |
| lasso/config/profile.py  -- TOML save/load                 |
| lasso/config/sharing.py  -- export, import, versioning,    |
|   diff, team profile dirs (LASSO_PROFILE_DIR env)           |
+------------------------------------------------------------+
```

---

## 5. Data Flow

### 5.1 Command Flow: Input to Execution to Audit

```
Raw command string (e.g. "python3 script.py")
         |
         v
+-- CommandGate.check() -----------------------------------------+
|  1. Strip null bytes                                           |
|  2. Reject control characters (\x00-\x08, \x0a-\x1f, \x7f)   |
|  3. Check shell operators if disallowed (|;&`$(){}><)          |
|  4. shlex.split() -> [command, ...args]                        |
|  5. Extract base command name (strip path, handle Windows)     |
|  6. Whitelist/blacklist lookup                                 |
|  7. User-configured blocked_args check                         |
|  8. Hardcoded DANGEROUS_ARGS check (find -exec, etc.)          |
|  9. For each argument:                                         |
|     a. Unicode lookalike detection                             |
|     b. URL-encoded traversal detection (raw)                   |
|     c. URL-decode, check standard path traversal               |
|     d. Check double-encoding                                   |
|     e. Symlink resolution + re-check                           |
+---> CommandVerdict(allowed=True/False, command, args, reason)  |
+----------------------------------------------------------------+
         |
    [if allowed]
         |
         v
+-- Backend Execution -------------------------------------------+
|  DockerBackend.exec(container_id, ["python3", "script.py"])    |
|  - docker.api.exec_create(container_id, cmd, workdir="/workspace")
|  - docker.api.exec_start(exec_id, demux=True)                 |
|  - docker.api.exec_inspect(exec_id) -> exit_code              |
|  Returns: ExecResult(exit_code, stdout, stderr, duration_ms)   |
+----------------------------------------------------------------+
         |
         v
+-- Audit Logging -----------------------------------------------+
|  AuditLogger.log_command(command, args, outcome, detail)       |
|  1. Create AuditEvent with UUID, timestamp, sandbox_id         |
|  2. Check rotation (max_log_size_mb threshold)                 |
|  3. Serialize to JSON (compact, sorted keys)                   |
|  4. Compute HMAC-SHA256 signature:                             |
|     sig = HMAC(key, f"{prev_chain_hash}:{payload}")            |
|  5. Update chain_hash = sig (for next entry)                   |
|  6. Append signed JSON line to .jsonl file                     |
|  7. Dispatch to webhooks (async, background threads)           |
+----------------------------------------------------------------+
```

### 5.2 Profile Resolution Order

```
CLI argument (e.g. "development")
         |
         v
  +-- Is it a builtin name? ---+
  |  (BUILTIN_PROFILES dict)   |
  |  standard, open, offline,  |
  |  strict, evaluation        |
  +---+---YES---->  factory(working_dir) -> SandboxProfile
      |
      NO
      |
      v
  +-- Is it a .lasso/ local file? ---+
  |  .lasso/<name>.toml              |
  +---+---YES---->  load_profile_from_path() -> SandboxProfile
      |
      NO
      |
      v
  +-- Is it in LASSO_PROFILE_DIR? ---+
  |  (env var, colon-separated)      |
  |  Search each dir for <name>.toml |
  +---+---YES---->  load_profile() -> SandboxProfile
      |
      NO
      |
      v
  +-- Is it in ~/.lasso/profiles/? --+
  |  (DEFAULT_PROFILE_DIR)           |
  +---+---YES---->  load_profile() -> SandboxProfile
      |
      NO --> FileNotFoundError
```

### 5.3 Audit Event Lifecycle

```
  AuditEvent created
       |
       v
  Serialize to JSON (compact, sorted keys)
       |
       v
  [sign_entries=True?]
  YES: chain_input = f"{prev_chain_hash}:{json_payload}"
       sig = HMAC-SHA256(signing_key, chain_input)
       chain_hash = sig  (stored for next event)
       event.signature = sig
       |
       v
  Re-serialize with signature included
       |
       v
  [rotation check: file size > max_log_size_mb * 1024 * 1024?]
  YES: current.jsonl -> current.jsonl.1
       .1 -> .2, .2 -> .3, ..., beyond rotation_count deleted
       |
       v
  Append line to {sandbox_id}_{timestamp}.jsonl
       |
       v
  [webhooks configured?]
  YES: For each webhook where event_type in wh.events:
       - Spawn daemon thread
       - POST JSON with X-Lasso-Signature header
       - Retry with exponential backoff (0.5s, 1s, 2s, ...)
       - Max retry_count attempts

  VERIFICATION (lasso/core/audit_verify.py):
  - Read .jsonl line by line
  - For each entry: strip "sig", serialize, compute expected HMAC
  - Compare chain: each sig must equal HMAC(key, prev_hash + payload)
  - Report: valid/invalid, total_entries, first_break_at, errors
```

---

## 6. State Management

### 6.1 In-Memory SandboxRegistry

```
SandboxRegistry
  |
  |-- _sandboxes: dict[str, Sandbox]    # sandbox_id -> Sandbox object
  |-- _backend: ContainerBackend | None  # shared backend for all sandboxes
  |-- _store: StateStore                 # persistent state on disk
  |
  Methods:
    create(profile)  -> Sandbox   # register + persist to state store
    get(id)          -> Sandbox   # by 12-char hex ID
    get_by_name(n)   -> Sandbox   # by profile name (first match)
    list_all()       -> [status]  # all sandbox status dicts
    stop(id)         -> bool      # stop + record in state store
    stop_all()       -> int       # stop all running sandboxes
    remove(id)       -> bool      # stop + remove from registry + store
    reconcile()      -> {id: action}  # compare store vs live containers
    shutdown()       -> None      # stop all + save state
```

### 6.2 Disk Persistence via StateStore

```
~/.lasso/
  |-- state.json          # RegistryState document
  |     {
  |       "version": 1,
  |       "updated_at": "2026-03-17T10:00:00Z",
  |       "sandboxes": {
  |         "a1b2c3d4e5f6": {
  |           "sandbox_id": "a1b2c3d4e5f6",
  |           "profile_name": "development",
  |           "container_id": "sha256:abc...",
  |           "state": "running",
  |           "created_at": "2026-03-17T09:55:00Z"
  |         }
  |       }
  |     }
  |
  |-- profiles/            # saved TOML profiles
  |     |-- my-profile.toml
  |     |-- .history/      # profile version archive
  |           |-- my-profile/
  |                 |-- v1_2026-03-15T12-00-00.toml
  |                 |-- v2_2026-03-16T14-30-00.toml
  |
  |-- dashboard_token      # dashboard login token (0600 perms)
  |-- .audit_key           # HMAC signing key (0600 perms, 32 bytes)

File locking:
  - fcntl (Linux/macOS) or msvcrt (Windows)
  - Atomic writes: write to .tmp, then os.replace()
  - lasso/core/state.py :: StateStore
```

### 6.3 Container Lifecycle States

```
  CREATED ---------> CONFIGURING ---------> RUNNING
     |                   |                     |
     |                   | (start failed)      | sandbox.stop()
     |                   v                     v
     |                 ERROR               STOPPED
     |                                        |
     +---- sandbox.stop() ------------------>-+
                                              |
                                     registry.remove()
                                     (container removed,
                                      state store updated)
```

State transitions are recorded in the audit log as `lifecycle` events.
The `StateStore` persists the current state to disk after every
transition so that LASSO can reconcile after a crash.

---

## 7. Authentication Architecture

### 7.1 Dashboard Auth (Token-Based Sessions)

```
+----------+       +----------+       +-----------+
|  Browser |------>| /login   |------>| Dashboard |
|          |  GET  | (auth.py)|  POST | Auth      |
+----------+       +----------+       +-----------+
     |                  |                    |
     |  1. Show login   |                    |
     |     form with    |                    |
     |     CSRF token   |                    |
     |                  |                    |
     |  2. POST token   |                    |
     |  + csrf_token    |                    |
     |                  |-- validate() ----->|
     |                  |   secrets.compare_ |
     |                  |   digest()         |
     |                  |                    |
     |  3. Set session  |                    |
     |     cookie       |                    |
     |                  |                    |
     |  4. All dashboard|                    |
     |     routes check |                    |
     |     @require_login                    |
     +------------------+--------------------+

Token storage: ~/.lasso/dashboard_token (0600 perms)
Generated on first run, printed to console.
Bypass: LASSO_DASHBOARD_PUBLIC=1 env var.
CSRF: per-session token, validated on all dashboard POST requests.
        API routes (/api/*) exempt from CSRF (use API keys instead).
```

**Key file:** `lasso/dashboard/auth.py` -- `DashboardAuth`, `require_login`,
`validate_csrf`, `csrf_token_html`

### 7.2 Agent Auth (GitHub Token Injection)

```
Agent auth is configured per-profile via the AgentAuthConfig section:

SandboxProfile.agent_auth:
  github_token_env: "GITHUB_TOKEN"     # env var name
  opencode_provider: "anthropic"       # LLM provider
  opencode_api_key_env: "OPENCODE_API_KEY"

The token is injected into the container environment at creation time,
allowing agents (Claude Code, OpenCode) to authenticate with
their respective LLM providers without exposing credentials to the
host system.

Key file: lasso/config/schema.py :: AgentAuthConfig
```

---

## 8. Extension Points

### 8.1 Adding New Container Backends

Implement the `ContainerBackend` ABC defined in `lasso/backends/base.py`.
The interface has 15 methods:

```python
class ContainerBackend(ABC):
    def is_available(self) -> bool: ...
    def get_info(self) -> dict[str, Any]: ...
    def create(self, config: ContainerConfig) -> str: ...
    def start(self, container_id: str) -> None: ...
    def stop(self, container_id: str, timeout: int = 10) -> None: ...
    def remove(self, container_id: str, force: bool = False) -> None: ...
    def exec(self, container_id: str, command: list[str], timeout: int = 300) -> ExecResult: ...
    def inspect(self, container_id: str) -> ContainerInfo: ...
    def logs(self, container_id: str, tail: int = 100) -> str: ...
    def list_containers(self, label_filter: str = "lasso") -> list[ContainerInfo]: ...
    def create_network(self, name: str, internal: bool = True, ...) -> str: ...
    def remove_network(self, name: str) -> None: ...
    def build_image(self, dockerfile_content: str, tag: str) -> str: ...
    def image_exists(self, tag: str) -> bool: ...
```

Register the backend in `lasso/backends/detect.py :: detect_backend()`.
The `FakeBackend` in tests demonstrates a minimal in-memory implementation.

### 8.2 Adding New Agent Providers

Implement the `AgentProvider` ABC defined in `lasso/agents/base.py`:

```python
class AgentProvider(ABC):
    @property
    def agent_type(self) -> AgentType: ...       # e.g. AgentType.OPENCODE
    @property
    def display_name(self) -> str: ...           # e.g. "OpenCode"
    def is_installed(self) -> bool: ...          # shutil.which() check
    def get_version(self) -> Optional[str]: ...  # parse --version output
    def generate_config(self, profile: SandboxProfile) -> AgentConfig: ...
    def generate_rules(self, profile: SandboxProfile) -> str: ...
    def get_start_command(self) -> list[str]: ... # e.g. ["opencode"]
```

Register the new provider class in `lasso/agents/registry.py :: _load_providers()`.
The registry auto-detects installed agents in priority order.

### 8.3 Custom Profiles and Profile Sharing

```
Creating a custom profile:
  1. Define via Python:  SandboxProfile(name="my-profile", filesystem=..., ...)
  2. Save to TOML:       lasso profile save my-profile.toml
  3. Load:               lasso create my-profile --dir .

Profile sharing (lasso/config/sharing.py):
  - export_profile(name, output_path)  -- TOML with integrity hash
  - import_profile(path, name)         -- validate + verify hash + save
  - save_profile_versioned()           -- auto-increment version, archive old
  - list_profile_versions(name)        -- list archived versions
  - diff_profiles(a, b)               -- human-readable diff

Team sharing:
  - Set LASSO_PROFILE_DIR=/path/to/shared/profiles
  - Supports colon-separated paths for multiple directories
  - Personal profiles in ~/.lasso/profiles/ always included as fallback
```

### 8.4 Webhook Integrations

Configure webhooks in the profile's `audit.webhooks` list:

```toml
[[audit.webhooks]]
enabled = true
url = "https://siem.internal/api/events"
events = ["violation", "lifecycle", "command"]
secret = "hmac-shared-secret"
timeout_seconds = 5
retry_count = 2
```

Webhook delivery (`lasso/core/webhooks.py :: WebhookDispatcher`):
- Async via daemon threads (never blocks command execution)
- HMAC-SHA256 payload signature (`X-Lasso-Signature: t=<timestamp>,sha256=<hex>`), timestamp included in signed payload
- Headers: `X-Lasso-Event`, `X-Lasso-Delivery`, `X-Lasso-Timestamp`
- Exponential backoff on retries (0.5s base, 2x multiplier)
- Event types: `command`, `lifecycle`, `violation`, `file`, `network`

Test a webhook via the CLI or dashboard.

---

## Appendix: Key File Reference

| Component | File | Primary Class/Function |
|-----------|------|----------------------|
| Sandbox orchestrator | `lasso/core/sandbox.py` | `Sandbox`, `SandboxRegistry` |
| Command validation | `lasso/core/commands.py` | `CommandGate`, `CommandVerdict` |
| Audit logging | `lasso/core/audit.py` | `AuditLogger`, `AuditEvent` |
| Audit verification | `lasso/core/audit_verify.py` | `verify_audit_log()` |
| Network policy | `lasso/core/network.py` | `NetworkPolicy` |
| Guardrails | `lasso/core/guardrails.py` | `GuardrailEngine` |
| State persistence | `lasso/core/state.py` | `StateStore`, `SandboxRecord` |
| Webhook dispatch | `lasso/core/webhooks.py` | `WebhookDispatcher` |
| Backend ABC | `lasso/backends/base.py` | `ContainerBackend`, `ContainerConfig` |
| Docker/Podman | `lasso/backends/docker_backend.py` | `DockerBackend` |
| Backend detection | `lasso/backends/detect.py` | `detect_backend()` |
| Profile converter | `lasso/backends/converter.py` | `profile_to_container_config()` |
| Dashboard | `lasso/dashboard/app.py` | `create_app()`, `dashboard_bp` |
| Dashboard auth | `lasso/dashboard/auth.py` | `DashboardAuth`, `init_dashboard_auth()` |
| Agent ABC | `lasso/agents/base.py` | `AgentProvider`, `AgentConfig` |
| Agent registry | `lasso/agents/registry.py` | `detect_agent()`, `list_agents()` |
| Config schema | `lasso/config/schema.py` | `SandboxProfile` (10 sub-models) |
| Builtin profiles | `lasso/config/defaults.py` | `BUILTIN_PROFILES` |
| Profile sharing | `lasso/config/sharing.py` | `export_profile()`, `import_profile()` |
| CLI | `lasso/cli/main.py` | Typer app with sub-commands |
