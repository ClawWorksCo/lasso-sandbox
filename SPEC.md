# LASSO Product Specification

> For team review. Estimated review time: 4-6 hours for 2 reviewers.

## What is LASSO?

LASSO runs AI coding agents (Claude Code, OpenCode) inside isolated Docker containers. Every command the agent runs is controlled, logged, and auditable.

**One sentence:** "pip install lasso-sandbox, then `lasso shell --agent claude-code` gives you Claude Code in a secure sandbox."

---

## Target Users

- Bank data/analytics team (2-5 developers)
- Windows machines with Docker Desktop or Podman
- Currently using Claude Code and OpenCode for daily coding
- Need DORA/EU AI Act compliance evidence for AI agent usage

---

## Core Features

### KEEP / REMOVE checklist

Mark each feature: [x] keep or [ ] remove

#### Sandbox Creation & Management
- [x] `lasso shell --agent claude-code` — create sandbox + drop into terminal
- [x] `lasso shell --agent opencode` — same for OpenCode
- [x] `lasso attach <id>` — reconnect to a running sandbox
- [x] `lasso status` — list running sandboxes
- [x] `lasso stop <id>` — stop a sandbox (container keeps state)
- [x] `lasso stop all` — stop everything
- [x] `lasso create` — create without entering terminal
- [x] `lasso exec <id> -- <command>` — run single command in sandbox
- [ ] ~~`lasso interactive`~~ — removed in 1.2.0 (replaced by `lasso shell`)
- [ ] ~~`lasso quickstart`~~ — removed in 1.2.0 (overlapped with `lasso shell`)
- [ ] ~~`lasso run`~~ — removed in 1.2.0 (confusing with `shell`)

#### Dashboard (Web UI)
- [x] Agent-first create wizard (pick agent -> pick security -> set dir -> create)
- [x] Sandbox cards showing status, agent, security level
- [x] Sandbox detail page with connection instructions
- [x] Quick command executor in sandbox detail
- [x] "Open Terminal" button with copy-paste `lasso attach` command
- [x] Security Policies page (view/compare profiles)
- [x] System Health page
- [x] No login required (localhost only, `LASSO_DASHBOARD_AUTH=1` to enable)
- [ ] Audit log viewer in dashboard (currently exists but basic)
- [ ] Profile editor in dashboard (currently exists — 7 tab form)

#### Security Controls
- [x] Command whitelist — only allowed commands can execute
- [x] Blocked argument patterns — e.g., `git push --force` blocked
- [x] Network isolation — NONE (offline), RESTRICTED (package registries only)
- [x] Read-only root filesystem
- [x] Non-root user (uid 1000)
- [x] All capabilities dropped (`cap_drop: ALL`)
- [x] no-new-privileges flag
- [x] Resource limits (memory, CPU, PIDs)
- [x] Database port blocking (MSSQL, PostgreSQL, MySQL, etc.)
- [x] IPv4 + IPv6 iptables enforcement
- [x] Container image pinned to SHA256 digest
- [ ] Command gate plugins (entry_points system) — adds complexity, no current users
- [ ] ~~MCP server~~ — removed in 1.2.0 (not needed for CLI agents)
- [ ] Guardrails engine (agent MD file checking) — not used by team
- [ ] gVisor / Kata isolation levels — requires extra runtime installs
- [ ] ~~Warm pool~~ — removed in 1.2.0 (premature optimization)

#### Audit & Compliance
- [x] HMAC-SHA256 signed, hash-chained audit log (JSONL)
- [x] `lasso audit view` — view audit trail
- [x] `lasso audit verify` — verify chain integrity
- [x] `lasso check --security-audit` — security audit against a profile
- [x] Tamper-evident: any modification breaks the chain
- [ ] DORA compliance report generator — marketing feature, not core
- [ ] EU AI Act compliance report generator — same
- [ ] Webhook dispatch to SIEM — enterprise feature, not needed yet
- [ ] Syslog forwarding — same

#### Profiles (Security Policies)
- [x] `development` — standard coding (git, npm, pip, python, restricted network)
- [x] `strict` — banking compliance (no network, read-only git, full audit)
- [x] `evaluation` — maximum lockdown (ls, cat, grep only)
- [x] Profile inheritance (`extends`) — team profiles extend builtins
- [x] Profile locking and hash verification
- [x] `lasso profile list/export/import/diff`
- [ ] ~~`bank-analysis` profile~~ — removed in 1.2.0 (merged into `strict`)
- [ ] Community profiles in `profiles/` directory — 6 TOML files, adds review burden
- [ ] Profile versioning with history archive — over-engineered for current use

#### Agent Support
- [x] Claude Code — pre-installed in sandbox, auto-whitelisted
- [x] OpenCode — pre-installed in sandbox, auto-whitelisted
- [x] Agent guardrails markdown generation (CLAUDE.md, etc.)
- [x] `--agent` flag on create/shell commands
- [ ] ~~Aider, Codex, Goose, Gemini CLI, Cursor, VS Code, Copilot~~ — all removed in 1.2.0
- [ ] Agent auto-detection — unnecessary if user specifies `--agent`

#### Configuration
- [x] `lasso-config.toml` — operational settings
- [x] Environment variable overrides (`LASSO_*`)
- [x] `lasso config show` — display resolved config
- [x] Team config template (`examples/team-config/`)
- [x] `lasso init --from-config` — bootstrap from team config
- [ ] `lasso config validate` — CI feature, not needed yet
- [ ] `lasso config init` — scaffolding, overlaps with `lasso init`

#### Developer/Build
- [x] `lasso prebuild` — pre-build all preset images
- [x] `lasso doctor` — system diagnostics
- [x] `lasso version` — version info
- [ ] ~~REST API (19+ endpoints)~~ — removed in 1.2.0 (no API consumers)
- [ ] ~~Python SDK (LassoClient, SandboxHandle)~~ — removed in 1.2.0 (no SDK consumers)
- [ ] ~~OpenAPI/Swagger UI~~ — removed in 1.2.0 (no API consumers)
- [ ] ~~Prometheus metrics~~ — removed in 1.2.0 (no monitoring system)
- [ ] GitHub Actions CI workflows — nice but not blocking
- [ ] Pre-commit hooks — nice but not blocking

---

## Sandbox Session Persistence

### Current behavior
- Sandbox = Docker container. It runs until stopped.
- `lasso shell` creates a sandbox and enters it. Typing `exit` leaves the terminal but the container keeps running.
- `lasso attach <id>` reconnects to a running sandbox.
- `lasso stop <id>` stops the container. Files in `/workspace` (mounted from host) are preserved.
- State store at `~/.lasso/state.json` tracks which sandboxes exist.

### Recommended approach for the team
1. **Start of day:** `lasso shell --agent claude-code --dir ~/Projects/my-repo`
2. **Work:** Use Claude Code inside the sandbox. All file changes happen in your project directory (mounted from host).
3. **Break/switch task:** Type `exit`. Sandbox keeps running in background.
4. **Resume:** `lasso attach <id>` or `lasso status` to find the ID.
5. **End of day:** `lasso stop all`.
6. **Next day:** `lasso shell --agent claude-code --dir ~/Projects/my-repo` (new sandbox, but your code is on the host — nothing lost).

### What persists across sessions
- **Your code** — always on the host filesystem, never lost
- **Audit trail** — JSONL files in `./audit/` directory
- **Sandbox state** — `~/.lasso/state.json` tracks running sandboxes

### What does NOT persist
- **In-container state** — pip packages installed during the session, temp files in /tmp, shell history inside the container. These are lost when the sandbox is stopped.
- **Agent conversation history** — Claude Code stores conversation in `/home/agent/.claude/` inside the container. This is lost on stop. To preserve, mount a host directory for agent state (future feature).

---

## File Inventory (for review)

### Must review (security-critical) — ~2,500 lines
| File | Lines | What it does |
|------|-------|-------------|
| `lasso/core/commands.py` | 460 | Command gate — validates every command |
| `lasso/core/audit.py` | 450 | HMAC-signed audit logging |
| `lasso/core/network.py` | 200 | iptables rule generation |
| `lasso/core/sandbox.py` | 750 | Sandbox lifecycle orchestrator |
| `lasso/backends/converter.py` | 200 | Profile -> Docker container config |
| `lasso/backends/image_builder.py` | 250 | Dockerfile generation + preset images |

### Should review (user-facing) — ~3,500 lines
| File | Lines | What it does |
|------|-------|-------------|
| `lasso/cli/main.py` | 2900 | All CLI commands |
| `lasso/dashboard/app.py` | 700 | Web dashboard routes |
| `lasso/config/schema.py` | 600 | Pydantic config models |
| `lasso/config/profile.py` | 300 | Profile loading + inheritance |

### Can skip (supporting) — ~12,000 lines
- `lasso/agents/` — agent config generators (claude-code + opencode only)
- `lasso/dashboard/templates/` — HTML templates
- `lasso/core/compliance.py` — compliance reports
- `tests/` — test suite (1,836 unit + 56 integration)

### Estimated review scope after removing marked items
- **Security-critical:** ~2,500 lines (half a day)
- **User-facing:** ~3,500 lines (half a day)
- **Total:** ~6,000 lines for 2 reviewers in 1 day

---

## Architecture (simplified)

```
User runs: lasso shell --agent claude-code --dir ~/my-project

1. CLI parses flags
2. Loads "development" profile (security policy)
3. Adds "claude" to command whitelist
4. Checks preset image exists (lasso-preset:claude-code)
5. Docker: create container (0.1s)
6. Docker: start container (0.4s)
7. Apply iptables rules via batched script (0.5s)
8. Log "sandbox started" to audit trail
9. os.execvp("docker", ["docker", "exec", "-it", ...])
   -> User gets a real terminal inside the container
   -> Claude Code is available, type "claude" to start

Inside the container:
- User is "sandbox" (uid 1000, non-root)
- /workspace is mounted from ~/my-project (read-write)
- /tmp is tmpfs (writable, cleared on stop)
- Everything else is read-only
- Network: only pypi.org, npmjs.org, github.com reachable
- All commands logged to audit trail with HMAC signatures
```

---

## What was stripped in v1.2.0

The following were removed as agreed:

1. **7 agent providers removed** (kept only claude-code + opencode)
2. **REST API removed** (lasso/api/)
3. **Python SDK removed** (lasso/sdk/, LassoClient, SandboxHandle)
4. **MCP server removed** (lasso/mcp/)
5. **Compliance reports removed** (lasso/core/compliance.py)
6. **Plugin system removed** (lasso/plugins/)
7. **Community profiles removed** (profiles/ directory)
8. **Redundant CLI commands removed** (interactive, quickstart, run)
9. **Warm pool removed** (lasso/core/warm_pool.py)
10. **Extra preset images removed** (kept only base, claude-code, opencode)
11. **OpenAPI/Swagger UI removed**
12. **Prometheus metrics removed**

**Removed: ~6,000 lines**
**Remaining codebase: ~13,000 lines** (of which ~6,000 need review)

---

## Open Questions for You

1. ~~**Aider/Codex presets**~~ — removed in 1.2.0.
2. ~~**REST API**~~ — removed in 1.2.0.
3. **Audit log viewer in dashboard** — keep or remove? It's basic but functional.
4. **Profile editor in dashboard** — keep or remove? It's complex (7 tabs).
5. **Agent conversation persistence** — mount `~/.claude` from host into container so Claude Code remembers conversations across sessions? This is a small change but affects the security model (more host paths exposed).
</content>
</invoke>