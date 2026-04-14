# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.3] - 2026-04-14

### Fixed
- **Windows state.json Permission Denied**: Use `%LOCALAPPDATA%\lasso` on Windows instead of `~\.lasso` (avoids Controlled Folder Access blocks). Self-healing for files with bad NTFS ACLs from prior versions.
- **Session volume too narrow**: mount at `/home/agent` (was `/home/agent/.local`) so `.config/`, `.cache/` are also writable
- **OpenCode auth.json wrong path**: check Unix-style `~/.local/share/opencode/auth.json` first on all platforms
- **Bind mount creates parent dirs as root**: pre-create `.local/share/opencode`, `.config`, `.cache` with correct ownership in Dockerfile
- **Copilot API blocked by network policy**: added GitHub Copilot domains (`api.*.githubcopilot.com`, `copilot-proxy.githubusercontent.com`, `models.dev`) to standard profile's allowed domains

### Added
- `lasso/utils/paths.py` — centralized cross-platform LASSO directory resolution
- `lasso prebuild --agent opencode` — build only one agent's image instead of all presets
- Dashboard "Open Terminal" now launches the agent (e.g. OpenCode) instead of just bash

### Changed
- All 10 files using `Path.home() / ".lasso"` migrated to `get_lasso_dir()` for Windows compatibility

## [1.6.2] - 2026-04-14

### Added
- Configurable sandbox-template images via `opencode_template` / `claude_code_template` in config.toml (supports private registries, mirrors, digest pinning)
- Env vars `LASSO_OPENCODE_TEMPLATE` and `LASSO_CLAUDE_CODE_TEMPLATE`
- 17 new unit tests for template-based image building

### Fixed
- SPEC.md stale `/home/sandbox/` path
- Template Dockerfile USER ordering made explicit (always `USER root` before CA cert)
- `docker pull` uses SDK's built-in image parsing (was manual split)
- Log message corrected: "Using sandbox-template" (was "Pulling" after pull)

## [1.6.1] - 2026-04-14

### Fixed
- **OpenCode TUI hang**: multiple layered fixes for corporate network environments:
  - `NODE_EXTRA_CA_CERTS` now always set (was conditional on --ca-cert) — eliminates models.dev timeout
  - `/tmp` tmpfs mounted with `exec` permission — fixes native .node addon loading (file watcher)
  - Auto session volume (`lasso-session-opencode`) created for agent sandboxes
  - `/home/agent/.local` directory pre-created in images for session volume mount target
  - OpenCode auth.json path detection fixed for cross-platform compatibility

## [1.6.0] - 2026-04-14

### Changed
- **Agent presets now use Docker sandbox-templates** (`docker/sandbox-templates:opencode`, `docker/sandbox-templates:claude-code`) as base images instead of building from `python:3.12-slim` with curl install. Eliminates SSL certificate issues on corporate networks — `docker pull` uses the host certificate store.
- Container user changed from `sandbox` to `agent` (UID 1000 unchanged) to match sandbox-templates
- All mount targets updated: `/home/sandbox/` → `/home/agent/`
- `lasso prebuild` and `lasso quickstart` now pull pre-built images instead of building from scratch (faster, no network calls inside container)

### Added
- `AGENT_BASE_IMAGES` dict for configurable sandbox-template image sources
- Automatic fallback to building from scratch if sandbox-template pull fails (air-gapped support)

## [1.5.3] - 2026-04-13

### Fixed
- **Windows state file crash**: `[WinError 5] Access is denied` on `os.replace()` — added retry loop with direct-write fallback
- **OpenCode image build fails behind corporate proxy**: `curl` now always installed before agent install commands in Dockerfile
- **`lasso quickstart` and `lasso prebuild` missing `--ca-cert`**: corporate CA cert now passed through to image builds
- **Dashboard browse-dirs 400 on non-existent path**: falls back to nearest existing parent directory
- **"Sandbox not found" after dashboard Open Terminal**: added container-name-based fallback reconnection when state file is corrupt
- Empty/corrupt state files handled gracefully on all platforms

## [1.5.2] - 2026-04-13

### Added
- mypy configuration in pyproject.toml + Makefile typecheck target
- 10 property-based tests for CommandGate using Hypothesis
- hypothesis added to dev dependencies

### Changed
- Extracted up/shell/attach into cli/sandbox_cmds.py (main.py 1665→1246 lines)
- Coverage threshold set to 65% (realistic for current test suite)

### Fixed
- Checkpoint thread safety: added threading.Lock for in-process concurrency

## [1.5.1] - 2026-04-13

### Added
- `lasso quickstart` — guided setup wizard (doctor + prebuild + proxy in one command)
- `lasso reset` — cleanup command (stop sandboxes + proxy, optional `--prune`/`--hard`)
- Auto-mount `~/.ssh` and `~/.gitconfig` read-only into sandboxes (opt-out with `--no-auto-mount`)
- OpenCode `auth.json` auto-mount for seamless Copilot auth passthrough
- `--env-file` flag for loading dotenv files into sandboxes
- `--agent-arg` flag for passing extra args to agent binary (e.g., `--continue`)
- `--ssh` explicit flag for SSH key mounting
- `TERM` env var passthrough to container (fixes OpenCode TUI rendering)
- Windows Terminal integration docs (`docs/workflows/windows-terminal.md`)

### Fixed
- `--resume` now correctly restarts stopped containers (was silently failing)
- Socket proxy image pinned to `0.2` tag (was `:latest` — supply chain risk)
- Terminal size detection includes TERM, COLUMNS, LINES on all exec paths
- Dead `log_mcp_tool_call()` method removed from audit.py

### Changed
- README documents command gate limitation for interactive sessions
- Audit key co-location documented with external storage guidance
- Coverage threshold raised from 60% to 70%
- Removed `demo.py` and `presentation/` directory

## [1.5.0] - 2026-04-13

### Added
- **`--mount`, `--env`, `--pass-env` flags on `lasso up`** — one-command workflow with custom mounts and env vars
- **Named Docker volume support** (`--session-volume`) — persists agent state (SQLite sessions, history) across sandbox restarts
- **Corporate CA certificate injection** — `ca_cert_path` in config auto-installs certs into container trust store with NODE_EXTRA_CA_CERTS, SSL_CERT_FILE, REQUESTS_CA_BUNDLE
- **Docker-from-Docker via socket proxy** (`--docker`) — enables `docker build` inside sandboxes using Tecnativa socket proxy with restricted API (no exec/volumes/auth)
- **Session resume** (`--resume`) — reconnects to existing sandbox matching working dir, passes `--continue` to OpenCode/Claude Code
- **`find_existing()` method on SandboxRegistry** — finds running/stopped sandboxes by working directory
- **`team-opencode` example profile** — full-access OpenCode sandbox with DfD, session persistence, and team tool access
- 39 new unit tests (session volumes, CA certs, Docker-from-Docker, session resume)

## [1.4.5] - 2026-04-12

### Fixed
- Stale "minimal"/"development" profile names in audit.py, CLI help text, profile editor
- Keyboard accessibility: policy card radios now focusable (was display:none)
- Builtin profile edit flow: now duplicates to new custom profile instead of dead-end abort
- Sandbox creation errors flash messages instead of losing form state
- System Health page now accessible from sidebar navigation
- "New Sandbox" sidebar link now opens create wizard via hash detection
- Consistent stop confirmation dialog across all views
- Flash messages now have dismiss button and auto-dismiss
- Breadcrumbs standardized to "Sandbox Rules" matching sidebar nav
- Profile badge based on network mode properties, not hardcoded profile names
- New profile wizard applies base profile defaults to Step 3 checkboxes
- Audit log page now shows newest-first (matching detail view)
- Network mode icons: lock (offline), warning (restricted), globe (full)
- Terminal quick command open by default for running sandboxes

### Added
- Delete/remove actions for stopped sandboxes and saved profiles
- ARIA live regions for HTMX-refreshed sandbox status and audit feed
- Directory browser keyboard navigation (tabindex, Enter key support)
- Visual feedback for "no agent" selection in create wizard
- Keyboard shortcut `c` toggles create wizard

### Changed
- Cleaned all remaining stale doc references across 10+ files (compliance, threat model, network egress, SPEC)

## [1.4.4] - 2026-04-12

### Fixed
- Dashboard CSS/JS missing from pip installs (pyproject.toml + MANIFEST.in packaging)
- SECURITY.md version table updated to 1.4.x (was 0.4.x)
- Removed stale API key check from `lasso doctor` (REST API removed in 1.2.0)
- Makefile install-dev now installs all optional deps
- Removed MCPSecurityConfig (MCP removed in 1.2.0)
- Dashboard errors now show flash messages instead of silent redirects
- Auth login message no longer misleading when using GITHUB_TOKEN env var
- Claude Code strict profile detection checks NetworkMode.RESTRICTED (not just name-based)
- Platform-aware fix hints in `lasso doctor` (Windows/macOS/Linux)
- Added `lasso --version` flag

### Changed
- Updated all stale docs (architecture, threat model, air-gapped, secrets) to remove REST API/SDK/MCP references
- CONTRIBUTING.md: fixed Python version (3.10+), removed mypy reference
- Pre-commit ruff updated to v0.11.6
- Cleaned up TODO.md

## [1.4.3] - 2026-04-12

### Fixed
- Self-XSS in profile editor domain tag input (innerHTML → textContent)
- Hardcoded /tmp/lasso-sandbox in create form (now uses dynamic default)
- Profile edit checkboxes now respect blacklist/whitelist mode
- Hardcoded /login URL in login template (now uses url_for)
- IPv4-mapped IPv6 SSRF bypass (::ffff:127.0.0.1)
- Removed dead _is_safe_webhook_url function
- Removed empty plugin entry points from pyproject.toml

## [1.4.2] - 2026-04-12

### Fixed
- DNS resolution in network.py and webhooks.py no longer blocks indefinitely; added 5-second timeout via threaded wrapper
- Claude Code provider now restricts Read/Glob/Grep to working directory in strict/offline profiles
- Deduplicated `_DATABASE_PORTS` into a single canonical `DATABASE_PORTS` constant in schema.py (was defined in 4 files with drift — security_audit.py was missing port 1434/MSSQL Browser)

### Changed
- Unit test count: 1084

## [1.4.1] - 2026-04-11

### Fixed
- IPv4-mapped IPv6 SSRF bypass in webhook IP validation (e.g. `::ffff:127.0.0.1`)

## [1.4.0] - 2026-04-10

### Added
- Batched iptables rule application (single `docker exec` instead of per-rule calls, ~20x faster)
- iptables binary removal after firewall setup to prevent in-container rule flushing

## [1.3.0] - 2026-04-08

### Changed
- Profile mode enforcement in blacklist command mode (previously ignored)
- Improved container reconnection security: falls back to strict profile when original is unavailable

## [1.2.0] - 2026-04-06

### Removed (Simplification)
- REST API (19+ endpoints), Python SDK (`LassoClient`/`SandboxHandle`), and MCP server (JSON-RPC) — no current consumers
- 7 agent providers (Cursor, Aider, Goose, Gemini CLI, Codex, VS Code, Copilot) — only `claude-code` and `opencode` remain
- Warm pool (`lasso/core/warm_pool.py`) — premature optimization
- DORA/EU AI Act compliance report generators
- Community profiles directory
- Plugin system (`entry_points`)

See SPEC.md for the full keep/remove rationale.

## [1.1.0] - 2026-04-02

### Added
- Git repository access control (`GitRepoAccessConfig`) with PII-aware history blocking
- Profile inheritance via `extends` field with deep merge

### Changed
- Upgraded to Pydantic v2 model serialization throughout

## [1.0.0] - 2026-03-28

### Added
- Stable release: core sandbox orchestrator, command gate, audit logging, network isolation
- 2 production agent providers: Claude Code, OpenCode
- 5 builtin profiles: standard, open, offline, strict, evaluation
- Multi-sandbox registry with persistent state and container reconnection
- Gradual authorization modes: observe, assist, autonomous
- `lasso up` / `lasso down` lifecycle commands

### Changed
- Total test count: 1084 unit tests

## [0.4.1] - 2026-03-22

### Fixed
- Project URLs updated from Tailscale IPs to GitHub (ClawWorksCo/lasso-sandbox)
- PyPI package metadata now points to correct public repository

## [0.4.0] - 2026-03-22

### Added
- `lasso compliance report dora` command to generate DORA and EU AI Act compliance evidence reports with article-level mapping from audit logs
- `lasso doctor` command with 10 comprehensive system diagnostic checks and `--fix` flag for auto-remediation
- `lasso quickstart` command for one-command setup (auto-detects agent, initializes config, creates sandbox)
- `lasso profile install` command to install community profiles from bundled profile pack
- 5 community profiles: `frontend-dev`, `data-science`, `ci-runner`, `banking-norway`, `healthcare`
- gVisor and Kata Containers isolation levels for stronger sandbox containment
- Syslog log forwarding (UDP/TCP/Unix socket) for SIEM integration
- 30 real Docker integration tests covering container escape, network isolation, E2E attack scenarios, filesystem isolation, and audit verification
- PyPI publishing setup with `lasso-sandbox` package name and Makefile
- CVE-2025-59536 case study documentation
- External signing key documentation with practical examples

### Changed
- Standardized CLI error and success message formatting
- First-run experience now auto-creates `~/.lasso/` directory
- Total test count: 1102 unit tests, 100 integration tests

## [0.3.1] - 2026-03-22

### Security
- Install iptables in container image so network firewall rules actually apply (was silently missing)
- Fail sandbox startup when iptables rules fail instead of silent continue
- Remove unauthenticated API bypass when no API keys are configured (now returns 401)
- Add `@require_login` to dashboard `/api/sandboxes` routes
- Fix audit log rotation chain breakage (reset hash chain per rotated file)
- Add SSRF blocking in webhook test endpoint (reject private/loopback IPs)
- Restrict `audit verify` to home/tmp paths to prevent file oracle attacks
- Fix MCP `file_read`/`file_write` command injection via `shlex.quote()`
- Add MCP `sandbox_create` working directory validation
- Fix command gate `blocked_args` short flag bypass (`-f` vs `--force`)
- Fix sed `DANGEROUS_ARGS` pattern that incorrectly blocked all sed usage
- Add interpreter commands to `DANGEROUS_ARGS` (`python3 -c`, `node -e`, etc.)
- Add `no-new-privileges` to container `security_opt`
- Include timestamp in webhook HMAC signature to prevent replay attacks
- Add signing key co-location warning when key is stored next to audit logs
- Profile name path traversal prevention
- API key file permissions set to `chmod 0o600`
- Remove API key query parameter support (header-only authentication)

### Fixed
- Remove false seccomp claim from README
- Fix documentation inconsistencies (step count, provider count)
- Add honest command gate limitations documentation

### Added
- `bank-analysis` as a real builtin profile
- 74 new security regression tests (1202 total)

## [0.3.0] - 2026-03-19

### Added
- 5 new agent providers: Cursor, Aider, Goose, Gemini CLI, and Codex (9 total supported agents)
- Zero-config `lasso run <agent>` command that auto-selects profile and generates agent-specific configuration
- Agent alias resolution (e.g., `claude` resolves to `claude-code`)
- Git config auto-injection (`user.name`/`user.email` detected and passed into sandbox)
- Credential passthrough via `--env KEY=VALUE` and `--pass-env` CLI flags
- `extra_env` field on `SandboxProfile` for programmatic environment variable injection
- Profile Modes for gradual authorization (audit, standard, privileged)
- MCP server security policy enforcement with sandbox-level access control
- Security review framework for pre-deployment profile auditing
- Checkpoint versioning for tracking verified LASSO releases
- VS Code IDE support as fourth agent provider (shell wrapper, settings.json generation)
- `writable_paths` validation in `FilesystemConfig` to block system-critical mounts
- Database access blocking (SSMS/MSSQL, PostgreSQL, MySQL, MongoDB, Redis)
- GitHub OAuth device flow authentication
- Air-gapped deployment guide
- CI/CD pipeline examples for GitHub Actions, GitLab CI, and Azure DevOps
- Architecture documentation
- HTML presentation materials (English and Norwegian) with interactive demo
- Lasso rope SVG logo and branding
- 201 new tests (1640 total)

### Changed
- Renamed to "Layered Agent Sandbox Security Orchestrator"
- Profiles renamed: `data-analysis` to `offline`, `risk-analysis` to `strict`
- MCP server test coverage expanded from 40 to 73 tests
- Dashboard now surfaces all security controls on sandbox detail page
- Podman-first container strategy with Docker fallback

### Fixed
- Critical: profile mode was ignored in BLACKLIST command mode
- VS Code shell wrapper and Windows support issues
- 6 security issues in `writable_paths` validation and security audit
- Critical checkpoint versioning issues (file lock, HMAC signing, TOCTOU)
- 4 MCP server security bypass vulnerabilities (handshake requirement, null client enforcement)

## [0.2.0] - 2026-03-16

### Added
- REST API with 15+ endpoints: full CRUD for sandboxes, profile management, audit log access, system health
- API key authentication with `X-API-Key` header and rate limiting (100 req/min)
- MCP server with JSON-RPC 2.0 transport (7 tools: `sandbox_exec`, `sandbox_create/stop/status/list`, `file_read/write`)
- Enterprise dashboard with dark theme (1,700+ lines custom CSS, zero external dependencies)
  - Real-time HTMX live updates (5s refresh)
  - Terminal-style command executor
  - Tabbed profile editor (7 tabs, keyboard navigation)
  - Audit log viewer with filtering and pagination
  - Token authentication and CSRF protection
  - Mobile responsive with ARIA accessibility labels
- Python SDK for programmatic LASSO control (local + remote modes, context managers)
- Webhook support for sandbox events with HMAC signing, async dispatch, event filtering, and retry
- GitHub Copilot Enterprise provider with `copilot-instructions.md` and org auth system
- Warm pool for pre-provisioned sandbox containers
- Profile sharing: export/import with integrity hashes, versioning, team directories (`LASSO_PROFILE_DIR`), diff/compare tool
- State persistence across restarts via `~/.lasso/state.json`
- OpenAPI 3.0 spec (`GET /api/v1/openapi.json`) with Swagger UI at `/api/v1/docs`
- Prometheus metrics endpoint (`GET /metrics` with 5 metric families)
- Graceful shutdown handlers (SIGINT/SIGTERM/SIGBREAK, atexit)
- Audit log rotation (`max_log_size_mb` + `rotation_count`)
- Unicode lookalike path traversal attack blocking
- Compliance documentation: DORA mapping (Article 5-30), EU AI Act mapping (Article 9-15)
- Security threat model with CVE case studies
- Windows compatibility: platform-aware defaults, Docker Desktop path conversion, `ntpath.basename`, read-only file cleanup

### Changed
- Dashboard auth upgraded with CSRF protection on all POST forms
- Command gate expanded to 6-layer validation (null bytes, control chars, URL-encoded traversal, symlinks, dangerous args for 25+ commands, whitelist/blacklist)
- Network enforcement: iptables rules applied to containers on start
- Test suite: 576 unit + 96 security regression + 68 API + 40 MCP + 40 Copilot + 28 dashboard auth tests

## [0.1.0] - 2026-03-16

### Added
- Core sandbox orchestrator with Docker backend
- Command gate with whitelist/blacklist modes for controlling agent tool access
- Tamper-evident audit logging with SHA-256 hash chain verification
- Security profiles (`default`, `strict`, `permissive`) with TOML configuration
- Network policy enforcement (allow/deny rules per sandbox)
- Filesystem isolation with configurable read-only and writable mount paths
- Resource limits (CPU, memory, PIDs) per sandbox
- Agent providers: OpenCode, Claude Code, GitHub Copilot
- CLI: `lasso create`, `lasso exec`, `lasso stop`, `lasso audit`, `lasso profile`
- `lasso setup` for guided first-time configuration
- Dashboard web UI for sandbox monitoring and management

[1.6.3]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v1.6.2...v1.6.3
[1.6.2]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v1.6.1...v1.6.2
[1.6.1]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v1.5.3...v1.6.0
[1.5.3]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v1.5.2...v1.5.3
[1.5.2]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v1.5.1...v1.5.2
[1.5.1]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v1.4.5...v1.5.0
[1.4.5]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v1.4.4...v1.4.5
[1.4.4]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v1.4.3...v1.4.4
[1.4.3]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v1.4.2...v1.4.3
[1.4.2]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v0.4.1...v1.0.0
[0.4.1]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ClawWorksCo/lasso-sandbox/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ClawWorksCo/lasso-sandbox/releases/tag/v0.1.0
