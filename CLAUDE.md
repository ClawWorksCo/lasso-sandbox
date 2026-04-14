# LASSO — Layered Agent Sandbox Security Orchestrator

## Project Overview
LASSO provides sandboxed execution environments for AI agents using containers (Docker/Podman) with configurable command blacklists, network access control, filesystem isolation, and tamper-evident audit logging. Designed for security-conscious teams and compliance-ready for regulated environments (DORA, EU AI Act, ISO 27001). Primary platform: Windows (via Docker/Podman), developed on Linux.

## Architecture
```
lasso/
├── agents/         ← AI agent provider support (2 providers)
│   ├── base.py           AgentProvider ABC, AgentType enum, AgentConfig
│   ├── claude_code.py    Claude Code provider (CLAUDE.md guardrails)
│   ├── opencode.py       OpenCode provider (plugin + opencode.json config)
│   ├── guardrails_export.py  Export guardrails for agents
│   ├── registry.py       Agent auto-detection and provider registry
│   └── plugins/
│       └── opencode-lasso-plugin.js  OpenCode sandbox plugin
├── auth/           ← Authentication
│   └── github.py         GitHub OAuth Device Flow (RFC 8628), token storage
├── backends/       ← Pluggable container backends
│   ├── base.py           ContainerBackend ABC (15-method interface)
│   ├── converter.py      SandboxProfile → ContainerConfig bridge
│   ├── detect.py         Auto-detect Docker/Podman
│   ├── docker_backend.py Docker SDK implementation (also works with Podman)
│   └── image_builder.py  Custom Dockerfile generation per profile
├── cli/
│   ├── main.py           Typer CLI: up, down, shell, attach, create, exec,
│   │                      status, stop, why, init, doctor, prebuild, dashboard
│   │                      Aliases: ps→status, rm→stop
│   │                      Flags: --quiet, --json on most commands
│   └── doctor.py         System diagnostics
├── config/
│   ├── schema.py         Pydantic models (SandboxProfile, NetworkPolicy, etc.)
│   ├── profile.py        TOML profile save/load
│   ├── defaults.py       5 builtin profiles (standard, open, offline, strict, evaluation)
│   ├── operational.py    Operational config (dashboard, defaults, audit, containers)
│   └── sharing.py        Profile export/import/diff/versioning, LASSO_PROFILE_DIR
├── core/
│   ├── sandbox.py        Sandbox orchestrator + SandboxRegistry (multi-sandbox management)
│   ├── commands.py       Command gate (multi-stage validation pipeline)
│   ├── audit.py          HMAC-signed, hash-chained JSONL audit logger + rotation
│   ├── audit_verify.py   Independent audit log verification
│   ├── checkpoint.py     Sandbox checkpoint management
│   ├── guardrails.py     Agent MD guardrails engine
│   ├── security_audit.py Security audit checks
│   ├── state.py          StateStore — persistent sandbox state to ~/.lasso/state.json
│   ├── webhooks.py       WebhookDispatcher — async audit event delivery with HMAC signatures
│   └── network.py        Network policy rules (iptables generation)
├── dashboard/
│   ├── app.py            Flask + HTMX web dashboard (create_app factory)
│   ├── auth.py           Dashboard token auth + CSRF protection
│   └── templates/        Jinja2 templates (Pico CSS, dark theme)
│       ├── base.html, index.html, sandbox.html, profiles.html, audit.html, check.html ...
│       └── partials/     HTMX partial templates (sandbox_table, audit_feed, exec_result ...)
├── profiles/             Built-in profile TOML files
└── utils/
    ├── crypto.py         HMAC signing, file hashing
    ├── filelock.py       Cross-platform file locking
    └── merge.py          Deep merge utility
```

## Running
```bash
lasso doctor                         # verify system + container runtime
lasso auth login                     # GitHub OAuth device flow
lasso init --profile standard        # bootstrap project with .lasso/
lasso up --dir .                     # create and start sandbox (auto-detects agent)
lasso create standard --dir .        # create sandbox with specific profile
lasso status                         # list all sandboxes (alias: lasso ps)
lasso exec <id> -- python3 test.py   # run command in sandbox
lasso attach <id>                    # attach to running sandbox
lasso shell <id>                     # open shell in sandbox
lasso stop <id>                      # stop sandbox (alias: lasso rm <id>)
lasso down                           # stop all sandboxes
lasso audit view ./audit/log.jsonl   # view audit trail
lasso audit verify ./audit/log.jsonl # verify HMAC integrity
lasso dashboard                      # web UI on :8080
lasso prebuild                       # pre-build container images
```

## Testing
```bash
python3 -m pytest tests/ -m "not integration" -q  # unit tests
python3 -m pytest tests/ -q                        # all tests incl. Docker
ruff check lasso/                                  # lint
```

## Key Design Decisions
- Container-based (Docker/Podman) for cross-platform Windows support
- TOML over YAML: YAML 1.1 parses bare "NO" (Norway ISO code) as boolean false
- Pluggable backend: ContainerBackend ABC, FakeBackend for testing
- Defense in depth: command gate + container isolation + network policy + guardrails + audit logging
- TDD: FakeBackend enables fast unit tests, Docker integration tests separate
- Custom images per profile: only whitelisted tools installed
- Multi-sandbox: SandboxRegistry manages concurrent sandboxes with persistent state
- Blacklist-default profiles: standard profile blocks dangerous commands, allows everything else
- 2 agent providers: Claude Code and OpenCode (subscription auth, no API keys)
