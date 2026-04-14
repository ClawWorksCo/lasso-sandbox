# LASSO

Run AI coding agents safely inside sandboxed Docker containers.

LASSO wraps Claude Code, OpenCode, and other AI agents in isolated containers with command filtering, network control, and tamper-evident audit logging. Every action the agent takes is controlled and recorded.

## Quick Start

```bash
pip install lasso-sandbox

# Pre-build images (one time, ~2 min)
lasso prebuild

# Start coding with Claude Code
lasso up --agent claude-code --dir ~/my-project

# Or start from the dashboard
lasso dashboard
```

That's it. Claude Code opens in a sandboxed terminal with your project files mounted.

## What It Does

When an AI agent runs inside LASSO:

- **Dangerous commands are blocked** — `rm`, `docker`, `sudo`, `ssh`, `nc`, and 30+ others can't execute
- **Network is controlled** — only package registries and AI APIs are reachable (configurable)
- **Files are isolated** — the agent can only see your project directory, nothing else
- **Everything is logged** — every command is recorded with tamper-proof signatures
- **Your code stays on your machine** — files are mounted from your computer, never copied into the container

## Commands

```bash
lasso up                              # Start a sandbox (auto-detect agent + profile)
lasso up --agent claude-code          # Start with Claude Code
lasso up --agent opencode             # Start with OpenCode
lasso down                            # Stop all sandboxes

lasso shell --agent claude-code       # Create sandbox + drop into terminal
lasso attach <id>                     # Reconnect to a running sandbox
lasso status                          # List running sandboxes
lasso stop <id>                       # Stop a sandbox

lasso why "pip install requests"      # Check if a command would be allowed
lasso dashboard                       # Open the web dashboard
lasso prebuild                        # Pre-build container images
```

## Dashboard

The web dashboard is the easiest way to use LASSO:

```bash
lasso dashboard
# Opens at http://127.0.0.1:8080
```

From the dashboard you can:
- Create sandboxes with one click (pick agent + security profile)
- Open a terminal window connected to any running sandbox
- View and edit security profiles visually
- Browse activity logs
- Create custom profiles with the profile editor

## Security Profiles

LASSO comes with 5 built-in profiles:

| Profile | Commands | Internet | Best For |
|---------|----------|----------|----------|
| **standard** | Block dangerous, allow rest | Package registries + AI APIs | Everyday coding |
| **open** | Block dangerous, allow rest | Full internet | Research, browsing docs |
| **offline** | Block dangerous, allow rest | None | Sensitive data work |
| **strict** | Approved commands only | None | Compliance-critical work |
| **evaluation** | Read-only only | None | Testing untrusted agents |

Create custom profiles via the dashboard or TOML files:

```toml
# team-secure.toml
extends = "strict"
name = "team-secure"

[commands.blocked_args]
git = ["push --force", "config --global"]
```

## How It Works

```
lasso up --agent claude-code --dir ~/my-project

1. Loads the "standard" security profile
2. Creates a Docker container from a pre-built image
3. Mounts ~/my-project as /workspace (read-write)
4. Mounts ~/.claude for authentication (read-write)
5. Applies network firewall rules (iptables)
6. Starts Claude Code inside the container
7. Logs everything to a tamper-evident audit trail

Inside the container:
- Non-root user (uid 1000)
- Read-only root filesystem
- All capabilities dropped
- No new privileges allowed
- Database ports blocked
- Cloud metadata blocked
```

## Container Security

> **Note:** In interactive mode (`lasso up`, `lasso shell`), the agent has a raw PTY inside the container. The command gate and per-command audit logging apply only to `lasso exec` commands. Interactive sessions rely on container-level isolation (cap_drop ALL, no-new-privileges, read-only root, network policy).

Every sandbox has these protections:

- `cap_drop: ALL` — no Linux capabilities
- `no-new-privileges` — prevents privilege escalation
- Read-only root filesystem
- Non-root user (uid 1000)
- Resource limits (memory, CPU, PIDs)
- Database port blocking (PostgreSQL, MySQL, MSSQL, etc.)
- IPv4 + IPv6 firewall rules
- iptables binaries removed after rule setup

## Audit Trail

Every command is logged with HMAC-SHA256 signatures in a hash chain:

```bash
lasso audit view audit/<id>.jsonl     # View the audit trail
lasso audit verify audit/<id>.jsonl   # Verify chain integrity
```

Each entry records: timestamp, command, outcome (allowed/blocked), reason, and a tamper-proof signature.

## Extra Folder Mounts

Mount additional directories into the sandbox:

```bash
# Read-write mount
lasso shell --agent claude-code --dir ~/project --mount ~/data:/data

# Read-only mount for shared context
lasso shell --agent claude-code --dir ~/project --mount ~/team-docs:/context:ro
```

## Requirements

- Python 3.10+
- Docker Desktop or Podman
- ~2 GB disk for container images

## Install

```bash
# From PyPI
pip install lasso-sandbox

# With all extras (dashboard + Docker SDK + keyring)
pip install lasso-sandbox[all]

# From source
git clone https://github.com/ClawWorksCo/lasso-sandbox.git
cd lasso-sandbox
pip install -e ".[all]"
```

## License

Apache 2.0
