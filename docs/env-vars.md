# LASSO Environment Variables

All LASSO environment variables are optional. They override values from config
files (`~/.lasso/config.toml` and `.lasso/config.toml`).

## Precedence

From highest to lowest:

1. **Environment variables** (`LASSO_*`) -- documented below
2. **`LASSO_CONFIG`** -- path to an additional config file
3. **Project config** -- `.lasso/config.toml` in the working directory
4. **User config** -- `~/.lasso/config.toml`
5. **Built-in defaults**

## Configuration File Path

| Variable | Description | Example |
|----------|-------------|---------|
| `LASSO_CONFIG` | Path to an additional TOML config file. Loaded after project/user configs but before individual env var overrides. | `LASSO_CONFIG=/etc/lasso/team.toml` |

## Default Behavior

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `LASSO_DEFAULT_ISOLATION` | Container isolation backend. One of: `container`, `gvisor`, `kata`. | `container` | `LASSO_DEFAULT_ISOLATION=gvisor` |
| `LASSO_DEFAULT_PROFILE` | Profile to use when none is specified on the command line. | `development` | `LASSO_DEFAULT_PROFILE=strict` |
| `LASSO_DEFAULT_AGENT` | Default AI agent type (`claude-code` or `opencode`). | *(none)* | `LASSO_DEFAULT_AGENT=claude-code` |

## Dashboard

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `LASSO_DASHBOARD_PORT` | Port for the web dashboard. | `8080` | `LASSO_DASHBOARD_PORT=9090` |
| `LASSO_DASHBOARD_HOST` | Bind address for the dashboard. | `127.0.0.1` | `LASSO_DASHBOARD_HOST=0.0.0.0` |
| `LASSO_DASHBOARD_PUBLIC` | Whether to allow non-localhost access. Boolean: `true`/`1`/`yes` or `false`/`0`/`no`. | `false` | `LASSO_DASHBOARD_PUBLIC=true` |

## Audit

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `LASSO_AUDIT_DIR` | Default directory for audit log files. | `./audit` | `LASSO_AUDIT_DIR=/var/log/lasso/audit` |

## Containers

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `LASSO_BASE_IMAGE` | Default base Docker image for sandboxes. | `python:3.12-slim` | `LASSO_BASE_IMAGE=python:3.11-slim@sha256:abc123...` |

## Config File Format

The config file uses TOML. Here is a complete example with all defaults:

```toml
[defaults]
isolation = "container"
profile = "development"
# agent = "claude-code"  # optional

[dashboard]
port = 8080
host = "127.0.0.1"
public = false

[audit]
default_log_dir = "./audit"
# siem_webhook_url = "https://siem.example.com/webhook"  # optional

[containers]
base_image = "python:3.12-slim"
```

## Usage in CI/CD

Environment variables are ideal for CI pipelines where config files are not practical:

```yaml
# GitHub Actions example
env:
  LASSO_DEFAULT_ISOLATION: gvisor
  LASSO_DEFAULT_PROFILE: strict
  LASSO_AUDIT_DIR: /tmp/lasso-audit
```

## Verifying Configuration

Use `lasso config show` to see the fully resolved configuration (after all
layers are merged):

```bash
lasso config show           # pretty-print TOML
lasso config show --json    # JSON output
lasso config validate       # check config and profile files for errors
```
