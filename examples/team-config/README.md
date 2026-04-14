# Team LASSO Configuration Template

This is a template repository for managing your team's LASSO sandbox configuration. Fork or copy it to create a shared, version-controlled configuration that all team members use.

## Contents

```
.
├── lasso-config.toml              # Operational settings (dashboard, audit)
├── profiles/
│   ├── team-development.toml      # Development sandbox (extends "standard")
│   └── team-strict.toml           # Compliance sandbox (extends "strict" profile)
├── templates/                     # Agent guardrails configs (pick the ones you use)
│   ├── CLAUDE.md                  # Claude Code guardrails
│   └── opencode.json              # OpenCode agent config
├── scripts/
│   ├── onboard.sh                 # Linux/macOS onboarding
│   └── onboard.ps1                # Windows onboarding
├── .github/workflows/
│   └── validate.yml               # CI: validate profiles on every push
└── pyproject.toml                 # Pins lasso-sandbox version
```

## Quick Start

### New team member onboarding

**Linux / macOS:**
```bash
git clone <this-repo>
cd <this-repo>
bash scripts/onboard.sh
```

**Windows (PowerShell):**
```powershell
git clone <this-repo>
cd <this-repo>
.\scripts\onboard.ps1
```

The onboarding script will:
1. Install `lasso-sandbox` (pinned version)
2. Copy team profiles to `~/.lasso/profiles/`
3. Copy team config to `~/.lasso/config.toml`
4. Verify the container runtime (Docker or Podman)
5. Run `lasso check` to validate the setup

### Alternative: Bootstrap via `lasso init`

Instead of running the onboarding script, you can point LASSO at this config repo directly:

```bash
lasso init --from-config /path/to/this-repo
```

This copies profiles, config, and templates into your project's `.lasso/` directory.

### Creating a sandbox

```bash
# Development work
lasso create team-development --dir .

# Compliance/audit work
lasso create team-strict --dir .
```

## Customizing

### Adding a new profile

1. Create `profiles/my-profile.toml`
2. Use `extends` to inherit from a built-in profile:
   ```toml
   extends = "standard"
   name = "my-profile"
   ```
3. Override only the fields you need
4. Push — CI will validate the TOML automatically

### Changing allowed network domains

Edit the `[network]` section in your profile:
```toml
[network]
mode = "restricted"
allowed_domains = [
    "pypi.org",
    "files.pythonhosted.org",
    "your-internal-registry.example.com",
]
```

### Configuring webhook alerts

Edit `lasso-config.toml`:
```toml
[[audit.webhooks]]
enabled = true
url = "https://your-siem.example.com/api/lasso-events"
events = ["violation", "lifecycle"]
secret = "your-hmac-secret"
```

### Agent configuration

The `templates/` directory contains guardrails configs for each supported agent. Copy the ones your team uses into your project:

```bash
# For Claude Code
cp templates/CLAUDE.md ./CLAUDE.md

# For OpenCode
cp templates/opencode.json ./opencode.json
```

Or use `lasso init` to generate and merge them automatically:

```bash
# Generate + merge with existing configs (won't overwrite what you have)
lasso init --agent claude-code --profile team-development --merge

# Use team templates as overlay
lasso init --agent claude-code --profile team-development --templates ./templates/
```

## CI Validation

The `.github/workflows/validate.yml` workflow runs `lasso config validate` on every push that modifies profiles or config files. This catches TOML syntax errors and invalid field values before they reach team members.

## Version Pinning

The `pyproject.toml` pins `lasso-sandbox>=1.6.3`. When upgrading LASSO:
1. Update the version in `pyproject.toml`
2. Update the version in both `scripts/onboard.sh` and `scripts/onboard.ps1`
3. Test profiles still validate: `lasso config validate profiles/*.toml`
4. Push and verify CI passes
