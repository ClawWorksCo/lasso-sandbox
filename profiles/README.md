# LASSO Profiles

Pre-built sandbox security policies. Each profile defines what an AI agent
can and cannot do inside a sandbox.

## Built-in Profiles

| Profile | Network | Commands | Use Case |
|---------|---------|----------|----------|
| `standard` | Limited (package registries) | Allowlist | Everyday coding with git, npm, pip, python |
| `open` | Limited (package registries) | Blocklist | Maximum flexibility, dangerous commands blocked |
| `offline` | Offline (no network) | Allowlist | Air-gapped work, no external access |
| `strict` | Offline (no network) | Allowlist | High-security work, full audit trail |
| `evaluation` | Offline (no network) | Minimal allowlist | Evaluating untrusted agents, read-only |

## Using Profiles

```bash
# Create a sandbox with a specific profile
lasso create standard --dir .

# Or use lasso up (auto-detects the best profile)
lasso up
```

## Customizing

Create team profiles that extend built-ins:

```toml
# team-secure.toml
extends = "strict"
name = "team-secure"
description = "Team profile with custom allowed repos"

[git_access]
allowed_repos = ["myorg/my-repo"]
```

Save to `~/.lasso/profiles/team-secure.toml` or use the dashboard
profile editor to create profiles visually.

## Dashboard

The LASSO dashboard provides a visual profile editor for creating and
customizing profiles without editing TOML files. Run `lasso dashboard`
to access it.
