# Agent Guardrails Alignment

How LASSO agent configs relate to existing team guardrails, and how to compose them without conflict.

## Problem

Teams already have agent configuration files checked into their repos:
- `CLAUDE.md` with project-specific rules
- `.vscode/settings.json` with workspace preferences

Running `lasso init` must **compose** with these files, not silently overwrite them.

## Design Principle: Compose, Not Replace

LASSO generates agent configs that layer security policy on top of whatever the team already has. There are three composition modes:

| Mode | Flag | Behavior |
|------|------|----------|
| Default | (none) | Writes LASSO configs; merges `settings.json` |
| No overwrite | `--no-overwrite` | Skips any file that already exists on disk |
| Merge | `--merge` | Deep-merges with existing files on disk |
| Templates | `--templates DIR` | Overlays team templates onto LASSO output |

These flags work on both `lasso init` and `lasso agent config --write`.

## Composition Rules by File Type

### JSON files (`.json`)
Deep merge. LASSO config is the **base**, overlay values **win** on conflict.

- Dict keys are recursively merged
- List values are unioned (deduplicated, preserving order)
- Scalar values: overlay replaces base

Example: if your `.vscode/settings.json` has `"editor.fontSize": 14` and LASSO generates `"terminal.integrated.shell.linux": "/usr/bin/bash"`, the merged result contains both keys.

### Markdown files (`.md`)
Append. LASSO content comes first, then a horizontal rule separator (`---`), then the overlay/template content.

This preserves both LASSO security rules and team-specific instructions in a single file that agents read top-to-bottom.

### Other files
Full replacement. The template or existing file takes precedence over LASSO output. This covers formats where merging is ambiguous (YAML, TOML, plain text).

## Usage Examples

### Preserve existing configs during init
```bash
# Skip files your team already has
lasso init --profile development --no-overwrite
```

### Merge LASSO security into existing agent configs
```bash
# Deep-merge JSON, append markdown
lasso init --profile strict --merge
```

### Apply team templates
```bash
# Team keeps templates in .lasso-templates/
lasso init --profile development --templates .lasso-templates/

# Same works with agent config command
lasso agent config claude-code --write --templates .lasso-templates/
```

### Team template directory structure
```
.lasso-templates/
  CLAUDE.md              # Team rules appended after LASSO guardrails
  .vscode/
    settings.json        # Deep-merged with LASSO settings
```

## Dual Enforcement Model

LASSO provides defense-in-depth through two independent enforcement layers:

### Layer 1: Agent-Level Guardrails
Generated config files that tell the agent what it should and should not do. These are **advisory** -- the agent reads them and (usually) complies, but a jailbroken or buggy agent could ignore them.

- Blocked command lists in `CLAUDE.md`, `opencode.json`, etc.
- Permission denials in agent-native config formats
- Rules and conventions that shape agent behavior

### Layer 2: Container-Level Command Gate
The LASSO command gate intercepts every command the agent tries to execute inside the sandbox. This is **enforced** -- no command bypasses it regardless of what the agent decides.

- Whitelist/blacklist validation before execution
- Blocked argument patterns (e.g., `git push --force`)
- Network policy enforcement at the container level
- Filesystem isolation via container mounts

Both layers derive from the same LASSO profile, so they are always in sync. The agent-level guardrails reduce friction (the agent will not even attempt blocked commands), while the container-level gate provides the hard security boundary.

## Exporting Guardrails for Review

Use `lasso agent guardrails` to see exactly what a profile blocks:

```bash
# Human-readable table
lasso agent guardrails claude-code --profile strict

# Machine-readable JSON (for CI pipelines)
lasso agent guardrails opencode --profile development --json

# Merge with your team's existing denial list
lasso agent guardrails claude-code --existing "curl,wget,nc,ncat"
```

The `--existing` flag unions your team's denials with LASSO's profile-derived denials, giving you a single unified view of what the agent cannot do.

The JSON output includes:
- `blocked_commands`: sorted list of all blocked command patterns
- `command_mode`: whitelist or blacklist
- `whitelisted_commands`: the allowed command set (whitelist mode only)
- `network_mode`: none, restricted, or full
- `blocked_ports`: TCP ports the agent cannot reach
- `allowed_domains` / `blocked_domains`: domain-level network policy
- `isolation_level`: container, gvisor, or kata
- `mode`: observe, assist, or autonomous

## CI Integration

Export guardrails as JSON in CI to validate that your security policy has not drifted:

```yaml
# .github/workflows/lasso-check.yml
- name: Check guardrails
  run: |
    lasso agent guardrails claude-code --profile strict --json > guardrails.json
    diff guardrails.json expected-guardrails.json
```

## Workflow: Team Already Has Guardrails

1. **Do not replace** -- use `--no-overwrite` or `--merge`
2. **Verify alignment** -- run `lasso agent guardrails` to compare
3. **Export additions** -- let LASSO add its container-level restrictions on top of existing agent-level denials
4. **Test** -- verify commands are handled correctly at both layers before deploying

## Workflow: Starting Fresh

1. Run `lasso init --agent opencode --profile development`
2. Review generated configs in `.lasso/` and project root
3. Customize as needed for team requirements
4. Check configs into version control

## FAQ

**Q: What if I use `--merge` and `--templates` together?**
A: Templates are applied first (overlaid onto LASSO output), then the result is merged with existing files on disk. This gives you three layers: LASSO base + team template + existing on-disk config.

**Q: Does `--no-overwrite` prevent LASSO from creating new files?**
A: No. It only skips files that already exist. New files (ones LASSO generates that do not yet exist on disk) are always written.

**Q: Can I see what LASSO would write without actually writing?**
A: Yes. Use `lasso agent config <agent> --profile <profile>` without the `--write` flag to preview all generated files.

**Q: How do I combine `--no-overwrite` with `--templates`?**
A: Templates are applied to the in-memory LASSO output before any disk write. If the target file already exists and `--no-overwrite` is set, the entire file (including template overlay) is skipped.
