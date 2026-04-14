# Contributing to LASSO

Thank you for your interest in contributing to LASSO. This guide covers how to set up a development environment, run tests, and submit changes.

## Getting Started

### Prerequisites

- Python 3.10+
- Docker (for integration tests)
- Git

### Install for Development

```bash
git clone https://github.com/ClawWorksCo/lasso-sandbox.git
cd lasso-sandbox
pip install -e ".[dev]"
```

This installs LASSO in editable mode along with all development dependencies (pytest, ruff, etc.).

## Running Tests

**Unit tests only** (fast, no Docker required):

```bash
python3 -m pytest tests/ -m "not integration" -q
```

**All tests** (unit + integration, requires Docker):

```bash
python3 -m pytest tests/ -q
```

All tests must pass before submitting a PR.

## Code Style

- **Formatter/linter**: [ruff](https://docs.astral.sh/ruff/), configured in `pyproject.toml`. Run `ruff check .` and `ruff format .` before committing.
- **Data models**: [pydantic](https://docs.pydantic.dev/) for all configuration and data models.
- **CLI**: [typer](https://typer.tiangolo.com/) for command-line interface.
- **Output**: [rich](https://rich.readthedocs.io/) for terminal output and formatting.

## Commit Messages

We prefer [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add timeout option to sandbox profiles
fix: prevent command gate bypass via shell expansion
docs: update Windows setup guide
test: add integration tests for network isolation
```

## Submitting a Pull Request

### PR Checklist

Before opening a PR, verify:

- [ ] All tests pass (`python3 -m pytest tests/ -q`).
- [ ] `CHANGELOG.md` is updated with a summary of your changes.
- [ ] No new security warnings from `ruff check .`.
- [ ] New functionality includes corresponding tests.
- [ ] Code follows the style guidelines above.

### Process

1. Fork the repository and create a feature branch.
2. Make your changes and commit with descriptive messages.
3. Push your branch and open a PR against `main`.
4. Address any review feedback.

## Security-Sensitive Areas

The following files and directories require extra scrutiny during review. Changes to these areas will receive additional review from maintainers:

| Path | Concern |
|------|---------|
| `lasso/core/commands.py` | Command gate -- controls which commands agents can execute |
| `lasso/core/audit.py` | Audit log signing -- integrity of the tamper-evident log |
| `lasso/backends/` | Container configuration -- sandbox isolation boundaries |
| `lasso/core/network.py` | iptables rules -- network isolation enforcement |

If your PR touches any of these areas, please include a brief security rationale in the PR description explaining why the change is safe.

## Questions?

Open a [GitHub Discussion](https://github.com/ClawWorksCo/lasso-sandbox/discussions) or file an issue. We are happy to help.
