"""Shared constants and console instances for LASSO CLI modules."""

from __future__ import annotations

from rich.console import Console

from lasso.agents.registry import AGENT_CLI_COMMANDS  # noqa: F401 — re-export

console = Console()
err_console = Console(stderr=True)

# Blocked environment variable keys (same set as the Pydantic validator in schema.py)
_BLOCKED_ENV_KEYS = {
    "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH",
    "DOCKER_HOST", "DOCKER_SOCK",
    "HOME", "USER", "SHELL", "LANG", "LC_ALL",
}
_BLOCKED_ENV_PREFIXES = ("LASSO_", "LD_")
