"""Operational configuration — settings that control LASSO behavior.

Separate from security profiles (which define sandbox rules), operational
config controls things like dashboard port, default profile, and audit
log location.

Precedence (highest wins):
    1. Environment variables (LASSO_*)
    2. LASSO_CONFIG env var pointing to a file
    3. Project-level .lasso/config.toml
    4. User-level ~/.lasso/config.toml
    5. Built-in defaults
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import tomli
from pydantic import BaseModel, Field

from lasso.utils.paths import get_lasso_dir

logger = logging.getLogger("lasso.config.operational")


# ---------------------------------------------------------------------------
# Config section models
# ---------------------------------------------------------------------------


class DefaultsConfig(BaseModel):
    """Default isolation mode, profile, and agent."""

    isolation: str = Field(default="container", pattern=r"^(container|gvisor|kata)$")
    profile: str = Field(default="standard")
    agent: str | None = Field(default=None)


class DashboardConfig(BaseModel):
    """Dashboard server settings."""

    port: int = Field(default=8080, ge=1, le=65535)
    host: str = Field(default="127.0.0.1")
    public: bool = Field(default=False)


class AuditOperationalConfig(BaseModel):
    """Audit log defaults."""

    default_log_dir: str = Field(default="./audit")
    siem_webhook_url: str | None = Field(default=None)


class ContainersConfig(BaseModel):
    """Container runtime settings."""

    base_image: str = Field(default="python:3.12-slim")
    ca_cert_path: str | None = Field(default=None, description="Path to corporate CA cert (PEM format)")
    opencode_template: str = Field(
        default="docker/sandbox-templates:opencode",
        description="Sandbox-template image for OpenCode agent",
    )
    claude_code_template: str = Field(
        default="docker/sandbox-templates:claude-code",
        description="Sandbox-template image for Claude Code agent",
    )


class LassoConfig(BaseModel):
    """Top-level operational configuration."""

    defaults: DefaultsConfig = Field(default_factory=DefaultsConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    audit: AuditOperationalConfig = Field(default_factory=AuditOperationalConfig)
    containers: ContainersConfig = Field(default_factory=ContainersConfig)


# ---------------------------------------------------------------------------
# Environment variable mappings
# ---------------------------------------------------------------------------

_ENV_OVERRIDES: dict[str, tuple[str, str]] = {
    "LASSO_DEFAULT_ISOLATION": ("defaults", "isolation"),
    "LASSO_DEFAULT_PROFILE": ("defaults", "profile"),
    "LASSO_DEFAULT_AGENT": ("defaults", "agent"),
    "LASSO_AUDIT_DIR": ("audit", "default_log_dir"),
    "LASSO_DASHBOARD_PORT": ("dashboard", "port"),
    "LASSO_DASHBOARD_HOST": ("dashboard", "host"),
    "LASSO_DASHBOARD_PUBLIC": ("dashboard", "public"),
    "LASSO_BASE_IMAGE": ("containers", "base_image"),
    "LASSO_CA_CERT": ("containers", "ca_cert_path"),
    "LASSO_OPENCODE_TEMPLATE": ("containers", "opencode_template"),
    "LASSO_CLAUDE_CODE_TEMPLATE": ("containers", "claude_code_template"),
}


def _apply_env_overrides(config: LassoConfig) -> LassoConfig:
    """Apply environment variable overrides to config.

    Environment variables have the highest precedence — they override
    everything from config files.
    """
    data = config.model_dump()
    for env_var, (section, key) in _ENV_OVERRIDES.items():
        value = os.environ.get(env_var)
        if value is not None:
            # Type coercion based on the current (default or file-loaded) type
            current = data[section][key]
            if isinstance(current, bool):
                data[section][key] = value.lower() in ("true", "1", "yes")
            elif isinstance(current, int):
                try:
                    data[section][key] = int(value)
                except ValueError:
                    logger.warning("Invalid integer for %s: %s", env_var, value)
                    continue
            else:
                data[section][key] = value
    return LassoConfig(**data)


# ---------------------------------------------------------------------------
# Deep merge utility
# ---------------------------------------------------------------------------


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep merge two dicts. Override values win for leaf keys."""
    from lasso.utils.merge import deep_merge
    return deep_merge(base, override, list_strategy="replace")


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------


def load_config(
    working_dir: str = ".",
    config_path: str | None = None,
) -> LassoConfig:
    """Load operational config with layered precedence.

    Precedence (highest wins):
        1. Environment variables (LASSO_*)
        2. LASSO_CONFIG env var pointing to a file
        3. Project-level config (``config_path`` or ``<working_dir>/.lasso/config.toml``)
        4. User-level config (``~/.lasso/config.toml``)
        5. Built-in defaults

    Args:
        working_dir: Project directory to look for ``.lasso/config.toml``.
        config_path: Explicit path to a project config file.

    Returns:
        Fully resolved :class:`LassoConfig`.
    """
    data: dict = {}

    # Layer 1 — user-level config (~/.lasso/config.toml)
    user_config = get_lasso_dir() / "config.toml"
    if user_config.exists():
        try:
            with open(user_config, "rb") as f:
                user_data = tomli.load(f)
            data = _deep_merge(data, user_data)
        except Exception as e:
            logger.warning("Failed to load user config %s: %s", user_config, e)

    # Layer 2 — project-level config
    if config_path:
        project_config = Path(config_path)
    else:
        project_config = Path(working_dir) / ".lasso" / "config.toml"

    if project_config.exists():
        try:
            with open(project_config, "rb") as f:
                project_data = tomli.load(f)
            data = _deep_merge(data, project_data)
        except Exception as e:
            logger.warning("Failed to load project config %s: %s", project_config, e)

    # Layer 3 — LASSO_CONFIG env var
    env_config = os.environ.get("LASSO_CONFIG")
    if env_config:
        env_config_path = Path(env_config)
        if env_config_path.exists():
            try:
                with open(env_config_path, "rb") as f:
                    env_data = tomli.load(f)
                data = _deep_merge(data, env_data)
            except Exception as e:
                logger.warning("Failed to load LASSO_CONFIG %s: %s", env_config, e)

    # Build config from merged file data
    config = LassoConfig(**data) if data else LassoConfig()

    # Layer 4 — environment variable overrides (highest precedence)
    config = _apply_env_overrides(config)

    return config
