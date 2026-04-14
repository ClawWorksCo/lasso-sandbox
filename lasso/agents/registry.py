"""Agent registry — discover and manage available agent providers.

Priority: OpenCode first (bank default), Claude Code second.
"""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path

logger = logging.getLogger("lasso.agents.registry")

from lasso.agents.base import AgentConfig, AgentProvider, AgentType

# Ordered by priority — OpenCode first
_PROVIDERS: list[type[AgentProvider]] = []


def _load_providers() -> list[type[AgentProvider]]:
    """Lazy-load provider classes."""
    global _PROVIDERS
    if not _PROVIDERS:
        from lasso.agents.claude_code import ClaudeCodeProvider
        from lasso.agents.opencode import OpenCodeProvider
        _PROVIDERS = [
            OpenCodeProvider, ClaudeCodeProvider,
        ]
    return _PROVIDERS


def get_provider(agent_type: AgentType) -> AgentProvider:
    """Get a specific provider by type."""
    for cls in _load_providers():
        provider = cls()
        if provider.agent_type == agent_type:
            return provider
    raise ValueError(f"Unknown agent type: {agent_type}")


def detect_agent() -> AgentProvider | None:
    """Auto-detect the best available agent. OpenCode first, then Claude Code."""
    for cls in _load_providers():
        provider = cls()
        if provider.is_installed():
            return provider
    return None


def list_agents() -> list[dict]:
    """List all known agents with their availability status."""
    results = []
    for cls in _load_providers():
        provider = cls()
        results.append(provider.info())
    return results


# Mapping of friendly agent names to AgentType values.
# Allows users to type `lasso shell --agent claude` instead of `lasso run claude-code`.
AGENT_ALIASES: dict[str, AgentType] = {
    "opencode": AgentType.OPENCODE,
    "claude": AgentType.CLAUDE_CODE,
    "claude-code": AgentType.CLAUDE_CODE,
}

# CLI binary names for each agent type.
# Used by cli/main.py (to exec into containers) and core/sandbox.py (to
# whitelist agent binaries).
AGENT_CLI_COMMANDS: dict[str, list[str]] = {
    "claude-code": ["claude"],
    "opencode": ["opencode"],
}

# Default profile to use for each agent type when running zero-config.
AGENT_DEFAULT_PROFILES: dict[AgentType, str] = {
    AgentType.OPENCODE: "standard",
    AgentType.CLAUDE_CODE: "standard",
}


def resolve_agent_alias(name: str) -> AgentType | None:
    """Resolve a user-friendly agent name to an AgentType, or None if not an agent."""
    return AGENT_ALIASES.get(name.lower())


def _merge_settings_json(existing_text: str, new_text: str) -> str:
    """Merge LASSO keys into an existing settings.json, preserving user keys.

    Uses deep merge so nested objects are merged recursively rather than
    replaced wholesale.

    If the existing file is not valid JSON, raises ``json.JSONDecodeError``
    so the caller can fall back to backing up and overwriting.
    """
    existing = json.loads(existing_text)
    new = json.loads(new_text)
    merged = AgentConfig.merge_json_configs(existing, new)
    return json.dumps(merged, indent=2)


def write_agent_config(
    config: AgentConfig,
    target_dir: str | Path,
    templates_dir: str | Path | None = None,
    no_overwrite: bool = False,
    merge: bool = False,
) -> list[Path]:
    """Write generated agent config files to a directory.

    Parameters
    ----------
    config:
        The agent configuration produced by a provider.
    target_dir:
        Root directory where config files are written.
    templates_dir:
        Optional directory containing team template overrides.  If a file
        with the same relative path exists in ``templates_dir``, it is
        composed with the LASSO-generated content:

        - ``.json`` files: deep-merged (LASSO as base, template as overlay)
        - ``.md`` files: template content appended after LASSO content
        - Other files: template replaces LASSO output entirely
    no_overwrite:
        When True, skip any file that already exists on disk.
    merge:
        When True and a target file already exists, merge LASSO output into
        it (JSON deep-merge or markdown append) instead of overwriting.

    Returns list of paths written.
    """
    target = Path(target_dir)
    templates = Path(templates_dir) if templates_dir else None
    written: list[Path] = []

    all_files: dict[str, str] = {}
    all_files.update(config.config_files)
    all_files.update(config.rules_files)

    for rel_path, content in all_files.items():
        dest = target / rel_path

        # Path traversal protection: ensure dest stays within target dir
        try:
            resolved_dest = dest.resolve()
            resolved_target = target.resolve()
            if not (resolved_dest == resolved_target or resolved_target in resolved_dest.parents):
                logger.warning("Path traversal blocked in agent config: %s", rel_path)
                continue
        except (OSError, ValueError):
            logger.warning("Invalid path in agent config: %s", rel_path)
            continue

        # --no-overwrite: skip files that already exist
        if no_overwrite and dest.exists():
            continue

        # Apply team template overlay if available
        if templates:
            template_file = templates / rel_path
            if template_file.is_file():
                template_content = template_file.read_text(encoding="utf-8")
                content = _apply_template_overlay(content, template_content, rel_path)

        # --merge: merge with existing file on disk
        if merge and dest.exists():
            existing_content = dest.read_text(encoding="utf-8")
            content = _apply_template_overlay(existing_content, content, rel_path)

        dest.parent.mkdir(parents=True, exist_ok=True)

        # Legacy merge-or-backup logic for settings.json — use file lock
        # to prevent read-modify-write races with concurrent processes.
        if dest.name == "settings.json" and dest.exists() and not merge:
            from lasso.utils.filelock import locked_file
            try:
                with locked_file(str(dest), "r+") as f:
                    existing_text = f.read()
                    merged = _merge_settings_json(existing_text, content)
                    f.seek(0)
                    f.write(merged)
                    f.truncate()
            except (json.JSONDecodeError, ValueError):
                backup = dest.with_suffix(".json.bak")
                shutil.copy2(dest, backup)
                dest.write_text(content, encoding="utf-8")
        else:
            dest.write_text(content, encoding="utf-8")
        written.append(dest)

    return written


def _apply_template_overlay(base_content: str, overlay_content: str, rel_path: str) -> str:
    """Merge overlay content into base content based on file type.

    - .json: deep merge (base as base, overlay wins on conflict)
    - .md: append overlay after base with separator
    - Other: overlay replaces base entirely
    """
    suffix = Path(rel_path).suffix.lower()

    if suffix == ".json":
        try:
            base_dict = json.loads(base_content)
            overlay_dict = json.loads(overlay_content)
            merged = AgentConfig.merge_json_configs(base_dict, overlay_dict)
            return json.dumps(merged, indent=2)
        except (json.JSONDecodeError, ValueError):
            # If either side is invalid JSON, overlay replaces
            return overlay_content

    if suffix == ".md":
        return AgentConfig.merge_markdown_configs(base_content, overlay_content)

    # All other file types: overlay replaces entirely
    return overlay_content
