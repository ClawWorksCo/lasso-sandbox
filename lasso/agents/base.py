"""Agent provider interface — abstracts how LASSO configures and launches AI coding agents.

Each agent (OpenCode, Claude Code, etc.) has its own config format, permission
model, and rules files. LASSO translates its universal SandboxProfile into
agent-specific configurations, then launches the agent inside a sandboxed container.

Defense-in-depth:
  Layer 1: Container isolation (Docker/Podman)
  Layer 2: Agent-native permissions (generated from LASSO profile)
  Layer 3: LASSO command gate (pre-filters before agent executes)
  Layer 4: Tamper-evident audit logging
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from lasso.config.schema import CommandMode, NetworkMode, SandboxProfile


def generate_guardrails_markdown(profile: SandboxProfile, agent_name: str = "") -> str:
    """Generate markdown guardrails content from a sandbox profile.

    This is the shared implementation used by all agent providers.
    Each provider's ``generate_rules()`` delegates here so the guardrails
    format stays consistent across agents.
    """
    rules = [
        f"# LASSO Secured Environment \u2014 {profile.name}",
        "",
        f"You are operating inside a LASSO sandbox (profile: `{profile.name}`).",
        "The following constraints are enforced at both the agent and container level.",
        "",
    ]

    # Command restrictions
    if profile.commands.mode == CommandMode.WHITELIST:
        rules.append("## Allowed Commands")
        rules.append("ONLY use the following commands:")
        rules.append("")
        for cmd in sorted(profile.commands.whitelist):
            rules.append(f"- `{cmd}`")
        rules.append("")
        rules.append("All other commands will be **blocked by the sandbox**. Do not attempt them.")
    else:
        rules.append("## Blocked Commands")
        rules.append("Do NOT use any of these commands:")
        rules.append("")
        for cmd in sorted(profile.commands.blacklist):
            rules.append(f"- `{cmd}`")
    rules.append("")

    # Blocked argument patterns
    if profile.commands.blocked_args:
        rules.append("## Restricted Arguments")
        for cmd, patterns in profile.commands.blocked_args.items():
            for p in patterns:
                rules.append(f"- `{cmd} {p}` \u2014 blocked")
        rules.append("")

    # Network
    rules.append("## Network Access")
    if profile.network.mode == NetworkMode.NONE:
        rules.append("**No network access.** Do not attempt curl, wget, fetch, or any network operations.")
        rules.append("Do not use WebFetch or WebSearch tools.")
    elif profile.network.mode == NetworkMode.RESTRICTED:
        rules.append("Network is restricted. Only these domains are reachable:")
        for domain in profile.network.allowed_domains:
            rules.append(f"- `{domain}`")
        rules.append("")
        rules.append("All other domains are blocked at the network level.")
    else:
        rules.append("Network access is unrestricted.")
    rules.append("")

    # Filesystem
    rules.append("## Filesystem")
    rules.append(f"- Working directory: `{profile.filesystem.working_dir}`")
    rules.append("- Do NOT read or write files outside the working directory.")
    rules.append("- System paths (`/etc`, `/usr`, etc.) are read-only.")
    if profile.filesystem.hidden_paths:
        rules.append("- The following paths are hidden and inaccessible:")
        for p in profile.filesystem.hidden_paths:
            rules.append(f"  - `{p}`")
    rules.append("")

    # Compliance
    rules.append("## Compliance & Audit")
    rules.append("- Every action is recorded in a tamper-evident, HMAC-signed audit log.")
    rules.append("- Do not include personally identifiable information (PII) in outputs.")
    rules.append("- Do not attempt to exfiltrate any data outside the sandbox.")
    rules.append("- Violations will be logged, flagged, and may terminate the session.")
    if profile.tags:
        rules.append(f"- Compliance: {', '.join(profile.tags)}")
    rules.append("")

    # Guardrail rules
    if profile.guardrails.rules:
        rules.append("## Guardrail Rules")
        for rule in profile.guardrails.rules:
            if rule.enabled:
                marker = {"critical": "CRITICAL", "error": "ERROR",
                          "warning": "WARN", "info": "INFO"}.get(rule.severity, "INFO")
                rules.append(f"- **[{marker}]** {rule.description}")
        rules.append("")

    return "\n".join(rules)


class AgentType(str, Enum):
    OPENCODE = "opencode"
    CLAUDE_CODE = "claude-code"


@dataclass
class AgentConfig:
    """Generated agent-specific configuration files."""
    agent_type: AgentType
    config_files: dict[str, str]  # relative_path → content
    rules_files: dict[str, str]   # relative_path → content
    env_vars: dict[str, str] = field(default_factory=dict)
    command: list[str] = field(default_factory=list)  # command to start the agent

    @staticmethod
    def merge_json_configs(base: dict, overlay: dict) -> dict:
        """Deep merge two JSON configs. Overlay values win on conflict.

        - dict + dict: recursively merged
        - list + list: union (deduplicated, preserving order)
        - all other types: overlay replaces base
        """
        result = base.copy()
        for key, value in overlay.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = AgentConfig.merge_json_configs(result[key], value)
            elif key in result and isinstance(result[key], list) and isinstance(value, list):
                # Union lists, deduplicate while preserving order.
                # Cannot use dict.fromkeys() because list elements may be
                # unhashable (e.g. dicts).  Fall back to an O(n^2) scan for
                # elements that are not hashable.
                seen: list = []
                deduped: list = []
                for item in result[key] + value:
                    try:
                        if item not in seen:
                            seen.append(item)
                            deduped.append(item)
                    except TypeError:
                        # Unhashable and comparison fails — include it
                        deduped.append(item)
                result[key] = deduped
            else:
                result[key] = value
        return result

    @staticmethod
    def merge_markdown_configs(base: str, overlay: str) -> str:
        """Append overlay content after base content for markdown configs.

        Inserts a horizontal rule separator between the two sections so the
        resulting file has clear provenance (LASSO-generated vs team template).
        """
        return f"{base.rstrip()}\n\n---\n\n{overlay.strip()}\n"


class AgentProvider(ABC):
    """Abstract interface for AI coding agent providers."""

    @property
    @abstractmethod
    def agent_type(self) -> AgentType:
        """The agent type identifier."""

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable name for display."""

    @abstractmethod
    def is_installed(self) -> bool:
        """Check if this agent is installed on the system."""

    @abstractmethod
    def get_version(self) -> str | None:
        """Get the installed version, or None if not installed."""

    @abstractmethod
    def generate_config(self, profile: SandboxProfile) -> AgentConfig:
        """Generate agent-specific config from a LASSO SandboxProfile.

        This translates LASSO's universal security policy into the agent's
        native configuration format — permissions, rules, tool access, etc.
        """

    @abstractmethod
    def generate_rules(self, profile: SandboxProfile) -> str:
        """Generate the agent's rules/instructions file content.

        For OpenCode: AGENTS.md
        For Claude Code: CLAUDE.md
        """

    @abstractmethod
    def get_start_command(self, resume: bool = False) -> list[str]:
        """Command to launch the agent inside the sandbox.

        Args:
            resume: When True, append agent-specific flags to continue
                    an existing session (e.g. ``--continue`` for OpenCode).
        """

    def info(self) -> dict[str, Any]:
        """Agent provider summary."""
        return {
            "type": self.agent_type.value,
            "name": self.display_name,
            "installed": self.is_installed(),
            "version": self.get_version(),
        }
