"""Composable agent guardrails export.

Translates a LASSO SandboxProfile's command/network policy into a
provider-agnostic guardrails config that teams can review, version-control,
and compose with their own existing denial lists.

Usage:
    from lasso.agents.guardrails_export import export_agent_guardrails
    guardrails = export_agent_guardrails("claude-code", profile)
"""

from __future__ import annotations

from typing import Any

from lasso.config.schema import CommandMode, SandboxProfile


def export_agent_guardrails(
    agent_type: str,
    profile: SandboxProfile,
    existing_denials: list[str] | None = None,
) -> dict[str, Any]:
    """Generate agent permission configs matching a profile's command policy.

    Combines the profile's blocked commands/args with optional existing
    team denials to produce a unified agent guardrails config.

    Parameters
    ----------
    agent_type:
        The agent type string (e.g. "claude-code", "opencode").
    profile:
        The sandbox profile whose command and network policies to export.
    existing_denials:
        Optional list of existing team-level command denials to merge in.
        These are unioned with the profile-derived denials.

    Returns
    -------
    dict with keys:
        - agent_type: the agent identifier
        - profile: the profile name
        - blocked_commands: sorted list of blocked command strings
        - network_mode: the network isolation mode
        - blocked_ports: list of blocked TCP ports
        - allowed_domains: list of allowed domains (restricted mode)
        - blocked_domains: list of explicitly blocked domains
        - isolation_level: container/gvisor/kata
        - mode: the profile's authorization mode (observe/assist/autonomous)
    """
    blocked: set[str] = set()

    # From profile blacklist (always blocked regardless of mode)
    for cmd in profile.commands.blacklist:
        blocked.add(cmd)

    # Blocked args become specific denials (e.g. "git push --force")
    for cmd, args in profile.commands.blocked_args.items():
        for arg in args:
            blocked.add(f"{cmd} {arg}")

    # In whitelist mode, we note non-whitelisted commands are implicitly blocked
    # but we can't enumerate them -- the blocked set only contains explicit denials

    # Add existing team denials
    if existing_denials:
        blocked.update(existing_denials)

    return {
        "agent_type": agent_type,
        "profile": profile.name,
        "blocked_commands": sorted(blocked),
        "network_mode": profile.network.mode.value,
        "blocked_ports": profile.network.blocked_ports,
        "allowed_domains": profile.network.allowed_domains,
        "blocked_domains": profile.network.blocked_domains,
        "isolation_level": profile.isolation,
        "mode": profile.mode.value,
        "command_mode": profile.commands.mode.value,
        "whitelisted_commands": (
            sorted(profile.commands.whitelist)
            if profile.commands.mode == CommandMode.WHITELIST
            else None
        ),
    }
