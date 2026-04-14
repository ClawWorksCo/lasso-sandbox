"""Claude Code agent provider — generates CLAUDE.md and settings from LASSO profiles.

Claude Code's permission model differs from OpenCode:
  - CLAUDE.md: instruction file with behavioral rules
  - .claude/settings.json: tool permissions (allowedTools, blockedCommands)
  - Permission modes: allowAll, askAll, or per-tool

LASSO generates both files, translating its universal policy into
Claude Code's native format.
"""

from __future__ import annotations

import json
import shutil
import subprocess

from lasso.agents.base import AgentConfig, AgentProvider, AgentType, generate_guardrails_markdown
from lasso.config.schema import CommandMode, NetworkMode, SandboxProfile


class ClaudeCodeProvider(AgentProvider):

    @property
    def agent_type(self) -> AgentType:
        return AgentType.CLAUDE_CODE

    @property
    def display_name(self) -> str:
        return "Claude Code"

    def is_installed(self) -> bool:
        return shutil.which("claude") is not None

    def get_version(self) -> str | None:
        try:
            result = subprocess.run(
                ["claude", "--version"],
                capture_output=True, timeout=5,
            )
            return result.stdout.decode("utf-8").strip()
        except Exception:
            return None

    def generate_config(self, profile: SandboxProfile) -> AgentConfig:
        settings = self._build_settings(profile)
        claude_md = self.generate_rules(profile)

        return AgentConfig(
            agent_type=self.agent_type,
            config_files={
                ".claude/settings.json": json.dumps(settings, indent=2),
            },
            rules_files={
                "CLAUDE.md": claude_md,
            },
            env_vars=self._build_env_vars(profile),
            command=self.get_start_command(),
        )

    def generate_rules(self, profile: SandboxProfile) -> str:
        """Generate CLAUDE.md with LASSO guardrails."""
        return generate_guardrails_markdown(profile, agent_name=self.display_name)

    def get_start_command(self, resume: bool = False) -> list[str]:
        cmd = ["claude"]
        if resume:
            cmd.append("--continue")
        return cmd

    def _build_settings(self, profile: SandboxProfile) -> dict:
        """Build .claude/settings.json from a LASSO profile."""
        settings: dict = {
            "permissions": self._build_permissions(profile),
            "env": self._build_env_vars(profile),
        }

        return settings

    def _build_permissions(self, profile: SandboxProfile) -> dict:
        """Translate LASSO policy to Claude Code permission format."""
        perms: dict = {}

        # Build allowed/denied tool lists
        allowed = []
        denied = []

        # Bash commands
        if profile.commands.mode == CommandMode.WHITELIST:
            for cmd in profile.commands.whitelist:
                allowed.append(f"Bash({cmd} *)")
            # Explicitly deny dangerous commands
            for cmd in ["rm", "dd", "mkfs", "reboot", "shutdown",
                        "mount", "umount", "chroot", "nsenter", "unshare"]:
                denied.append(f"Bash({cmd} *)")

        elif profile.commands.mode == CommandMode.BLACKLIST:
            for cmd in profile.commands.blacklist:
                denied.append(f"Bash({cmd} *)")

        # Network tools
        if profile.network.mode == NetworkMode.NONE:
            denied.extend([
                "WebFetch(*)",
                "WebSearch(*)",
                "Bash(curl *)",
                "Bash(wget *)",
                "Bash(ssh *)",
            ])

        # File tools — scope Write/Edit to working directory.
        # In strict/offline profiles, also restrict Read/Glob/Grep to the
        # working directory to prevent information leakage from the host
        # filesystem.  In standard/open profiles, broad read access is
        # acceptable since the agent is already inside a container.
        workdir = profile.filesystem.working_dir
        is_restrictive = (
            profile.network.mode in (NetworkMode.NONE, NetworkMode.RESTRICTED)
            or profile.name in ("strict", "offline")
        )
        if is_restrictive:
            allowed.extend([
                f"Read({workdir}/*)",
                f"Glob({workdir}/*)",
                f"Grep({workdir}/*)",
            ])
        else:
            allowed.extend([
                "Read(*)",
                "Glob(*)",
                "Grep(*)",
            ])
        allowed.extend([
            f"Write({workdir}/*)",
            f"Edit({workdir}/*)",
        ])

        perms["allowedTools"] = allowed
        perms["deniedTools"] = denied

        return perms

    def _build_env_vars(self, profile: SandboxProfile) -> dict:
        return {
            "LASSO_SANDBOX": "true",
            "LASSO_PROFILE": profile.name,
            "LASSO_NETWORK_MODE": profile.network.mode.value,
        }
