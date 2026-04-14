"""OpenCode agent provider — generates opencode.json and AGENTS.md from LASSO profiles.

OpenCode's permission system maps cleanly to LASSO's:
  - bash permissions: pattern-based ("git *": "allow", "*": "deny")
  - edit permissions: path-based ("*.py": "allow", "*": "deny")
  - external_directory: "deny" (stay in sandbox)
  - tools: enable/disable per tool

LASSO generates both the config and the rules file, injecting guardrails
that the agent must follow. This is defense-in-depth — even if a command
passes OpenCode's permission system, the container still blocks it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from lasso.agents.base import AgentConfig, AgentProvider, AgentType, generate_guardrails_markdown
from lasso.config.schema import CommandMode, NetworkMode, SandboxProfile


class OpenCodeProvider(AgentProvider):

    @property
    def agent_type(self) -> AgentType:
        return AgentType.OPENCODE

    @property
    def display_name(self) -> str:
        return "OpenCode"

    def is_installed(self) -> bool:
        return shutil.which("opencode") is not None

    def get_version(self) -> str | None:
        try:
            result = subprocess.run(
                ["opencode", "version"],
                capture_output=True, timeout=5,
            )
            return result.stdout.decode("utf-8").strip() or result.stderr.decode("utf-8").strip()
        except Exception:
            return None

    def generate_config(self, profile: SandboxProfile) -> AgentConfig:
        plugin_js = self._get_plugin_source()
        opencode_json = self._build_opencode_json(profile, has_plugin=bool(plugin_js))
        agents_md = self.generate_rules(profile)

        config_files = {
            "opencode.json": json.dumps(opencode_json, indent=2),
        }
        if plugin_js:
            config_files[".opencode/plugins/lasso-security.js"] = plugin_js

        return AgentConfig(
            agent_type=self.agent_type,
            config_files=config_files,
            rules_files={
                "AGENTS.md": agents_md,
            },
            env_vars=self._build_env_vars(profile),
            command=self.get_start_command(),
        )

    def generate_rules(self, profile: SandboxProfile) -> str:
        """Generate AGENTS.md with LASSO guardrails injected."""
        return generate_guardrails_markdown(profile, agent_name=self.display_name)

    def get_start_command(self, resume: bool = False) -> list[str]:
        cmd = ["opencode"]
        if resume:
            cmd.append("--continue")
        return cmd

    def _build_opencode_json(self, profile: SandboxProfile, has_plugin: bool = False) -> dict:
        """Build the opencode.json config from a LASSO profile."""
        config: dict = {
            "$schema": "https://opencode.ai/config.json",
            "permission": self._build_permissions(profile),
            "tools": self._build_tools(profile),
        }

        # Disable auto-update in sandbox
        config["autoupdate"] = False

        # Disable sharing
        config["share"] = "disabled"

        # Point instructions at our generated AGENTS.md
        config["instructions"] = ["AGENTS.md"]

        # Register the LASSO security plugin only if the plugin file exists
        if has_plugin:
            config["plugin"] = [".opencode/plugins/lasso-security.js"]

        # Include LLM provider auth settings if configured
        if profile.agent_auth and profile.agent_auth.opencode_provider:
            config["provider"] = profile.agent_auth.opencode_provider
            config["api_key_env"] = profile.agent_auth.opencode_api_key_env

        return config

    def _build_permissions(self, profile: SandboxProfile) -> dict:
        """Translate LASSO command/network/filesystem policy to OpenCode permissions."""
        perms: dict = {}

        # --- Bash permissions ---
        # Build bash_perms with careful insertion order: per-command rules
        # first, wildcard ("*") last, so that specific denials take
        # precedence in consumers that evaluate rules in order.
        bash_perms: dict = {}

        if profile.commands.mode == CommandMode.WHITELIST:
            bash_perms["*"] = "deny"  # default deny
            for cmd in profile.commands.whitelist:
                bash_perms[f"{cmd} *"] = "allow"
                # Also allow the bare command without args
                bash_perms[cmd] = "allow"

            # Apply blocked_args overrides
            for cmd, blocked_patterns in profile.commands.blocked_args.items():
                for pattern in blocked_patterns:
                    bash_perms[f"{cmd} {pattern}"] = "deny"
                    bash_perms[f"{cmd} {pattern} *"] = "deny"

        elif profile.commands.mode == CommandMode.BLACKLIST:
            # Per-command denials first, wildcard allow last
            for cmd in profile.commands.blacklist:
                bash_perms[f"{cmd} *"] = "deny"
                bash_perms[cmd] = "deny"
            bash_perms["*"] = "allow"  # wildcard last

        perms["bash"] = bash_perms

        # --- Edit permissions ---
        # Allow editing within the profile's working directory, deny everything else
        workdir = profile.filesystem.working_dir
        perms["edit"] = {
            "*": "deny",
            f"{workdir}/*": "allow",
            f"{workdir}/**/*": "allow",
        }

        # --- Read permissions ---
        perms["read"] = {
            "*": "allow",  # reading is generally safe
        }

        # --- External directory ---
        perms["external_directory"] = "deny"

        # --- Web fetch ---
        if profile.network.mode == NetworkMode.NONE:
            perms["webfetch"] = "deny"
        elif profile.network.mode == NetworkMode.RESTRICTED:
            perms["webfetch"] = "ask"
        else:
            perms["webfetch"] = "allow"

        # --- Task (subagent) ---
        perms["task"] = "allow"

        return perms

    def _build_tools(self, profile: SandboxProfile) -> dict:
        """Configure which OpenCode tools are enabled."""
        tools = {
            "write": True,
            "edit": True,
            "bash": True,
            "read": True,
            "glob": True,
            "grep": True,
            "list": True,
        }

        # Disable web-related tools if no network
        if profile.network.mode == NetworkMode.NONE:
            tools["webfetch"] = False
            tools["websearch"] = False

        return tools

    def _build_env_vars(self, profile: SandboxProfile) -> dict:
        """Environment variables for the sandbox — also consumed by the LASSO plugin."""
        env = {
            "LASSO_SANDBOX": "true",
            "LASSO_PROFILE": profile.name,
            "LASSO_NETWORK_MODE": profile.network.mode.value,
            "LASSO_COMMAND_MODE": profile.commands.mode.value,
            "LASSO_AUDIT_DIR": profile.audit.log_dir,
        }

        if profile.commands.mode == CommandMode.WHITELIST:
            env["LASSO_WHITELIST"] = ",".join(profile.commands.whitelist)
        else:
            env["LASSO_BLACKLIST"] = ",".join(profile.commands.blacklist)

        # Encode blocked args as JSON to avoid ambiguity with `:` and `,`
        # separators when command names or patterns contain those characters.
        if profile.commands.blocked_args:
            env["LASSO_BLOCKED_ARGS"] = json.dumps(
                {cmd: list(patterns) for cmd, patterns in profile.commands.blocked_args.items()}
            )

        return env

    @staticmethod
    def _get_plugin_source() -> str | None:
        """Read the bundled LASSO plugin for OpenCode."""
        plugin_path = Path(__file__).parent / "plugins" / "opencode-lasso-plugin.js"
        if plugin_path.exists():
            return plugin_path.read_text()
        return None
