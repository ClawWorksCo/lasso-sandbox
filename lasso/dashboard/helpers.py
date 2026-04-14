"""LASSO Dashboard — shared helper functions and constants."""

from __future__ import annotations

import json
import os
import platform
import shutil
import tempfile
from pathlib import Path
from typing import Any

from lasso.config.defaults import BUILTIN_PROFILES
from lasso.config.profile import list_profiles
from lasso.config.schema import (
    AuditConfig,
    CommandConfig,
    CommandMode,
    FilesystemConfig,
    NetworkConfig,
    NetworkMode,
    ResourceConfig,
    SandboxProfile,
)
from lasso.core.sandbox import SandboxRegistry

# ---------------------------------------------------------------------------
# Agent CLI command mapping
# ---------------------------------------------------------------------------

AGENT_COMMANDS = {
    "claude-code": "claude",
    "opencode": "opencode",
}

# ---------------------------------------------------------------------------
# Audit log reader utility
# ---------------------------------------------------------------------------


def read_audit_log(
    path: str | Path,
    tail: int = 50,
    event_type: str | None = None,
    offset: int = 0,
) -> list[dict]:
    """Read a JSONL audit log, optionally filtered and paginated."""
    entries: list[dict] = []
    path = Path(path)
    if not path.exists():
        return entries
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event_type and entry.get("type") != event_type:
                    continue
                entries.append(entry)
    except (OSError, PermissionError):
        return entries
    # Apply offset + tail for pagination
    if offset:
        entries = entries[offset:]
    return entries[-tail:] if tail else entries


def _system_capabilities() -> dict[str, Any]:
    """Gather system info for the check page."""
    caps: dict[str, Any] = {}

    # Docker / Podman
    caps["docker"] = shutil.which("docker") is not None
    caps["podman"] = shutil.which("podman") is not None

    # Linux namespaces
    caps["user_ns"] = Path("/proc/self/ns/user").exists()
    caps["mount_ns"] = Path("/proc/self/ns/mnt").exists()
    caps["pid_ns"] = Path("/proc/self/ns/pid").exists()
    caps["net_ns"] = Path("/proc/self/ns/net").exists()

    # Cgroups v2
    caps["cgroups_v2"] = Path("/sys/fs/cgroup/cgroup.controllers").exists()

    # Platform
    caps["platform"] = platform.platform()
    caps["python"] = platform.python_version()

    return caps


def _get_registry() -> SandboxRegistry:
    from flask import current_app

    reg = current_app.config.get("REGISTRY")
    if reg is None:
        # Auto-detect a container backend so reconnection to existing
        # containers works even when the dashboard is started standalone.
        backend = current_app.config.get("BACKEND")
        if backend is None:
            try:
                from lasso.backends.detect import detect_backend

                backend = detect_backend()
                current_app.config["BACKEND"] = backend
            except Exception:
                pass
        reg = SandboxRegistry(backend=backend)
        current_app.config["REGISTRY"] = reg
    return reg


def _get_backend():
    from flask import current_app

    return current_app.config.get("BACKEND")


def _default_sandbox_dir() -> str:
    """Return a platform-appropriate default sandbox directory."""
    return str(Path(tempfile.gettempdir()) / "lasso-sandbox")


def _get_all_profiles() -> list[dict]:
    """Return combined list of builtin + saved profiles."""
    profiles = []
    for name, factory in BUILTIN_PROFILES.items():
        p = factory(_default_sandbox_dir())
        profiles.append({
            "name": name,
            "description": p.description,
            "source": "builtin",
            "cmd_mode": p.commands.mode.value,
            "net_mode": p.network.mode.value,
            "mem_limit": f"{p.resources.max_memory_mb}MB",
            "tags": p.tags,
        })
    for saved in list_profiles():
        if "error" not in saved:
            saved["source"] = "saved"
            saved["description"] = saved.get("description", "")
            profiles.append(saved)
    return profiles


def _state_color(state: str) -> str:
    """Map sandbox state to a CSS color class."""
    return {
        "running": "state-running",
        "created": "state-created",
        "configuring": "state-configuring",
        "stopped": "state-stopped",
        "paused": "state-paused",
        "error": "state-error",
    }.get(state, "")


def _security_level_label(sb: dict) -> str:
    """Return a human-readable security level string for a sandbox."""
    cmd = sb.get("command_mode", "")
    net = sb.get("network_mode", "")
    if cmd == "allowlist" and net == "none":
        return "Strict"
    if cmd == "allowlist" and net in ("restricted", "full"):
        return "Standard"
    if cmd == "denylist":
        return "Permissive"
    return cmd.capitalize() if cmd else "Custom"


def _enrich_sandbox(sb: dict, registry: SandboxRegistry) -> dict:
    """Add agent and security_level fields to a sandbox status dict."""
    agent = ""
    sandbox_obj = registry.get(sb["id"])
    if sandbox_obj:
        agent = sandbox_obj.profile.extra_env.get("LASSO_AGENT", "")
    sb["agent"] = agent
    sb["security_level"] = _security_level_label(sb)
    return sb


def _validate_working_dir(working_dir: str) -> str | None:
    """Validate working directory path. Returns error message or None if valid."""
    if len(working_dir) > 4096:
        return "Path too long."

    try:
        path = Path(working_dir).resolve()
    except (OSError, ValueError):
        return "Invalid path."

    if not path.is_dir():
        return f"Directory does not exist: {working_dir}"

    # Block system directories
    _BLOCKED = {
        Path("/"), Path("/etc"), Path("/proc"), Path("/sys"),
        Path("/dev"), Path("/boot"), Path("/var/run"),
    }
    if platform.system() == "Windows":
        _BLOCKED.update({
            Path("C:\\"), Path("C:\\Windows"), Path("C:\\Windows\\System32"),
            Path("C:\\Program Files"), Path("C:\\Program Files (x86)"),
        })
    if path in _BLOCKED:
        return f"System directory not allowed: {working_dir}"

    # Must be under home or temp directory
    home = Path(os.path.normcase(str(Path.home().resolve())))
    tmp = Path(os.path.normcase(str(Path(tempfile.gettempdir()).resolve())))
    path_norm = Path(os.path.normcase(str(path)))
    if not (path_norm.is_relative_to(home) or path_norm.is_relative_to(tmp)):
        return "Working directory must be under home or temp directory."

    return None


def _parse_profile_form(form) -> dict:
    """Parse form data into kwargs suitable for building a SandboxProfile."""
    # Commands
    commands_list = form.getlist("commands")
    extra_cmds = form.get("extra_commands", "").strip()
    if extra_cmds:
        for cmd in extra_cmds.split(","):
            cmd = cmd.strip()
            if cmd and cmd not in commands_list:
                commands_list.append(cmd)

    cmd_mode_str = form.get("cmd_mode", "whitelist")
    if cmd_mode_str not in ("whitelist", "blacklist"):
        cmd_mode_str = "whitelist"
    cmd_mode = CommandMode.WHITELIST if cmd_mode_str == "whitelist" else CommandMode.BLACKLIST

    # Network
    net_mode_str = form.get("net_mode", "none")
    net_mode = NetworkMode(net_mode_str)
    allowed_domains_raw = form.get("allowed_domains", "")
    allowed_domains = [d.strip() for d in allowed_domains_raw.split(",") if d.strip()]
    try:
        blocked_ports = [int(p) for p in form.getlist("blocked_ports")]
    except (ValueError, TypeError):
        blocked_ports = []

    # Resources
    try:
        max_memory_mb = int(form.get("max_memory_mb", "4096"))
    except (ValueError, TypeError):
        max_memory_mb = 4096
    try:
        max_cpu_percent = int(form.get("max_cpu_percent", "50"))
    except (ValueError, TypeError):
        max_cpu_percent = 50
    try:
        max_pids = int(form.get("max_pids", "100"))
    except (ValueError, TypeError):
        max_pids = 100

    # Audit
    audit_enabled = "audit_enabled" in form
    audit_command_output = "audit_command_output" in form
    audit_file_diffs = "audit_file_diffs" in form

    # Shell operators
    allow_shell_operators = "allow_shell_operators" in form

    # Max execution seconds
    try:
        max_execution_seconds = int(form.get("max_execution_seconds", "300"))
    except (ValueError, TypeError):
        max_execution_seconds = 300

    return {
        "commands_list": commands_list,
        "cmd_mode": cmd_mode,
        "allow_shell_operators": allow_shell_operators,
        "max_execution_seconds": max_execution_seconds,
        "net_mode": net_mode,
        "allowed_domains": allowed_domains,
        "blocked_ports": blocked_ports,
        "max_memory_mb": max_memory_mb,
        "max_cpu_percent": max_cpu_percent,
        "max_pids": max_pids,
        "audit_enabled": audit_enabled,
        "audit_command_output": audit_command_output,
        "audit_file_diffs": audit_file_diffs,
    }


def _build_profile(name: str, description: str, parsed: dict, extends: str | None = None) -> SandboxProfile:
    """Build a SandboxProfile from parsed form data."""
    commands_kwargs: dict[str, Any] = {
        "mode": parsed["cmd_mode"],
        "allow_shell_operators": parsed["allow_shell_operators"],
        "max_execution_seconds": parsed["max_execution_seconds"],
    }
    if parsed["cmd_mode"] == CommandMode.WHITELIST:
        commands_kwargs["whitelist"] = parsed["commands_list"]
    else:
        commands_kwargs["blacklist"] = parsed["commands_list"]

    return SandboxProfile(
        name=name,
        description=description,
        extends=extends or None,
        filesystem=FilesystemConfig(working_dir=_default_sandbox_dir()),
        commands=CommandConfig(**commands_kwargs),
        network=NetworkConfig(
            mode=parsed["net_mode"],
            allowed_domains=parsed["allowed_domains"],
            blocked_ports=parsed["blocked_ports"],
        ),
        resources=ResourceConfig(
            max_memory_mb=parsed["max_memory_mb"],
            max_cpu_percent=parsed["max_cpu_percent"],
            max_pids=parsed["max_pids"],
        ),
        audit=AuditConfig(
            enabled=parsed["audit_enabled"],
            include_command_output=parsed["audit_command_output"],
            include_file_diffs=parsed["audit_file_diffs"],
            sign_entries=True,
        ),
    )
