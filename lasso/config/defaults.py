"""Built-in default profiles for common use cases.

Three main profiles for everyday work, plus two specialized ones.
Designed for a bank data team using AI coding agents.
"""

from lasso.config.schema import (
    AuditConfig,
    CommandConfig,
    CommandMode,
    FilesystemConfig,
    GitRepoAccessConfig,
    GuardrailsConfig,
    NetworkConfig,
    NetworkMode,
    ProfileMode,
    ResourceConfig,
    SandboxProfile,
)

# Commands that are always blocked regardless of profile.
# These are dangerous system administration commands that have
# no place in a coding sandbox.
_ALWAYS_BLOCKED = [
    "rm", "dd", "mkfs", "mount", "umount", "chroot",
    "insmod", "rmmod", "modprobe", "reboot", "shutdown",
    "systemctl", "service", "iptables", "ip6tables",
    "nft", "tc", "nsenter", "unshare",
    "docker", "podman", "kubectl", "helm",
    "su", "sudo", "passwd", "useradd", "usermod", "groupadd",
    "crontab", "at",
    "nc", "ncat", "netcat", "socat", "telnet",
    "ssh", "scp", "sftp",
    "pkill", "kill", "killall",
    "fdisk", "parted",
]

# Safe blocked_args applied to all profiles that allow these commands.
_STANDARD_BLOCKED_ARGS = {
    "git": [
        "push --force", "push -f",
        "reset --hard",
        "clean -f", "clean -fd",
        "remote add", "remote set-url",
        "config --global",
    ],
    "pip": ["install --user", "install --target", "install --pre"],
    "chmod": ["777", "u+s", "g+s"],
}

# Domains needed for AI agents and package managers.
_AI_DOMAINS = [
    "api.anthropic.com", "cdn.anthropic.com", "statsig.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
]

_PACKAGE_DOMAINS = [
    "pypi.org", "files.pythonhosted.org",
    "registry.npmjs.org",
    "github.com", "api.github.com",
    "crates.io",
]

_COPILOT_DOMAINS = [
    "copilot-proxy.githubusercontent.com",
    "api.githubcopilot.com",
    "copilot-telemetry.githubusercontent.com",
    "default.exp-tas.com",
    "*.ghcr.io",
]


# =========================================================================
# Main profiles (these cover 95% of use cases)
# =========================================================================

def standard_profile(working_dir: str, name: str = "standard") -> SandboxProfile:
    """Standard sandbox — blocklist mode, internet for packages + AI APIs.

    The default profile. Blocks dangerous commands but allows everything
    else. Internet access limited to package registries and AI APIs.
    Good for everyday coding with Claude Code or OpenCode.
    """
    return SandboxProfile(
        name=name,
        description="Blocks dangerous commands, allows everything else. "
        "Internet limited to package registries and AI APIs.",
        tags=["default", "development"],
        mode=ProfileMode.AUTONOMOUS,
        filesystem=FilesystemConfig(working_dir=working_dir),
        commands=CommandConfig(
            mode=CommandMode.BLACKLIST,
            blacklist=list(_ALWAYS_BLOCKED),
            blocked_args=dict(_STANDARD_BLOCKED_ARGS),
            allow_shell_operators=True,
            max_execution_seconds=600,
        ),
        network=NetworkConfig(
            mode=NetworkMode.RESTRICTED,
            allowed_domains=_PACKAGE_DOMAINS + _AI_DOMAINS + _COPILOT_DOMAINS,
            allowed_ports=[80, 443],
        ),
        resources=ResourceConfig(max_memory_mb=8192, max_cpu_percent=75, max_pids=300),
    )


def open_profile(working_dir: str, name: str = "open") -> SandboxProfile:
    """Open sandbox — blocklist mode, full internet access.

    For research, browsing documentation, accessing APIs, and prototyping.
    Same command restrictions as standard but with unrestricted internet.
    Use when you need to access websites, APIs, or download resources.
    """
    return SandboxProfile(
        name=name,
        description="Blocks dangerous commands, allows everything else. "
        "Full internet access for research and API calls.",
        tags=["research", "flexible"],
        mode=ProfileMode.AUTONOMOUS,
        filesystem=FilesystemConfig(working_dir=working_dir),
        commands=CommandConfig(
            mode=CommandMode.BLACKLIST,
            blacklist=list(_ALWAYS_BLOCKED),
            blocked_args=dict(_STANDARD_BLOCKED_ARGS),
            allow_shell_operators=True,
            max_execution_seconds=600,
        ),
        network=NetworkConfig(
            mode=NetworkMode.FULL,
            # Database ports still blocked even in full mode
        ),
        resources=ResourceConfig(max_memory_mb=8192, max_cpu_percent=75, max_pids=300),
    )


def offline_profile(working_dir: str, name: str = "offline") -> SandboxProfile:
    """Offline sandbox — blocklist mode, no internet.

    For working with sensitive data or when you don't want any network
    access. Same command flexibility as standard but completely isolated.
    All activity logged with full output capture.
    """
    return SandboxProfile(
        name=name,
        description="Blocks dangerous commands, allows everything else. "
        "No internet access. Full audit trail for sensitive work.",
        tags=["offline", "sensitive-data"],
        mode=ProfileMode.AUTONOMOUS,
        filesystem=FilesystemConfig(working_dir=working_dir),
        commands=CommandConfig(
            mode=CommandMode.BLACKLIST,
            blacklist=list(_ALWAYS_BLOCKED),
            blocked_args=dict(_STANDARD_BLOCKED_ARGS),
            allow_shell_operators=True,
            max_execution_seconds=600,
        ),
        network=NetworkConfig(mode=NetworkMode.NONE),
        resources=ResourceConfig(max_memory_mb=8192, max_cpu_percent=75, max_pids=300),
        audit=AuditConfig(
            enabled=True,
            include_command_output=True,
            include_file_diffs=True,
            sign_entries=True,
        ),
    )


# =========================================================================
# Specialized profiles (for specific situations)
# =========================================================================

def strict_profile(working_dir: str, name: str = "strict") -> SandboxProfile:
    """Strict sandbox — whitelist mode, no internet, full audit.

    Maximum security. Only specific commands allowed. No internet.
    Git history restricted to prevent PII exposure. Full audit trail
    with command output capture. For compliance-critical work.
    """
    return SandboxProfile(
        name=name,
        description="Maximum security. Only approved commands allowed, "
        "no internet, git restricted, full audit trail.",
        tags=["compliance", "strict"],
        mode=ProfileMode.OBSERVE,
        filesystem=FilesystemConfig(
            working_dir=working_dir,
            hidden_paths=[
                "/etc/shadow", "/etc/gshadow", "/root",
                "/etc/ssh", "/etc/ssl/private",
                "/etc/passwd", "/etc/sudoers", "/proc", "~/.ssh/",
            ],
            max_disk_mb=20480,
        ),
        commands=CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=[
                "python3", "pip", "git",
                "ls", "cat", "head", "tail", "grep", "find",
                "wc", "sort", "uniq", "diff",
                "mkdir", "cp", "mv", "touch", "echo", "test",
                "Rscript", "R", "jupyter",
            ],
            blocked_args={
                "git": [
                    "push", "push --force",
                    "remote add", "remote set-url",
                    "log -p", "log --patch",
                    "diff", "show", "config",
                    "reset --hard", "clean",
                ],
                "pip": ["install --user", "install -e", "install --target"],
            },
            allow_shell_operators=False,
            max_execution_seconds=600,
        ),
        network=NetworkConfig(mode=NetworkMode.NONE),
        resources=ResourceConfig(
            max_memory_mb=8192,
            max_cpu_percent=50,
            max_pids=150,
        ),
        guardrails=GuardrailsConfig(enforce=True),
        audit=AuditConfig(
            enabled=True,
            include_command_output=True,
            include_file_diffs=True,
            sign_entries=True,
        ),
        git_access=GitRepoAccessConfig(
            access_mode="read",
            block_git_history_content=True,
        ),
    )


def evaluation_profile(working_dir: str, name: str = "evaluation") -> SandboxProfile:
    """Evaluation sandbox — read-only, no internet, for testing untrusted agents."""
    return SandboxProfile(
        name=name,
        description="Read-only commands only. No internet. "
        "For safely evaluating untrusted AI agents.",
        tags=["evaluation", "untrusted"],
        mode=ProfileMode.OBSERVE,
        filesystem=FilesystemConfig(working_dir=working_dir),
        commands=CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=["ls", "cat", "head", "tail", "grep", "wc", "echo", "test"],
            allow_shell_operators=False,
        ),
        network=NetworkConfig(mode=NetworkMode.NONE),
        resources=ResourceConfig(max_memory_mb=2048, max_cpu_percent=25, max_pids=100),
        audit=AuditConfig(
            enabled=True,
            include_command_output=True,
            sign_entries=True,
        ),
    )


BUILTIN_PROFILES = {
    "standard": standard_profile,
    "open": open_profile,
    "offline": offline_profile,
    "strict": strict_profile,
    "evaluation": evaluation_profile,
}
