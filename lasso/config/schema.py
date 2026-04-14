"""LASSO configuration schema — Pydantic models defining all sandbox settings."""

from __future__ import annotations

import hashlib
import os
import platform
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class CommandMode(str, Enum):
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"


class NetworkMode(str, Enum):
    NONE = "none"            # No network access at all
    RESTRICTED = "restricted" # Only allowed domains/ports
    FULL = "full"            # Unrestricted (not recommended)


class AuditFormat(str, Enum):
    JSON = "json"
    JSONL = "jsonl"


class SandboxState(str, Enum):
    CREATED = "created"
    CONFIGURING = "configuring"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERROR = "error"


class ProfileMode(str, Enum):
    """Gradual authorization modes for sandbox command access.

    Controls which subset of the whitelist is active:
    - OBSERVE: read-only commands only (ls, cat, grep, etc.)
    - ASSIST: curated development commands (observe + python3, git, pip, etc.)
    - AUTONOMOUS: full whitelist from the profile configuration
    """
    OBSERVE = "observe"
    ASSIST = "assist"
    AUTONOMOUS = "autonomous"


# ---------------------------------------------------------------------------
# Config sub-models
# ---------------------------------------------------------------------------

def _default_read_only_paths() -> list[str]:
    """Platform-appropriate default read-only paths."""
    if platform.system() == "Windows":
        return [
            r"C:\Windows",
            r"C:\Program Files",
            r"C:\Program Files (x86)",
        ]
    return ["/usr", "/lib", "/lib64", "/bin", "/sbin"]


def _default_hidden_paths() -> list[str]:
    """Platform-appropriate default hidden paths."""
    if platform.system() == "Windows":
        return [
            r"C:\Users\Default",
            r"C:\Windows\System32\config",
        ]
    return ["/etc/shadow", "/etc/gshadow", "/root"]


# Paths that must never be writable inside a sandbox.
_BLOCKED_WRITABLE_PREFIXES = (
    "/etc", "/root", "/bin", "/sbin", "/usr", "/boot",
    "/proc", "/sys", "/dev",
)
# Allowed writable prefixes (absolute paths must start with one of these).
_ALLOWED_WRITABLE_PREFIXES = (
    "/home", "/tmp", "/var/tmp", "/workspace",
)
# Relative path prefixes that target system directories and must never be writable.
_BLOCKED_RELATIVE_STARTS = (
    "etc", "proc", "sys", "dev", "root",
    "bin", "sbin", "usr", "boot",
)

# Sensitive dotfile directories that must never be writable from a sandbox.
_SENSITIVE_DOTDIRS = frozenset({
    ".ssh", ".gnupg", ".aws", ".azure", ".kube",
    ".docker", ".npmrc", ".pypirc", ".netrc",
    ".git-credentials", ".password-store",
})

# Environment variable names that must never be set via extra_env.
# Consolidated in one place to avoid duplication between class attributes
# and the validator method.
_BLOCKED_ENV_KEYS = frozenset({
    "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH",
    "DOCKER_HOST", "DOCKER_SOCK",
    "HOME", "USER", "SHELL", "LANG", "LC_ALL",
})
_BLOCKED_ENV_PREFIXES = ("LASSO_", "LD_")
# LASSO_ keys that the CLI legitimately needs to set via extra_env
_LASSO_ALLOWED_KEYS = frozenset({
    "LASSO_AGENT",
    "LASSO_EXTRA_MOUNTS",
    "LASSO_INJECT_GIT_IDENTITY",
    "LASSO_NO_AUTO_MOUNT",
})


class FilesystemConfig(BaseModel):
    """Controls what the agent can see and write to."""
    working_dir: str = Field(
        description="Primary working directory mounted read-write inside the sandbox."
    )
    read_only_paths: list[str] = Field(
        default_factory=_default_read_only_paths,
        description="Paths mounted read-only inside the sandbox.",
    )
    writable_paths: list[str] = Field(
        default_factory=list,
        description="Additional paths mounted read-write (beyond working_dir).",
    )
    hidden_paths: list[str] = Field(
        default_factory=_default_hidden_paths,
        description="Paths completely invisible inside the sandbox.",
    )
    max_disk_mb: int = Field(
        default=10240,
        ge=0,
        description="Maximum disk usage in MB (enforced via tmpfs / quota).",
    )
    temp_dir_mb: int = Field(
        default=512,
        ge=0,
        description="Size of /tmp tmpfs inside sandbox in MB.",
    )
    session_volume: str | None = Field(
        default=None,
        description="Docker named volume for agent state persistence.",
    )
    session_volume_target: str = Field(
        default="/home/agent",
        description="Mount point for session volume inside container.",
    )

    @field_validator("writable_paths")
    @classmethod
    def validate_writable_paths(cls, paths: list[str]) -> list[str]:
        """Reject system-critical paths and paths with traversal components."""
        validated: list[str] = []
        for raw in paths:
            p = raw.strip()
            if not p:
                continue

            # Reject path traversal
            if ".." in p:
                raise ValueError(
                    f"Path traversal ('..') is not allowed in writable_paths: {p!r}"
                )

            # Normalize: resolve relative paths, but keep them relative for storage
            path_obj = Path(p)
            if path_obj.is_absolute():
                normalized = str(path_obj.resolve())
            else:
                # Relative path (e.g. "./data") -- allowed, normalize dots
                normalized = str(path_obj)

            # For absolute paths, check against blocked prefixes
            if Path(normalized).is_absolute():
                # On Windows, skip the Unix-specific prefix checks since
                # the container interior is always Linux. The converter
                # handles Windows→Docker path translation separately.
                norm_lower = os.path.normcase(normalized)
                for blocked in _BLOCKED_WRITABLE_PREFIXES:
                    blocked_norm = os.path.normcase(blocked)
                    if norm_lower == blocked_norm or norm_lower.startswith(blocked_norm + os.sep):
                        raise ValueError(
                            f"System-critical path is not allowed as writable: {p!r}"
                        )

                # On Unix, require paths under known safe prefixes.
                # On Windows, absolute paths are valid (the converter
                # handles mount translation to Docker format).
                if platform.system() != "Windows":
                    allowed = any(
                        normalized == prefix or normalized.startswith(prefix + "/")
                        for prefix in _ALLOWED_WRITABLE_PREFIXES
                    )
                    if not allowed:
                        raise ValueError(
                            f"Writable path must be under one of "
                            f"{_ALLOWED_WRITABLE_PREFIXES}: {p!r}"
                        )

                # HIGH-1: Bare /home is too broad -- require at least one
                # subdirectory level (e.g. /home/username).
                if normalized == "/home":
                    raise ValueError(
                        f"Bare '/home' is too broad as a writable path; "
                        f"specify a subdirectory (e.g. '/home/username'): {p!r}"
                    )
            else:
                # HIGH-2: Relative paths must not target system directories.
                # A relative path like "etc/passwd" or "proc/self/environ"
                # could resolve to a system directory when the working_dir
                # is "/" or when bind-mounted into a container.
                first_component = Path(normalized).parts[0] if Path(normalized).parts else ""
                if first_component in _BLOCKED_RELATIVE_STARTS:
                    raise ValueError(
                        f"Relative path targets a system directory and is not "
                        f"allowed as writable: {p!r}"
                    )

            # Check path components against sensitive dotdir blocklist
            for component in Path(normalized).parts:
                if component in _SENSITIVE_DOTDIRS:
                    raise ValueError(
                        f"Sensitive directory '{component}' is not allowed "
                        f"in writable_paths: {p!r}"
                    )

            validated.append(normalized)
        return validated


class CommandConfig(BaseModel):
    """Controls which commands the agent can execute."""
    mode: CommandMode = Field(
        default=CommandMode.WHITELIST,
        description="Whether the command list is a whitelist or blacklist.",
    )
    whitelist: list[str] = Field(
        default_factory=lambda: [
            "python3", "pip", "git", "ls", "cat", "head", "tail",
            "grep", "find", "wc", "sort", "uniq", "diff", "mkdir",
            "cp", "mv", "touch", "echo", "printf", "test",
        ],
        description="Commands allowed when mode is 'whitelist'.",
    )
    blacklist: list[str] = Field(
        default_factory=lambda: [
            "rm", "dd", "mkfs", "mount", "umount", "chroot",
            "insmod", "rmmod", "modprobe", "reboot", "shutdown",
            "systemctl", "service", "iptables", "ip6tables",
            "nft", "tc", "nsenter", "unshare",
        ],
        description="Commands blocked when mode is 'blacklist'.",
    )
    observe_whitelist: list[str] = Field(
        default_factory=lambda: [
            "ls", "cat", "head", "tail", "grep", "find",
            "wc", "echo", "test", "file", "du", "df",
        ],
        description="Read-only commands allowed in OBSERVE mode.",
    )
    assist_whitelist: list[str] = Field(
        default_factory=lambda: [
            "ls", "cat", "head", "tail", "grep", "find",
            "wc", "echo", "test", "file", "du", "df",
            "python3", "git", "pip", "npm", "node", "make", "cargo", "go",
        ],
        description="Curated development commands allowed in ASSIST mode.",
    )
    blocked_args: dict[str, list[str]] = Field(
        default_factory=lambda: {
            "git": ["push", "push --force"],
            "pip": ["install --user"],
        },
        description="Per-command argument patterns that are blocked even if the command is allowed.",
    )
    allow_shell_operators: bool = Field(
        default=False,
        description="Whether to allow pipes (|), redirects (>, >>), and subshells ($()).",
    )
    max_execution_seconds: int = Field(
        default=300,
        ge=1,
        description="Maximum wall-clock time for a single command execution.",
    )


# Canonical list of database ports that must be blocked in all sandbox modes.
# This is the single source of truth — imported by security_audit, network, and sandbox.
DATABASE_PORTS: list[int] = [
    1433,   # MSSQL / SQL Server / SSMS
    1434,   # MSSQL Browser
    3306,   # MySQL
    5432,   # PostgreSQL
    27017,  # MongoDB
    6379,   # Redis
    9042,   # Cassandra
    8123,   # ClickHouse HTTP
    9000,   # ClickHouse native
    1521,   # Oracle
    5984,   # CouchDB
]

# Human-readable names for database ports (used in status display and error messages).
DATABASE_PORT_NAMES: dict[int, str] = {
    1433: "MSSQL/SQL Server", 1434: "MSSQL Browser",
    3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
    6379: "Redis", 9042: "Cassandra", 8123: "ClickHouse HTTP",
    9000: "ClickHouse native", 1521: "Oracle", 5984: "CouchDB",
}


class NetworkConfig(BaseModel):
    """Controls agent network access."""
    mode: NetworkMode = Field(
        default=NetworkMode.RESTRICTED,
        description="Network isolation mode.",
    )
    allowed_domains: list[str] = Field(
        default_factory=list,
        description="Domains the agent can reach (restricted mode only).",
    )
    blocked_domains: list[str] = Field(
        default_factory=list,
        description="Domains explicitly blocked (restricted mode, applied after allow).",
    )
    allowed_ports: list[int] = Field(
        default_factory=lambda: [80, 443],
        description="TCP ports the agent may connect to.",
    )
    blocked_ports: list[int] = Field(
        default_factory=lambda: list(DATABASE_PORTS),
        description="TCP ports always blocked (database servers). Applied even in full network mode.",
    )
    allowed_cidrs: list[str] = Field(
        default_factory=list,
        description="CIDR ranges the agent may reach (e.g. '10.0.0.0/8').",
    )
    blocked_cidrs: list[str] = Field(
        default_factory=lambda: [
            "169.254.169.254/32",  # cloud metadata
            "10.0.0.0/8",         # private ranges
            "172.16.0.0/12",
            "192.168.0.0/16",
        ],
        description="CIDR ranges always blocked (even in full mode).",
    )
    dns_servers: list[str] = Field(
        default_factory=lambda: ["1.1.1.1", "8.8.8.8"],
        description="DNS servers available inside sandbox.",
    )


class ResourceConfig(BaseModel):
    """Controls resource limits via cgroups v2."""
    max_memory_mb: int = Field(default=4096, ge=64)
    max_cpu_percent: int = Field(default=50, ge=1, le=100)
    max_pids: int = Field(default=100, ge=1)
    max_open_files: int = Field(default=1024, ge=64)
    max_file_size_mb: int = Field(default=100, ge=1)


class GuardrailRule(BaseModel):
    """A single guardrail rule."""
    id: str
    description: str
    severity: str = Field(default="error", pattern=r"^(info|warning|error|critical)$")
    enabled: bool = True


class GuardrailsConfig(BaseModel):
    """Agent instruction guardrails."""
    agent_md_path: str | None = Field(
        default=None,
        description="Path to the agent's instruction file (injected into sandbox).",
    )
    enforce: bool = Field(
        default=True,
        description="Whether guardrail violations block execution.",
    )
    rules: list[GuardrailRule] = Field(
        default_factory=lambda: [
            GuardrailRule(
                id="no-escape",
                description="Agent must not attempt to access paths outside working_dir.",
                severity="critical",
            ),
            GuardrailRule(
                id="no-exfiltration",
                description="Agent must not transmit file contents to external hosts.",
                severity="critical",
            ),
            GuardrailRule(
                id="log-modifications",
                description="All file modifications must be logged in audit trail.",
                severity="error",
            ),
        ],
    )
    custom_rules_path: str | None = Field(
        default=None,
        description="Path to a TOML file with additional custom rules.",
    )


class AgentAuthConfig(BaseModel):
    """Authentication configuration for AI agent providers."""
    github_token_env: str = Field(
        default="GITHUB_TOKEN",
        description="Environment variable name containing the GitHub token.",
    )
    opencode_provider: str | None = Field(
        default=None,
        description="LLM provider for OpenCode (e.g., 'anthropic', 'openai').",
    )
    opencode_api_key_env: str = Field(
        default="OPENCODE_API_KEY",
        description="Environment variable name containing the OpenCode LLM API key.",
    )


class WebhookConfig(BaseModel):
    """Webhook notification configuration for SIEM/SOAR/monitoring integration."""
    enabled: bool = False
    url: str = Field(default="", description="Webhook endpoint URL.")
    events: list[str] = Field(
        default_factory=lambda: ["violation", "lifecycle"],
        description="Event types to send: command, lifecycle, violation, file, network",
    )
    secret: str | None = Field(
        default=None,
        description="HMAC secret for webhook signature verification.",
    )
    timeout_seconds: int = Field(default=5, ge=1, le=30)
    retry_count: int = Field(default=2, ge=0, le=5)


class GitRepoAccessConfig(BaseModel):
    """Fine-grained GitHub repository access control.

    Controls which repositories the agent can interact with and how.
    Designed for environments where agents work with org-owned repos
    and git history may contain PII (names, emails in commits/diffs).
    """
    allowed_repos: list[str] = Field(
        default_factory=list,
        description="GitHub repos the agent can access (org/repo format). Empty = all repos.",
    )
    access_mode: str = Field(
        default="read",
        pattern=r"^(read|read-write)$",
        description="Access level: 'read' (clone/pull only) or 'read-write' (push allowed).",
    )
    block_git_history_content: bool = Field(
        default=True,
        description=(
            "Block git log --patch, git diff, git show that reveal file content "
            "changes. Prevents PII exposure from commit history."
        ),
    )


class AuditConfig(BaseModel):
    """Audit logging configuration."""
    enabled: bool = True
    log_dir: str = Field(
        default="./audit",
        description="Directory for audit log files.",
    )
    log_format: AuditFormat = AuditFormat.JSONL
    include_timestamps: bool = True
    include_command_output: bool = Field(
        default=False,
        description="Whether to log command stdout/stderr (may contain sensitive data).",
    )
    include_file_diffs: bool = Field(
        default=True,
        description="Whether to log diffs of file modifications.",
    )
    max_log_size_mb: int = Field(default=100, ge=1)
    rotation_count: int = Field(default=10, ge=1)
    sign_entries: bool = Field(
        default=True,
        description="HMAC-sign each audit entry for tamper detection.",
    )
    signing_key_path: str | None = Field(
        default=None,
        description="Path to HMAC signing key. Auto-generated if missing.",
    )
    syslog_address: str | None = Field(
        default=None,
        description="Syslog address for log forwarding (e.g., '/dev/log', 'udp://siem.company.com:514'). "
                    "When configured, each audit entry is also forwarded via syslog.",
    )
    syslog_facility: str = Field(
        default="local0",
        description="Syslog facility for forwarded entries.",
    )
    webhooks: list[WebhookConfig] = Field(
        default_factory=list,
        description="Webhook endpoints for event notification (SIEM/SOAR integration).",
    )


# ---------------------------------------------------------------------------
# Top-level sandbox profile
# ---------------------------------------------------------------------------

class SandboxProfile(BaseModel):
    """Complete sandbox configuration profile — the root document."""

    name: str = Field(description="Human-readable name for this sandbox.")
    description: str = Field(default="", description="Purpose of this sandbox.")
    version: str = Field(default="1", description="Profile schema version.")
    extends: str | None = Field(
        default=None,
        description="Base profile to inherit from. Scalar fields are overridden, "
                    "list fields are appended by default. Use _merge_strategy annotations for control.",
    )
    profile_version: int = Field(
        default=1,
        ge=1,
        description="Auto-incrementing version number for profile sharing/history.",
    )
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    updated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    tags: list[str] = Field(default_factory=list)
    mode: ProfileMode = Field(
        default=ProfileMode.OBSERVE,
        description="Gradual authorization mode: observe (read-only), assist (curated dev), autonomous (full).",
    )

    filesystem: FilesystemConfig
    commands: CommandConfig = Field(default_factory=CommandConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    resources: ResourceConfig = Field(default_factory=ResourceConfig)
    guardrails: GuardrailsConfig = Field(default_factory=GuardrailsConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    git_access: GitRepoAccessConfig = Field(
        default_factory=GitRepoAccessConfig,
        description="Fine-grained GitHub repository access control.",
    )
    agent_auth: AgentAuthConfig | None = Field(
        default=None,
        description="Authentication settings for AI agent providers (OpenCode).",
    )
    extra_env: dict[str, str] = Field(
        default_factory=dict,
        description="Additional environment variables to inject into the sandbox.",
    )

    @field_validator("extra_env")
    @classmethod
    def validate_extra_env(cls, env: dict[str, str]) -> dict[str, str]:
        """Block dangerous environment variable names that could bypass isolation."""
        for key in env:
            if key.upper() in _BLOCKED_ENV_KEYS:
                raise ValueError(
                    f"Environment variable '{key}' is blocked for security "
                    f"reasons and cannot be set via extra_env."
                )
            for prefix in _BLOCKED_ENV_PREFIXES:
                if key.upper().startswith(prefix) and key.upper() not in _LASSO_ALLOWED_KEYS:
                    raise ValueError(
                        f"Cannot set '{key}' via extra_env (blocked prefix '{prefix}')"
                    )
        return env
    docker_from_docker: bool = Field(
        default=False,
        description="Enable Docker-from-Docker via socket proxy.",
    )
    isolation: str = Field(
        default="container",
        pattern=r"^(container|gvisor|kata)$",
        description="Isolation level: container (default), gvisor (syscall interception), kata (VM isolation, Linux only).",
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v.replace("-", "").replace("_", "").isalnum():
            raise ValueError("Profile name must be alphanumeric (hyphens/underscores OK).")
        return v

    def config_hash(self) -> str:
        """Deterministic SHA-256 of the config for integrity verification."""
        payload = self.model_dump_json(exclude={"created_at", "updated_at"})
        return hashlib.sha256(payload.encode()).hexdigest()

    def summary(self) -> dict:
        """One-line summary for listing profiles."""
        return {
            "name": self.name,
            "working_dir": self.filesystem.working_dir,
            "cmd_mode": self.commands.mode.value,
            "net_mode": self.network.mode.value,
            "mem_limit": f"{self.resources.max_memory_mb}MB",
            "audit": self.audit.enabled,
            "hash": self.config_hash()[:12],
        }
