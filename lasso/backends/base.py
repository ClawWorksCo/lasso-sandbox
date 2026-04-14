"""Abstract backend interface for container/sandbox runtimes.

All isolation backends must implement this interface. LASSO's core engine
talks exclusively through this abstraction — it never calls Docker/Podman
directly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class BackendType(str, Enum):
    DOCKER = "docker"
    PODMAN = "podman"


class IsolationLevel(str, Enum):
    CONTAINER = "container"   # Standard Docker/Podman containers
    GVISOR = "gvisor"         # gVisor (runsc) — syscall interception, no direct kernel access
    KATA = "kata"             # Kata Containers — full VM isolation (Linux only)


class ContainerState(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    REMOVED = "removed"
    ERROR = "error"


@dataclass
class ContainerConfig:
    """Platform-agnostic container configuration derived from a SandboxProfile."""
    image: str = "python:3.12-slim"
    name: str = ""
    working_dir: str = "/workspace"
    hostname: str = "lasso-sandbox"

    # Filesystem
    bind_mounts: list[dict[str, str]] = field(default_factory=list)
    volumes: list[dict[str, str]] = field(default_factory=list)
    # Each dict: {"name": "vol-name", "target": "/container/path", "mode": "rw"}
    read_only_root: bool = True
    tmpfs_mounts: dict[str, str] = field(default_factory=dict)

    # Resource limits
    mem_limit: str = "4g"
    cpu_quota: int = 50000       # microseconds per 100ms period
    cpu_period: int = 100000
    pids_limit: int = 100

    # Network
    network_mode: str = "none"   # "none", "bridge", or custom network name
    dns: list[str] = field(default_factory=list)

    # Environment
    environment: dict[str, str] = field(default_factory=dict)

    # Security
    security_opt: list[str] = field(default_factory=list)
    cap_drop: list[str] = field(default_factory=lambda: ["ALL"])
    cap_add: list[str] = field(default_factory=list)
    user: str = "1000:1000"
    runtime: str = ""  # OCI runtime override: "runsc" (gVisor), "kata-runtime" (Kata), "" (default)


@dataclass
class ExecResult:
    """Result of executing a command inside a container."""
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int = 0


@dataclass
class ContainerInfo:
    """Status information about a running container."""
    container_id: str
    name: str
    state: ContainerState
    image: str
    created_at: str = ""
    pid: int = 0
    memory_usage_mb: float = 0.0
    cpu_percent: float = 0.0
    network_mode: str = ""


class ContainerBackend(ABC):
    """Abstract interface for container runtimes (Docker, Podman, etc.)."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this backend is installed and operational."""

    @abstractmethod
    def get_info(self) -> dict[str, Any]:
        """Return runtime version and capability information."""

    @abstractmethod
    def create(self, config: ContainerConfig) -> str:
        """Create a container. Returns the container ID."""

    @abstractmethod
    def start(self, container_id: str) -> None:
        """Start a created container."""

    @abstractmethod
    def stop(self, container_id: str, timeout: int = 10) -> None:
        """Stop a running container."""

    @abstractmethod
    def remove(self, container_id: str, force: bool = False) -> None:
        """Remove a container."""

    @abstractmethod
    def exec(self, container_id: str, command: list[str],
             timeout: int = 300, user: str | None = None) -> ExecResult:
        """Execute a command inside a running container.

        Args:
            container_id: Container to exec in.
            command: Command and arguments.
            timeout: Max seconds to wait.
            user: Override the user to run as (e.g. "root"). Defaults to
                  the container's configured user.
        """

    @abstractmethod
    def inspect(self, container_id: str) -> ContainerInfo:
        """Get container status and resource usage."""

    @abstractmethod
    def logs(self, container_id: str, tail: int = 100) -> str:
        """Get container logs."""

    @abstractmethod
    def list_containers(self, label_filter: str = "lasso") -> list[ContainerInfo]:
        """List containers managed by LASSO."""

    @abstractmethod
    def create_network(self, name: str, internal: bool = True,
                       allowed_cidrs: list[str] | None = None) -> str:
        """Create an isolated network. Returns network ID."""

    @abstractmethod
    def remove_network(self, name: str) -> None:
        """Remove a network."""

    @abstractmethod
    def build_image(self, dockerfile_content: str, tag: str) -> str:
        """Build a container image from a Dockerfile string. Returns image ID."""

    @abstractmethod
    def image_exists(self, tag: str) -> bool:
        """Check if an image exists locally."""

    def get_native_client(self) -> Any:
        """Return the underlying native client (e.g. docker.DockerClient).

        Optional — backends that don't expose a native client may return None.
        Used by detect_isolation_levels() to query runtime capabilities.
        """
        return None
