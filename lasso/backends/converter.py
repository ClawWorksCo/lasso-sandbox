"""Convert SandboxProfile → ContainerConfig.

This is the bridge between LASSO's domain model and the container runtime.
All platform-specific translation happens here.
"""

from __future__ import annotations

import os
import platform
import re
import subprocess
from pathlib import Path

from lasso.backends.base import ContainerConfig
from lasso.config.schema import NetworkMode, SandboxProfile

_FORBIDDEN_MOUNT_SOURCES = frozenset({
    # Unix
    "/", "/etc", "/proc", "/sys", "/dev", "/boot",
    "/var/run", "/run", "/root", "/bin", "/sbin", "/usr",
    # Windows
    "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
    "C:\\System Volume Information",
})


def _validate_mount_source(path: str) -> None:
    """Reject dangerous host paths as mount sources."""
    # Reject symlinks to prevent TOCTOU attacks: a symlink could point
    # to a safe target at validation time but be retargeted before exec.
    if os.path.islink(path):
        raise ValueError(f"Symlinks not allowed as mount sources: {path}")

    # Resolve and normalize
    try:
        resolved = str(Path(path).resolve())
    except (OSError, ValueError):
        raise ValueError(f"Invalid mount path: {path}")

    # Normalize for case-insensitive comparison on Windows
    resolved_norm = os.path.normcase(resolved)

    for forbidden in _FORBIDDEN_MOUNT_SOURCES:
        forbidden_norm = os.path.normcase(forbidden)
        if resolved_norm == forbidden_norm or resolved_norm.startswith(forbidden_norm + os.sep):
            # Exception: /usr/local and similar subdirs are OK for read-only
            if resolved_norm.startswith(os.path.normcase("/usr/local")):
                continue
            raise ValueError(f"Forbidden mount source: {path} (resolves to {resolved})")

    # Block container runtime sockets
    if "docker.sock" in resolved or "podman.sock" in resolved:
        raise ValueError(f"Container socket mount is not allowed: {path}")


def _to_docker_mount_path(host_path: str) -> str:
    """Convert a host path to Docker mount format.

    On Windows, Docker Desktop expects Unix-style paths with the drive
    letter lowercased:  C:\\Users\\me\\project  ->  /c/Users/me/project

    On Linux/macOS, paths are returned unchanged.
    """
    if platform.system() != "Windows":
        return host_path

    # Normalise to forward slashes
    path = host_path.replace("\\", "/")

    # Convert drive letter: C:/foo -> /c/foo
    match = re.match(r"^([A-Za-z]):/(.*)$", path)
    if match:
        drive = match.group(1).lower()
        rest = match.group(2)
        return f"/{drive}/{rest}"

    return path


def profile_to_container_config(profile: SandboxProfile) -> ContainerConfig:
    """Translate a SandboxProfile into a platform-agnostic ContainerConfig."""

    bind_mounts = _build_mounts(profile)
    network_mode = _resolve_network_mode(profile)
    tmpfs = _build_tmpfs(profile)
    environment = _build_environment(profile)
    cap_add = _resolve_cap_add(profile)

    runtime = _resolve_runtime(profile)

    # Build named volume mounts for session persistence
    volumes = _build_volumes(profile)

    # Docker-from-Docker: override network mode and inject DOCKER_HOST
    if profile.docker_from_docker:
        network_mode = "lasso-sandbox-net"
        environment["DOCKER_HOST"] = "tcp://lasso-socket-proxy:2375"

    # NOTE: ContainerConfig.image is intentionally left as the default empty
    # string here. The image is set later in sandbox.py:_start_with_backend()
    # after ensure_image() builds/pulls the correct image for this profile.
    return ContainerConfig(
        name=f"lasso-{profile.name}",
        working_dir="/workspace",
        hostname="lasso-sandbox",
        bind_mounts=bind_mounts,
        volumes=volumes,
        read_only_root=True,
        tmpfs_mounts=tmpfs,
        mem_limit=f"{profile.resources.max_memory_mb}m",
        cpu_quota=profile.resources.max_cpu_percent * 1000,
        cpu_period=100000,
        pids_limit=profile.resources.max_pids,
        network_mode=network_mode,
        dns=profile.network.dns_servers if profile.network.mode != NetworkMode.NONE else [],
        environment=environment,
        security_opt=["no-new-privileges"],
        cap_drop=["ALL"],
        cap_add=cap_add,
        user="1000:1000",
        runtime=runtime,
    )


def _build_volumes(profile: SandboxProfile) -> list[dict[str, str]]:
    """Build named Docker volume specs from the profile's filesystem config."""
    volumes: list[dict[str, str]] = []
    if profile.filesystem.session_volume:
        volumes.append({
            "name": profile.filesystem.session_volume,
            "target": profile.filesystem.session_volume_target,
            "mode": "rw",
        })
    return volumes


def _opencode_auth_path() -> str | None:
    """Return the host path to OpenCode's auth.json, or None if not found.

    Checks Unix-style path first (works on all platforms when OpenCode
    was installed via the standard installer), then falls back to the
    Windows %LOCALAPPDATA% location.

    - Unix-first: ~/.local/share/opencode/auth.json
    - Windows fallback: %LOCALAPPDATA%/opencode/auth.json
    """
    # Try the Unix-style path first (works on Linux, macOS, and WSL)
    unix_path = os.path.join(os.path.expanduser("~"), ".local", "share", "opencode", "auth.json")
    if os.path.isfile(unix_path):
        return unix_path

    # Windows fallback via LOCALAPPDATA
    if platform.system() == "Windows":
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        if local_app_data:
            win_path = os.path.join(local_app_data, "opencode", "auth.json")
            if os.path.isfile(win_path):
                return win_path

    # Return the Unix path as default even if the file doesn't exist yet
    # (caller checks os.path.isfile before mounting)
    if platform.system() == "Windows":
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        if local_app_data:
            return os.path.join(local_app_data, "opencode", "auth.json")
        return None
    return unix_path


def _auto_mount_credentials(home: str) -> list[dict[str, str]]:
    """Auto-mount SSH keys and git config if they exist on the host.

    Both are mounted read-only so the sandbox can use them for git
    operations but cannot modify them.

    Returns a list of mount dicts ready to append to the mounts list.
    """
    mounts: list[dict[str, str]] = []

    # SSH directory
    ssh_dir = os.path.join(home, ".ssh")
    if os.path.isdir(ssh_dir) and not os.path.islink(ssh_dir):
        mounts.append({
            "source": _to_docker_mount_path(ssh_dir),
            "target": "/home/agent/.ssh",
            "mode": "ro",
        })

    # Git config file
    gitconfig = os.path.join(home, ".gitconfig")
    if os.path.isfile(gitconfig) and not os.path.islink(gitconfig):
        mounts.append({
            "source": _to_docker_mount_path(gitconfig),
            "target": "/home/agent/.gitconfig",
            "mode": "ro",
        })

    return mounts


def _build_mounts(profile: SandboxProfile) -> list[dict[str, str]]:
    """Build bind mount specs from the profile's filesystem config.

    On Windows, host paths are converted to Docker Desktop mount format
    (e.g. C:\\Users\\me -> /c/Users/me).
    """
    mounts = []

    # Working directory -> /workspace (read-write)
    _validate_mount_source(profile.filesystem.working_dir)
    mounts.append({
        "source": _to_docker_mount_path(profile.filesystem.working_dir),
        "target": "/workspace",
        "mode": "rw",
    })

    # Additional writable paths — mount under /mnt/writable/<index> to ensure
    # the container target is always a valid Linux path (host paths like
    # C:\Users\me\data would be invalid inside the container).
    for idx, path in enumerate(profile.filesystem.writable_paths):
        _validate_mount_source(path)
        mounts.append({
            "source": _to_docker_mount_path(path),
            "target": f"/mnt/writable/{idx}",
            "mode": "rw",
        })

    # Mount AI agent config/auth so agents can authenticate and persist state
    agent = profile.extra_env.get("LASSO_AGENT", "")
    home = os.path.expanduser("~")

    _AGENT_MOUNTS = {
        "claude-code": [
            # Auth tokens, history, cache
            (".claude", ".claude", "rw"),
            # Claude config file (settings, project preferences)
            (".claude.json", ".claude.json", "rw"),
        ],
        "opencode": [
            (".opencode", ".opencode", "rw"),
        ],
    }
    for host_name, container_name, mode in _AGENT_MOUNTS.get(agent, []):
        host_path = os.path.join(home, host_name)
        container_path = f"/home/agent/{container_name}"
        if os.path.exists(host_path):
            mounts.append({
                "source": _to_docker_mount_path(host_path),
                "target": container_path,
                "mode": mode,
            })

    # OpenCode auth.json — file mount that takes precedence over session volume
    if agent == "opencode":
        auth_path = _opencode_auth_path()
        if auth_path and os.path.isfile(auth_path):
            mounts.append({
                "source": _to_docker_mount_path(auth_path),
                "target": "/home/agent/.local/share/opencode/auth.json",
                "mode": "ro",
            })

    # Auto-mount SSH keys and git config (opt-out via LASSO_NO_AUTO_MOUNT)
    if not profile.extra_env.get("LASSO_NO_AUTO_MOUNT", ""):
        mounts.extend(_auto_mount_credentials(home))

    # Extra mounts from --mount flag or dashboard
    import json as _json
    import logging

    logger = logging.getLogger(__name__)
    # Blocked container-side mount targets (sensitive paths inside the container)
    _BLOCKED_TARGETS = {"/etc", "/proc", "/sys", "/dev", "/bin", "/sbin", "/usr", "/boot", "/root"}

    extra_mounts_json = profile.extra_env.get("LASSO_EXTRA_MOUNTS", "")
    if extra_mounts_json:
        try:
            extra_mounts = _json.loads(extra_mounts_json)
            for m in extra_mounts:
                source = m["source"]
                target = m["target"]
                _validate_mount_source(source)
                # Validate container-side target path
                if target in _BLOCKED_TARGETS or any(
                    target.startswith(b + "/") for b in _BLOCKED_TARGETS
                ):
                    logger.warning("Blocked mount target: %s", target)
                    continue
                mounts.append({
                    "source": _to_docker_mount_path(source),
                    "target": target,
                    "mode": m.get("mode", "rw"),
                })
        except (ValueError, KeyError) as e:
            logger.warning("Invalid extra mounts: %s", e)

    return mounts


def _resolve_network_mode(profile: SandboxProfile) -> str:
    """Map LASSO network mode to container network mode.

    NONE uses Docker's ``none`` network (no connectivity at all).
    RESTRICTED and FULL both use ``bridge`` — iptables rules applied
    inside the container after startup handle the actual restriction.
    """
    if profile.network.mode == NetworkMode.NONE:
        return "none"
    return "bridge"


def _build_tmpfs(profile: SandboxProfile) -> dict[str, str]:
    """Build tmpfs mount specs."""
    return {
        "/tmp": f"size={profile.filesystem.temp_dir_mb}m,mode=1777,exec",
    }


def _detect_git_identity() -> dict[str, str]:
    """Detect the host git user.name and user.email for commit attribution."""
    env: dict[str, str] = {}
    try:
        name = subprocess.run(
            ["git", "config", "user.name"],
            capture_output=True, text=True, timeout=5,
        )
        email = subprocess.run(
            ["git", "config", "user.email"],
            capture_output=True, text=True, timeout=5,
        )
        if name.returncode == 0 and name.stdout.strip():
            env["GIT_AUTHOR_NAME"] = name.stdout.strip()
            env["GIT_COMMITTER_NAME"] = name.stdout.strip()
        if email.returncode == 0 and email.stdout.strip():
            env["GIT_AUTHOR_EMAIL"] = email.stdout.strip()
            env["GIT_COMMITTER_EMAIL"] = email.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return env


def _build_environment(profile: SandboxProfile) -> dict[str, str]:
    """Build environment variables for the container."""
    env = {
        "LASSO_SANDBOX_NAME": profile.name,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TERM": "xterm-256color",
        "HOME": "/home/agent",
    }
    # Only inject git identity if explicitly requested via extra_env
    # (defense against PII leakage to untrusted sandbox code)
    if profile.extra_env.get("LASSO_INJECT_GIT_IDENTITY", "").lower() in ("true", "1", "yes"):
        env.update(_detect_git_identity())

    # Always set NODE_EXTRA_CA_CERTS so Node.js native addons and tools
    # trust the system CA bundle (harmless if the file doesn't exist inside
    # the container — Node simply ignores it).
    ca_bundle = "/etc/ssl/certs/ca-certificates.crt"
    env["NODE_EXTRA_CA_CERTS"] = ca_bundle

    # If a corporate CA cert is configured, also point Python/requests at
    # the system trust store so TLS connections trust the corporate CA.
    from lasso.config.operational import load_config
    op_config = load_config()
    if op_config.containers.ca_cert_path:
        env["SSL_CERT_FILE"] = ca_bundle
        env["REQUESTS_CA_BUNDLE"] = ca_bundle

    # Apply user env (can override non-safety keys)
    env.update(profile.extra_env)
    # Re-enforce safety keys (user can't override these)
    env["HOME"] = "/home/agent"
    env["LANG"] = "C.UTF-8"
    env["LC_ALL"] = "C.UTF-8"
    env["TERM"] = "xterm-256color"
    env["LASSO_SANDBOX_NAME"] = profile.name
    return env


def _resolve_cap_add(profile: SandboxProfile) -> list[str]:
    """Determine additional capabilities needed for network policy enforcement.

    When network rules (iptables) need to be applied inside the container,
    the container needs NET_ADMIN capability temporarily during setup.

    Dependency: the container image MUST have iptables installed for these
    rules to work.  image_builder.generate_dockerfile() automatically adds
    the iptables package when needs_network_rules() is True.  If iptables
    is missing, _apply_network_policy() in sandbox.py will raise a
    RuntimeError at startup.
    """
    if needs_network_rules(profile):
        return ["NET_ADMIN"]
    return []


def _resolve_runtime(profile: SandboxProfile) -> str:
    """Map isolation level to OCI runtime name."""
    level = getattr(profile, "isolation", "container")
    if level == "gvisor":
        return "runsc"
    if level == "kata":
        return "io.containerd.kata.v2"
    return ""


def needs_network_rules(profile: SandboxProfile) -> bool:
    """Check whether this profile requires iptables rules applied post-start.

    - NONE mode: Docker's network_mode="none" already provides full isolation
      (no interfaces except loopback). No iptables rules needed, and adding
      NET_ADMIN capability for NONE mode is unnecessary.
    - RESTRICTED mode: iptables rules enforce allow-list inside the container.
    - FULL mode with blocked_cidrs: iptables rules block specific CIDRs.
    - FULL mode without blocked_cidrs: no rules needed.
    """
    mode = profile.network.mode
    if mode == NetworkMode.NONE:
        return False  # Docker handles NONE isolation, no iptables needed
    if mode == NetworkMode.RESTRICTED:
        return True
    if mode == NetworkMode.FULL and profile.network.blocked_cidrs:
        return True
    return False
