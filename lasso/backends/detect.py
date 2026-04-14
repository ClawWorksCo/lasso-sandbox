"""Auto-detect available container backends.

Tries Podman or Docker via their compatible API sockets.
On Windows, Podman is the recommended runtime (no Docker Desktop license
required for enterprise use). Falls back to native subprocess mode.
"""

from __future__ import annotations

import logging

from lasso.backends.base import ContainerBackend

logger = logging.getLogger("lasso.backends")


def detect_backend() -> ContainerBackend | None:
    """Detect and return the best available container backend.

    Priority:
    1. Docker (also works with Podman via DOCKER_HOST)
    2. None (native subprocess fallback)
    """
    # Try Docker / Podman (Docker-compatible API)
    try:
        from lasso.backends.docker_backend import DockerBackend
        backend = DockerBackend()
        if backend.is_available():
            info = backend.get_info()
            logger.info(
                "Using %s %s (%s)",
                info.get("runtime", "docker"),
                info.get("version", "unknown"),
                info.get("os", "unknown"),
            )
            return backend
    except ImportError:
        logger.debug("docker package not installed")
    except Exception as e:
        logger.debug("Docker backend unavailable: %s", e)

    logger.warning("No container runtime detected — using native subprocess mode")
    return None


def detect_isolation_levels() -> list[str]:
    """Detect which isolation levels are available on this system."""
    levels = ["container"]  # Always available if Docker/Podman works

    backend = detect_backend()
    if backend is None:
        return levels

    # Check for gVisor (runsc)
    try:
        _info = backend.get_info()
        client = backend.get_native_client()
        if client is None:
            return levels
        runtimes = client.api.info().get("Runtimes", {})
        if "runsc" in runtimes:
            levels.append("gvisor")
        # Check for Kata
        for name in runtimes:
            if "kata" in name.lower():
                levels.append("kata")
                break
    except Exception:
        pass

    return levels


def require_backend() -> ContainerBackend:
    """Detect a backend or raise with a helpful message."""
    backend = detect_backend()
    if backend is None:
        import platform
        if platform.system() == "Windows":
            install_msg = (
                "LASSO requires Podman or Docker for full sandbox isolation.\n"
                "Recommended for Windows:\n"
                "  - Podman Desktop: https://podman-desktop.io/\n"
                "    (free for enterprise, no license required)\n"
                "Alternative:\n"
                "  - Docker Desktop: https://docs.docker.com/get-docker/\n"
                "    (requires paid license for enterprise use)"
            )
        else:
            install_msg = (
                "LASSO requires Podman or Docker for full sandbox isolation.\n"
                "Install one of:\n"
                "  - Podman: https://podman.io/getting-started/installation\n"
                "  - Docker: https://docs.docker.com/get-docker/"
            )
        raise RuntimeError(
            f"No container runtime available.\n\n"
            f"{install_msg}\n\n"
            f"Or run with --native flag for software-only isolation (not recommended)."
        )
    return backend
