"""Shared fixtures for LASSO integration tests.

Provides Docker backend detection, sandbox registry, and pre-configured
sandbox fixtures that automatically clean up containers on teardown.
"""

import os

import pytest

from lasso.backends.docker_backend import DockerBackend
from lasso.config.defaults import (
    evaluation_profile,
    standard_profile,
    strict_profile,
)
from lasso.config.schema import (
    AuditConfig,
    ProfileMode,
)
from lasso.core.sandbox import Sandbox, SandboxRegistry


@pytest.fixture(scope="module")
def docker_backend():
    """Detect Docker backend; skip entire module if unavailable."""
    backend = DockerBackend()
    if not backend.is_available():
        pytest.skip("Docker daemon not available")
    return backend


@pytest.fixture
def registry(docker_backend, tmp_path):
    """Create a SandboxRegistry backed by Docker with isolated state dir."""
    return SandboxRegistry(backend=docker_backend, state_dir=str(tmp_path / "state"))


@pytest.fixture
def dev_sandbox(registry, tmp_path):
    """Create a development sandbox, yield it, clean up on teardown."""
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    # Ensure the directory is writable by uid 1000 (the container user)
    os.chmod(str(workspace), 0o777)

    profile = standard_profile(str(workspace))
    # Use autonomous mode so we can test all commands
    profile.mode = ProfileMode.AUTONOMOUS
    # Point audit logs to tmp_path so they don't pollute the system
    profile.audit = AuditConfig(
        enabled=True,
        log_dir=str(tmp_path / "audit"),
        sign_entries=True,
        include_command_output=True,
    )
    sb = registry.create(profile)
    registry.start(sb)
    yield sb
    _cleanup_sandbox(sb, registry)


@pytest.fixture
def strict_sandbox(registry, tmp_path):
    """Create a strict sandbox, yield it, clean up on teardown."""
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    os.chmod(str(workspace), 0o777)

    profile = strict_profile(str(workspace))
    # Keep observe mode to test restricted commands
    profile.audit = AuditConfig(
        enabled=True,
        log_dir=str(tmp_path / "audit"),
        sign_entries=True,
        include_command_output=True,
    )
    sb = registry.create(profile)
    registry.start(sb)
    yield sb
    _cleanup_sandbox(sb, registry)


@pytest.fixture
def minimal_sandbox(registry, tmp_path):
    """Create a minimal sandbox (no network), yield it, clean up on teardown."""
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    os.chmod(str(workspace), 0o777)

    profile = evaluation_profile(str(workspace))
    profile.audit = AuditConfig(
        enabled=True,
        log_dir=str(tmp_path / "audit"),
        sign_entries=True,
    )
    sb = registry.create(profile)
    registry.start(sb)
    yield sb
    _cleanup_sandbox(sb, registry)


def _cleanup_sandbox(sb: Sandbox, registry: SandboxRegistry):
    """Stop and remove a sandbox container, ignoring errors."""
    try:
        sb.stop()
    except Exception:
        pass
    # Belt-and-suspenders: force remove by container ID
    try:
        backend = registry._backend
        if backend and sb._container_id:
            try:
                backend.stop(sb._container_id)
            except Exception:
                pass
            try:
                backend.remove(sb._container_id)
            except Exception:
                pass
    except Exception:
        pass
