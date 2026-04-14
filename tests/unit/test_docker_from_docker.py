"""Tests for Docker-from-Docker via socket proxy.

Verifies that docker_from_docker=True on a profile:
1. Removes docker/podman from the command blacklist
2. Sets DOCKER_HOST and network_mode in the container config
3. Allows docker commands through the command gate
"""

import pytest

from lasso.backends.converter import profile_to_container_config
from lasso.config.defaults import standard_profile
from lasso.config.schema import SandboxState
from lasso.core.sandbox import Sandbox
from tests.conftest import FakeBackend


@pytest.fixture
def dfd_profile(tmp_path):
    """Standard profile with docker_from_docker enabled."""
    profile = standard_profile(str(tmp_path), name="dfd-test")
    profile.docker_from_docker = True
    return profile


@pytest.fixture
def normal_profile(tmp_path):
    """Standard profile with docker_from_docker disabled (default)."""
    return standard_profile(str(tmp_path), name="normal-test")


class TestDockerFromDockerSchema:
    def test_default_is_false(self, normal_profile):
        assert normal_profile.docker_from_docker is False

    def test_can_enable(self, dfd_profile):
        assert dfd_profile.docker_from_docker is True


class TestDockerFromDockerConverter:
    def test_network_mode_is_sandbox_net(self, dfd_profile):
        config = profile_to_container_config(dfd_profile)
        assert config.network_mode == "lasso-sandbox-net"

    def test_docker_host_set(self, dfd_profile):
        config = profile_to_container_config(dfd_profile)
        assert config.environment["DOCKER_HOST"] == "tcp://lasso-socket-proxy:2375"

    def test_normal_profile_no_docker_host(self, normal_profile):
        config = profile_to_container_config(normal_profile)
        assert "DOCKER_HOST" not in config.environment

    def test_normal_profile_uses_bridge(self, normal_profile):
        config = profile_to_container_config(normal_profile)
        # Standard profile uses restricted network -> bridge
        assert config.network_mode == "bridge"


class TestDockerFromDockerSandbox:
    def test_docker_removed_from_blacklist(self, dfd_profile):
        """Sandbox init should remove docker/podman from blacklist."""
        sb = Sandbox(dfd_profile, backend=FakeBackend())
        assert "docker" not in sb.profile.commands.blacklist
        assert "podman" not in sb.profile.commands.blacklist

    def test_normal_profile_keeps_docker_blocked(self, normal_profile):
        """Normal profile should keep docker/podman blocked."""
        sb = Sandbox(normal_profile, backend=FakeBackend())
        assert "docker" in sb.profile.commands.blacklist
        assert "podman" in sb.profile.commands.blacklist

    def test_docker_command_allowed(self, dfd_profile):
        """Docker commands should pass the command gate when DfD is enabled."""
        backend = FakeBackend()
        sb = Sandbox(dfd_profile, backend=backend)
        sb.start()
        result = sb.exec("docker ps")
        assert not result.blocked
        sb.stop()

    def test_docker_command_blocked_without_dfd(self, normal_profile):
        """Docker commands should be blocked when DfD is not enabled."""
        backend = FakeBackend()
        sb = Sandbox(normal_profile, backend=backend)
        sb.start()
        result = sb.exec("docker ps")
        assert result.blocked
        sb.stop()

    def test_profile_deep_copy_isolation(self, dfd_profile):
        """Changes to sandbox profile should not affect the original."""
        original_blacklist = list(dfd_profile.commands.blacklist)
        Sandbox(dfd_profile, backend=FakeBackend())
        # The original profile's blacklist should be unchanged
        assert dfd_profile.commands.blacklist == original_blacklist


class TestDockerFromDockerLifecycle:
    def test_start_and_stop(self, dfd_profile):
        """DfD sandbox should start and stop cleanly with FakeBackend."""
        backend = FakeBackend()
        sb = Sandbox(dfd_profile, backend=backend)
        sb.start()
        assert sb.state == SandboxState.RUNNING
        sb.stop()
        assert sb.state == SandboxState.STOPPED

    def test_context_manager(self, dfd_profile):
        """DfD sandbox should work as a context manager."""
        backend = FakeBackend()
        with Sandbox(dfd_profile, backend=backend) as sb:
            assert sb.state == SandboxState.RUNNING
            result = sb.exec("docker info")
            assert not result.blocked
