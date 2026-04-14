"""Tests for converting SandboxProfile → ContainerConfig.

This is the bridge between LASSO's config schema and the container backend.
TDD: write these tests first, then implement the converter.
"""

import pytest

from lasso.backends.base import ContainerConfig
from lasso.backends.converter import profile_to_container_config
from lasso.config.schema import (
    CommandConfig,
    CommandMode,
    FilesystemConfig,
    NetworkConfig,
    NetworkMode,
    ResourceConfig,
    SandboxProfile,
)


@pytest.fixture
def evaluation_profile():
    return SandboxProfile(
        name="test-minimal",
        filesystem=FilesystemConfig(working_dir="/tmp/test"),
        commands=CommandConfig(mode=CommandMode.WHITELIST),
        network=NetworkConfig(mode=NetworkMode.NONE),
        resources=ResourceConfig(max_memory_mb=512, max_cpu_percent=25, max_pids=50),
    )


@pytest.fixture
def dev_profile():
    return SandboxProfile(
        name="test-dev",
        filesystem=FilesystemConfig(
            working_dir="/home/user/project",
            writable_paths=["/home/user/.cache"],
        ),
        commands=CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=["python3", "pip", "git", "ls"],
            allow_shell_operators=True,
        ),
        network=NetworkConfig(
            mode=NetworkMode.RESTRICTED,
            allowed_domains=["pypi.org", "github.com"],
            allowed_ports=[80, 443],
            dns_servers=["1.1.1.1"],
        ),
        resources=ResourceConfig(max_memory_mb=4096, max_cpu_percent=75, max_pids=200),
    )


class TestProfileToContainerConfig:
    def test_returns_container_config(self, evaluation_profile):
        config = profile_to_container_config(evaluation_profile)
        assert isinstance(config, ContainerConfig)

    def test_container_name_derived_from_profile(self, evaluation_profile):
        config = profile_to_container_config(evaluation_profile)
        assert "test-minimal" in config.name
        assert config.name.startswith("lasso-")

    def test_working_dir_mounted(self, evaluation_profile):
        config = profile_to_container_config(evaluation_profile)
        mount_targets = [m["target"] for m in config.bind_mounts]
        assert "/workspace" in mount_targets

    def test_working_dir_source(self, evaluation_profile):
        config = profile_to_container_config(evaluation_profile)
        workspace_mount = next(m for m in config.bind_mounts if m["target"] == "/workspace")
        assert workspace_mount["source"] == "/tmp/test"

    def test_network_none_maps_to_none(self, evaluation_profile):
        config = profile_to_container_config(evaluation_profile)
        assert config.network_mode == "none"

    def test_network_restricted_creates_custom_network(self, dev_profile):
        config = profile_to_container_config(dev_profile)
        # Restricted mode should still use a network, not "none"
        assert config.network_mode != "none"

    def test_memory_limit_converted(self, evaluation_profile):
        config = profile_to_container_config(evaluation_profile)
        assert config.mem_limit == "512m"

    def test_memory_limit_dev(self, dev_profile):
        config = profile_to_container_config(dev_profile)
        assert config.mem_limit == "4096m"

    def test_cpu_quota_calculated(self, evaluation_profile):
        config = profile_to_container_config(evaluation_profile)
        # 25% CPU = 25000 microseconds per 100000 period
        assert config.cpu_quota == 25000
        assert config.cpu_period == 100000

    def test_pids_limit(self, evaluation_profile):
        config = profile_to_container_config(evaluation_profile)
        assert config.pids_limit == 50

    def test_capabilities_dropped(self, evaluation_profile):
        config = profile_to_container_config(evaluation_profile)
        assert "ALL" in config.cap_drop

    def test_read_only_root(self, evaluation_profile):
        config = profile_to_container_config(evaluation_profile)
        assert config.read_only_root is True

    def test_tmpfs_for_tmp(self, evaluation_profile):
        config = profile_to_container_config(evaluation_profile)
        assert "/tmp" in config.tmpfs_mounts

    def test_environment_contains_sandbox_id(self, evaluation_profile):
        config = profile_to_container_config(evaluation_profile)
        assert "LASSO_SANDBOX_NAME" in config.environment
        assert config.environment["LASSO_SANDBOX_NAME"] == "test-minimal"

    def test_dns_servers_set(self, dev_profile):
        config = profile_to_container_config(dev_profile)
        assert "1.1.1.1" in config.dns

    def test_writable_paths_mounted(self, dev_profile):
        config = profile_to_container_config(dev_profile)
        mount_sources = [m["source"] for m in config.bind_mounts]
        assert "/home/user/.cache" in mount_sources

    def test_hostname_set(self, evaluation_profile):
        config = profile_to_container_config(evaluation_profile)
        assert config.hostname == "lasso-sandbox"
