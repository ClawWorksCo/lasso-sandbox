"""Tests for named Docker volume support for session persistence.

Validates the full pipeline: schema fields, converter logic, and
ContainerConfig output when session_volume is configured.
"""

import pytest

from lasso.backends.base import ContainerConfig
from lasso.backends.converter import profile_to_container_config
from lasso.config.schema import (
    FilesystemConfig,
    SandboxProfile,
)


@pytest.fixture
def basic_profile():
    """Profile without session volume configured."""
    return SandboxProfile(
        name="test-no-volume",
        filesystem=FilesystemConfig(working_dir="/tmp/test"),
    )


@pytest.fixture
def session_volume_profile():
    """Profile with session volume configured."""
    return SandboxProfile(
        name="test-session-vol",
        filesystem=FilesystemConfig(
            working_dir="/tmp/test",
            session_volume="agent-state",
            session_volume_target="/home/agent",
        ),
    )


@pytest.fixture
def custom_target_profile():
    """Profile with session volume and custom mount target."""
    return SandboxProfile(
        name="test-custom-target",
        filesystem=FilesystemConfig(
            working_dir="/tmp/test",
            session_volume="my-data",
            session_volume_target="/data/persistent",
        ),
    )


class TestFilesystemConfigSessionVolume:
    """Test the schema-level session_volume fields."""

    def test_session_volume_default_is_none(self):
        fs = FilesystemConfig(working_dir="/tmp/test")
        assert fs.session_volume is None

    def test_session_volume_target_default(self):
        fs = FilesystemConfig(working_dir="/tmp/test")
        assert fs.session_volume_target == "/home/agent"

    def test_session_volume_can_be_set(self):
        fs = FilesystemConfig(
            working_dir="/tmp/test",
            session_volume="my-volume",
        )
        assert fs.session_volume == "my-volume"

    def test_session_volume_target_can_be_overridden(self):
        fs = FilesystemConfig(
            working_dir="/tmp/test",
            session_volume="my-volume",
            session_volume_target="/data/state",
        )
        assert fs.session_volume_target == "/data/state"


class TestContainerConfigVolumes:
    """Test the ContainerConfig volumes field."""

    def test_volumes_default_empty(self):
        config = ContainerConfig()
        assert config.volumes == []

    def test_volumes_can_be_populated(self):
        config = ContainerConfig(
            volumes=[{"name": "test-vol", "target": "/mnt/data", "mode": "rw"}]
        )
        assert len(config.volumes) == 1
        assert config.volumes[0]["name"] == "test-vol"


class TestConverterSessionVolume:
    """Test profile_to_container_config with session volumes."""

    def test_no_volume_when_not_configured(self, basic_profile):
        config = profile_to_container_config(basic_profile)
        assert config.volumes == []

    def test_volume_added_when_configured(self, session_volume_profile):
        config = profile_to_container_config(session_volume_profile)
        assert len(config.volumes) == 1
        vol = config.volumes[0]
        assert vol["name"] == "agent-state"
        assert vol["target"] == "/home/agent"
        assert vol["mode"] == "rw"

    def test_custom_target_respected(self, custom_target_profile):
        config = profile_to_container_config(custom_target_profile)
        assert len(config.volumes) == 1
        vol = config.volumes[0]
        assert vol["name"] == "my-data"
        assert vol["target"] == "/data/persistent"
        assert vol["mode"] == "rw"

    def test_bind_mounts_still_present_with_volume(self, session_volume_profile):
        config = profile_to_container_config(session_volume_profile)
        # Should still have the workspace bind mount
        assert len(config.bind_mounts) >= 1
        workspace_mount = config.bind_mounts[0]
        assert workspace_mount["target"] == "/workspace"


class TestFakeBackendSessionVolume:
    """Test that FakeBackend correctly receives volume config."""

    def test_volume_config_reaches_backend(self, session_volume_profile):
        from tests.conftest import FakeBackend

        backend = FakeBackend()
        config = profile_to_container_config(session_volume_profile)
        config.image = "python:3.12-slim"  # FakeBackend needs an image

        cid = backend.create(config)
        assert cid.startswith("fake-")

        # Verify the config stored in FakeBackend has volumes
        stored_config = backend.containers[cid]["config"]
        assert len(stored_config.volumes) == 1
        assert stored_config.volumes[0]["name"] == "agent-state"


class TestCLISessionVolumeFlag:
    """Test that --session-volume flag applies to profile correctly."""

    def test_session_volume_applied_to_profile(self):
        """Simulate what the CLI does when --session-volume is passed."""
        profile = SandboxProfile(
            name="test-cli",
            filesystem=FilesystemConfig(working_dir="/tmp/test"),
        )
        assert profile.filesystem.session_volume is None

        # This is what the CLI does:
        profile.filesystem.session_volume = "my-agent-state"

        assert profile.filesystem.session_volume == "my-agent-state"

        config = profile_to_container_config(profile)
        assert len(config.volumes) == 1
        assert config.volumes[0]["name"] == "my-agent-state"
        assert config.volumes[0]["target"] == "/home/agent"
