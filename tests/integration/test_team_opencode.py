"""Integration test for the team-opencode profile.

Validates that the team-opencode.toml example profile loads correctly
and all fields are parsed to the expected values. This is a schema-level
test -- it does NOT require Docker.
"""

from pathlib import Path

import pytest

from lasso.config.profile import load_profile_from_path
from lasso.config.schema import CommandMode, NetworkMode

PROFILE_PATH = Path(__file__).resolve().parents[2] / "examples" / "profiles" / "team-opencode.toml"


@pytest.mark.integration
class TestTeamOpencodeProfile:
    """Verify the team-opencode profile loads and parses correctly."""

    @pytest.fixture(autouse=True)
    def load_profile(self):
        self.profile = load_profile_from_path(PROFILE_PATH)

    def test_profile_loads_successfully(self):
        assert self.profile is not None

    def test_name(self):
        assert self.profile.name == "team-opencode"

    def test_description(self):
        assert "OpenCode" in self.profile.description
        assert "Docker-from-Docker" in self.profile.description

    def test_docker_from_docker_enabled(self):
        assert self.profile.docker_from_docker is True

    def test_commands_mode_is_blacklist(self):
        assert self.profile.commands.mode == CommandMode.BLACKLIST

    def test_commands_blacklist_contents(self):
        assert "rm -rf /" in self.profile.commands.blacklist
        assert "dd" in self.profile.commands.blacklist
        assert "mkfs" in self.profile.commands.blacklist

    def test_network_mode_is_full(self):
        assert self.profile.network.mode == NetworkMode.FULL

    def test_network_blocked_ports_empty(self):
        assert self.profile.network.blocked_ports == []

    def test_filesystem_working_dir(self):
        assert self.profile.filesystem.working_dir == "."

    def test_filesystem_writable_paths(self):
        writable = self.profile.filesystem.writable_paths
        assert "/workspace" in writable
        assert "/home/agent/.local" in writable
        assert "/tmp" in writable

    def test_session_volume_set(self):
        assert self.profile.filesystem.session_volume == "opencode-agent-data"

    def test_session_volume_target(self):
        assert self.profile.filesystem.session_volume_target == "/home/agent/.local"

    def test_resources_memory(self):
        assert self.profile.resources.max_memory_mb == 8192

    def test_resources_pids(self):
        assert self.profile.resources.max_pids == 256
