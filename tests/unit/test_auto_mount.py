"""Tests for auto-mounting SSH keys, git config, and OpenCode auth.

Covers:
- _opencode_auth_path() platform detection
- _auto_mount_credentials() SSH + gitconfig auto-detection
- LASSO_NO_AUTO_MOUNT opt-out via converter
- OpenCode auth.json file mount for agent=opencode
- _apply_auto_mount_flags() CLI helper
"""

import json
import os
from unittest.mock import patch

from lasso.backends.converter import (
    _auto_mount_credentials,
    _opencode_auth_path,
    profile_to_container_config,
)
from lasso.cli.helpers import _apply_auto_mount_flags
from lasso.config.schema import (
    CommandConfig,
    CommandMode,
    FilesystemConfig,
    NetworkConfig,
    NetworkMode,
    ResourceConfig,
    SandboxProfile,
)


def _make_profile(**extra_env) -> SandboxProfile:
    """Create a minimal profile for testing."""
    return SandboxProfile(
        name="test-automount",
        filesystem=FilesystemConfig(working_dir="/tmp/test"),
        commands=CommandConfig(mode=CommandMode.WHITELIST),
        network=NetworkConfig(mode=NetworkMode.NONE),
        resources=ResourceConfig(max_memory_mb=512, max_cpu_percent=25, max_pids=50),
        extra_env=dict(extra_env),
    )


# -----------------------------------------------------------------------
# _opencode_auth_path
# -----------------------------------------------------------------------

class TestOpenCodeAuthPath:
    @patch("lasso.backends.converter.os.path.isfile", return_value=False)
    @patch("lasso.backends.converter.platform.system", return_value="Linux")
    def test_linux_path(self, _mock_sys, _mock_isfile):
        path = _opencode_auth_path()
        assert path.endswith(".local/share/opencode/auth.json")

    @patch("lasso.backends.converter.os.path.isfile", return_value=False)
    @patch("lasso.backends.converter.platform.system", return_value="Darwin")
    def test_macos_path(self, _mock_sys, _mock_isfile):
        path = _opencode_auth_path()
        assert path.endswith(".local/share/opencode/auth.json")

    @patch("lasso.backends.converter.os.path.isfile", return_value=False)
    @patch("lasso.backends.converter.platform.system", return_value="Windows")
    @patch.dict(os.environ, {"LOCALAPPDATA": "C:\\Users\\test\\AppData\\Local"})
    def test_windows_path(self, _mock_sys, _mock_isfile):
        path = _opencode_auth_path()
        assert "opencode" in path
        assert path.endswith("auth.json")

    @patch("lasso.backends.converter.os.path.isfile", return_value=False)
    @patch("lasso.backends.converter.platform.system", return_value="Windows")
    @patch.dict(os.environ, {}, clear=True)
    def test_windows_no_localappdata(self, _mock_sys, _mock_isfile):
        # Remove LOCALAPPDATA entirely
        os.environ.pop("LOCALAPPDATA", None)
        path = _opencode_auth_path()
        assert path is None

    def test_unix_path_preferred_when_exists(self, tmp_path):
        """When the Unix-style path exists, it should be returned even on Windows."""
        auth_dir = tmp_path / ".local" / "share" / "opencode"
        auth_dir.mkdir(parents=True)
        auth_file = auth_dir / "auth.json"
        auth_file.write_text('{"token": "test"}')

        with patch("lasso.backends.converter.os.path.expanduser", return_value=str(tmp_path)):
            with patch("lasso.backends.converter.platform.system", return_value="Windows"):
                path = _opencode_auth_path()
                assert path == str(auth_file)


# -----------------------------------------------------------------------
# _auto_mount_credentials
# -----------------------------------------------------------------------

class TestAutoMountCredentials:
    def test_mounts_ssh_when_exists(self, tmp_path):
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_rsa").touch()

        mounts = _auto_mount_credentials(str(tmp_path))
        ssh_mounts = [m for m in mounts if m["target"] == "/home/agent/.ssh"]
        assert len(ssh_mounts) == 1
        assert ssh_mounts[0]["mode"] == "ro"
        assert ssh_mounts[0]["source"] == str(ssh_dir)

    def test_mounts_gitconfig_when_exists(self, tmp_path):
        gitconfig = tmp_path / ".gitconfig"
        gitconfig.write_text("[user]\n  name = Test\n")

        mounts = _auto_mount_credentials(str(tmp_path))
        git_mounts = [m for m in mounts if m["target"] == "/home/agent/.gitconfig"]
        assert len(git_mounts) == 1
        assert git_mounts[0]["mode"] == "ro"
        assert git_mounts[0]["source"] == str(gitconfig)

    def test_mounts_both_when_both_exist(self, tmp_path):
        (tmp_path / ".ssh").mkdir()
        (tmp_path / ".gitconfig").write_text("[user]\n  name = Test\n")

        mounts = _auto_mount_credentials(str(tmp_path))
        targets = [m["target"] for m in mounts]
        assert "/home/agent/.ssh" in targets
        assert "/home/agent/.gitconfig" in targets

    def test_no_mounts_when_nothing_exists(self, tmp_path):
        mounts = _auto_mount_credentials(str(tmp_path))
        assert mounts == []

    def test_skips_ssh_symlink(self, tmp_path):
        """Symlinked .ssh should not be mounted (security: TOCTOU risk)."""
        real_dir = tmp_path / "real_ssh"
        real_dir.mkdir()
        ssh_link = tmp_path / ".ssh"
        ssh_link.symlink_to(real_dir)

        mounts = _auto_mount_credentials(str(tmp_path))
        ssh_mounts = [m for m in mounts if m["target"] == "/home/agent/.ssh"]
        assert len(ssh_mounts) == 0

    def test_skips_gitconfig_symlink(self, tmp_path):
        """Symlinked .gitconfig should not be mounted."""
        real_file = tmp_path / "real_gitconfig"
        real_file.write_text("[user]\n  name = Test\n")
        gitconfig_link = tmp_path / ".gitconfig"
        gitconfig_link.symlink_to(real_file)

        mounts = _auto_mount_credentials(str(tmp_path))
        git_mounts = [m for m in mounts if m["target"] == "/home/agent/.gitconfig"]
        assert len(git_mounts) == 0


# -----------------------------------------------------------------------
# OpenCode auth.json mount in converter
# -----------------------------------------------------------------------

class TestOpenCodeAuthMount:
    def test_opencode_auth_mounted_when_exists(self, tmp_path):
        """When agent=opencode and auth.json exists, it should be mounted ro."""
        auth_dir = tmp_path / ".local" / "share" / "opencode"
        auth_dir.mkdir(parents=True)
        auth_file = auth_dir / "auth.json"
        auth_file.write_text('{"token": "test"}')

        profile = _make_profile(LASSO_AGENT="opencode", LASSO_NO_AUTO_MOUNT="1")

        with patch("lasso.backends.converter.os.path.expanduser", return_value=str(tmp_path)):
            with patch("lasso.backends.converter._opencode_auth_path", return_value=str(auth_file)):
                config = profile_to_container_config(profile)

        auth_mounts = [m for m in config.bind_mounts
                       if m["target"] == "/home/agent/.local/share/opencode/auth.json"]
        assert len(auth_mounts) == 1
        assert auth_mounts[0]["mode"] == "ro"

    def test_opencode_auth_not_mounted_when_missing(self, tmp_path):
        """When auth.json doesn't exist, no mount should be added."""
        profile = _make_profile(LASSO_AGENT="opencode", LASSO_NO_AUTO_MOUNT="1")

        with patch("lasso.backends.converter.os.path.expanduser", return_value=str(tmp_path)):
            with patch("lasso.backends.converter._opencode_auth_path",
                       return_value=str(tmp_path / "nonexistent" / "auth.json")):
                config = profile_to_container_config(profile)

        auth_mounts = [m for m in config.bind_mounts
                       if m["target"] == "/home/agent/.local/share/opencode/auth.json"]
        assert len(auth_mounts) == 0

    def test_non_opencode_agent_no_auth_mount(self, tmp_path):
        """Other agents should not get the OpenCode auth mount."""
        auth_dir = tmp_path / ".local" / "share" / "opencode"
        auth_dir.mkdir(parents=True)
        (auth_dir / "auth.json").write_text('{"token": "test"}')

        profile = _make_profile(LASSO_AGENT="claude-code", LASSO_NO_AUTO_MOUNT="1")

        with patch("lasso.backends.converter.os.path.expanduser", return_value=str(tmp_path)):
            config = profile_to_container_config(profile)

        auth_mounts = [m for m in config.bind_mounts
                       if m["target"] == "/home/agent/.local/share/opencode/auth.json"]
        assert len(auth_mounts) == 0


# -----------------------------------------------------------------------
# LASSO_NO_AUTO_MOUNT opt-out
# -----------------------------------------------------------------------

class TestNoAutoMountOptOut:
    def test_auto_mount_disabled_by_env(self, tmp_path):
        """LASSO_NO_AUTO_MOUNT=1 should suppress SSH/gitconfig mounts."""
        (tmp_path / ".ssh").mkdir()
        (tmp_path / ".gitconfig").write_text("[user]\n  name = Test\n")

        profile = _make_profile(LASSO_NO_AUTO_MOUNT="1")

        with patch("lasso.backends.converter.os.path.expanduser", return_value=str(tmp_path)):
            config = profile_to_container_config(profile)

        targets = [m["target"] for m in config.bind_mounts]
        assert "/home/agent/.ssh" not in targets
        assert "/home/agent/.gitconfig" not in targets

    def test_auto_mount_enabled_by_default(self, tmp_path):
        """Without LASSO_NO_AUTO_MOUNT, SSH/gitconfig should be mounted."""
        (tmp_path / ".ssh").mkdir()
        (tmp_path / ".gitconfig").write_text("[user]\n  name = Test\n")

        profile = _make_profile()

        with patch("lasso.backends.converter.os.path.expanduser", return_value=str(tmp_path)):
            config = profile_to_container_config(profile)

        targets = [m["target"] for m in config.bind_mounts]
        assert "/home/agent/.ssh" in targets
        assert "/home/agent/.gitconfig" in targets


# -----------------------------------------------------------------------
# _apply_auto_mount_flags CLI helper
# -----------------------------------------------------------------------

class TestApplyAutoMountFlags:
    def test_no_auto_mount_sets_env(self):
        profile = _make_profile()
        _apply_auto_mount_flags(profile, no_auto_mount=True)
        assert profile.extra_env.get("LASSO_NO_AUTO_MOUNT") == "1"

    def test_default_does_nothing(self):
        profile = _make_profile()
        _apply_auto_mount_flags(profile)
        assert "LASSO_NO_AUTO_MOUNT" not in profile.extra_env

    def test_ssh_flag_adds_explicit_mount(self, tmp_path):
        """--ssh should add an explicit extra mount even when auto-mount is off."""
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()

        profile = _make_profile()

        with patch("lasso.cli.helpers.Path.home", return_value=tmp_path):
            _apply_auto_mount_flags(profile, ssh=True, no_auto_mount=True)

        assert profile.extra_env.get("LASSO_NO_AUTO_MOUNT") == "1"
        extra = json.loads(profile.extra_env.get("LASSO_EXTRA_MOUNTS", "[]"))
        ssh_mounts = [m for m in extra if m["target"] == "/home/agent/.ssh"]
        assert len(ssh_mounts) == 1
        assert ssh_mounts[0]["mode"] == "ro"

    def test_ssh_flag_without_dir_warns(self, tmp_path, capsys):
        """--ssh with no ~/.ssh should warn, not crash."""
        profile = _make_profile()

        with patch("lasso.cli.helpers.Path.home", return_value=tmp_path):
            # Should not raise
            _apply_auto_mount_flags(profile, ssh=True)

        # No mount added since ~/.ssh doesn't exist
        extra = json.loads(profile.extra_env.get("LASSO_EXTRA_MOUNTS", "[]"))
        assert len(extra) == 0
