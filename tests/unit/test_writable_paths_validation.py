"""Tests for FilesystemConfig.writable_paths validation.

Ensures that system-critical paths cannot be mounted as writable,
path traversal is blocked, and only allowed prefixes are accepted.
"""

from __future__ import annotations

import pytest

from lasso.config.schema import FilesystemConfig

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fs(**overrides) -> FilesystemConfig:
    """Build a FilesystemConfig with sensible defaults + overrides."""
    defaults = {"working_dir": "/home/user/project"}
    defaults.update(overrides)
    return FilesystemConfig(**defaults)


# ---------------------------------------------------------------------------
# Accepted paths
# ---------------------------------------------------------------------------

class TestWritablePathsAccepted:
    """Paths that should pass validation."""

    def test_empty_list_allowed(self):
        fs = _make_fs(writable_paths=[])
        assert fs.writable_paths == []

    def test_home_subdir(self):
        fs = _make_fs(writable_paths=["/home/user/data"])
        assert "/home/user/data" in fs.writable_paths

    def test_tmp_path(self):
        fs = _make_fs(writable_paths=["/tmp/scratch"])
        assert "/tmp/scratch" in fs.writable_paths

    def test_var_tmp_path(self):
        fs = _make_fs(writable_paths=["/var/tmp/build"])
        assert "/var/tmp/build" in fs.writable_paths

    def test_workspace_path(self):
        fs = _make_fs(writable_paths=["/workspace/output"])
        assert "/workspace/output" in fs.writable_paths

    def test_relative_path_allowed(self):
        fs = _make_fs(writable_paths=["./data"])
        assert "data" in fs.writable_paths

    def test_multiple_valid_paths(self):
        paths = ["/home/user/a", "/tmp/b", "/workspace/c"]
        fs = _make_fs(writable_paths=paths)
        assert len(fs.writable_paths) == 3

    def test_bare_relative_path(self):
        fs = _make_fs(writable_paths=["output"])
        assert "output" in fs.writable_paths

    def test_whitespace_stripped(self):
        fs = _make_fs(writable_paths=["  /tmp/data  "])
        assert "/tmp/data" in fs.writable_paths

    def test_empty_string_filtered(self):
        fs = _make_fs(writable_paths=["", "  ", "/tmp/ok"])
        assert len(fs.writable_paths) == 1


# ---------------------------------------------------------------------------
# Rejected: path traversal
# ---------------------------------------------------------------------------

class TestWritablePathsTraversal:
    """Paths containing '..' must be rejected."""

    def test_dotdot_relative(self):
        with pytest.raises(ValueError, match="Path traversal"):
            _make_fs(writable_paths=["../etc/shadow"])

    def test_dotdot_absolute(self):
        with pytest.raises(ValueError, match="Path traversal"):
            _make_fs(writable_paths=["/home/user/../../etc"])

    def test_dotdot_in_middle(self):
        with pytest.raises(ValueError, match="Path traversal"):
            _make_fs(writable_paths=["/home/../root"])


# ---------------------------------------------------------------------------
# Rejected: system-critical paths
# ---------------------------------------------------------------------------

class TestWritablePathsBlockedSystem:
    """System-critical paths must be rejected even when absolute."""

    @pytest.mark.parametrize("path", [
        "/etc",
        "/etc/passwd",
        "/root",
        "/root/.ssh",
        "/bin",
        "/bin/sh",
        "/sbin",
        "/sbin/init",
        "/usr",
        "/usr/lib",
        "/boot",
        "/boot/grub",
        "/proc",
        "/proc/1/cmdline",
        "/sys",
        "/sys/kernel",
        "/dev",
        "/dev/sda",
    ])
    def test_blocked_system_path(self, path: str):
        with pytest.raises(ValueError, match="System-critical path"):
            _make_fs(writable_paths=[path])


# ---------------------------------------------------------------------------
# Rejected: paths outside allowed prefixes
# ---------------------------------------------------------------------------

class TestWritablePathsDisallowedPrefixes:
    """Absolute paths that don't start with an allowed prefix must be rejected."""

    @pytest.mark.parametrize("path", [
        "/opt/secret",
        "/var/log",
        "/srv/data",
        "/mnt/external",
        "/run/user",
    ])
    def test_disallowed_prefix(self, path: str):
        with pytest.raises(ValueError, match="Writable path must be under"):
            _make_fs(writable_paths=[path])

    def test_lib_rejected(self):
        """'/lib/modules' may resolve to /usr/lib/modules (symlink), either way blocked."""
        with pytest.raises(ValueError):
            _make_fs(writable_paths=["/lib/modules"])


# ---------------------------------------------------------------------------
# Mixed valid + invalid (first invalid triggers error)
# ---------------------------------------------------------------------------

class TestWritablePathsMixed:
    """A single invalid path in the list should reject the whole config."""

    def test_valid_then_invalid(self):
        with pytest.raises(ValueError):
            _make_fs(writable_paths=["/tmp/ok", "/etc/bad"])

    def test_invalid_then_valid(self):
        with pytest.raises(ValueError):
            _make_fs(writable_paths=["/root/.ssh", "/home/user/ok"])


# ---------------------------------------------------------------------------
# HIGH-1: Bare /home must be rejected
# ---------------------------------------------------------------------------

class TestWritablePathsBareHome:
    """Bare /home is too broad and must be rejected."""

    def test_bare_home_rejected(self):
        with pytest.raises(ValueError, match="too broad"):
            _make_fs(writable_paths=["/home"])

    def test_home_subdir_accepted(self):
        fs = _make_fs(writable_paths=["/home/username"])
        assert "/home/username" in fs.writable_paths

    def test_home_deep_subdir_accepted(self):
        fs = _make_fs(writable_paths=["/home/user/projects/data"])
        assert "/home/user/projects/data" in fs.writable_paths

    def test_bare_tmp_still_accepted(self):
        """Bare /tmp is fine -- it's a designated scratch space."""
        fs = _make_fs(writable_paths=["/tmp"])
        assert "/tmp" in fs.writable_paths

    def test_bare_workspace_still_accepted(self):
        fs = _make_fs(writable_paths=["/workspace"])
        assert "/workspace" in fs.writable_paths


# ---------------------------------------------------------------------------
# HIGH-2: Relative paths targeting system directories
# ---------------------------------------------------------------------------

class TestWritablePathsRelativeSystemDirs:
    """Relative paths like etc/passwd must be rejected."""

    @pytest.mark.parametrize("path", [
        "etc/passwd",
        "etc/shadow",
        "proc/self/environ",
        "sys/kernel",
        "dev/sda",
        "root/.ssh",
        "bin/sh",
        "sbin/init",
        "usr/lib",
        "boot/grub",
    ])
    def test_relative_system_dir_rejected(self, path: str):
        with pytest.raises(ValueError, match="system directory"):
            _make_fs(writable_paths=[path])

    def test_safe_relative_path_accepted(self):
        fs = _make_fs(writable_paths=["data"])
        assert "data" in fs.writable_paths

    def test_safe_relative_nested_accepted(self):
        fs = _make_fs(writable_paths=["output/results"])
        assert "output/results" in fs.writable_paths

    def test_relative_dotslash_safe(self):
        fs = _make_fs(writable_paths=["./build"])
        assert "build" in fs.writable_paths
