"""Tests for Windows compatibility paths — no Windows required.

Verifies that LASSO behaves correctly on non-Linux/non-Unix platforms by
monkeypatching platform detection and OS-specific calls.
"""

import os
import platform
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

from lasso.config.schema import AuditConfig
from lasso.core.audit import AuditLogger

# ---------------------------------------------------------------------------
# Audit: _load_or_create_signing_key with os.chmod failure
# ---------------------------------------------------------------------------

class TestAuditChmodFailure:
    def test_key_created_when_chmod_raises(self, tmp_path, monkeypatch):
        """On Windows, os.chmod may raise OSError. The key should still be created."""
        original_chmod = os.chmod

        def failing_chmod(path, mode):
            raise OSError("chmod not supported on this platform")

        monkeypatch.setattr(os, "chmod", failing_chmod)

        config = AuditConfig(
            enabled=True,
            log_dir=str(tmp_path / "audit"),
            sign_entries=True,
            signing_key_path=None,
        )
        logger = AuditLogger("test-chmod", config)

        # The signing key should still be populated
        assert logger._signing_key is not None
        assert isinstance(logger._signing_key, bytes)
        assert len(logger._signing_key) == 32

        # [AU-1] Key is now at ~/.lasso/.audit_key (not inside log dir)
        key_path = Path.home() / ".lasso" / ".audit_key"
        assert key_path.exists()
        assert key_path.read_bytes() == logger._signing_key

    def test_existing_key_loaded_when_chmod_raises(self, tmp_path, monkeypatch):
        """Even if chmod fails, loading an existing key should work fine."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir(parents=True)
        key_path = audit_dir / "custom_audit_key"
        known_key = b"x" * 32
        key_path.write_bytes(known_key)

        def failing_chmod(path, mode):
            raise OSError("chmod not supported")

        monkeypatch.setattr(os, "chmod", failing_chmod)

        config = AuditConfig(
            enabled=True,
            log_dir=str(audit_dir),
            sign_entries=True,
            signing_key_path=str(key_path),
        )
        logger = AuditLogger("test-existing", config)

        assert logger._signing_key == known_key


# ---------------------------------------------------------------------------
# Sandbox: _exec_native platform-correct PATH
# ---------------------------------------------------------------------------

class TestNativeExecPath:
    def test_windows_path_has_backslash_semicolons(self, tmp_path, monkeypatch):
        """When platform is Windows, PATH should use Windows conventions."""
        monkeypatch.setattr(platform, "system", lambda: "Windows")

        from lasso.config.defaults import evaluation_profile
        from lasso.core.sandbox import Sandbox

        profile = evaluation_profile(str(tmp_path), name="win-test")
        # Add "echo" to whitelist so it passes the command gate
        profile.commands.whitelist.append("echo")
        sb = Sandbox(profile)
        sb.start()

        # Monkeypatch subprocess.run to capture the env without actually running
        captured_env = {}

        def mock_run(cmd, **kwargs):
            captured_env.update(kwargs.get("env", {}))
            result = MagicMock()
            result.returncode = 0
            result.stdout = b"ok"
            result.stderr = b""
            return result

        monkeypatch.setattr(subprocess, "run", mock_run)

        sb.exec("echo hello")

        assert "PATH" in captured_env
        path_val = captured_env["PATH"]
        assert "\\" in path_val
        assert ";" in path_val

    def test_linux_path_has_forward_slashes(self, tmp_path, monkeypatch):
        """When platform is Linux, PATH should use Unix conventions."""
        monkeypatch.setattr(platform, "system", lambda: "Linux")

        from lasso.config.defaults import evaluation_profile
        from lasso.core.sandbox import Sandbox

        profile = evaluation_profile(str(tmp_path), name="linux-test")
        profile.commands.whitelist.append("echo")
        sb = Sandbox(profile)
        sb.start()

        captured_env = {}

        def mock_run(cmd, **kwargs):
            captured_env.update(kwargs.get("env", {}))
            result = MagicMock()
            result.returncode = 0
            result.stdout = b"ok"
            result.stderr = b""
            return result

        monkeypatch.setattr(subprocess, "run", mock_run)

        sb.exec("echo hello")

        assert "PATH" in captured_env
        path_val = captured_env["PATH"]
        assert "/" in path_val
        assert "\\" not in path_val


# ---------------------------------------------------------------------------
# Converter: Windows path to Docker mount format
# ---------------------------------------------------------------------------

class TestDockerMountPathConversion:
    def test_windows_drive_letter_conversion(self, monkeypatch):
        """C:\\Users\\me\\project -> /c/Users/me/project on Windows."""
        monkeypatch.setattr(platform, "system", lambda: "Windows")

        from lasso.backends.converter import _to_docker_mount_path

        result = _to_docker_mount_path(r"C:\Users\me\project")
        assert result == "/c/Users/me/project"

    def test_windows_lowercase_drive(self, monkeypatch):
        """d:\\data -> /d/data on Windows."""
        monkeypatch.setattr(platform, "system", lambda: "Windows")

        from lasso.backends.converter import _to_docker_mount_path

        result = _to_docker_mount_path(r"d:\data")
        assert result == "/d/data"

    def test_linux_path_unchanged(self, monkeypatch):
        """Linux paths should pass through unchanged."""
        monkeypatch.setattr(platform, "system", lambda: "Linux")

        from lasso.backends.converter import _to_docker_mount_path

        result = _to_docker_mount_path("/home/user/project")
        assert result == "/home/user/project"

    def test_windows_forward_slash_input(self, monkeypatch):
        """C:/Users/me/project should also be converted on Windows."""
        monkeypatch.setattr(platform, "system", lambda: "Windows")

        from lasso.backends.converter import _to_docker_mount_path

        result = _to_docker_mount_path("C:/Users/me/project")
        assert result == "/c/Users/me/project"

    def test_unc_path_on_windows(self, monkeypatch):
        """UNC paths without drive letters should normalise slashes."""
        monkeypatch.setattr(platform, "system", lambda: "Windows")

        from lasso.backends.converter import _to_docker_mount_path

        result = _to_docker_mount_path(r"\\server\share\dir")
        assert "/" in result
        assert "\\" not in result


# ---------------------------------------------------------------------------
# Schema: platform-dependent defaults
# ---------------------------------------------------------------------------

class TestPlatformDefaults:
    def test_read_only_paths_linux(self, monkeypatch):
        """On Linux, default read_only_paths should contain Unix paths."""
        monkeypatch.setattr(platform, "system", lambda: "Linux")

        from lasso.config.schema import _default_read_only_paths

        paths = _default_read_only_paths()
        assert "/usr" in paths
        assert "/bin" in paths

    def test_read_only_paths_windows(self, monkeypatch):
        """On Windows, default read_only_paths should contain Windows paths."""
        monkeypatch.setattr(platform, "system", lambda: "Windows")

        from lasso.config.schema import _default_read_only_paths

        paths = _default_read_only_paths()
        assert any("Windows" in p for p in paths)
        assert any("Program Files" in p for p in paths)

    def test_hidden_paths_linux(self, monkeypatch):
        """On Linux, default hidden_paths should contain Unix paths."""
        monkeypatch.setattr(platform, "system", lambda: "Linux")

        from lasso.config.schema import _default_hidden_paths

        paths = _default_hidden_paths()
        assert "/etc/shadow" in paths

    def test_hidden_paths_windows(self, monkeypatch):
        """On Windows, default hidden_paths should contain Windows paths."""
        monkeypatch.setattr(platform, "system", lambda: "Windows")

        from lasso.config.schema import _default_hidden_paths

        paths = _default_hidden_paths()
        assert any("System32" in p or "Default" in p for p in paths)


# ---------------------------------------------------------------------------
# CommandGate: backslash path handling
# ---------------------------------------------------------------------------

class TestCommandGateWindowsPaths:
    def test_backslash_path_triggers_symlink_resolution(self):
        """Arguments with backslashes should be treated as paths."""
        from lasso.config.schema import CommandConfig, CommandMode
        from lasso.core.commands import CommandGate

        config = CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=["cat"],
        )
        gate = CommandGate(config)

        # A backslash-containing arg should be resolved (not ignored)
        verdict = gate.check(r"cat C:\file.txt")
        assert verdict.allowed  # no traversal, just a normal path

    def test_command_name_extraction_with_forward_slash(self):
        """C:/Python/python3.exe should extract 'python3.exe' as command name."""
        from lasso.config.schema import CommandConfig, CommandMode
        from lasso.core.commands import CommandGate

        config = CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=["python3.exe"],
        )
        gate = CommandGate(config)

        # Use forward slashes (works cross-platform with shlex)
        verdict = gate.check("C:/Python/python3.exe --version")
        assert verdict.command == "python3.exe"
        assert verdict.allowed

    def test_command_name_extraction_uses_os_basename(self):
        """os.path.basename should handle platform-native separators."""
        # On any platform, os.path.basename handles the native separator
        result = os.path.basename("/usr/bin/python3")
        assert result == "python3"


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Dashboard: _validate_working_dir uses tempdir not /tmp
# ---------------------------------------------------------------------------

class TestValidateWorkingDir:
    def test_accepts_temp_directory(self, tmp_path):
        """Working dirs under the system temp dir should be accepted."""
        from lasso.dashboard.app import _validate_working_dir

        # tmp_path is a real directory under the system temp dir
        project = tmp_path / "project"
        project.mkdir()
        result = _validate_working_dir(str(project))
        assert result is None  # no error

    def test_accepts_home_directory(self, tmp_path, monkeypatch):
        """Working dirs under home should be accepted."""
        from lasso.dashboard.app import _validate_working_dir

        # Use an existing directory under home
        home = Path.home()
        result = _validate_working_dir(str(home))
        assert result is None

    def test_rejects_path_traversal(self):
        """Paths with .. that resolve to system dirs should be rejected."""
        from lasso.dashboard.app import _validate_working_dir

        result = _validate_working_dir("/home/user/../../../etc")
        assert result is not None
        # Now correctly blocked as a system directory (not just string matching)
        assert "not allowed" in result.lower() or "does not exist" in result.lower()


# ---------------------------------------------------------------------------
# Profile schema: profile_version field
# ---------------------------------------------------------------------------

class TestProfileVersion:
    def test_default_profile_version(self, tmp_path):
        """New profiles should have profile_version = 1."""
        from lasso.config.defaults import evaluation_profile

        p = evaluation_profile(str(tmp_path))
        assert p.profile_version == 1

    def test_profile_version_in_dump(self, tmp_path):
        """profile_version should appear in serialized profile."""
        from lasso.config.defaults import evaluation_profile

        p = evaluation_profile(str(tmp_path))
        data = p.model_dump()
        assert "profile_version" in data
        assert data["profile_version"] == 1

    def test_profile_version_round_trips(self, tmp_path):
        """profile_version should survive save/load."""
        from lasso.config.defaults import evaluation_profile
        from lasso.config.profile import load_profile, save_profile

        p = evaluation_profile(str(tmp_path), name="vtest")
        p.profile_version = 5

        save_profile(p, profile_dir=tmp_path)
        loaded = load_profile("vtest", profile_dir=tmp_path)
        assert loaded.profile_version == 5
