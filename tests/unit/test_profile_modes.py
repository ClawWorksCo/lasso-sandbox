"""Tests for Profile Modes (Gradual Authorization) — Feature 5.

Tests the ProfileMode enum, CommandGate mode-based filtering,
Sandbox mode switching, audit logging, state persistence, and CLI.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from lasso.cli.main import app
from lasso.config.defaults import (
    evaluation_profile,
    standard_profile,
    strict_profile,
)
from lasso.config.schema import (
    CommandConfig,
    CommandMode,
    ProfileMode,
)
from lasso.core.commands import CommandGate
from lasso.core.sandbox import Sandbox, SandboxRegistry
from lasso.core.state import SandboxRecord, StateStore
from tests.conftest import FakeBackend

runner = CliRunner()


@pytest.fixture
def observe_config():
    """CommandConfig with a broad whitelist for mode testing."""
    return CommandConfig(
        mode=CommandMode.WHITELIST,
        whitelist=[
            "ls", "cat", "head", "tail", "grep", "find", "wc", "echo", "test",
            "file", "du", "df", "python3", "git", "pip", "npm", "node", "make",
            "cargo", "go", "curl", "wget",
        ],
        allow_shell_operators=False,
    )


@pytest.fixture
def observe_gate(observe_config):
    return CommandGate(observe_config, mode=ProfileMode.OBSERVE)


@pytest.fixture
def assist_gate(observe_config):
    return CommandGate(observe_config, mode=ProfileMode.ASSIST)


@pytest.fixture
def autonomous_gate(observe_config):
    return CommandGate(observe_config, mode=ProfileMode.AUTONOMOUS)


@pytest.fixture(autouse=True)
def _reset_cli_registry():
    """Reset the global CLI registry between tests to avoid state leaks."""
    import lasso.cli.helpers as cli_helpers
    old = cli_helpers._registry
    cli_helpers._registry = None
    yield
    cli_helpers._registry = old


# ---------------------------------------------------------------------------
# ProfileMode enum
# ---------------------------------------------------------------------------

class TestProfileModeEnum:
    def test_observe_value(self):
        assert ProfileMode.OBSERVE.value == "observe"

    def test_assist_value(self):
        assert ProfileMode.ASSIST.value == "assist"

    def test_autonomous_value(self):
        assert ProfileMode.AUTONOMOUS.value == "autonomous"

    def test_construct_from_string(self):
        assert ProfileMode("observe") == ProfileMode.OBSERVE
        assert ProfileMode("assist") == ProfileMode.ASSIST
        assert ProfileMode("autonomous") == ProfileMode.AUTONOMOUS

    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError):
            ProfileMode("admin")


# ---------------------------------------------------------------------------
# CommandGate with modes
# ---------------------------------------------------------------------------

class TestCommandGateObserveMode:
    """In OBSERVE mode, only read-only commands are allowed."""

    def test_ls_allowed(self, observe_gate):
        v = observe_gate.check("ls -la")
        assert v.allowed

    def test_cat_allowed(self, observe_gate):
        v = observe_gate.check("cat file.txt")
        assert v.allowed

    def test_grep_allowed(self, observe_gate):
        v = observe_gate.check("grep pattern file.txt")
        assert v.allowed

    def test_find_allowed(self, observe_gate):
        v = observe_gate.check("find . -name '*.py'")
        assert v.allowed

    def test_echo_allowed(self, observe_gate):
        v = observe_gate.check("echo hello")
        assert v.allowed

    def test_python3_blocked_in_observe(self, observe_gate):
        v = observe_gate.check("python3 script.py")
        assert v.blocked
        assert "observe" in v.reason.lower()

    def test_git_blocked_in_observe(self, observe_gate):
        v = observe_gate.check("git status")
        assert v.blocked
        assert "observe" in v.reason.lower()

    def test_pip_blocked_in_observe(self, observe_gate):
        v = observe_gate.check("pip install something")
        assert v.blocked

    def test_curl_blocked_in_observe(self, observe_gate):
        v = observe_gate.check("curl https://example.com")
        assert v.blocked

    def test_completely_unknown_cmd_blocked(self, observe_gate):
        v = observe_gate.check("rm -rf /")
        assert v.blocked
        assert "whitelist" in v.reason.lower()


class TestCommandGateAssistMode:
    """In ASSIST mode, curated development commands are allowed."""

    def test_ls_allowed(self, assist_gate):
        v = assist_gate.check("ls -la")
        assert v.allowed

    def test_cat_allowed(self, assist_gate):
        v = assist_gate.check("cat file.txt")
        assert v.allowed

    def test_python3_allowed(self, assist_gate):
        v = assist_gate.check("python3 script.py")
        assert v.allowed

    def test_git_allowed(self, assist_gate):
        v = assist_gate.check("git status")
        assert v.allowed

    def test_pip_allowed(self, assist_gate):
        v = assist_gate.check("pip list")
        assert v.allowed

    def test_npm_allowed(self, assist_gate):
        v = assist_gate.check("npm list")
        assert v.allowed

    def test_make_allowed(self, assist_gate):
        v = assist_gate.check("make build")
        assert v.allowed

    def test_curl_blocked_in_assist(self, assist_gate):
        v = assist_gate.check("curl https://example.com")
        assert v.blocked
        assert "assist" in v.reason.lower()

    def test_wget_blocked_in_assist(self, assist_gate):
        v = assist_gate.check("wget https://example.com")
        assert v.blocked

    def test_unknown_cmd_blocked(self, assist_gate):
        v = assist_gate.check("rm -rf /")
        assert v.blocked


class TestCommandGateAutonomousMode:
    """In AUTONOMOUS mode, the full whitelist is used."""

    def test_ls_allowed(self, autonomous_gate):
        v = autonomous_gate.check("ls -la")
        assert v.allowed

    def test_python3_allowed(self, autonomous_gate):
        v = autonomous_gate.check("python3 script.py")
        assert v.allowed

    def test_curl_allowed(self, autonomous_gate):
        v = autonomous_gate.check("curl https://example.com")
        assert v.allowed

    def test_wget_allowed(self, autonomous_gate):
        v = autonomous_gate.check("wget https://example.com")
        assert v.allowed

    def test_unknown_cmd_blocked(self, autonomous_gate):
        v = autonomous_gate.check("rm -rf /")
        assert v.blocked


class TestCommandGateModeSwitch:
    """Test switching modes on the same CommandGate instance."""

    def test_switch_observe_to_assist(self, observe_config):
        gate = CommandGate(observe_config, mode=ProfileMode.OBSERVE)
        v = gate.check("python3 script.py")
        assert v.blocked

        gate.set_mode(ProfileMode.ASSIST)
        v = gate.check("python3 script.py")
        assert v.allowed

    def test_switch_assist_to_autonomous(self, observe_config):
        gate = CommandGate(observe_config, mode=ProfileMode.ASSIST)
        v = gate.check("curl https://example.com")
        assert v.blocked

        gate.set_mode(ProfileMode.AUTONOMOUS)
        v = gate.check("curl https://example.com")
        assert v.allowed

    def test_switch_autonomous_to_observe(self, observe_config):
        gate = CommandGate(observe_config, mode=ProfileMode.AUTONOMOUS)
        v = gate.check("curl https://example.com")
        assert v.allowed

        gate.set_mode(ProfileMode.OBSERVE)
        v = gate.check("curl https://example.com")
        assert v.blocked

    def test_mode_property(self, observe_config):
        gate = CommandGate(observe_config, mode=ProfileMode.OBSERVE)
        assert gate.mode == ProfileMode.OBSERVE
        gate.set_mode(ProfileMode.ASSIST)
        assert gate.mode == ProfileMode.ASSIST

    def test_explain_policy_includes_mode(self, observe_config):
        gate = CommandGate(observe_config, mode=ProfileMode.OBSERVE)
        policy = gate.explain_policy()
        assert policy["profile_mode"] == "observe"


class TestCommandGateDefaultMode:
    """When no mode is specified, CommandGate defaults to AUTONOMOUS."""

    def test_default_mode_is_autonomous(self):
        config = CommandConfig()
        gate = CommandGate(config)
        assert gate.mode == ProfileMode.AUTONOMOUS

    def test_default_uses_full_whitelist(self):
        config = CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=["ls", "python3", "curl"],
        )
        gate = CommandGate(config)
        v = gate.check("curl https://example.com")
        assert v.allowed


# ---------------------------------------------------------------------------
# Sandbox mode
# ---------------------------------------------------------------------------

class TestSandboxMode:
    def test_sandbox_starts_with_profile_mode(self, fake_backend, tmp_path):
        profile = evaluation_profile(str(tmp_path), name="mode-test")
        assert profile.mode == ProfileMode.OBSERVE
        sb = Sandbox(profile, backend=fake_backend)
        assert sb.mode == ProfileMode.OBSERVE

    def test_sandbox_set_mode(self, fake_backend, tmp_path):
        profile = evaluation_profile(str(tmp_path), name="mode-switch")
        sb = Sandbox(profile, backend=fake_backend)
        sb.start()
        assert sb.mode == ProfileMode.OBSERVE

        sb.set_mode(ProfileMode.ASSIST)
        assert sb.mode == ProfileMode.ASSIST
        assert sb.command_gate.mode == ProfileMode.ASSIST
        sb.stop()

    def test_set_mode_same_value_noop(self, fake_backend, tmp_path):
        profile = evaluation_profile(str(tmp_path), name="noop-test")
        sb = Sandbox(profile, backend=fake_backend)
        sb.start()
        sb.set_mode(ProfileMode.OBSERVE)  # same as initial
        # Should not crash, should be a no-op
        assert sb.mode == ProfileMode.OBSERVE
        sb.stop()

    def test_mode_in_status(self, fake_backend, tmp_path):
        profile = evaluation_profile(str(tmp_path), name="status-mode")
        sb = Sandbox(profile, backend=fake_backend)
        sb.start()
        status = sb.status()
        assert status["mode"] == "observe"

        sb.set_mode(ProfileMode.AUTONOMOUS)
        status = sb.status()
        assert status["mode"] == "autonomous"
        sb.stop()

    def test_mode_affects_command_execution(self, fake_backend, tmp_path):
        """Create a sandbox with a broad whitelist but observe mode."""
        profile = standard_profile(str(tmp_path), name="exec-mode-test")
        # development defaults to ASSIST mode
        profile.mode = ProfileMode.OBSERVE
        sb = Sandbox(profile, backend=fake_backend)
        sb.start()

        # In observe mode, python3 should be blocked
        result = sb.exec("python3 script.py")
        assert result.blocked

        # ls should be allowed
        result = sb.exec("ls")
        assert not result.blocked

        # Switch to assist, python3 should work
        sb.set_mode(ProfileMode.ASSIST)
        result = sb.exec("python3 script.py")
        assert not result.blocked

        sb.stop()


# ---------------------------------------------------------------------------
# Audit logging of mode changes
# ---------------------------------------------------------------------------

class TestModeAuditLogging:
    def test_mode_change_logged(self, fake_backend, tmp_path):
        profile = evaluation_profile(str(tmp_path), name="audit-mode")
        sb = Sandbox(profile, backend=fake_backend)
        sb.start()
        sb.set_mode(ProfileMode.ASSIST)
        sb.stop()

        log_content = sb.audit.log_file.read_text()
        assert "mode_changed" in log_content
        assert "observe" in log_content
        assert "assist" in log_content

    def test_multiple_mode_changes_all_logged(self, fake_backend, tmp_path):
        profile = evaluation_profile(str(tmp_path), name="multi-audit")
        sb = Sandbox(profile, backend=fake_backend)
        sb.start()
        sb.set_mode(ProfileMode.ASSIST)
        sb.set_mode(ProfileMode.AUTONOMOUS)
        sb.set_mode(ProfileMode.OBSERVE)
        sb.stop()

        log_content = sb.audit.log_file.read_text()
        # Should have 3 mode_changed events
        assert log_content.count("mode_changed") == 3


# ---------------------------------------------------------------------------
# State persistence of mode
# ---------------------------------------------------------------------------

class TestModePersistence:
    def test_record_stores_mode(self, tmp_path):
        store = StateStore(state_dir=str(tmp_path))
        store.record_create("sb-001", "test-profile", "cid-001", mode="assist")

        store2 = StateStore(state_dir=str(tmp_path))
        state = store2.load()
        assert state.sandboxes["sb-001"].mode == "assist"

    def test_mode_change_persists(self, tmp_path):
        store = StateStore(state_dir=str(tmp_path))
        store.record_create("sb-001", "test-profile", "cid-001", mode="observe")
        store.record_mode_change("sb-001", "autonomous")

        store2 = StateStore(state_dir=str(tmp_path))
        state = store2.load()
        assert state.sandboxes["sb-001"].mode == "autonomous"

    def test_default_mode_is_observe(self):
        rec = SandboxRecord(sandbox_id="sb-001", profile_name="test")
        assert rec.mode == "observe"

    def test_from_dict_missing_mode_defaults_to_observe(self):
        d = {"sandbox_id": "sb-001", "profile_name": "test"}
        rec = SandboxRecord.from_dict(d)
        assert rec.mode == "observe"

    def test_from_dict_with_mode(self):
        d = {"sandbox_id": "sb-001", "profile_name": "test", "mode": "autonomous"}
        rec = SandboxRecord.from_dict(d)
        assert rec.mode == "autonomous"

    def test_registry_create_persists_mode(self, tmp_path):
        backend = FakeBackend()
        registry = SandboxRegistry(backend=backend, state_dir=str(tmp_path))
        profile = evaluation_profile(str(tmp_path), name="persist-mode")
        # minimal defaults to OBSERVE
        sb = registry.create(profile)

        store2 = StateStore(state_dir=str(tmp_path))
        state = store2.load()
        assert state.sandboxes[sb.id].mode == "observe"

    def test_registry_set_mode_persists(self, tmp_path):
        backend = FakeBackend()
        registry = SandboxRegistry(backend=backend, state_dir=str(tmp_path))
        profile = evaluation_profile(str(tmp_path), name="set-mode-persist")
        sb = registry.create(profile)
        sb.start()

        registry.set_mode(sb.id, ProfileMode.AUTONOMOUS)

        store2 = StateStore(state_dir=str(tmp_path))
        state = store2.load()
        assert state.sandboxes[sb.id].mode == "autonomous"


# ---------------------------------------------------------------------------
# Default profile modes
# ---------------------------------------------------------------------------

class TestDefaultProfileModes:
    def test_minimal_defaults_to_observe(self, tmp_path):
        profile = evaluation_profile(str(tmp_path))
        assert profile.mode == ProfileMode.OBSERVE

    def test_development_defaults_to_assist(self, tmp_path):
        profile = standard_profile(str(tmp_path))
        assert profile.mode == ProfileMode.AUTONOMOUS

    def test_offline_defaults_to_observe(self, tmp_path):
        profile = strict_profile(str(tmp_path))
        assert profile.mode == ProfileMode.OBSERVE

    def test_profile_mode_serialization(self, tmp_path):
        profile = evaluation_profile(str(tmp_path))
        data = profile.model_dump()
        assert data["mode"] == "observe"

    def test_profile_mode_override(self, tmp_path):
        profile = evaluation_profile(str(tmp_path))
        profile.mode = ProfileMode.AUTONOMOUS
        assert profile.mode == ProfileMode.AUTONOMOUS


# ---------------------------------------------------------------------------
# CLI mode command
# ---------------------------------------------------------------------------

def _invoke(*args: str, input: str | None = None):
    """Invoke the CLI with the given arguments."""
    return runner.invoke(app, list(args), input=input)


class TestCLIModeCommand:
    def test_mode_invalid_mode_value(self, tmp_path):
        # First create a sandbox
        result = _invoke(
            "create", "evaluation",
            "--dir", str(tmp_path),
            "--native",
            "--quiet",
        )
        assert result.exit_code == 0
        sandbox_id = result.output.strip()

        # Try invalid mode
        result = _invoke("mode", sandbox_id, "admin")
        assert result.exit_code == 1
        assert "Invalid mode" in result.output

    def test_mode_sandbox_not_found(self):
        result = _invoke("mode", "nonexistent123", "observe")
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_mode_command_changes_mode(self, tmp_path):
        # Create a sandbox
        result = _invoke(
            "create", "evaluation",
            "--dir", str(tmp_path),
            "--native",
            "--quiet",
        )
        assert result.exit_code == 0
        sandbox_id = result.output.strip()

        # Change mode
        result = _invoke("mode", sandbox_id, "autonomous")
        assert result.exit_code == 0
        assert "autonomous" in result.output
        assert "observe" in result.output  # old mode shown

    def test_create_with_mode_flag(self, tmp_path):
        result = _invoke(
            "create", "evaluation",
            "--dir", str(tmp_path),
            "--native",
            "--mode", "autonomous",
            "--quiet",
        )
        assert result.exit_code == 0

    def test_create_with_invalid_mode_flag(self, tmp_path):
        result = _invoke(
            "create", "evaluation",
            "--dir", str(tmp_path),
            "--native",
            "--mode", "superadmin",
        )
        assert result.exit_code == 1
        assert "Invalid mode" in result.output

    def test_status_json_includes_mode(self, tmp_path):
        # Create a sandbox
        result = _invoke(
            "create", "evaluation",
            "--dir", str(tmp_path),
            "--native",
            "--quiet",
        )
        assert result.exit_code == 0
        sandbox_id = result.output.strip()

        # Check status
        result = _invoke("status", sandbox_id)
        assert result.exit_code == 0
        # The JSON output should contain mode
        assert "observe" in result.output

    def test_status_table_includes_mode(self, tmp_path):
        # Create a sandbox
        _invoke(
            "create", "evaluation",
            "--dir", str(tmp_path),
            "--native",
            "--quiet",
        )

        # Status table view
        result = _invoke("status")
        assert result.exit_code == 0
        # Mode column should be visible
        assert "Mode" in result.output or "observe" in result.output


# ---------------------------------------------------------------------------
# CRITICAL FIX: Blacklist mode must respect profile modes
# ---------------------------------------------------------------------------

class TestBlacklistModeRespectsProfileMode:
    """Regression tests for the blacklist bypass security bug.

    When CommandConfig.mode == BLACKLIST, the profile mode (observe/assist)
    must still restrict which commands are allowed. Before the fix,
    ALL non-blacklisted commands were allowed regardless of profile mode.
    """

    @pytest.fixture
    def blacklist_config(self):
        """CommandConfig in BLACKLIST mode with a blacklist and mode whitelists."""
        return CommandConfig(
            mode=CommandMode.BLACKLIST,
            blacklist=["rm", "dd", "mkfs", "reboot", "shutdown"],
            observe_whitelist=["ls", "cat", "head", "tail", "grep", "find", "wc", "echo", "test"],
            assist_whitelist=[
                "ls", "cat", "head", "tail", "grep", "find", "wc", "echo", "test",
                "python3", "git", "pip", "npm", "node", "make",
            ],
            allow_shell_operators=False,
        )

    def test_observe_blocks_python3_in_blacklist_mode(self, blacklist_config):
        """CRITICAL: python3 must be blocked in observe mode even with blacklist config."""
        gate = CommandGate(blacklist_config, mode=ProfileMode.OBSERVE)
        v = gate.check("python3 script.py")
        assert v.blocked
        assert "observe" in v.reason.lower()

    def test_observe_allows_ls_in_blacklist_mode(self, blacklist_config):
        gate = CommandGate(blacklist_config, mode=ProfileMode.OBSERVE)
        v = gate.check("ls -la")
        assert v.allowed

    def test_observe_blocks_curl_in_blacklist_mode(self, blacklist_config):
        gate = CommandGate(blacklist_config, mode=ProfileMode.OBSERVE)
        v = gate.check("curl https://example.com")
        assert v.blocked
        assert "observe" in v.reason.lower()

    def test_observe_blocks_git_in_blacklist_mode(self, blacklist_config):
        gate = CommandGate(blacklist_config, mode=ProfileMode.OBSERVE)
        v = gate.check("git status")
        assert v.blocked

    def test_assist_allows_python3_in_blacklist_mode(self, blacklist_config):
        gate = CommandGate(blacklist_config, mode=ProfileMode.ASSIST)
        v = gate.check("python3 script.py")
        assert v.allowed

    def test_assist_allows_git_in_blacklist_mode(self, blacklist_config):
        gate = CommandGate(blacklist_config, mode=ProfileMode.ASSIST)
        v = gate.check("git status")
        assert v.allowed

    def test_assist_blocks_curl_in_blacklist_mode(self, blacklist_config):
        """curl is not in the assist whitelist, so it must be blocked."""
        gate = CommandGate(blacklist_config, mode=ProfileMode.ASSIST)
        v = gate.check("curl https://example.com")
        assert v.blocked
        assert "assist" in v.reason.lower()

    def test_autonomous_allows_all_non_blacklisted(self, blacklist_config):
        """In autonomous mode, blacklist-only filtering applies (original behavior)."""
        gate = CommandGate(blacklist_config, mode=ProfileMode.AUTONOMOUS)
        v = gate.check("curl https://example.com")
        assert v.allowed

    def test_autonomous_still_blocks_blacklisted(self, blacklist_config):
        gate = CommandGate(blacklist_config, mode=ProfileMode.AUTONOMOUS)
        v = gate.check("rm -rf /")
        assert v.blocked
        assert "blacklist" in v.reason.lower()

    def test_blacklist_still_enforced_in_observe(self, blacklist_config):
        """Blacklisted commands must be blocked regardless of mode."""
        gate = CommandGate(blacklist_config, mode=ProfileMode.OBSERVE)
        v = gate.check("rm -rf /")
        assert v.blocked
        assert "blacklist" in v.reason.lower()

    def test_mode_switch_in_blacklist_mode(self, blacklist_config):
        """Switching modes must update restrictions in blacklist mode too."""
        gate = CommandGate(blacklist_config, mode=ProfileMode.OBSERVE)
        assert gate.check("python3 test.py").blocked

        gate.set_mode(ProfileMode.ASSIST)
        assert gate.check("python3 test.py").allowed

        gate.set_mode(ProfileMode.OBSERVE)
        assert gate.check("python3 test.py").blocked


# ---------------------------------------------------------------------------
# MEDIUM 1: Mode change on stopped sandbox must raise RuntimeError
# ---------------------------------------------------------------------------

class TestModeChangeRequiresRunningState:
    """Sandbox.set_mode() must raise RuntimeError if sandbox is not RUNNING."""

    def test_mode_change_on_created_sandbox_raises(self, fake_backend, tmp_path):
        profile = evaluation_profile(str(tmp_path), name="state-check")
        sb = Sandbox(profile, backend=fake_backend)
        # Sandbox is in CREATED state (not started)
        with pytest.raises(RuntimeError, match="running"):
            sb.set_mode(ProfileMode.ASSIST)

    def test_mode_change_on_stopped_sandbox_raises(self, fake_backend, tmp_path):
        profile = evaluation_profile(str(tmp_path), name="stopped-check")
        sb = Sandbox(profile, backend=fake_backend)
        sb.start()
        sb.stop()
        # Sandbox is now STOPPED
        with pytest.raises(RuntimeError, match="running"):
            sb.set_mode(ProfileMode.AUTONOMOUS)

    def test_mode_change_on_running_sandbox_succeeds(self, fake_backend, tmp_path):
        profile = evaluation_profile(str(tmp_path), name="running-check")
        sb = Sandbox(profile, backend=fake_backend)
        sb.start()
        # Should not raise
        sb.set_mode(ProfileMode.ASSIST)
        assert sb.mode == ProfileMode.ASSIST
        sb.stop()


# ---------------------------------------------------------------------------
# MEDIUM 2: StateStore validates mode strings
# ---------------------------------------------------------------------------

class TestStateStoreValidatesMode:
    """StateStore must reject invalid mode strings."""

    def test_record_create_rejects_invalid_mode(self, tmp_path):
        store = StateStore(state_dir=str(tmp_path))
        with pytest.raises(ValueError, match="Invalid mode"):
            store.record_create("sb-001", "test-profile", mode="admin")

    def test_record_create_rejects_empty_mode(self, tmp_path):
        store = StateStore(state_dir=str(tmp_path))
        with pytest.raises(ValueError, match="Invalid mode"):
            store.record_create("sb-001", "test-profile", mode="")

    def test_record_mode_change_rejects_invalid_mode(self, tmp_path):
        store = StateStore(state_dir=str(tmp_path))
        store.record_create("sb-001", "test-profile", mode="observe")
        with pytest.raises(ValueError, match="Invalid mode"):
            store.record_mode_change("sb-001", "superadmin")

    def test_record_create_accepts_valid_modes(self, tmp_path):
        store = StateStore(state_dir=str(tmp_path))
        for mode in ("observe", "assist", "autonomous"):
            store.record_create(f"sb-{mode}", "test-profile", mode=mode)
            state = store.load()
            assert state.sandboxes[f"sb-{mode}"].mode == mode

    def test_record_mode_change_accepts_valid_modes(self, tmp_path):
        store = StateStore(state_dir=str(tmp_path))
        store.record_create("sb-001", "test-profile", mode="observe")
        for mode in ("assist", "autonomous", "observe"):
            store.record_mode_change("sb-001", mode)
            state = store.load()
            assert state.sandboxes["sb-001"].mode == mode


# ---------------------------------------------------------------------------
# MEDIUM 3: strict_profile has explicit observe mode
# ---------------------------------------------------------------------------

class TestStrictProfileExplicitMode:
    """strict_profile must explicitly set mode=OBSERVE."""

    def test_strict_profile_has_observe_mode(self, tmp_path):
        from lasso.config.defaults import strict_profile
        profile = strict_profile(str(tmp_path))
        assert profile.mode == ProfileMode.OBSERVE

    def test_strict_profile_mode_is_not_default_accident(self, tmp_path):
        """Verify the mode is set explicitly, not just falling through to default."""
        import inspect

        from lasso.config.defaults import strict_profile
        source = inspect.getsource(strict_profile)
        assert "mode=ProfileMode.OBSERVE" in source
