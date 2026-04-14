"""Tests for the Sandbox class using a container backend.

Uses a fake backend to test sandbox orchestration logic without
requiring a real container runtime.
"""

import pytest

from lasso.config.defaults import evaluation_profile
from lasso.config.schema import SandboxState
from lasso.core.sandbox import Sandbox
from tests.conftest import FakeBackend


@pytest.fixture
def sandbox(fake_backend, tmp_path):
    profile = evaluation_profile(str(tmp_path), name="test-sandbox")
    return Sandbox(profile, backend=fake_backend)


class TestSandboxLifecycleWithBackend:
    def test_start_creates_and_starts_container(self, sandbox, fake_backend):
        sandbox.start()
        assert sandbox.state == SandboxState.RUNNING
        assert len(fake_backend.containers) == 1
        methods = [c[0] for c in fake_backend.calls]
        assert "create" in methods
        assert "start" in methods

    def test_stop_stops_and_removes_container(self, sandbox, fake_backend):
        sandbox.start()
        sandbox.stop()
        assert sandbox.state == SandboxState.STOPPED
        methods = [c[0] for c in fake_backend.calls]
        assert "stop" in methods
        assert "remove" in methods

    def test_context_manager(self, fake_backend, tmp_path):
        profile = evaluation_profile(str(tmp_path), name="ctx-test")
        with Sandbox(profile, backend=fake_backend) as sb:
            assert sb.state == SandboxState.RUNNING
        methods = [c[0] for c in fake_backend.calls]
        assert "stop" in methods

    def test_exec_passes_through_backend(self, sandbox, fake_backend):
        sandbox.start()
        # Record exec count after start (iptables rules are applied during start)
        pre_exec_count = len([c for c in fake_backend.calls if c[0] == "exec"])
        result = sandbox.exec("ls -la")
        assert not result.blocked
        # Verify backend.exec was called once more (for the user command)
        exec_calls = [c for c in fake_backend.calls if c[0] == "exec"]
        assert len(exec_calls) == pre_exec_count + 1

    def test_exec_blocked_command_never_reaches_backend(self, sandbox, fake_backend):
        sandbox.start()
        # Record exec count after start (iptables rules are applied during start)
        pre_exec_count = len([c for c in fake_backend.calls if c[0] == "exec"])
        result = sandbox.exec("curl https://evil.com")
        assert result.blocked
        exec_calls = [c for c in fake_backend.calls if c[0] == "exec"]
        assert len(exec_calls) == pre_exec_count  # blocked before reaching backend

    def test_exec_on_stopped_sandbox_fails(self, sandbox):
        result = sandbox.exec("ls")
        assert result.blocked
        assert "not running" in result.block_reason.lower()

    def test_backend_unavailable_raises(self, tmp_path):
        backend = FakeBackend(available=False)
        profile = evaluation_profile(str(tmp_path), name="fail-test")
        sb = Sandbox(profile, backend=backend)
        with pytest.raises(RuntimeError, match="not available"):
            sb.start()


class TestSandboxCommandGateIntegration:
    def test_whitelisted_command_allowed(self, sandbox, fake_backend):
        sandbox.start()
        result = sandbox.exec("ls")
        assert not result.blocked
        assert result.stdout == "file1.txt\nfile2.py\n"

    def test_non_whitelisted_command_blocked(self, sandbox, fake_backend):
        sandbox.start()
        result = sandbox.exec("rm -rf /")
        assert result.blocked
        assert "whitelist" in result.block_reason.lower()

    def test_shell_operators_blocked(self, sandbox, fake_backend):
        sandbox.start()
        result = sandbox.exec("ls | grep foo")
        assert result.blocked

    def test_path_traversal_blocked(self, sandbox, fake_backend):
        sandbox.start()
        result = sandbox.exec("cat ../../etc/passwd")
        assert result.blocked


class TestSandboxAuditIntegration:
    def test_audit_log_created_on_start(self, sandbox):
        sandbox.start()
        assert sandbox.audit.log_file is not None
        sandbox.stop()

    def test_blocked_commands_audited(self, sandbox):
        sandbox.start()
        sandbox.exec("curl evil.com")
        log_content = sandbox.audit.log_file.read_text()
        assert "blocked" in log_content
        sandbox.stop()

    def test_successful_commands_audited(self, sandbox):
        sandbox.start()
        sandbox.exec("ls")
        log_content = sandbox.audit.log_file.read_text()
        assert "command" in log_content
        sandbox.stop()
