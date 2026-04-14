"""End-to-end sandbox tests — full lifecycle with real command execution."""

import json
from pathlib import Path

import pytest

from lasso.config.defaults import evaluation_profile, strict_profile
from lasso.config.schema import ProfileMode
from lasso.core.sandbox import Sandbox, SandboxRegistry


@pytest.fixture
def tmp_workdir(tmp_path):
    """Create a temporary working directory with test files."""
    (tmp_path / "data.csv").write_text("id,name,value\n1,test,42\n")
    (tmp_path / "script.py").write_text("print('hello from sandbox')\n")
    return str(tmp_path)


class TestSandboxLifecycle:
    def test_create_start_stop(self, tmp_workdir):
        profile = evaluation_profile(tmp_workdir, name="test-lifecycle")
        with Sandbox(profile) as sb:
            assert sb.state.value == "running"
            status = sb.status()
            assert status["name"] == "test-lifecycle"
            assert status["state"] == "running"
        assert sb.state.value == "stopped"

    def test_exec_allowed_command(self, tmp_workdir):
        profile = evaluation_profile(tmp_workdir, name="test-exec")
        with Sandbox(profile) as sb:
            result = sb.exec("ls")
            # Should succeed (might use fallback if unshare needs root)
            assert not result.blocked

    def test_exec_blocked_command(self, tmp_workdir):
        profile = evaluation_profile(tmp_workdir, name="test-blocked")
        with Sandbox(profile) as sb:
            result = sb.exec("curl https://evil.com")
            assert result.blocked
            assert "not in the whitelist" in result.block_reason

    def test_exec_blocked_rm(self, tmp_workdir):
        profile = evaluation_profile(tmp_workdir, name="test-rm")
        with Sandbox(profile) as sb:
            result = sb.exec("rm -rf /")
            assert result.blocked

    def test_exec_shell_operators_blocked(self, tmp_workdir):
        profile = evaluation_profile(tmp_workdir, name="test-pipes")
        with Sandbox(profile) as sb:
            result = sb.exec("ls | grep data")
            assert result.blocked
            assert "Shell operators" in result.block_reason

    def test_exec_path_traversal_blocked(self, tmp_workdir):
        profile = evaluation_profile(tmp_workdir, name="test-traversal")
        with Sandbox(profile) as sb:
            result = sb.exec("cat ../../etc/passwd")
            assert result.blocked
            assert "Path traversal" in result.block_reason

    def test_blocked_count_increments(self, tmp_workdir):
        profile = evaluation_profile(tmp_workdir, name="test-counts")
        with Sandbox(profile) as sb:
            sb.exec("rm foo")
            sb.exec("curl bar")
            sb.exec("wget baz")
            assert sb._blocked_count == 3
            assert sb._exec_count == 3


class TestAuditLogging:
    def test_audit_log_created(self, tmp_workdir):
        profile = evaluation_profile(tmp_workdir, name="test-audit")
        profile.audit.log_dir = str(Path(tmp_workdir) / "audit")

        with Sandbox(profile) as sb:
            sb.exec("ls")
            sb.exec("rm evil")
            log_path = sb.audit.log_file

        assert log_path is not None
        assert log_path.exists()

        lines = log_path.read_text().strip().split("\n")
        # Should have: lifecycle start, lifecycle running, exec ls, blocked rm, lifecycle stopped
        assert len(lines) >= 4

        # Verify JSON structure
        for line in lines:
            entry = json.loads(line)
            assert "event_id" in entry
            assert "ts" in entry
            assert "sandbox_id" in entry
            assert "type" in entry

    def test_audit_records_blocked_commands(self, tmp_workdir):
        profile = evaluation_profile(tmp_workdir, name="test-audit-block")
        profile.audit.log_dir = str(Path(tmp_workdir) / "audit")

        with Sandbox(profile) as sb:
            sb.exec("curl https://evil.com")
            log_path = sb.audit.log_file

        lines = log_path.read_text().strip().split("\n")
        entries = [json.loads(l) for l in lines]
        blocked = [e for e in entries if e.get("outcome") == "blocked"]
        assert len(blocked) >= 1
        assert blocked[0]["action"] == "curl https://evil.com"


class TestBankingProfile:
    def test_banking_profile_blocks_network_tools(self, tmp_workdir):
        profile = strict_profile(tmp_workdir, name="test-bank")
        with Sandbox(profile) as sb:
            assert sb.exec("curl https://anything.com").blocked
            assert sb.exec("wget http://anything.com").blocked
            assert sb.exec("ssh user@host").blocked

    def test_banking_profile_allows_python(self, tmp_workdir):
        profile = strict_profile(tmp_workdir, name="test-bank-py")
        profile.mode = ProfileMode.AUTONOMOUS
        with Sandbox(profile) as sb:
            result = sb.exec("python3 --version")
            assert not result.blocked

    def test_banking_profile_blocks_git_push(self, tmp_workdir):
        profile = strict_profile(tmp_workdir, name="test-bank-git")
        profile.mode = ProfileMode.AUTONOMOUS
        profile.commands.whitelist.append("git")
        with Sandbox(profile) as sb:
            result = sb.exec("git push origin main")
            assert result.blocked
            assert "Blocked argument" in result.block_reason

    def test_banking_profile_blocks_shell_operators(self, tmp_workdir):
        profile = strict_profile(tmp_workdir, name="test-bank-shell")
        profile.mode = ProfileMode.AUTONOMOUS
        with Sandbox(profile) as sb:
            # Parentheses in raw command strings are blocked (could be subshells)
            assert sb.exec("python3 -c 'import os; os.system(\"ls\")'").blocked
            assert sb.exec("ls | python3 -").blocked  # pipes blocked
            # But running a script file works fine
            assert not sb.exec("python3 script.py").blocked


class TestSandboxRegistry:
    def test_registry_create_and_list(self, tmp_workdir):
        registry = SandboxRegistry()
        p1 = evaluation_profile(tmp_workdir, name="reg-test-1")
        p2 = evaluation_profile(tmp_workdir, name="reg-test-2")

        sb1 = registry.create(p1)
        sb2 = registry.create(p2)
        sb1.start()
        sb2.start()

        assert len(registry) == 2
        statuses = registry.list_all()
        names = {s["name"] for s in statuses}
        assert "reg-test-1" in names
        assert "reg-test-2" in names

        registry.stop_all()

    def test_registry_get_by_name(self, tmp_workdir):
        registry = SandboxRegistry()
        profile = evaluation_profile(tmp_workdir, name="find-me")
        sb = registry.create(profile)

        found = registry.get_by_name("find-me")
        assert found is not None
        assert found.id == sb.id

        sb.stop()
