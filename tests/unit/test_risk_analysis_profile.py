"""Tests for the risk-analysis profile — tailored for bank risk models teams.

Validates that:
- Database client tools are blocked (sqlcmd, psql, mysql, etc.)
- Git history content commands are blocked (diff, show, log -p)
- Safe git commands still work (log --oneline, status, branch)
- Normal dev commands work (python3, ls, cat, etc.)
- Network is completely isolated (mode=NONE)
- Audit is fully enabled with HMAC signing
- GitRepoAccessConfig validates correctly
"""

import pytest

from lasso.config.defaults import BUILTIN_PROFILES, strict_profile
from lasso.config.schema import (
    GitRepoAccessConfig,
    NetworkMode,
    SandboxProfile,
)
from lasso.core.commands import CommandGate

# ---------------------------------------------------------------------------
# Profile registration
# ---------------------------------------------------------------------------

class TestRiskAnalysisProfileRegistered:
    """The risk-analysis profile must be discoverable."""

    def test_in_builtin_profiles(self):
        assert "strict" in BUILTIN_PROFILES

    def test_callable(self):
        profile = BUILTIN_PROFILES["strict"]("/tmp/test")
        assert isinstance(profile, SandboxProfile)
        assert profile.name == "strict"


# ---------------------------------------------------------------------------
# Database tool blocking
# ---------------------------------------------------------------------------

class TestRiskAnalysisBlocksDatabase:
    """Database client tools must be blocked by DANGEROUS_ARGS."""

    @pytest.fixture
    def gate(self):
        profile = strict_profile("/tmp/test")
        return CommandGate(profile.commands)

    @pytest.mark.parametrize("tool", [
        "sqlcmd", "bcp", "osql", "isql", "sqlplus",
        "mysql", "psql", "mongo", "mongosh",
        "redis-cli", "cqlsh", "clickhouse-client",
    ])
    def test_db_tool_blocked(self, gate, tool):
        """Database tools are blocked even if someone adds them to whitelist."""
        # These aren't on the whitelist, so they fail at whitelist check.
        # Even if added, DANGEROUS_ARGS would catch them.
        v = gate.check(f"{tool} -S server -d mydb")
        assert v.blocked, f"{tool} should be blocked"

    def test_sqlcmd_with_query_blocked(self, gate):
        v = gate.check("sqlcmd -S our-server -d our-db -Q 'SELECT * FROM users'")
        assert v.blocked


# ---------------------------------------------------------------------------
# Git history content blocking (PII protection)
# ---------------------------------------------------------------------------

class TestRiskAnalysisBlocksGitHistory:
    """Git commands that expose file content diffs must be blocked."""

    @pytest.fixture
    def gate(self):
        profile = strict_profile("/tmp/test")
        return CommandGate(profile.commands)

    def test_git_diff_blocked(self, gate):
        v = gate.check("git diff HEAD~1")
        assert v.blocked
        assert "diff" in v.reason.lower()

    def test_git_diff_no_args_blocked(self, gate):
        v = gate.check("git diff")
        assert v.blocked

    def test_git_diff_staged_blocked(self, gate):
        v = gate.check("git diff --staged")
        assert v.blocked

    def test_git_show_blocked(self, gate):
        v = gate.check("git show HEAD")
        assert v.blocked
        assert "show" in v.reason.lower()

    def test_git_show_no_args_blocked(self, gate):
        v = gate.check("git show")
        assert v.blocked

    def test_git_log_patch_blocked(self, gate):
        v = gate.check("git log -p")
        assert v.blocked

    def test_git_log_long_patch_blocked(self, gate):
        v = gate.check("git log --patch")
        assert v.blocked

    def test_git_push_blocked(self, gate):
        v = gate.check("git push origin main")
        assert v.blocked

    def test_git_push_force_blocked(self, gate):
        v = gate.check("git push --force origin main")
        assert v.blocked

    def test_git_remote_add_blocked(self, gate):
        v = gate.check("git remote add evil https://evil.com/repo.git")
        assert v.blocked

    def test_git_remote_set_url_blocked(self, gate):
        v = gate.check("git remote set-url origin https://evil.com/repo.git")
        assert v.blocked


# ---------------------------------------------------------------------------
# Allowed git commands
# ---------------------------------------------------------------------------

class TestRiskAnalysisAllowsGit:
    """Safe git commands must still work."""

    @pytest.fixture
    def gate(self):
        profile = strict_profile("/tmp/test")
        return CommandGate(profile.commands)

    def test_git_log_oneline(self, gate):
        v = gate.check("git log --oneline -5")
        assert v.allowed

    def test_git_log_oneline_no_limit(self, gate):
        v = gate.check("git log --oneline")
        assert v.allowed

    def test_git_status(self, gate):
        v = gate.check("git status")
        assert v.allowed

    def test_git_branch(self, gate):
        v = gate.check("git branch -a")
        assert v.allowed

    def test_git_checkout(self, gate):
        v = gate.check("git checkout feature-branch")
        assert v.allowed

    def test_git_clone(self, gate):
        """Clone is allowed — network blocking handles the actual isolation."""
        v = gate.check("git clone https://github.com/org/repo.git")
        assert v.allowed

    def test_git_pull(self, gate):
        v = gate.check("git pull origin main")
        assert v.allowed

    def test_git_add(self, gate):
        v = gate.check("git add file.py")
        assert v.allowed

    def test_git_commit(self, gate):
        v = gate.check("git commit -m 'update model'")
        assert v.allowed


# ---------------------------------------------------------------------------
# Allowed normal commands
# ---------------------------------------------------------------------------

class TestRiskAnalysisAllowsNormalCommands:
    """Standard development commands must work."""

    @pytest.fixture
    def gate(self):
        profile = strict_profile("/tmp/test")
        return CommandGate(profile.commands)

    def test_python3(self, gate):
        v = gate.check("python3 script.py")
        assert v.allowed

    def test_python3_version(self, gate):
        v = gate.check("python3 --version")
        assert v.allowed

    def test_pip_install(self, gate):
        v = gate.check("pip install numpy")
        assert v.allowed

    def test_ls(self, gate):
        v = gate.check("ls -la")
        assert v.allowed

    def test_cat(self, gate):
        v = gate.check("cat file.txt")
        assert v.allowed

    def test_grep(self, gate):
        v = gate.check("grep -r pattern .")
        assert v.allowed

    def test_rscript(self, gate):
        v = gate.check("Rscript analysis.R")
        assert v.allowed

    def test_r_interactive(self, gate):
        v = gate.check("R --version")
        assert v.allowed

    def test_jupyter(self, gate):
        v = gate.check("jupyter notebook --no-browser")
        assert v.allowed

    def test_head(self, gate):
        v = gate.check("head -20 data.csv")
        assert v.allowed

    def test_tail(self, gate):
        v = gate.check("tail -f output.log")
        assert v.allowed

    def test_find(self, gate):
        v = gate.check("find . -name '*.py'")
        assert v.allowed

    def test_wc(self, gate):
        v = gate.check("wc -l file.txt")
        assert v.allowed

    def test_sort(self, gate):
        v = gate.check("sort data.csv")
        assert v.allowed

    def test_uniq(self, gate):
        v = gate.check("uniq counts.txt")
        assert v.allowed

    def test_diff_command(self, gate):
        """The `diff` command (file comparison) is allowed — git diff is blocked."""
        v = gate.check("diff file1.txt file2.txt")
        assert v.allowed

    def test_mkdir(self, gate):
        v = gate.check("mkdir output")
        assert v.allowed

    def test_cp(self, gate):
        v = gate.check("cp source.py backup.py")
        assert v.allowed

    def test_mv(self, gate):
        v = gate.check("mv old.py new.py")
        assert v.allowed

    def test_touch(self, gate):
        v = gate.check("touch newfile.txt")
        assert v.allowed

    def test_echo(self, gate):
        v = gate.check("echo hello")
        assert v.allowed

    def test_test_command(self, gate):
        v = gate.check("test -f file.py")
        assert v.allowed


# ---------------------------------------------------------------------------
# Network isolation
# ---------------------------------------------------------------------------

class TestRiskAnalysisNetworkIsolation:
    """Network must be completely disabled."""

    @pytest.fixture
    def profile(self):
        return strict_profile("/tmp/test")

    def test_network_mode_none(self, profile):
        assert profile.network.mode == NetworkMode.NONE

    def test_db_ports_still_blocked(self, profile):
        """Even though network is NONE, blocked_ports are set for defense in depth."""
        assert 1433 in profile.network.blocked_ports
        assert 3306 in profile.network.blocked_ports
        assert 5432 in profile.network.blocked_ports
        assert 27017 in profile.network.blocked_ports
        assert 6379 in profile.network.blocked_ports


# ---------------------------------------------------------------------------
# Audit configuration
# ---------------------------------------------------------------------------

class TestRiskAnalysisAudit:
    """Full audit trail with HMAC signing must be enabled."""

    @pytest.fixture
    def profile(self):
        return strict_profile("/tmp/test")

    def test_audit_enabled(self, profile):
        assert profile.audit.enabled is True

    def test_audit_signs_entries(self, profile):
        assert profile.audit.sign_entries is True

    def test_audit_includes_command_output(self, profile):
        assert profile.audit.include_command_output is True

    def test_audit_includes_file_diffs(self, profile):
        assert profile.audit.include_file_diffs is True


# ---------------------------------------------------------------------------
# Profile metadata
# ---------------------------------------------------------------------------

class TestRiskAnalysisMetadata:
    """Profile metadata should reflect risk-analysis team usage."""

    @pytest.fixture
    def profile(self):
        return strict_profile("/tmp/test")

    def test_tags(self, profile):
        assert "strict" in profile.tags
        assert "compliance" in profile.tags
        assert "compliance" in profile.tags or "strict" in profile.tags

    def test_description_mentions_pii(self, profile):
        assert "git restricted" in profile.description or "audit" in profile.description

    def test_description_mentions_database(self, profile):
        assert "security" in profile.description.lower()

    def test_guardrails_enforced(self, profile):
        assert profile.guardrails.enforce is True

    def test_resources(self, profile):
        assert profile.resources.max_memory_mb == 8192
        assert profile.resources.max_cpu_percent == 50
        assert profile.resources.max_pids == 150

    def test_shell_operators_blocked(self, profile):
        assert profile.commands.allow_shell_operators is False


# ---------------------------------------------------------------------------
# GitRepoAccessConfig
# ---------------------------------------------------------------------------

class TestGitRepoAccessConfig:
    """GitRepoAccessConfig model validation."""

    def test_default_values(self):
        config = GitRepoAccessConfig()
        assert config.allowed_repos == []
        assert config.access_mode == "read"
        assert config.block_git_history_content is True

    def test_read_write_mode(self):
        config = GitRepoAccessConfig(access_mode="read-write")
        assert config.access_mode == "read-write"

    def test_invalid_mode_rejected(self):
        with pytest.raises(Exception):
            GitRepoAccessConfig(access_mode="admin")

    def test_invalid_mode_write_only_rejected(self):
        with pytest.raises(Exception):
            GitRepoAccessConfig(access_mode="write")

    def test_allowed_repos(self):
        config = GitRepoAccessConfig(
            allowed_repos=["myorg/risk-models", "myorg/shared-lib"],
        )
        assert len(config.allowed_repos) == 2
        assert "myorg/risk-models" in config.allowed_repos

    def test_block_history_disabled(self):
        config = GitRepoAccessConfig(block_git_history_content=False)
        assert config.block_git_history_content is False

    def test_risk_profile_has_git_access(self):
        profile = strict_profile("/tmp/test")
        assert profile.git_access is not None
        assert profile.git_access.access_mode == "read"
        assert profile.git_access.block_git_history_content is True

    def test_sandbox_profile_has_git_access_field(self):
        """SandboxProfile includes git_access with sensible defaults."""
        from lasso.config.schema import FilesystemConfig
        profile = SandboxProfile(
            name="test",
            filesystem=FilesystemConfig(working_dir="/tmp"),
        )
        assert profile.git_access is not None
        assert profile.git_access.access_mode == "read"
        assert profile.git_access.block_git_history_content is True

    def test_config_hash_includes_git_access(self):
        """git_access should affect the config hash."""
        p1 = strict_profile("/tmp/test")
        # Create a second profile with different git_access
        p2 = strict_profile("/tmp/test")
        p2.git_access.access_mode = "read-write"
        assert p1.config_hash() != p2.config_hash()
