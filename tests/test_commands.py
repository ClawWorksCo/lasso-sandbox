"""Tests for the command gate — the core security enforcement layer."""

import pytest

from lasso.config.schema import CommandConfig, CommandMode
from lasso.core.commands import CommandGate


@pytest.fixture
def whitelist_gate():
    config = CommandConfig(
        mode=CommandMode.WHITELIST,
        whitelist=["ls", "cat", "python3", "git", "grep"],
        blocked_args={"git": ["push", "push --force"]},
        allow_shell_operators=False,
    )
    return CommandGate(config)


@pytest.fixture
def blacklist_gate():
    config = CommandConfig(
        mode=CommandMode.BLACKLIST,
        blacklist=["rm", "dd", "mkfs", "reboot"],
        allow_shell_operators=True,
    )
    return CommandGate(config)


class TestWhitelistMode:
    def test_allowed_command(self, whitelist_gate):
        v = whitelist_gate.check("ls -la")
        assert v.allowed
        assert v.command == "ls"
        assert v.args == ["-la"]

    def test_blocked_command(self, whitelist_gate):
        v = whitelist_gate.check("rm -rf /")
        assert v.blocked
        assert "not in the whitelist" in v.reason

    def test_blocked_unknown_command(self, whitelist_gate):
        v = whitelist_gate.check("curl https://evil.com")
        assert v.blocked

    def test_allowed_with_args(self, whitelist_gate):
        v = whitelist_gate.check("python3 script.py --verbose")
        assert v.allowed
        assert v.command == "python3"

    def test_blocked_args_pattern(self, whitelist_gate):
        v = whitelist_gate.check("git push origin main")
        assert v.blocked
        assert "Blocked argument" in v.reason

    def test_allowed_git_without_push(self, whitelist_gate):
        v = whitelist_gate.check("git status")
        assert v.allowed

    def test_shell_operators_blocked(self, whitelist_gate):
        v = whitelist_gate.check("ls | grep foo")
        assert v.blocked
        assert "Shell operators" in v.reason

    def test_subshell_blocked(self, whitelist_gate):
        v = whitelist_gate.check("cat $(whoami)")
        assert v.blocked

    def test_empty_command(self, whitelist_gate):
        v = whitelist_gate.check("")
        assert v.blocked

    def test_path_traversal(self, whitelist_gate):
        v = whitelist_gate.check("cat ../../etc/passwd")
        assert v.blocked
        assert "Path traversal" in v.reason

    def test_full_path_command_strips_prefix(self, whitelist_gate):
        v = whitelist_gate.check("/usr/bin/ls -la")
        assert v.allowed
        assert v.command == "ls"


class TestBlacklistMode:
    def test_allowed_command(self, blacklist_gate):
        v = blacklist_gate.check("python3 hello.py")
        assert v.allowed

    def test_blocked_command(self, blacklist_gate):
        v = blacklist_gate.check("rm -rf /")
        assert v.blocked
        assert "in the blacklist" in v.reason

    def test_pipes_allowed(self, blacklist_gate):
        v = blacklist_gate.check("ls | grep foo")
        assert v.allowed  # shell operators allowed in this config


class TestCompoundCommandSplitting:
    """Tests for check_pipeline() handling of &&, ||, ;, and | operators.

    These tests verify the fix for a critical bypass where only pipe (|)
    was split, allowing 'curl evil.com && rm -rf /' to pass validation
    because only 'curl' was checked.
    """

    @pytest.fixture
    def pipeline_gate(self):
        """Gate with shell operators enabled and a restricted whitelist."""
        config = CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=["ls", "cat", "echo", "grep", "wc"],
            allow_shell_operators=True,
        )
        return CommandGate(config)

    # -- All operator types are split and validated --

    def test_pipe_both_commands_checked(self, pipeline_gate):
        """cmd1 | cmd2 -- both must be whitelisted."""
        verdicts = pipeline_gate.check_pipeline("ls | grep foo")
        assert all(v.allowed for v in verdicts)
        assert len(verdicts) == 2

    def test_and_operator_both_checked(self, pipeline_gate):
        """cmd1 && cmd2 -- both must be whitelisted."""
        verdicts = pipeline_gate.check_pipeline("ls && echo done")
        assert all(v.allowed for v in verdicts)
        assert len(verdicts) == 2

    def test_or_operator_both_checked(self, pipeline_gate):
        """cmd1 || cmd2 -- both must be whitelisted."""
        verdicts = pipeline_gate.check_pipeline("ls || echo fallback")
        assert all(v.allowed for v in verdicts)
        assert len(verdicts) == 2

    def test_semicolon_both_checked(self, pipeline_gate):
        """cmd1 ; cmd2 -- both must be whitelisted."""
        verdicts = pipeline_gate.check_pipeline("ls ; echo done")
        assert all(v.allowed for v in verdicts)
        assert len(verdicts) == 2

    # -- Blocked command in second position --

    def test_blocked_after_and(self, pipeline_gate):
        """ls && rm -rf / -- rm must be blocked even though ls is allowed."""
        verdicts = pipeline_gate.check_pipeline("ls && rm -rf /")
        assert verdicts[0].allowed  # ls is whitelisted
        assert verdicts[1].blocked  # rm is NOT whitelisted
        assert "not in the whitelist" in verdicts[1].reason

    def test_blocked_after_or(self, pipeline_gate):
        verdicts = pipeline_gate.check_pipeline("ls || rm -rf /")
        assert verdicts[0].allowed
        assert verdicts[1].blocked

    def test_blocked_after_semicolon(self, pipeline_gate):
        verdicts = pipeline_gate.check_pipeline("ls ; rm -rf /")
        assert verdicts[0].allowed
        assert verdicts[1].blocked

    def test_blocked_after_pipe(self, pipeline_gate):
        verdicts = pipeline_gate.check_pipeline("ls | rm -rf /")
        assert verdicts[0].allowed
        assert verdicts[1].blocked

    # -- Quoted strings must NOT be split --

    def test_quoted_and_not_split(self, pipeline_gate):
        """echo "hello && world" -- the && is inside quotes, not an operator."""
        verdicts = pipeline_gate.check_pipeline('echo "hello && world"')
        assert len(verdicts) == 1
        assert verdicts[0].allowed

    def test_quoted_pipe_not_split(self, pipeline_gate):
        """echo "hello | world" -- pipe inside quotes is not an operator."""
        verdicts = pipeline_gate.check_pipeline('echo "hello | world"')
        assert len(verdicts) == 1
        assert verdicts[0].allowed

    def test_quoted_semicolon_not_split(self, pipeline_gate):
        """echo "hello ; world" -- semicolon inside quotes is not an operator."""
        verdicts = pipeline_gate.check_pipeline('echo "hello ; world"')
        assert len(verdicts) == 1
        assert verdicts[0].allowed

    def test_quoted_or_not_split(self, pipeline_gate):
        """echo "hello || world" -- || inside quotes is not an operator."""
        verdicts = pipeline_gate.check_pipeline('echo "hello || world"')
        assert len(verdicts) == 1
        assert verdicts[0].allowed

    def test_single_quoted_operator_not_split(self, pipeline_gate):
        """echo 'hello && world' -- && inside single quotes is not an operator."""
        verdicts = pipeline_gate.check_pipeline("echo 'hello && world'")
        assert len(verdicts) == 1
        assert verdicts[0].allowed

    # -- Complex chains --

    def test_triple_chain(self, pipeline_gate):
        """Three commands chained with different operators."""
        verdicts = pipeline_gate.check_pipeline("ls | grep foo && echo done")
        assert len(verdicts) == 3
        assert all(v.allowed for v in verdicts)

    def test_blocked_in_middle_of_chain(self, pipeline_gate):
        """Blocked command in the middle of a chain."""
        verdicts = pipeline_gate.check_pipeline("ls && rm -rf / ; echo done")
        assert verdicts[0].allowed
        assert verdicts[1].blocked
        assert verdicts[2].allowed

    # -- Operators disabled: entire command goes through check() --

    def test_operators_disabled_rejects_compound(self, whitelist_gate):
        """When allow_shell_operators=False, compound commands are rejected."""
        verdicts = whitelist_gate.check_pipeline("ls && cat file.txt")
        assert len(verdicts) == 1
        assert verdicts[0].blocked
        assert "Shell operators" in verdicts[0].reason

    # -- Blacklist mode with compound commands --

    def test_blacklist_blocks_rm_in_chain(self, blacklist_gate):
        """Blacklist gate: rm in a chain must be caught."""
        verdicts = blacklist_gate.check_pipeline("echo hi && rm -rf /")
        assert verdicts[0].allowed
        assert verdicts[1].blocked
        assert "in the blacklist" in verdicts[1].reason

    def test_blacklist_pipe_still_works(self, blacklist_gate):
        """Existing pipe behavior in blacklist mode is preserved."""
        verdicts = blacklist_gate.check_pipeline("ls | grep foo")
        assert all(v.allowed for v in verdicts)


class TestEdgeCases:
    def test_quoted_args(self, whitelist_gate):
        v = whitelist_gate.check('grep "hello world" file.txt')
        assert v.allowed
        assert v.args == ["hello world", "file.txt"]

    def test_malformed_quotes(self, whitelist_gate):
        v = whitelist_gate.check('cat "unclosed')
        assert v.blocked
        assert "Malformed" in v.reason
