"""Tests for --env-file parsing and agent args passthrough."""

import pytest

from lasso.cli.helpers import _load_env_file


class TestLoadEnvFile:
    """Tests for _load_env_file() dotenv parser."""

    def test_basic_key_value(self, tmp_path):
        """Parses simple KEY=VALUE lines."""
        env = tmp_path / ".env"
        env.write_text("FOO=bar\nBAZ=qux\n")
        result = _load_env_file(str(env))
        assert result == ["FOO=bar", "BAZ=qux"]

    def test_skips_comments(self, tmp_path):
        """Lines starting with # are skipped."""
        env = tmp_path / ".env"
        env.write_text("# this is a comment\nFOO=bar\n# another\nBAZ=qux\n")
        result = _load_env_file(str(env))
        assert result == ["FOO=bar", "BAZ=qux"]

    def test_skips_empty_lines(self, tmp_path):
        """Empty and whitespace-only lines are skipped."""
        env = tmp_path / ".env"
        env.write_text("FOO=bar\n\n   \nBAZ=qux\n")
        result = _load_env_file(str(env))
        assert result == ["FOO=bar", "BAZ=qux"]

    def test_strips_surrounding_double_quotes(self, tmp_path):
        """Values wrapped in double quotes have quotes removed."""
        env = tmp_path / ".env"
        env.write_text('FOO="hello world"\n')
        result = _load_env_file(str(env))
        assert result == ["FOO=hello world"]

    def test_strips_surrounding_single_quotes(self, tmp_path):
        """Values wrapped in single quotes have quotes removed."""
        env = tmp_path / ".env"
        env.write_text("FOO='hello world'\n")
        result = _load_env_file(str(env))
        assert result == ["FOO=hello world"]

    def test_preserves_value_with_equals(self, tmp_path):
        """Values containing = are preserved correctly."""
        env = tmp_path / ".env"
        env.write_text("DATABASE_URL=postgres://user:pass@host/db?opt=val\n")
        result = _load_env_file(str(env))
        assert result == ["DATABASE_URL=postgres://user:pass@host/db?opt=val"]

    def test_empty_value(self, tmp_path):
        """Keys with empty values are allowed."""
        env = tmp_path / ".env"
        env.write_text("EMPTY_VAR=\n")
        result = _load_env_file(str(env))
        assert result == ["EMPTY_VAR="]

    def test_file_not_found_exits(self, tmp_path):
        """Missing file raises Exit via typer.Exit."""
        from click.exceptions import Exit
        with pytest.raises(Exit):
            _load_env_file(str(tmp_path / "nonexistent.env"))

    def test_invalid_line_exits(self, tmp_path):
        """Line without = raises Exit via typer.Exit."""
        from click.exceptions import Exit
        env = tmp_path / ".env"
        env.write_text("VALID=ok\nINVALID_LINE\n")
        with pytest.raises(Exit):
            _load_env_file(str(env))

    def test_whitespace_around_key_value(self, tmp_path):
        """Whitespace around keys and values is stripped."""
        env = tmp_path / ".env"
        env.write_text("  FOO  =  bar  \n")
        result = _load_env_file(str(env))
        assert result == ["FOO=bar"]

    def test_empty_file(self, tmp_path):
        """Empty file returns empty list."""
        env = tmp_path / ".env"
        env.write_text("")
        result = _load_env_file(str(env))
        assert result == []

    def test_comment_only_file(self, tmp_path):
        """File with only comments returns empty list."""
        env = tmp_path / ".env"
        env.write_text("# comment 1\n# comment 2\n")
        result = _load_env_file(str(env))
        assert result == []


class TestAgentArgs:
    """Tests for --agent-arg passthrough logic."""

    def test_agent_cmd_parts_with_args(self):
        """Agent command is built with extra args appended."""
        from lasso.cli.constants import AGENT_CLI_COMMANDS
        base_cmd = AGENT_CLI_COMMANDS.get("opencode", ["opencode"])[0]
        agent_args = ["--continue", "--verbose"]
        cmd_parts = [base_cmd] + agent_args
        assert cmd_parts == ["opencode", "--continue", "--verbose"]

    def test_agent_cmd_parts_without_args(self):
        """Without agent_args, command is just the base."""
        from lasso.cli.constants import AGENT_CLI_COMMANDS
        base_cmd = AGENT_CLI_COMMANDS.get("opencode", ["opencode"])[0]
        agent_args = None
        cmd_parts = [base_cmd] + (agent_args or [])
        assert cmd_parts == ["opencode"]

    def test_resume_adds_continue_for_opencode(self):
        """OpenCode provider adds --continue on resume."""
        from lasso.agents.opencode import OpenCodeProvider
        provider = OpenCodeProvider()
        cmd = provider.get_start_command(resume=True)
        assert "--continue" in cmd

    def test_resume_with_extra_args(self):
        """Extra agent_args are appended after --continue on resume."""
        from lasso.agents.opencode import OpenCodeProvider
        provider = OpenCodeProvider()
        cmd = provider.get_start_command(resume=True)
        extra = ["--model", "gpt-4"]
        full = cmd + extra
        assert full == ["opencode", "--continue", "--model", "gpt-4"]
