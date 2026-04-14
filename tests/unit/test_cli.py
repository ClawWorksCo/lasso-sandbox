"""Tests for the LASSO CLI — flags, aliases, error messages, and confirmations.

Uses typer.testing.CliRunner to invoke commands without spawning subprocesses.
All tests use --native mode (no container backend required).
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from lasso.cli.main import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _reset_cli_registry():
    """Reset the global CLI registry between tests to avoid state leaks."""
    import lasso.cli.helpers as cli_helpers
    old = cli_helpers._registry
    cli_helpers._registry = None
    yield
    cli_helpers._registry = old


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _invoke(*args: str, input: str | None = None):
    """Invoke the CLI with the given arguments."""
    return runner.invoke(app, list(args), input=input)


# -----------------------------------------------------------------------
# --quiet flag on create
# -----------------------------------------------------------------------


class TestQuietFlag:
    """The --quiet flag should suppress all output except the essential value."""

    def test_create_quiet_returns_sandbox_id(self, tmp_path):
        """lasso create --quiet should print only the sandbox ID."""
        result = _invoke(
            "create", "evaluation",
            "--dir", str(tmp_path),
            "--native",
            "--quiet",
        )
        assert result.exit_code == 0
        output = result.output.strip()
        # Should be a 12-char hex ID and nothing else
        assert len(output) == 12
        assert all(c in "0123456789abcdef" for c in output)

    def test_create_quiet_no_panels(self, tmp_path):
        """--quiet output should have no Rich markup or panels."""
        result = _invoke(
            "create", "evaluation",
            "--dir", str(tmp_path),
            "--native",
            "--quiet",
        )
        output = result.output.strip()
        # No Rich formatting characters
        assert "─" not in output
        assert "LASSO" not in output
        assert "Backend" not in output


# -----------------------------------------------------------------------
# --json flag
# -----------------------------------------------------------------------


class TestJsonFlag:
    """Commands with --json should output valid JSON."""

    def test_status_json_returns_valid_json(self):
        """lasso status --json returns a valid JSON array."""
        result = _invoke("status", "--json")
        assert result.exit_code == 0
        # Output should be valid JSON with no extra lines like "Backend: ..."
        data = json.loads(result.output.strip())
        assert isinstance(data, list)
        # Each entry (if any) should have standard sandbox fields
        for s in data:
            assert "id" in s
            assert "name" in s
            assert "state" in s

    def test_profile_list_json(self):
        """lasso profile list --json returns a JSON array of profiles."""
        result = _invoke("profile", "list", "--json")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        # Should contain at least the 3 builtins
        names = [p["name"] for p in data]
        assert "evaluation" in names
        assert "standard" in names
        assert "strict" in names
        assert len(names) >= 3
        # Each entry should have type field
        for p in data:
            assert p.get("type") in ("builtin", "saved")

    def test_agent_list_json(self):
        """lasso agent list --json returns a JSON array."""
        result = _invoke("agent", "list", "--json")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) >= 1
        # Each agent should have standard fields
        for a in data:
            assert "name" in a
            assert "type" in a

    def test_check_json(self):
        """lasso check --json returns structured JSON with platform info."""
        result = _invoke("check", "--json")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "platform" in data
        assert "lasso" in data["platform"]
        assert "container_runtime" in data
        assert "agents" in data


# -----------------------------------------------------------------------
# Error messages with next-step suggestions
# -----------------------------------------------------------------------


class TestErrorNextSteps:
    """Every error message should include a next-step suggestion."""

    def test_profile_not_found_suggests_list(self):
        """Profile not found error should suggest 'lasso profile list'."""
        result = _invoke("create", "nonexistent-profile-xyz", "--native")
        assert result.exit_code == 1
        combined = result.output + (result.output if not result.output else "")
        # The suggestion should be present in stderr or stdout
        # CliRunner merges output by default
        assert "lasso profile list" in result.output

    def test_sandbox_not_found_suggests_status(self):
        """Sandbox not found should suggest 'lasso status'."""
        result = _invoke("exec", "nonexistent123", "ls")
        assert result.exit_code == 1
        assert "lasso status" in result.output

    def test_sandbox_stop_not_found_suggests_status(self):
        """Stop non-existent sandbox should suggest 'lasso status'."""
        result = _invoke("stop", "nonexistent123", "--yes")
        assert result.exit_code == 1
        assert "lasso status" in result.output

    def test_agent_not_found_suggests_supported(self):
        """Unknown agent should list supported agents."""
        result = _invoke("agent", "config", "nonexistent-agent")
        assert result.exit_code == 1
        assert "opencode" in result.output
        assert "claude-code" in result.output

    def test_profile_show_not_found_suggests_list(self):
        """Profile show for unknown name should suggest list."""
        result = _invoke("profile", "show", "nonexistent-xyz")
        assert result.exit_code == 1
        assert "lasso profile list" in result.output

    def test_init_unknown_profile_suggests_list(self):
        """Init with unknown profile should suggest listing profiles."""
        result = _invoke("init", "--profile", "nonexistent-xyz")
        assert result.exit_code == 1
        assert "lasso profile list" in result.output


# -----------------------------------------------------------------------
# Confirmation on destructive operations
# -----------------------------------------------------------------------


class TestConfirmations:
    """Destructive operations should ask for confirmation."""

    def test_stop_all_no_sandboxes_exits_cleanly(self):
        """lasso stop all with no running sandboxes should exit cleanly."""
        result = _invoke("stop", "all")
        assert result.exit_code == 0
        assert "No running" in result.output

    def test_stop_all_with_sandbox_aborts_on_no(self, tmp_path):
        """lasso stop all with running sandboxes aborts on 'n'."""
        # First create a sandbox so there's something to stop
        _invoke("create", "evaluation", "--dir", str(tmp_path), "--native", "--quiet")
        result = _invoke("stop", "all", input="n\n")
        assert result.exit_code == 1  # typer.Abort

    def test_stop_all_yes_flag_skips_confirmation(self):
        """lasso stop all --yes should skip the confirmation prompt."""
        result = _invoke("stop", "all", "--yes")
        assert result.exit_code == 0
        assert "Stopped" in result.output or result.output.strip() == ""

    def test_profile_delete_requires_confirmation(self):
        """lasso profile delete should ask for confirmation."""
        result = _invoke("profile", "delete", "nonexistent", input="n\n")
        # Should abort
        assert result.exit_code == 1

    def test_profile_delete_yes_flag(self):
        """lasso profile delete --yes should skip confirmation."""
        result = _invoke("profile", "delete", "nonexistent-xyz", "--yes")
        # Should fail because profile doesn't exist, not because of confirmation
        assert result.exit_code == 1
        assert "not found" in result.output


# -----------------------------------------------------------------------
# Command aliases
# -----------------------------------------------------------------------


class TestAliases:
    """Short aliases should invoke the corresponding commands."""

    def test_ps_alias(self):
        """lasso ps should work like lasso status."""
        result = _invoke("ps")
        assert result.exit_code == 0
        # Should show either "No sandboxes" or a table
        assert "No sandboxes" in result.output or "LASSO" in result.output

    def test_ps_json_alias(self):
        """lasso ps --json should output JSON."""
        result = _invoke("ps", "--json")
        assert result.exit_code == 0
        data = json.loads(result.output.strip())
        assert isinstance(data, list)

    def test_rm_alias(self, tmp_path):
        """lasso rm should work like lasso stop."""
        result = _invoke("rm", "nonexistent123", "--yes")
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_rm_all_no_sandboxes(self):
        """lasso rm all with no running sandboxes should exit cleanly."""
        result = _invoke("rm", "all")
        assert result.exit_code == 0
        assert "No running" in result.output


# -----------------------------------------------------------------------
# Completions command
# -----------------------------------------------------------------------


class TestCompletions:
    """The completions command should show installation instructions."""

    def test_completions_shows_instructions(self):
        result = _invoke("completions")
        assert result.exit_code == 0
        assert "--install-completion" in result.output
        assert "--show-completion" in result.output


# -----------------------------------------------------------------------
# Version
# -----------------------------------------------------------------------


class TestVersion:
    def test_version(self):
        result = _invoke("version")
        assert result.exit_code == 0
        assert "LASSO v" in result.output


# -----------------------------------------------------------------------
# Create with rich output (non-quiet)
# -----------------------------------------------------------------------


class TestCreateRichOutput:
    def test_create_shows_panel(self, tmp_path):
        """Non-quiet create should show a rich panel with sandbox info."""
        result = _invoke(
            "create", "evaluation",
            "--dir", str(tmp_path),
            "--native",
        )
        assert result.exit_code == 0
        assert "Sandbox created" in result.output
        assert "lasso exec" in result.output
