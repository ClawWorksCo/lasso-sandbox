"""Tests for the quickstart and reset CLI commands.

Uses typer.testing.CliRunner to invoke commands without spawning subprocesses.
All tests mock out Docker/system calls to avoid side effects.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

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


def _invoke(*args: str, input: str | None = None):
    """Invoke the CLI with the given arguments."""
    return runner.invoke(app, list(args), input=input)


# -----------------------------------------------------------------------
# Quickstart tests
# -----------------------------------------------------------------------


class TestQuickstart:
    """Tests for the lasso quickstart command."""

    @patch("lasso.cli.doctor.run_doctor")
    @patch("lasso.cli.main._get_registry")
    @patch("lasso.backends.image_builder.prebuild_presets")
    def test_quickstart_basic(self, mock_prebuild, mock_registry, mock_doctor, tmp_path):
        """Quickstart should run doctor, detect agent, build images, print summary."""
        mock_report = MagicMock()
        mock_report.failed = 0
        mock_doctor.return_value = mock_report

        mock_backend = MagicMock()
        mock_backend.image_exists.return_value = True
        mock_reg = MagicMock()
        mock_reg._backend = mock_backend
        mock_registry.return_value = mock_reg

        result = _invoke("quickstart", "--dir", str(tmp_path))

        assert result.exit_code == 0
        assert "Setup complete" in result.output
        assert "lasso up" in result.output

    @patch("lasso.cli.doctor.run_doctor")
    def test_quickstart_doctor_fails(self, mock_doctor, tmp_path):
        """Quickstart should exit 1 if doctor checks fail."""
        mock_report = MagicMock()
        mock_report.failed = 2
        mock_doctor.return_value = mock_report

        result = _invoke("quickstart", "--dir", str(tmp_path))

        assert result.exit_code == 1

    @patch("lasso.cli.doctor.run_doctor")
    @patch("lasso.cli.main._get_registry")
    @patch("lasso.backends.image_builder.prebuild_presets")
    def test_quickstart_auto_detects_claude(
        self, mock_prebuild, mock_registry, mock_doctor, tmp_path
    ):
        """Quickstart should detect claude-code if CLAUDE.md exists."""
        (tmp_path / "CLAUDE.md").write_text("# Agent config")

        mock_report = MagicMock()
        mock_report.failed = 0
        mock_doctor.return_value = mock_report

        mock_backend = MagicMock()
        mock_backend.image_exists.return_value = True
        mock_reg = MagicMock()
        mock_reg._backend = mock_backend
        mock_registry.return_value = mock_reg

        result = _invoke("quickstart", "--dir", str(tmp_path))

        assert result.exit_code == 0
        assert "claude-code" in result.output

    @patch("lasso.cli.doctor.run_doctor")
    @patch("lasso.cli.main._get_registry")
    @patch("lasso.backends.image_builder.prebuild_presets")
    def test_quickstart_auto_detects_opencode(
        self, mock_prebuild, mock_registry, mock_doctor, tmp_path
    ):
        """Quickstart should detect opencode if opencode.json exists."""
        (tmp_path / "opencode.json").write_text("{}")

        mock_report = MagicMock()
        mock_report.failed = 0
        mock_doctor.return_value = mock_report

        mock_backend = MagicMock()
        mock_backend.image_exists.return_value = True
        mock_reg = MagicMock()
        mock_reg._backend = mock_backend
        mock_registry.return_value = mock_reg

        result = _invoke("quickstart", "--dir", str(tmp_path))

        assert result.exit_code == 0
        assert "opencode" in result.output

    @patch("lasso.cli.doctor.run_doctor")
    @patch("lasso.cli.main._get_registry")
    @patch("lasso.backends.image_builder.prebuild_presets")
    def test_quickstart_explicit_agent(
        self, mock_prebuild, mock_registry, mock_doctor, tmp_path
    ):
        """Quickstart should use --agent when specified."""
        mock_report = MagicMock()
        mock_report.failed = 0
        mock_doctor.return_value = mock_report

        mock_backend = MagicMock()
        mock_backend.image_exists.return_value = True
        mock_reg = MagicMock()
        mock_reg._backend = mock_backend
        mock_registry.return_value = mock_reg

        result = _invoke(
            "quickstart", "--dir", str(tmp_path), "--agent", "claude-code"
        )

        assert result.exit_code == 0
        assert "claude-code" in result.output

    @patch("lasso.cli.doctor.run_doctor")
    @patch("lasso.cli.main._get_registry")
    @patch("lasso.backends.image_builder.prebuild_presets")
    def test_quickstart_builds_missing_images(
        self, mock_prebuild, mock_registry, mock_doctor, tmp_path
    ):
        """Quickstart should call prebuild when images are missing."""
        mock_report = MagicMock()
        mock_report.failed = 0
        mock_doctor.return_value = mock_report

        mock_backend = MagicMock()
        mock_backend.image_exists.return_value = False
        mock_reg = MagicMock()
        mock_reg._backend = mock_backend
        mock_registry.return_value = mock_reg

        mock_prebuild.return_value = {"base": "lasso-preset:base"}

        result = _invoke("quickstart", "--dir", str(tmp_path))

        assert result.exit_code == 0
        mock_prebuild.assert_called_once()
        assert "Built" in result.output

    @patch("lasso.cli.doctor.run_doctor")
    @patch("lasso.cli.main._get_registry")
    @patch("lasso.backends.image_builder.prebuild_presets")
    def test_quickstart_skips_cached_images(
        self, mock_prebuild, mock_registry, mock_doctor, tmp_path
    ):
        """Quickstart should skip prebuild if all images are cached."""
        mock_report = MagicMock()
        mock_report.failed = 0
        mock_doctor.return_value = mock_report

        mock_backend = MagicMock()
        mock_backend.image_exists.return_value = True
        mock_reg = MagicMock()
        mock_reg._backend = mock_backend
        mock_registry.return_value = mock_reg

        result = _invoke("quickstart", "--dir", str(tmp_path))

        assert result.exit_code == 0
        mock_prebuild.assert_not_called()
        assert "Skipped" in result.output

    @patch("lasso.cli.doctor.run_doctor")
    @patch("lasso.cli.main._get_registry")
    @patch("lasso.backends.image_builder.prebuild_presets")
    def test_quickstart_no_agent_detected(
        self, mock_prebuild, mock_registry, mock_doctor, tmp_path
    ):
        """Quickstart should work when no agent is detected."""
        mock_report = MagicMock()
        mock_report.failed = 0
        mock_doctor.return_value = mock_report

        mock_backend = MagicMock()
        mock_backend.image_exists.return_value = True
        mock_reg = MagicMock()
        mock_reg._backend = mock_backend
        mock_registry.return_value = mock_reg

        result = _invoke("quickstart", "--dir", str(tmp_path))

        assert result.exit_code == 0
        assert "none detected" in result.output or "shell" in result.output


# -----------------------------------------------------------------------
# Reset tests
# -----------------------------------------------------------------------


class TestReset:
    """Tests for the lasso reset command."""

    @patch("lasso.cli.main._get_registry")
    @patch("subprocess.run")
    def test_reset_basic(self, mock_subprocess, mock_registry):
        """Reset should stop sandboxes and proxy, print summary."""
        mock_reg = MagicMock()
        mock_reg.list_all.return_value = [{"state": "running", "id": "abc"}]
        mock_reg.stop_all.return_value = 1
        mock_registry.return_value = mock_reg

        mock_subprocess.return_value = MagicMock(
            returncode=1, stdout="", stderr=""
        )

        result = _invoke("reset", "--yes")

        assert result.exit_code == 0
        assert "Reset complete" in result.output
        mock_reg.stop_all.assert_called_once()

    @patch("lasso.cli.main._get_registry")
    @patch("subprocess.run")
    def test_reset_no_running(self, mock_subprocess, mock_registry):
        """Reset with no running sandboxes should report accordingly."""
        mock_reg = MagicMock()
        mock_reg.list_all.return_value = []
        mock_registry.return_value = mock_reg

        mock_subprocess.return_value = MagicMock(
            returncode=1, stdout="", stderr=""
        )

        result = _invoke("reset", "--yes")

        assert result.exit_code == 0
        assert "No running sandboxes" in result.output

    @patch("lasso.cli.main._get_registry")
    @patch("subprocess.run")
    def test_reset_prune(self, mock_subprocess, mock_registry):
        """Reset --prune should attempt to remove stopped containers."""
        mock_reg = MagicMock()
        mock_reg.list_all.return_value = []
        mock_registry.return_value = mock_reg

        container_id = "abc123def456"

        def subprocess_side_effect(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            mock_result = MagicMock()
            if "ps" in cmd and "-a" in cmd:
                mock_result.returncode = 0
                mock_result.stdout = container_id + "\n"
            else:
                mock_result.returncode = 1
                mock_result.stdout = ""
            mock_result.stderr = ""
            return mock_result

        mock_subprocess.side_effect = subprocess_side_effect

        result = _invoke("reset", "--prune", "--yes")

        assert result.exit_code == 0
        assert "Removed 1 stopped container" in result.output

    @patch("lasso.cli.main._get_registry")
    @patch("subprocess.run")
    def test_reset_hard(self, mock_subprocess, mock_registry):
        """Reset --hard should attempt to remove volumes and images."""
        mock_reg = MagicMock()
        mock_reg.list_all.return_value = []
        mock_registry.return_value = mock_reg

        def subprocess_side_effect(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stderr = ""

            if "volume" in cmd and "ls" in cmd:
                mock_result.stdout = "lasso-session-vol\nopencode-data\nother-vol\n"
            elif "images" in cmd:
                mock_result.stdout = "lasso-preset:base\nlasso-preset:claude-code\nnginx:latest\n"
            else:
                mock_result.stdout = ""
                mock_result.returncode = 1

            return mock_result

        mock_subprocess.side_effect = subprocess_side_effect

        result = _invoke("reset", "--hard", "--yes")

        assert result.exit_code == 0
        assert "volume(s)" in result.output
        assert "image(s)" in result.output

    @patch("lasso.cli.main._get_registry")
    @patch("subprocess.run")
    def test_reset_requires_confirmation(self, mock_subprocess, mock_registry):
        """Reset without --yes should prompt for confirmation."""
        mock_reg = MagicMock()
        mock_reg.list_all.return_value = []
        mock_registry.return_value = mock_reg

        result = _invoke("reset", input="n\n")

        assert result.exit_code == 1  # Aborted

    @patch("lasso.cli.main._get_registry")
    @patch("subprocess.run")
    def test_reset_confirmation_yes(self, mock_subprocess, mock_registry):
        """Reset with confirmation 'y' should proceed."""
        mock_reg = MagicMock()
        mock_reg.list_all.return_value = []
        mock_registry.return_value = mock_reg

        mock_subprocess.return_value = MagicMock(
            returncode=1, stdout="", stderr=""
        )

        result = _invoke("reset", input="y\n")

        assert result.exit_code == 0
        assert "Reset complete" in result.output

    @patch("lasso.cli.main._get_registry")
    @patch("subprocess.run")
    def test_reset_hard_filters_volumes_correctly(
        self, mock_subprocess, mock_registry
    ):
        """Reset --hard should only remove volumes with lasso/opencode in name."""
        mock_reg = MagicMock()
        mock_reg.list_all.return_value = []
        mock_registry.return_value = mock_reg

        volume_rm_calls = []

        def subprocess_side_effect(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stderr = ""

            if "volume" in cmd and "ls" in cmd:
                mock_result.stdout = "my-lasso-vol\npostgres-data\nopencode-state\n"
            elif "volume" in cmd and "rm" in cmd:
                volume_rm_calls.append(cmd)
                mock_result.stdout = ""
            elif "images" in cmd:
                mock_result.stdout = ""
            else:
                mock_result.stdout = ""
                mock_result.returncode = 1

            return mock_result

        mock_subprocess.side_effect = subprocess_side_effect

        result = _invoke("reset", "--hard", "--yes")

        assert result.exit_code == 0
        assert "Removed 2 volume(s)" in result.output
