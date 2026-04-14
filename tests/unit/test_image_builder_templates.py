"""Tests for sandbox-template Dockerfile generation and pull logic."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from lasso.backends.image_builder import (
    _generate_template_dockerfile,
    _try_pull_template,
    ensure_image,
    generate_dockerfile,
)
from lasso.config.defaults import evaluation_profile, standard_profile

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _offline_profile():
    """Return a profile with NetworkMode.NONE (no iptables needed)."""
    return evaluation_profile("/tmp/test")


def _restricted_profile():
    """Return a profile with NetworkMode.RESTRICTED (needs iptables)."""
    return standard_profile("/tmp/test")


# ---------------------------------------------------------------------------
# Template Dockerfile generation
# ---------------------------------------------------------------------------


class TestGenerateTemplateDockerfileBasic:
    """test_generate_template_dockerfile_basic — FROM sandbox-templates,
    has labels, no useradd, no AGENT_INSTALLS, ends with CMD sleep infinity.
    """

    def test_from_sandbox_template(self):
        profile = _offline_profile()
        df = _generate_template_dockerfile(profile, "claude-code")
        assert df.startswith("FROM docker/sandbox-templates:claude-code")

    def test_has_labels(self):
        profile = _offline_profile()
        df = _generate_template_dockerfile(profile, "claude-code")
        assert "LABEL managed-by=lasso" in df
        assert f"LABEL lasso-profile={profile.name}" in df

    def test_no_useradd(self):
        profile = _offline_profile()
        df = _generate_template_dockerfile(profile, "claude-code")
        assert "useradd" not in df

    def test_no_agent_installs(self):
        profile = _offline_profile()
        df = _generate_template_dockerfile(profile, "claude-code")
        assert "nodesource" not in df
        assert "npm install" not in df
        assert "opencode.ai/install" not in df

    def test_ends_with_cmd_sleep(self):
        profile = _offline_profile()
        df = _generate_template_dockerfile(profile, "claude-code")
        assert df.strip().endswith('CMD ["sleep", "infinity"]')


class TestGenerateTemplateDockerfileWithIptables:
    """test_generate_template_dockerfile_with_iptables — USER root,
    apt install iptables, USER agent.
    """

    def test_iptables_installed_as_root(self):
        profile = _restricted_profile()
        df = _generate_template_dockerfile(profile, "claude-code")
        assert "USER root" in df
        assert "iptables" in df
        assert "USER agent" in df

    def test_user_agent_after_iptables(self):
        profile = _restricted_profile()
        df = _generate_template_dockerfile(profile, "claude-code")
        iptables_pos = df.index("iptables")
        user_agent_pos = df.rindex("USER agent")
        assert iptables_pos < user_agent_pos


class TestGenerateTemplateDockerfileWithCACert:
    """test_generate_template_dockerfile_with_ca_cert — cert content
    embedded, update-ca-certificates.
    """

    def test_ca_cert_embedded(self, tmp_path):
        cert_file = tmp_path / "ca.pem"
        cert_file.write_text("-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----")

        profile = _offline_profile()
        df = _generate_template_dockerfile(profile, "opencode", ca_cert_path=str(cert_file))

        assert "BEGIN CERTIFICATE" in df
        assert "update-ca-certificates" in df
        assert "USER root" in df

    def test_ca_cert_has_explicit_user_root(self, tmp_path):
        """USER root is always emitted before CA cert, even when iptables
        already switched to root."""
        cert_file = tmp_path / "ca.pem"
        cert_file.write_text("-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----")

        profile = _restricted_profile()
        df = _generate_template_dockerfile(profile, "opencode", ca_cert_path=str(cert_file))

        # Should have at least 2 USER root directives (iptables + CA cert)
        assert df.count("USER root") >= 2


# ---------------------------------------------------------------------------
# generate_dockerfile dispatch
# ---------------------------------------------------------------------------


class TestGenerateDockerfileDispatch:
    """test_generate_dockerfile_dispatches_to_template — generate_dockerfile
    with use_sandbox_template=True uses template base.
    """

    def test_dispatches_to_template(self):
        profile = _offline_profile()
        df = generate_dockerfile(profile, agent="claude-code", use_sandbox_template=True)
        assert "FROM docker/sandbox-templates:claude-code" in df
        assert "useradd" not in df

    def test_falls_back_to_full_build(self):
        """use_sandbox_template=False uses python:3.12-slim."""
        profile = _offline_profile()
        df = generate_dockerfile(profile, agent="claude-code", use_sandbox_template=False)
        assert "python:3.12-slim" in df
        assert "useradd" in df


# ---------------------------------------------------------------------------
# _try_pull_template
# ---------------------------------------------------------------------------


class TestTryPullTemplate:
    """Tests for _try_pull_template pull logic."""

    def test_pull_success(self):
        mock_client = MagicMock()
        mock_backend = MagicMock()
        mock_backend.get_native_client.return_value = mock_client

        result = _try_pull_template(mock_backend, "claude-code")

        assert result is True
        mock_client.images.pull.assert_called_once_with(
            "docker/sandbox-templates:claude-code"
        )

    def test_pull_failure(self):
        mock_client = MagicMock()
        mock_client.images.pull.side_effect = RuntimeError("network error")
        mock_backend = MagicMock()
        mock_backend.get_native_client.return_value = mock_client

        result = _try_pull_template(mock_backend, "claude-code")

        assert result is False

    def test_unknown_agent_returns_false(self):
        mock_backend = MagicMock()
        result = _try_pull_template(mock_backend, "unknown-agent-xyz")
        assert result is False
        mock_backend.get_native_client.assert_not_called()


# ---------------------------------------------------------------------------
# ensure_image with templates
# ---------------------------------------------------------------------------


class TestEnsureImageUsesTemplate:
    """test_ensure_image_uses_template — mock pull success, verify
    template dockerfile is used.
    """

    @patch("lasso.backends.image_builder._try_pull_template", return_value=True)
    def test_uses_template_on_pull_success(self, mock_pull, fake_backend):
        # Make image_exists return False so it actually builds
        fake_backend.image_exists = MagicMock(return_value=False)

        profile = _offline_profile()
        tag = ensure_image(fake_backend, profile, agent="claude-code")

        assert tag == "lasso-preset:claude-code"
        mock_pull.assert_called_once()
        # Verify the build was called (via fake_backend.calls)
        build_calls = [c for c in fake_backend.calls if c[0] == "build_image"]
        assert len(build_calls) == 1


class TestPrebuildBaseAlwaysFullBuild:
    """test_prebuild_base_always_full_build — base preset uses
    python:3.12-slim (never template).
    """

    def test_base_preset_uses_full_build(self):
        profile = _offline_profile()
        df = generate_dockerfile(profile, use_sandbox_template=False)
        assert "python:3.12-slim" in df
        assert "useradd" in df
        # No sandbox-template reference
        assert "sandbox-templates" not in df

    def test_base_preset_no_agent_no_template(self):
        """Without an agent, generate_dockerfile never dispatches to template."""
        profile = _offline_profile()
        df = generate_dockerfile(profile, agent=None, use_sandbox_template=True)
        assert "python:3.12-slim" in df
        assert "sandbox-templates" not in df
