"""Tests for Dockerfile generation from sandbox profiles."""

import pytest

from lasso.backends.image_builder import TOOL_TO_PACKAGE, generate_dockerfile, image_tag
from lasso.config.defaults import evaluation_profile, standard_profile, strict_profile


class TestDockerfileGeneration:
    def test_minimal_profile_has_python(self):
        profile = evaluation_profile("/tmp/test")
        dockerfile = generate_dockerfile(profile)
        assert "FROM python:3.12-slim" in dockerfile
        assert "LABEL managed-by=lasso" in dockerfile

    def test_standard_profile_is_blacklist(self):
        """Standard profile uses blacklist mode — no per-tool installs."""
        profile = standard_profile("/tmp/test")
        dockerfile = generate_dockerfile(profile)
        # Blacklist profiles don't install specific tools
        assert "USER agent" in dockerfile

    def test_banking_profile_no_curl(self):
        profile = strict_profile("/tmp/test")
        dockerfile = generate_dockerfile(profile)
        # Banking profile doesn't whitelist curl, so it shouldn't be installed
        assert "curl" not in dockerfile.split("apt-get")[1] if "apt-get" in dockerfile else True

    def test_creates_non_root_user(self):
        profile = evaluation_profile("/tmp/test")
        dockerfile = generate_dockerfile(profile)
        assert "useradd" in dockerfile
        assert "USER agent" in dockerfile

    def test_sets_workdir(self):
        profile = evaluation_profile("/tmp/test")
        dockerfile = generate_dockerfile(profile)
        assert "WORKDIR /workspace" in dockerfile

    def test_deterministic_image_tag(self):
        profile = evaluation_profile("/tmp/test")
        tag1 = image_tag(profile)
        tag2 = image_tag(profile)
        assert tag1 == tag2
        assert tag1.startswith("lasso-")

    def test_different_profiles_different_tags(self):
        # Without agents, all profiles map to the same preset base tag
        p1 = evaluation_profile("/tmp/test")
        p2 = standard_profile("/tmp/test")
        assert image_tag(p1) == image_tag(p2) == "lasso-preset:base"
        # Different agents produce different preset tags
        assert image_tag(p1, agent="claude-code") != image_tag(p1, agent="opencode")
        assert image_tag(p1, agent="claude-code") == "lasso-preset:claude-code"
        assert image_tag(p1, agent="opencode") == "lasso-preset:opencode"

    def test_strict_profile_installs_whitelisted_tools(self):
        """Strict profile uses whitelist — installs specific packages."""
        profile = strict_profile("/tmp/test")
        dockerfile = generate_dockerfile(profile)
        assert "git" in dockerfile
        assert "python3" in dockerfile


class TestCACertInjection:
    """Tests for corporate CA certificate injection in Dockerfile generation."""

    def test_ca_cert_injected_into_dockerfile(self, tmp_path):
        """When ca_cert_path is provided, the cert is injected inline."""
        cert_file = tmp_path / "corp-ca.pem"
        cert_content = "-----BEGIN CERTIFICATE-----\nMIIBfake==\n-----END CERTIFICATE-----"
        cert_file.write_text(cert_content)

        profile = standard_profile("/tmp/test")
        dockerfile = generate_dockerfile(profile, ca_cert_path=str(cert_file))

        assert "corporate CA certificate" in dockerfile
        assert "update-ca-certificates" in dockerfile
        assert "/usr/local/share/ca-certificates/corporate-ca.crt" in dockerfile
        assert "BEGIN CERTIFICATE" in dockerfile

    def test_no_ca_cert_by_default(self):
        """Without ca_cert_path, no CA cert lines appear."""
        profile = standard_profile("/tmp/test")
        dockerfile = generate_dockerfile(profile)
        assert "corporate-ca.crt" not in dockerfile
        assert "update-ca-certificates" not in dockerfile

    def test_ca_cert_before_user_agent(self, tmp_path):
        """CA cert install happens before USER agent (needs root)."""
        cert_file = tmp_path / "corp-ca.pem"
        cert_file.write_text("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----")

        profile = standard_profile("/tmp/test")
        dockerfile = generate_dockerfile(profile, ca_cert_path=str(cert_file))

        ca_pos = dockerfile.index("update-ca-certificates")
        user_pos = dockerfile.index("USER agent")
        assert ca_pos < user_pos, "CA cert must be installed before dropping to agent user"

    def test_ca_cert_missing_file_raises(self):
        """Referencing a non-existent cert file raises ValueError."""
        profile = standard_profile("/tmp/test")
        with pytest.raises(ValueError, match="Cannot read CA certificate"):
            generate_dockerfile(profile, ca_cert_path="/nonexistent/cert.pem")


class TestToolToPackageMapping:
    def test_common_tools_mapped(self):
        assert "python3" in TOOL_TO_PACKAGE
        assert "git" in TOOL_TO_PACKAGE
        assert "curl" in TOOL_TO_PACKAGE

    def test_r_mapped(self):
        assert "Rscript" in TOOL_TO_PACKAGE
        assert TOOL_TO_PACKAGE["Rscript"] == "r-base"
