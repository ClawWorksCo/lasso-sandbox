"""Tests for the LASSO Security Review Framework.

Covers:
- Individual security checks against built-in and intentionally insecure profiles
- Checklist generation format
- Sign-off save/load persistence
- Profile hash computation (deterministic)
- CLI integration via CliRunner
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from lasso.cli.main import app
from lasso.config.defaults import (
    BUILTIN_PROFILES,
    evaluation_profile,
    standard_profile,
    strict_profile,
)
from lasso.config.schema import (
    AuditConfig,
    CommandConfig,
    CommandMode,
    FilesystemConfig,
    GuardrailsConfig,
    NetworkConfig,
    NetworkMode,
    ResourceConfig,
    SandboxProfile,
)
from lasso.core.security_audit import (
    ReviewSignoff,
    SecurityAuditor,
    SecurityCheck,
    compute_profile_hash,
    load_signoffs,
    save_signoff,
)

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
# Test helpers -- intentionally insecure profiles
# -----------------------------------------------------------------------

def _insecure_profile(working_dir: str = "/tmp/test") -> SandboxProfile:
    """Create a deliberately insecure profile that should fail most checks."""
    return SandboxProfile(
        name="insecure-test",
        description="Intentionally insecure profile for testing.",
        filesystem=FilesystemConfig(
            working_dir=working_dir,
            hidden_paths=[],  # No sensitive paths hidden
            read_only_paths=[],  # No read-only system paths
        ),
        commands=CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=[
                "python3", "ls", "chmod", "chown", "tee",  # dangerous commands
            ],
            allow_shell_operators=True,  # shell operators enabled
        ),
        network=NetworkConfig(
            mode=NetworkMode.FULL,  # full network access
            blocked_ports=[],  # no blocked ports
        ),
        resources=ResourceConfig(
            max_memory_mb=65536,  # unrestricted
            max_cpu_percent=100,  # unrestricted
        ),
        guardrails=GuardrailsConfig(
            rules=[],  # no guardrails
        ),
        audit=AuditConfig(
            sign_entries=False,  # no audit signing
        ),
    )


def _partially_secure_profile(working_dir: str = "/tmp/test") -> SandboxProfile:
    """Create a profile that passes some checks but fails others."""
    return SandboxProfile(
        name="partial-test",
        description="Partially secure profile for testing.",
        filesystem=FilesystemConfig(
            working_dir=working_dir,
            hidden_paths=["/etc/shadow", "/root", "/etc/passwd", "/etc/sudoers", "/proc", "~/.ssh/"],
        ),
        commands=CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=["python3", "ls", "cat"],
            allow_shell_operators=True,  # fails this check
        ),
        network=NetworkConfig(
            mode=NetworkMode.RESTRICTED,
            blocked_ports=[1433, 3306, 5432, 27017, 6379],
        ),
        resources=ResourceConfig(max_memory_mb=4096, max_cpu_percent=50),
        audit=AuditConfig(sign_entries=True),
    )


# -----------------------------------------------------------------------
# SecurityCheck dataclass
# -----------------------------------------------------------------------


class TestSecurityCheck:
    """Tests for the SecurityCheck dataclass."""

    def test_create_passing_check(self):
        check = SecurityCheck(
            id="test-check",
            name="Test Check",
            description="A test check.",
            severity="high",
            passed=True,
            details="Everything is fine.",
        )
        assert check.id == "test-check"
        assert check.passed is True
        assert check.severity == "high"

    def test_create_failing_check(self):
        check = SecurityCheck(
            id="fail-check",
            name="Fail Check",
            description="A failing check.",
            severity="critical",
            passed=False,
            details="Something is wrong.",
        )
        assert check.passed is False
        assert check.severity == "critical"


# -----------------------------------------------------------------------
# Individual checks against built-in profiles
# -----------------------------------------------------------------------


class TestMinimalProfile:
    """Minimal profile should pass most security checks."""

    def setup_method(self):
        self.profile = evaluation_profile("/tmp/test")
        self.auditor = SecurityAuditor(self.profile)

    def test_no_full_network(self):
        result = self.auditor.check_no_full_network()
        assert result.passed is True
        assert result.severity == "critical"

    def test_audit_signing(self):
        result = self.auditor.check_audit_signing_enabled()
        assert result.passed is True

    def test_database_ports_blocked(self):
        result = self.auditor.check_database_ports_blocked()
        assert result.passed is True

    def test_dangerous_commands_blocked(self):
        result = self.auditor.check_dangerous_commands_blocked()
        assert result.passed is True

    def test_shell_operators_enabled(self):
        result = self.auditor.check_shell_operators_disabled()
        assert result.passed is True

    def test_resource_limits_set(self):
        result = self.auditor.check_resource_limits_set()
        assert result.passed is True

    def test_read_only_system(self):
        result = self.auditor.check_read_only_system()
        assert result.passed is True

    def test_guardrails_enabled(self):
        result = self.auditor.check_guardrails_enabled()
        assert result.passed is True

    def test_no_privileged_mode(self):
        result = self.auditor.check_capability_restrictions()
        assert result.passed is True


class TestStandardProfile:
    """Standard profile uses blocklist + shell operators ON."""

    def setup_method(self):
        self.profile = standard_profile("/tmp/test")
        self.auditor = SecurityAuditor(self.profile)

    def test_no_full_network(self):
        result = self.auditor.check_no_full_network()
        assert result.passed is True

    def test_shell_operators_on_in_standard(self):
        """Standard profile has shell operators ON (blocklist mode)."""
        result = self.auditor.check_shell_operators_disabled()
        assert result.passed is False  # correctly flags this

    def test_dangerous_commands_blocked(self):
        result = self.auditor.check_dangerous_commands_blocked()
        assert result.passed is True


class TestStrictProfile:
    """Strict profile should pass all checks."""

    def setup_method(self):
        self.profile = strict_profile("/tmp/test")
        self.auditor = SecurityAuditor(self.profile)

    def test_all_checks_pass_except_maybe_passwd(self):
        """Strict profile should pass almost all checks."""
        results = self.auditor.run_all_checks()
        critical_failures = [c for c in results if not c.passed and c.severity == "critical"]
        assert len(critical_failures) == 0, f"Critical failures: {critical_failures}"

    def test_no_full_network(self):
        result = self.auditor.check_no_full_network()
        assert result.passed is True

    def test_audit_signing(self):
        result = self.auditor.check_audit_signing_enabled()
        assert result.passed is True

    def test_shell_operators_enabled(self):
        result = self.auditor.check_shell_operators_disabled()
        assert result.passed is True


# -----------------------------------------------------------------------
# Insecure profile -- should fail most checks
# -----------------------------------------------------------------------


class TestInsecureProfile:
    """Intentionally insecure profile should fail most checks."""

    def setup_method(self):
        self.profile = _insecure_profile()
        self.auditor = SecurityAuditor(self.profile)

    def test_full_network_fails(self):
        result = self.auditor.check_no_full_network()
        assert result.passed is False
        assert result.severity == "critical"
        assert "full" in result.details.lower()

    def test_audit_signing_fails(self):
        result = self.auditor.check_audit_signing_enabled()
        assert result.passed is False
        assert result.severity == "critical"

    def test_database_ports_fails(self):
        result = self.auditor.check_database_ports_blocked()
        assert result.passed is False
        assert result.severity == "high"

    def test_dangerous_commands_fails(self):
        result = self.auditor.check_dangerous_commands_blocked()
        assert result.passed is False
        assert result.severity == "high"
        assert "chmod" in result.details or "chown" in result.details or "tee" in result.details

    def test_sensitive_paths_fails(self):
        result = self.auditor.check_filesystem_sensitive_hidden()
        assert result.passed is False
        assert result.severity == "high"

    def test_shell_operators_fails(self):
        result = self.auditor.check_shell_operators_disabled()
        assert result.passed is False
        assert result.severity == "medium"

    def test_resource_limits_fails(self):
        result = self.auditor.check_resource_limits_set()
        assert result.passed is False
        assert result.severity == "medium"

    def test_read_only_fails(self):
        result = self.auditor.check_read_only_system()
        assert result.passed is False
        assert result.severity == "medium"

    def test_guardrails_fails(self):
        result = self.auditor.check_guardrails_enabled()
        assert result.passed is False
        assert result.severity == "low"

    def test_privileged_mode_fails(self):
        result = self.auditor.check_capability_restrictions()
        assert result.passed is False
        assert result.severity == "critical"

    def test_run_all_checks_count(self):
        results = self.auditor.run_all_checks()
        assert len(results) == 10

    def test_most_checks_fail(self):
        results = self.auditor.run_all_checks()
        failed = [c for c in results if not c.passed]
        assert len(failed) >= 8, f"Expected >= 8 failures, got {len(failed)}"

    def test_summary_counts(self):
        summary = self.auditor.summary()
        assert summary["total"] == 10
        assert summary["failed"] >= 8
        assert summary["critical_failed"] >= 2


# -----------------------------------------------------------------------
# Partially secure profile
# -----------------------------------------------------------------------


class TestPartiallySecureProfile:
    """Mixed profile: passes some checks, fails others."""

    def setup_method(self):
        self.profile = _partially_secure_profile()
        self.auditor = SecurityAuditor(self.profile)

    def test_network_passes(self):
        result = self.auditor.check_no_full_network()
        assert result.passed is True

    def test_audit_signing_passes(self):
        result = self.auditor.check_audit_signing_enabled()
        assert result.passed is True

    def test_shell_operators_fails(self):
        result = self.auditor.check_shell_operators_disabled()
        assert result.passed is False

    def test_sensitive_paths_passes(self):
        result = self.auditor.check_filesystem_sensitive_hidden()
        assert result.passed is True


# -----------------------------------------------------------------------
# Checklist generation
# -----------------------------------------------------------------------


class TestChecklistGeneration:
    """Checklist output should be valid Markdown."""

    def test_checklist_has_header(self):
        profile = evaluation_profile("/tmp/test")
        auditor = SecurityAuditor(profile)
        checklist = auditor.generate_checklist()
        assert "# LASSO Security Review Checklist" in checklist
        assert "**Profile:** evaluation" in checklist

    def test_checklist_has_sections(self):
        profile = _insecure_profile()
        auditor = SecurityAuditor(profile)
        checklist = auditor.generate_checklist()
        assert "## CRITICAL" in checklist
        assert "## HIGH" in checklist
        assert "## MEDIUM" in checklist

    def test_checklist_has_pass_marks(self):
        profile = evaluation_profile("/tmp/test")
        auditor = SecurityAuditor(profile)
        checklist = auditor.generate_checklist()
        assert "- [x]" in checklist

    def test_checklist_has_fail_marks(self):
        profile = _insecure_profile()
        auditor = SecurityAuditor(profile)
        checklist = auditor.generate_checklist()
        assert "- [ ]" in checklist

    def test_checklist_has_summary(self):
        profile = evaluation_profile("/tmp/test")
        auditor = SecurityAuditor(profile)
        checklist = auditor.generate_checklist()
        assert "## Summary" in checklist
        assert "**Passed:**" in checklist

    def test_checklist_has_hash(self):
        profile = evaluation_profile("/tmp/test")
        auditor = SecurityAuditor(profile)
        checklist = auditor.generate_checklist()
        profile_hash = compute_profile_hash(profile)[:12]
        assert profile_hash in checklist


# -----------------------------------------------------------------------
# Profile hash computation
# -----------------------------------------------------------------------


class TestProfileHash:
    """Profile hash must be deterministic and stable."""

    def test_hash_is_64_hex_chars(self):
        profile = evaluation_profile("/tmp/test")
        h = compute_profile_hash(profile)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_is_deterministic(self):
        profile1 = evaluation_profile("/tmp/test")
        profile2 = evaluation_profile("/tmp/test")
        assert compute_profile_hash(profile1) == compute_profile_hash(profile2)

    def test_different_profiles_different_hashes(self):
        p1 = evaluation_profile("/tmp/test")
        p2 = standard_profile("/tmp/test")
        assert compute_profile_hash(p1) != compute_profile_hash(p2)

    def test_hash_excludes_timestamps(self):
        """Hash should be the same regardless of created_at / updated_at."""
        p1 = evaluation_profile("/tmp/test")
        p2 = evaluation_profile("/tmp/test")
        p1.created_at = "2024-01-01T00:00:00Z"
        p2.created_at = "2025-12-31T23:59:59Z"
        p1.updated_at = "2024-01-01T00:00:00Z"
        p2.updated_at = "2025-12-31T23:59:59Z"
        assert compute_profile_hash(p1) == compute_profile_hash(p2)

    def test_hash_matches_config_hash(self):
        """compute_profile_hash should produce the same result as SandboxProfile.config_hash."""
        profile = evaluation_profile("/tmp/test")
        assert compute_profile_hash(profile) == profile.config_hash()


# -----------------------------------------------------------------------
# Sign-off save/load
# -----------------------------------------------------------------------


class TestSignoffPersistence:
    """Sign-off save/load round-trip."""

    def test_save_creates_file(self, tmp_path):
        path = tmp_path / "REVIEWERS.md"
        signoff = ReviewSignoff(
            reviewer="Alice",
            date="2026-03-18",
            profile_hash="abcdef123456" * 5 + "abcd",
            version="1",
            checks_passed=10,
            checks_total=10,
            approved=True,
        )
        save_signoff(signoff, path)
        assert path.exists()
        content = path.read_text()
        assert "Alice" in content
        assert "2026-03-18" in content

    def test_save_and_load_roundtrip(self, tmp_path):
        path = tmp_path / "REVIEWERS.md"
        signoff = ReviewSignoff(
            reviewer="Bob",
            date="2026-03-18",
            profile_hash="a" * 64,
            version="1",
            checks_passed=8,
            checks_total=10,
            approved=False,
        )
        save_signoff(signoff, path)
        loaded = load_signoffs(path)
        assert len(loaded) == 1
        assert loaded[0].reviewer == "Bob"
        assert loaded[0].checks_passed == 8
        assert loaded[0].checks_total == 10
        assert loaded[0].approved is False

    def test_multiple_signoffs(self, tmp_path):
        path = tmp_path / "REVIEWERS.md"
        for i, name in enumerate(["Alice", "Bob", "Charlie"]):
            signoff = ReviewSignoff(
                reviewer=name,
                date=f"2026-03-{18 + i}",
                profile_hash="a" * 64,
                version="1",
                checks_passed=10 - i,
                checks_total=10,
                approved=(i == 0),
            )
            save_signoff(signoff, path)

        loaded = load_signoffs(path)
        assert len(loaded) == 3
        assert loaded[0].reviewer == "Alice"
        assert loaded[1].reviewer == "Bob"
        assert loaded[2].reviewer == "Charlie"

    def test_load_nonexistent_returns_empty(self, tmp_path):
        path = tmp_path / "nonexistent.md"
        assert load_signoffs(path) == []

    def test_save_creates_header(self, tmp_path):
        path = tmp_path / "REVIEWERS.md"
        signoff = ReviewSignoff(
            reviewer="Test",
            date="2026-03-18",
            profile_hash="b" * 64,
            version="1",
            checks_passed=5,
            checks_total=10,
            approved=False,
        )
        save_signoff(signoff, path)
        content = path.read_text()
        assert "# LASSO Security Review Sign-offs" in content
        assert "| Reviewer |" in content

    def test_save_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "deep" / "nested" / "REVIEWERS.md"
        signoff = ReviewSignoff(
            reviewer="Test",
            date="2026-03-18",
            profile_hash="c" * 64,
            version="1",
            checks_passed=10,
            checks_total=10,
            approved=True,
        )
        save_signoff(signoff, path)
        assert path.exists()


# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------


class TestSummary:
    """Summary method should return correct counts."""

    def test_all_pass_summary(self):
        profile = evaluation_profile("/tmp/test")
        auditor = SecurityAuditor(profile)
        summary = auditor.summary()
        assert summary["total"] == 10
        assert summary["failed"] >= 0
        assert summary["passed"] + summary["failed"] == summary["total"]

    def test_insecure_summary_severities(self):
        profile = _insecure_profile()
        auditor = SecurityAuditor(profile)
        summary = auditor.summary()
        # Should have failures at multiple severity levels
        assert summary["critical_failed"] >= 2
        assert summary["high_failed"] >= 2
        assert summary["medium_failed"] >= 2
        assert summary["low_failed"] >= 1

    def test_summary_keys(self):
        profile = evaluation_profile("/tmp/test")
        auditor = SecurityAuditor(profile)
        summary = auditor.summary()
        expected_keys = {
            "total", "passed", "failed",
            "critical_total", "critical_passed", "critical_failed",
            "high_total", "high_passed", "high_failed",
            "medium_total", "medium_passed", "medium_failed",
            "low_total", "low_passed", "low_failed",
        }
        assert set(summary.keys()) == expected_keys


# -----------------------------------------------------------------------
# CLI integration tests
# -----------------------------------------------------------------------

def _invoke(*args: str, input: str | None = None):
    """Invoke the CLI with the given arguments."""
    return runner.invoke(app, list(args), input=input)


class TestSecurityAuditCLI:
    """CLI integration for lasso check --security-audit."""

    def test_security_audit_minimal(self):
        """lasso check --security-audit --profile minimal should pass most checks."""
        result = _invoke("check", "--security-audit", "--profile", "evaluation")
        assert result.exit_code == 0
        assert "Security Audit" in result.output
        assert "PASS" in result.output

    def test_security_audit_development(self):
        """lasso check -s -p development should show some failures."""
        result = _invoke("check", "-s", "-p", "standard")
        assert result.exit_code == 0
        assert "Security Audit" in result.output
        # Development profile has shell operators enabled
        assert "FAIL" in result.output

    def test_security_audit_default_profile(self):
        """lasso check --security-audit without --profile defaults to development."""
        result = _invoke("check", "--security-audit")
        assert result.exit_code == 0
        assert "Security Audit" in result.output

    def test_security_audit_json(self):
        """lasso check --security-audit --json returns valid JSON."""
        result = _invoke("check", "--security-audit", "--profile", "evaluation", "--json")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "profile" in data
        assert "summary" in data
        assert "checks" in data
        assert isinstance(data["checks"], list)
        assert len(data["checks"]) == 10

    def test_security_audit_unknown_profile(self):
        """lasso check --security-audit --profile nonexistent should error."""
        result = _invoke("check", "--security-audit", "--profile", "nonexistent-xyz")
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_generate_checklist(self):
        """lasso check --generate-checklist should output Markdown."""
        result = _invoke("check", "--generate-checklist", "--profile", "evaluation")
        assert result.exit_code == 0
        assert "# LASSO Security Review Checklist" in result.output
        assert "- [x]" in result.output or "- [ ]" in result.output

    def test_sign_off(self, tmp_path, monkeypatch):
        """lasso check --security-audit --sign-off <name> should write REVIEWERS.md."""
        monkeypatch.chdir(tmp_path)
        result = _invoke(
            "check", "--security-audit",
            "--profile", "evaluation",
            "--sign-off", "TestReviewer",
        )
        assert result.exit_code == 0
        assert "Sign-off recorded" in result.output
        assert "TestReviewer" in result.output
        # Verify REVIEWERS.md was created
        reviewers = tmp_path / "REVIEWERS.md"
        assert reviewers.exists()
        content = reviewers.read_text()
        assert "TestReviewer" in content

    def test_security_audit_all_builtins(self):
        """All built-in profiles should be auditable without errors."""
        for name in BUILTIN_PROFILES:
            result = _invoke("check", "-s", "-p", name)
            assert result.exit_code == 0, f"Profile {name} failed: {result.output}"

    def test_check_json_still_works(self):
        """Existing lasso check --json should still work."""
        result = _invoke("check", "--json")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "platform" in data


# -----------------------------------------------------------------------
# HIGH-3: check_capability_restrictions replaces check_no_privileged_mode
# -----------------------------------------------------------------------


class TestCapabilityRestrictions:
    """Verify the renamed check_capability_restrictions works correctly."""

    def test_fails_when_all_three_conditions_met(self):
        """Full network + shell ops + unrestricted resources = privileged."""
        profile = SandboxProfile(
            name="priv-test",
            filesystem=FilesystemConfig(working_dir="/tmp/test"),
            commands=CommandConfig(allow_shell_operators=True),
            network=NetworkConfig(mode=NetworkMode.FULL),
            resources=ResourceConfig(max_cpu_percent=100, max_memory_mb=65536),
        )
        auditor = SecurityAuditor(profile)
        result = auditor.check_capability_restrictions()
        assert result.passed is False
        assert result.severity == "critical"

    def test_passes_when_network_restricted(self):
        """Restricted network alone should be enough to pass."""
        profile = SandboxProfile(
            name="net-restricted",
            filesystem=FilesystemConfig(working_dir="/tmp/test"),
            commands=CommandConfig(allow_shell_operators=True),
            network=NetworkConfig(mode=NetworkMode.RESTRICTED),
            resources=ResourceConfig(max_cpu_percent=100, max_memory_mb=65536),
        )
        auditor = SecurityAuditor(profile)
        result = auditor.check_capability_restrictions()
        assert result.passed is True

    def test_passes_when_shell_ops_disabled(self):
        """Disabled shell operators alone should be enough to pass."""
        profile = SandboxProfile(
            name="no-shell-ops",
            filesystem=FilesystemConfig(working_dir="/tmp/test"),
            commands=CommandConfig(allow_shell_operators=False),
            network=NetworkConfig(mode=NetworkMode.FULL),
            resources=ResourceConfig(max_cpu_percent=100, max_memory_mb=65536),
        )
        auditor = SecurityAuditor(profile)
        result = auditor.check_capability_restrictions()
        assert result.passed is True

    def test_passes_when_resources_limited(self):
        """Meaningful resource limits alone should be enough to pass."""
        profile = SandboxProfile(
            name="res-limited",
            filesystem=FilesystemConfig(working_dir="/tmp/test"),
            commands=CommandConfig(allow_shell_operators=True),
            network=NetworkConfig(mode=NetworkMode.FULL),
            resources=ResourceConfig(max_cpu_percent=50, max_memory_mb=4096),
        )
        auditor = SecurityAuditor(profile)
        result = auditor.check_capability_restrictions()
        assert result.passed is True

    def test_check_id_changed(self):
        """The check id should be 'capability-restrictions', not 'no-privileged-mode'."""
        profile = evaluation_profile("/tmp/test")
        auditor = SecurityAuditor(profile)
        result = auditor.check_capability_restrictions()
        assert result.id == "capability-restrictions"


# -----------------------------------------------------------------------
# HIGH-4: Full profile hash in sign-off round-trip
# -----------------------------------------------------------------------


class TestSignoffFullHash:
    """Sign-off must store and round-trip the full 64-char SHA-256 hash."""

    def test_full_hash_stored(self, tmp_path):
        """The saved file must contain the full hash, not a truncated one."""
        path = tmp_path / "REVIEWERS.md"
        full_hash = "abcdef0123456789" * 4  # 64 chars
        signoff = ReviewSignoff(
            reviewer="Auditor",
            date="2026-03-18",
            profile_hash=full_hash,
            version="1",
            checks_passed=10,
            checks_total=10,
            approved=True,
        )
        save_signoff(signoff, path)
        content = path.read_text()
        assert full_hash in content

    def test_full_hash_roundtrip(self, tmp_path):
        """Save and load should preserve the complete hash."""
        path = tmp_path / "REVIEWERS.md"
        full_hash = "f" * 64
        signoff = ReviewSignoff(
            reviewer="Reviewer",
            date="2026-03-18",
            profile_hash=full_hash,
            version="1",
            checks_passed=9,
            checks_total=10,
            approved=True,
        )
        save_signoff(signoff, path)
        loaded = load_signoffs(path)
        assert len(loaded) == 1
        assert loaded[0].profile_hash == full_hash
        assert len(loaded[0].profile_hash) == 64


# -----------------------------------------------------------------------
# MEDIUM-5: network.mode == NONE auto-passes database port check
# -----------------------------------------------------------------------


class TestDatabasePortsNetworkNone:
    """When network mode is NONE, all ports are blocked by definition."""

    def test_network_none_passes_even_with_empty_blocked_ports(self):
        profile = SandboxProfile(
            name="net-none",
            filesystem=FilesystemConfig(working_dir="/tmp/test"),
            network=NetworkConfig(
                mode=NetworkMode.NONE,
                blocked_ports=[],  # no explicit blocked ports
            ),
        )
        auditor = SecurityAuditor(profile)
        result = auditor.check_database_ports_blocked()
        assert result.passed is True
        assert "none" in result.details.lower()

    def test_network_restricted_still_checks_ports(self):
        profile = SandboxProfile(
            name="net-restricted",
            filesystem=FilesystemConfig(working_dir="/tmp/test"),
            network=NetworkConfig(
                mode=NetworkMode.RESTRICTED,
                blocked_ports=[],  # missing database ports
            ),
        )
        auditor = SecurityAuditor(profile)
        result = auditor.check_database_ports_blocked()
        assert result.passed is False

    def test_network_full_still_checks_ports(self):
        profile = SandboxProfile(
            name="net-full",
            filesystem=FilesystemConfig(working_dir="/tmp/test"),
            network=NetworkConfig(
                mode=NetworkMode.FULL,
                blocked_ports=[],  # missing database ports
            ),
        )
        auditor = SecurityAuditor(profile)
        result = auditor.check_database_ports_blocked()
        assert result.passed is False


# -----------------------------------------------------------------------
# MEDIUM-6: Malformed sign-off rows are rejected
# -----------------------------------------------------------------------


class TestSignoffMalformedRows:
    """Rows with unexpected cell counts must be silently skipped."""

    def test_row_with_too_few_cells_skipped(self, tmp_path):
        path = tmp_path / "REVIEWERS.md"
        # Write header + a valid row + a malformed row (only 3 cells)
        content = (
            "# LASSO Security Review Sign-offs\n"
            "\n"
            "| Reviewer | Date | Version | Profile Hash | Checks Passed | Approved |\n"
            "|----------|------|---------|-------------|---------------|----------|\n"
            "| Alice | 2026-03-18 | 1 | aaaa | 10/10 | Yes |\n"
            "| Bob | 2026-03-18 | only three cells |\n"
        )
        path.write_text(content, encoding="utf-8")
        loaded = load_signoffs(path)
        assert len(loaded) == 1
        assert loaded[0].reviewer == "Alice"

    def test_row_with_too_many_cells_skipped(self, tmp_path):
        path = tmp_path / "REVIEWERS.md"
        content = (
            "# LASSO Security Review Sign-offs\n"
            "\n"
            "| Reviewer | Date | Version | Profile Hash | Checks Passed | Approved |\n"
            "|----------|------|---------|-------------|---------------|----------|\n"
            "| Alice | 2026-03-18 | 1 | aaaa | 10/10 | Yes | extra | bonus |\n"
        )
        path.write_text(content, encoding="utf-8")
        loaded = load_signoffs(path)
        assert len(loaded) == 0

    def test_valid_rows_still_parsed(self, tmp_path):
        path = tmp_path / "REVIEWERS.md"
        content = (
            "# LASSO Security Review Sign-offs\n"
            "\n"
            "| Reviewer | Date | Version | Profile Hash | Checks Passed | Approved |\n"
            "|----------|------|---------|-------------|---------------|----------|\n"
            "| Alice | 2026-03-18 | 1 | aaaa | 10/10 | Yes |\n"
            "| bad row missing cells |\n"
            "| Charlie | 2026-03-19 | 2 | bbbb | 8/10 | No |\n"
        )
        path.write_text(content, encoding="utf-8")
        loaded = load_signoffs(path)
        assert len(loaded) == 2
        assert loaded[0].reviewer == "Alice"
        assert loaded[1].reviewer == "Charlie"
