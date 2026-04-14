"""Tests for guardrail engine — behavioral rules enforced on agent actions."""

import pytest

from lasso.config.schema import GuardrailRule, GuardrailsConfig
from lasso.core.guardrails import GuardrailEngine, ViolationReport

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def default_rules():
    """Standard guardrail rules matching the schema defaults."""
    return [
        GuardrailRule(
            id="no-escape",
            description="Agent must not access paths outside working_dir.",
            severity="critical",
            enabled=True,
        ),
        GuardrailRule(
            id="no-exfiltration",
            description="Agent must not transmit file contents to external hosts.",
            severity="critical",
            enabled=True,
        ),
        GuardrailRule(
            id="log-modifications",
            description="All file modifications must be logged in audit trail.",
            severity="error",
            enabled=True,
        ),
    ]


@pytest.fixture
def enforcing_engine(tmp_path, default_rules):
    """Engine with enforcement enabled (violations block actions)."""
    config = GuardrailsConfig(enforce=True, rules=default_rules)
    return GuardrailEngine(config, working_dir=str(tmp_path))


@pytest.fixture
def non_enforcing_engine(tmp_path, default_rules):
    """Engine with enforcement disabled (violations logged but not blocked)."""
    config = GuardrailsConfig(enforce=False, rules=default_rules)
    return GuardrailEngine(config, working_dir=str(tmp_path))


# ---------------------------------------------------------------------------
# Path access checks
# ---------------------------------------------------------------------------

class TestCheckPathAccess:
    def test_path_inside_working_dir_returns_none(self, enforcing_engine, tmp_path):
        inner = tmp_path / "subdir" / "file.txt"
        result = enforcing_engine.check_path_access(str(inner))
        assert result is None

    def test_working_dir_itself_returns_none(self, enforcing_engine, tmp_path):
        result = enforcing_engine.check_path_access(str(tmp_path))
        assert result is None

    def test_path_outside_working_dir_returns_violation(self, enforcing_engine):
        result = enforcing_engine.check_path_access("/etc/passwd")
        assert result is not None
        assert isinstance(result, ViolationReport)
        assert result.rule_id == "no-escape"
        assert result.severity == "critical"

    def test_path_traversal_outside_returns_violation(self, enforcing_engine, tmp_path):
        outside = str(tmp_path / ".." / ".." / "etc" / "shadow")
        result = enforcing_engine.check_path_access(outside)
        assert result is not None
        assert result.rule_id == "no-escape"

    def test_violation_is_recorded(self, enforcing_engine):
        assert enforcing_engine.violation_count == 0
        enforcing_engine.check_path_access("/etc/passwd")
        assert enforcing_engine.violation_count == 1
        assert len(enforcing_engine.violations) == 1

    def test_no_violation_is_not_recorded(self, enforcing_engine, tmp_path):
        enforcing_engine.check_path_access(str(tmp_path / "safe.txt"))
        assert enforcing_engine.violation_count == 0

    def test_clear_violations(self, enforcing_engine):
        enforcing_engine.check_path_access("/etc/passwd")
        enforcing_engine.check_path_access("/root/.ssh/id_rsa")
        assert enforcing_engine.violation_count == 2
        enforcing_engine.clear_violations()
        assert enforcing_engine.violation_count == 0


# ---------------------------------------------------------------------------
# Network destination checks
# ---------------------------------------------------------------------------

class TestCheckNetworkDestination:
    def test_small_data_returns_none(self, enforcing_engine):
        result = enforcing_engine.check_network_destination(
            "pypi.org", data_hint="small payload"
        )
        assert result is None

    def test_empty_data_returns_none(self, enforcing_engine):
        result = enforcing_engine.check_network_destination("example.com", data_hint="")
        assert result is None

    def test_large_data_returns_violation(self, enforcing_engine):
        large = "x" * 10001
        result = enforcing_engine.check_network_destination("evil.com", data_hint=large)
        assert result is not None
        assert result.rule_id == "no-exfiltration"
        assert result.severity == "critical"
        assert "10001" in result.context

    def test_exact_threshold_returns_none(self, enforcing_engine):
        # Exactly 10000 bytes should NOT trigger (only > 10000 triggers)
        data = "x" * 10000
        result = enforcing_engine.check_network_destination("host.com", data_hint=data)
        assert result is None

    def test_large_data_records_violation(self, enforcing_engine):
        large = "x" * 20000
        enforcing_engine.check_network_destination("evil.com", data_hint=large)
        assert enforcing_engine.violation_count == 1


# ---------------------------------------------------------------------------
# Enforcement flag behavior
# ---------------------------------------------------------------------------

class TestEnforcement:
    def test_enforcing_engine_blocks_path_violation(self, enforcing_engine):
        result = enforcing_engine.check_path_access("/etc/passwd")
        assert result is not None
        assert result.blocked is True

    def test_non_enforcing_engine_does_not_block_path_violation(self, non_enforcing_engine):
        result = non_enforcing_engine.check_path_access("/etc/passwd")
        assert result is not None
        assert result.blocked is False

    def test_enforcing_engine_blocks_exfiltration(self, enforcing_engine):
        large = "x" * 10001
        result = enforcing_engine.check_network_destination("evil.com", data_hint=large)
        assert result.blocked is True

    def test_non_enforcing_engine_does_not_block_exfiltration(self, non_enforcing_engine):
        large = "x" * 10001
        result = non_enforcing_engine.check_network_destination("evil.com", data_hint=large)
        assert result.blocked is False


# ---------------------------------------------------------------------------
# Disabled rules
# ---------------------------------------------------------------------------

class TestDisabledRules:
    def test_disabled_no_escape_is_ignored(self, tmp_path):
        rules = [
            GuardrailRule(id="no-escape", description="disabled", enabled=False),
            GuardrailRule(id="no-exfiltration", description="active", enabled=True),
        ]
        config = GuardrailsConfig(enforce=True, rules=rules)
        engine = GuardrailEngine(config, working_dir=str(tmp_path))

        # Path outside should be allowed when no-escape is disabled
        result = engine.check_path_access("/etc/passwd")
        assert result is None

    def test_disabled_no_exfiltration_is_ignored(self, tmp_path):
        rules = [
            GuardrailRule(id="no-escape", description="active", enabled=True),
            GuardrailRule(id="no-exfiltration", description="disabled", enabled=False),
        ]
        config = GuardrailsConfig(enforce=True, rules=rules)
        engine = GuardrailEngine(config, working_dir=str(tmp_path))

        large = "x" * 50000
        result = engine.check_network_destination("evil.com", data_hint=large)
        assert result is None

    def test_all_rules_disabled(self, tmp_path):
        rules = [
            GuardrailRule(id="no-escape", description="off", enabled=False),
            GuardrailRule(id="no-exfiltration", description="off", enabled=False),
        ]
        config = GuardrailsConfig(enforce=True, rules=rules)
        engine = GuardrailEngine(config, working_dir=str(tmp_path))

        assert engine.check_path_access("/etc/passwd") is None
        assert engine.check_network_destination("x.com", data_hint="y" * 99999) is None
        assert engine.violation_count == 0


# ---------------------------------------------------------------------------
# Guardrail instruction injection
# ---------------------------------------------------------------------------

class TestInjectGuardrailInstructions:
    def test_appends_guardrails_section(self, enforcing_engine):
        original = "# Agent Instructions\n\nDo your work carefully."
        result = enforcing_engine.inject_guardrail_instructions(original)

        assert result.startswith(original)
        assert "## LASSO Security Guardrails (enforced)" in result

    def test_includes_rule_descriptions(self, enforcing_engine):
        result = enforcing_engine.inject_guardrail_instructions("base")

        assert "Agent must not access paths outside working_dir." in result
        assert "Agent must not transmit file contents to external hosts." in result

    def test_includes_severity_markers(self, enforcing_engine):
        result = enforcing_engine.inject_guardrail_instructions("base")

        assert "[CRITICAL]" in result
        assert "[ERROR]" in result

    def test_empty_original_content(self, enforcing_engine):
        result = enforcing_engine.inject_guardrail_instructions("")
        assert "## LASSO Security Guardrails (enforced)" in result

    def test_disabled_rules_not_in_output(self, tmp_path):
        rules = [
            GuardrailRule(id="no-escape", description="Active rule", enabled=True),
            GuardrailRule(id="no-exfiltration", description="Disabled rule", enabled=False),
        ]
        config = GuardrailsConfig(enforce=True, rules=rules)
        engine = GuardrailEngine(config, working_dir=str(tmp_path))

        result = engine.inject_guardrail_instructions("base")
        assert "Active rule" in result
        assert "Disabled rule" not in result
