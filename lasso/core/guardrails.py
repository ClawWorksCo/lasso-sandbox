"""Guardrails — enforce behavioral rules on agent instructions and actions.

Manages agent.md files, validates them against guardrail rules, and
provides runtime checks for guardrail violations.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from lasso.config.schema import GuardrailRule, GuardrailsConfig


@dataclass
class ViolationReport:
    """A guardrail violation detected at runtime."""
    rule_id: str
    severity: str
    description: str
    context: str  # what triggered the violation
    blocked: bool  # was the action blocked?


class GuardrailEngine:
    """Runtime guardrail enforcement."""

    def __init__(self, config: GuardrailsConfig, working_dir: str):
        self.config = config
        self.working_dir = Path(working_dir).resolve()
        self._rules: dict[str, GuardrailRule] = {
            r.id: r for r in config.rules if r.enabled
        }
        self._violations: list[ViolationReport] = []

    def check_path_access(self, path: str) -> ViolationReport | None:
        """Check if accessing a path violates the no-escape guardrail."""
        rule = self._rules.get("no-escape")
        if not rule:
            return None

        resolved = Path(path).resolve()
        try:
            resolved.relative_to(self.working_dir)
            return None  # within working dir
        except ValueError:
            v = ViolationReport(
                rule_id="no-escape",
                severity=rule.severity,
                description=rule.description,
                context=f"Attempted access to {path} (outside {self.working_dir})",
                blocked=self.config.enforce,
            )
            self._violations.append(v)
            return v

    def check_network_destination(self, host: str, data_hint: str = "") -> ViolationReport | None:
        """Check if a network request might be exfiltrating data."""
        rule = self._rules.get("no-exfiltration")
        if not rule:
            return None

        # Naive heuristic: flags a single large payload. This is easily
        # bypassed by splitting data across multiple smaller requests.
        # A production deployment should layer this with cumulative
        # output tracking and/or network-level egress monitoring.
        if len(data_hint) > 10000:
            v = ViolationReport(
                rule_id="no-exfiltration",
                severity=rule.severity,
                description=rule.description,
                context=f"Large data payload ({len(data_hint)} bytes) to {host}",
                blocked=self.config.enforce,
            )
            self._violations.append(v)
            return v

        return None

    def get_agent_instructions(self) -> str | None:
        """Load the agent.md file if configured."""
        if not self.config.agent_md_path:
            return None
        if ".." in str(self.config.agent_md_path):
            return ""
        path = Path(self.config.agent_md_path)
        if path.exists():
            return path.read_text()
        return None

    def inject_guardrail_instructions(self, agent_md_content: str) -> str:
        """Append guardrail rules to agent instructions."""
        rules_section = "\n\n## LASSO Security Guardrails (enforced)\n\n"
        rules_section += "The following rules are enforced by the LASSO sandbox. "
        rules_section += "Violations will be logged and may block your actions.\n\n"

        for rule in self._rules.values():
            severity_marker = {
                "critical": "CRITICAL",
                "error": "ERROR",
                "warning": "WARN",
                "info": "INFO",
            }.get(rule.severity, "INFO")
            rules_section += f"- [{severity_marker}] {rule.description}\n"

        return agent_md_content + rules_section

    @property
    def violations(self) -> list[ViolationReport]:
        return list(self._violations)

    @property
    def violation_count(self) -> int:
        return len(self._violations)

    def clear_violations(self) -> None:
        self._violations.clear()
