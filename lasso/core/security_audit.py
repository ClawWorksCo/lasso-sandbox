"""Security audit framework -- pre-deployment review checks for sandbox profiles.

Runs a battery of security checks against a SandboxProfile configuration,
produces a human-readable Markdown checklist, and records reviewer sign-offs
for compliance audit trails (DORA, ISO 27001, EU AI Act).

Each check returns a SecurityCheck with severity (critical/high/medium/low),
pass/fail status, and human-readable details.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from lasso.config.schema import DATABASE_PORTS, NetworkMode, SandboxProfile
from lasso.core.commands import DANGEROUS_ARGS

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SecurityCheck:
    """Result of a single security check."""
    id: str
    name: str
    description: str
    severity: str  # critical, high, medium, low
    passed: bool
    details: str = ""


@dataclass
class ReviewSignoff:
    """A recorded reviewer sign-off for a profile security audit."""
    reviewer: str
    date: str
    profile_hash: str
    version: str
    checks_passed: int
    checks_total: int
    approved: bool


# ---------------------------------------------------------------------------
# Profile hash computation
# ---------------------------------------------------------------------------

def compute_profile_hash(profile: SandboxProfile) -> str:
    """Compute a deterministic SHA-256 hash of a serialized profile.

    Excludes timestamps (created_at, updated_at) so the hash is stable
    across re-serialization.  Used for tamper detection in sign-offs.
    """
    payload = profile.model_dump_json(exclude={"created_at", "updated_at"})
    return hashlib.sha256(payload.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Sign-off persistence
# ---------------------------------------------------------------------------

_REVIEWERS_HEADER = (
    "# LASSO Security Review Sign-offs\n"
    "\n"
    "Format: each review is appended below by `lasso check --sign-off`.\n"
    "\n"
    "| Reviewer | Date | Version | Profile Hash | Checks Passed | Approved |\n"
    "|----------|------|---------|-------------|---------------|----------|\n"
)


def load_signoffs(path: Path) -> list[ReviewSignoff]:
    """Load reviewer sign-offs from a REVIEWERS.md file.

    Parses the Markdown table rows after the header.  Returns an empty
    list if the file does not exist or contains no sign-off rows.
    """
    if not path.exists():
        return []

    signoffs: list[ReviewSignoff] = []
    text = path.read_text(encoding="utf-8")

    in_table = False
    for line in text.splitlines():
        stripped = line.strip()

        # Detect the header separator row (---|---|...)
        if stripped.startswith("|--") or stripped.startswith("|-"):
            in_table = True
            continue

        # Skip the header row itself (match the exact header pattern)
        if stripped.startswith("| Reviewer") and "Checks Passed" in stripped:
            continue

        if in_table and stripped.startswith("|") and stripped.endswith("|"):
            cells = [c.strip() for c in stripped.split("|")]
            # split on | produces ['', cell1, cell2, ..., '']
            cells = [c for c in cells if c != ""]

            # MEDIUM-6: Reject rows with unexpected cell count.
            # The table has exactly 6 columns: Reviewer, Date, Version,
            # Profile Hash, Checks Passed, Approved.
            if len(cells) != 6:
                continue

            approved_str = cells[5].lower()
            approved = approved_str in ("yes", "true")

            # Parse checks passed -- format "N/M"
            checks_parts = cells[4].split("/")
            checks_passed = int(checks_parts[0]) if checks_parts[0].isdigit() else 0
            checks_total = int(checks_parts[1]) if len(checks_parts) > 1 and checks_parts[1].isdigit() else 0

            signoffs.append(ReviewSignoff(
                reviewer=cells[0],
                date=cells[1],
                profile_hash=cells[3],
                version=cells[2],
                checks_passed=checks_passed,
                checks_total=checks_total,
                approved=approved,
            ))

    return signoffs


def save_signoff(signoff: ReviewSignoff, path: Path) -> None:
    """Append a reviewer sign-off to a REVIEWERS.md file.

    Creates the file with the standard header if it does not exist.
    """
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_REVIEWERS_HEADER, encoding="utf-8")

    approved_str = "Yes" if signoff.approved else "No"
    checks_str = f"{signoff.checks_passed}/{signoff.checks_total}"
    row = (
        f"| {signoff.reviewer} "
        f"| {signoff.date} "
        f"| {signoff.version} "
        f"| {signoff.profile_hash} "
        f"| {checks_str} "
        f"| {approved_str} |\n"
    )

    with open(path, "a", encoding="utf-8") as f:
        f.write(row)


# ---------------------------------------------------------------------------
# Security Auditor
# ---------------------------------------------------------------------------

# Use canonical database port list from schema (single source of truth).
_DATABASE_PORTS = DATABASE_PORTS

# Sensitive filesystem paths that should be hidden
_SENSITIVE_PATHS = [
    "/etc/shadow", "/root", "/etc/passwd",
    "/etc/sudoers", "/proc", "~/.ssh/",
]


class SecurityAuditor:
    """Runs a battery of security checks against a SandboxProfile.

    Usage::

        auditor = SecurityAuditor(profile)
        results = auditor.run_all_checks()
        print(auditor.generate_checklist())
        print(auditor.summary())
    """

    def __init__(self, profile: SandboxProfile):
        self.profile = profile
        self._checks = [
            self.check_no_full_network,
            self.check_audit_signing_enabled,
            self.check_database_ports_blocked,
            self.check_dangerous_commands_blocked,
            self.check_filesystem_sensitive_hidden,
            self.check_shell_operators_disabled,
            self.check_resource_limits_set,
            self.check_read_only_system,
            self.check_guardrails_enabled,
            self.check_capability_restrictions,
        ]

    def run_all_checks(self) -> list[SecurityCheck]:
        """Run all registered security checks and return results."""
        return [check() for check in self._checks]

    # -------------------------------------------------------------------
    # Individual checks
    # -------------------------------------------------------------------

    def check_no_full_network(self) -> SecurityCheck:
        """CRITICAL: Fails if network.mode == 'full'."""
        passed = self.profile.network.mode != NetworkMode.FULL
        details = (
            f"Network mode is '{self.profile.network.mode.value}'."
            if passed
            else "Network mode is 'full' -- unrestricted network access is a critical risk."
        )
        return SecurityCheck(
            id="no-full-network",
            name="No Full Network Access",
            description="Sandbox must not have unrestricted network access.",
            severity="critical",
            passed=passed,
            details=details,
        )

    def check_audit_signing_enabled(self) -> SecurityCheck:
        """CRITICAL: Fails if audit.sign_entries is False."""
        passed = self.profile.audit.sign_entries is True
        details = (
            "Audit entry HMAC signing is enabled."
            if passed
            else "Audit entry signing is disabled -- tamper detection unavailable."
        )
        return SecurityCheck(
            id="audit-signing-enabled",
            name="Audit Signing Enabled",
            description="Audit log entries must be HMAC-signed for tamper detection.",
            severity="critical",
            passed=passed,
            details=details,
        )

    def check_database_ports_blocked(self) -> SecurityCheck:
        """HIGH: Verifies critical database ports are in blocked_ports.

        If ``network.mode`` is ``NONE``, all ports are blocked by
        definition and this check automatically passes.
        """
        if self.profile.network.mode == NetworkMode.NONE:
            return SecurityCheck(
                id="database-ports-blocked",
                name="Database Ports Blocked",
                description="Ports 1433, 3306, 5432, 27017, 6379 must be in blocked_ports.",
                severity="high",
                passed=True,
                details="Network mode is 'none' -- all ports blocked by definition.",
            )

        blocked = set(self.profile.network.blocked_ports)
        required = set(_DATABASE_PORTS)
        missing = required - blocked
        passed = len(missing) == 0
        if passed:
            details = "All critical database ports are blocked."
        else:
            details = f"Missing blocked ports: {sorted(missing)}."
        return SecurityCheck(
            id="database-ports-blocked",
            name="Database Ports Blocked",
            description="Ports 1433, 3306, 5432, 27017, 6379 must be in blocked_ports.",
            severity="high",
            passed=passed,
            details=details,
        )

    def check_dangerous_commands_blocked(self) -> SecurityCheck:
        """HIGH: Verifies DANGEROUS_ARGS commands are not whitelisted."""
        # Commands with empty pattern list in DANGEROUS_ARGS are inherently
        # dangerous and should not appear in the whitelist.
        inherently_dangerous = {
            cmd for cmd, patterns in DANGEROUS_ARGS.items() if not patterns
        }
        whitelisted = set(self.profile.commands.whitelist)
        overlap = whitelisted & inherently_dangerous
        passed = len(overlap) == 0
        if passed:
            details = "No inherently dangerous commands are whitelisted."
        else:
            details = f"Dangerous commands in whitelist: {sorted(overlap)}."
        return SecurityCheck(
            id="dangerous-commands-blocked",
            name="Dangerous Commands Blocked",
            description="Inherently dangerous commands must not be in the whitelist.",
            severity="high",
            passed=passed,
            details=details,
        )

    def check_filesystem_sensitive_hidden(self) -> SecurityCheck:
        """HIGH: Verifies sensitive paths are in hidden_paths."""
        hidden = set(self.profile.filesystem.hidden_paths)
        required = set(_SENSITIVE_PATHS)
        missing = required - hidden
        passed = len(missing) == 0
        if passed:
            details = "All sensitive filesystem paths are hidden."
        else:
            details = f"Missing hidden paths: {sorted(missing)}."
        return SecurityCheck(
            id="filesystem-sensitive-hidden",
            name="Sensitive Paths Hidden",
            description="Sensitive paths (/etc/shadow, /root, /etc/passwd, /etc/sudoers, /proc, ~/.ssh/) must be in hidden_paths.",
            severity="high",
            passed=passed,
            details=details,
        )

    def check_shell_operators_disabled(self) -> SecurityCheck:
        """MEDIUM: Warns if allow_shell_operators is True."""
        passed = not self.profile.commands.allow_shell_operators
        details = (
            "Shell operators (pipes, redirects, subshells) are disabled."
            if passed
            else "Shell operators are enabled -- potential for command chaining exploits."
        )
        return SecurityCheck(
            id="shell-operators-disabled",
            name="Shell Operators Disabled",
            description="Shell operators should be disabled to prevent command chaining.",
            severity="medium",
            passed=passed,
            details=details,
        )

    def check_resource_limits_set(self) -> SecurityCheck:
        """MEDIUM: Verifies memory and CPU limits are reasonable."""
        mem = self.profile.resources.max_memory_mb
        cpu = self.profile.resources.max_cpu_percent
        issues = []
        if mem > 16384:
            issues.append(f"memory_mb={mem} exceeds 16 GB")
        if cpu > 90:
            issues.append(f"cpu_percent={cpu} exceeds 90%")
        passed = len(issues) == 0
        if passed:
            details = f"Resource limits: memory={mem}MB, cpu={cpu}%."
        else:
            details = f"Resource limits too permissive: {'; '.join(issues)}."
        return SecurityCheck(
            id="resource-limits-set",
            name="Resource Limits Set",
            description="Memory and CPU limits must be set to reasonable values.",
            severity="medium",
            passed=passed,
            details=details,
        )

    def check_read_only_system(self) -> SecurityCheck:
        """MEDIUM: Checks if read_only_paths include system directories."""
        read_only = set(self.profile.filesystem.read_only_paths)
        # At least /usr and /bin should be read-only on Linux
        expected = {"/usr", "/bin"}
        covered = read_only & expected
        passed = len(covered) >= 1
        if passed:
            details = f"System paths are read-only: {sorted(covered)}."
        else:
            details = "No system paths (/usr, /bin) are marked read-only."
        return SecurityCheck(
            id="read-only-system",
            name="Read-Only System Paths",
            description="System directories should be mounted read-only.",
            severity="medium",
            passed=passed,
            details=details,
        )

    def check_guardrails_enabled(self) -> SecurityCheck:
        """LOW: Checks if guardrail rules are configured."""
        rules = self.profile.guardrails.rules
        passed = len(rules) > 0
        if passed:
            details = f"{len(rules)} guardrail rule(s) configured."
        else:
            details = "No guardrail rules configured."
        return SecurityCheck(
            id="guardrails-enabled",
            name="Guardrails Configured",
            description="At least one guardrail rule should be configured.",
            severity="low",
            passed=passed,
            details=details,
        )

    def check_capability_restrictions(self) -> SecurityCheck:
        """CRITICAL: Verifies the profile implies meaningful capability restrictions.

        Since SandboxProfile does not expose a raw ``privileged`` container
        flag, this check infers privilege escalation risk from the
        combination of configuration knobs:
        - Network mode must not be FULL (unrestricted egress).
        - Shell operators must be disabled (prevents command chaining).
        - Resource limits must be meaningfully constrained (CPU < 100%
          **or** memory < 64 GB).

        A profile that violates **all three** conditions simultaneously is
        considered effectively privileged.
        """
        full_network = self.profile.network.mode == NetworkMode.FULL
        shell_ops = self.profile.commands.allow_shell_operators
        unrestricted_resources = (
            self.profile.resources.max_cpu_percent >= 100
            and self.profile.resources.max_memory_mb >= 65536
        )

        is_privileged = full_network and shell_ops and unrestricted_resources
        passed = not is_privileged

        if passed:
            restrictions: list[str] = []
            if not full_network:
                restrictions.append(f"network={self.profile.network.mode.value}")
            if not shell_ops:
                restrictions.append("shell_operators=disabled")
            if not unrestricted_resources:
                restrictions.append(
                    f"resources=limited(cpu={self.profile.resources.max_cpu_percent}%,"
                    f"mem={self.profile.resources.max_memory_mb}MB)"
                )
            details = f"Capability restrictions in place: {', '.join(restrictions)}."
        else:
            details = (
                "Profile has no meaningful capability restrictions: "
                "full network + shell operators + unrestricted resources."
            )
        return SecurityCheck(
            id="capability-restrictions",
            name="Capability Restrictions",
            description=(
                "Profile must restrict at least one of: network mode, "
                "shell operators, or resource limits."
            ),
            severity="critical",
            passed=passed,
            details=details,
        )

    # -------------------------------------------------------------------
    # Reporting
    # -------------------------------------------------------------------

    def generate_checklist(self) -> str:
        """Generate a Markdown checklist for human review."""
        results = self.run_all_checks()
        lines = [
            "# LASSO Security Review Checklist",
            "",
            f"**Profile:** {self.profile.name}",
            f"**Hash:** {compute_profile_hash(self.profile)[:12]}",
            f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
            "",
        ]

        # Group by severity
        for severity in ("critical", "high", "medium", "low"):
            checks = [c for c in results if c.severity == severity]
            if not checks:
                continue
            lines.append(f"## {severity.upper()}")
            lines.append("")
            for check in checks:
                mark = "x" if check.passed else " "
                lines.append(f"- [{mark}] **{check.name}**: {check.description}")
                if check.details:
                    lines.append(f"  - {check.details}")
            lines.append("")

        # Summary
        total = len(results)
        passed = sum(1 for c in results if c.passed)
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Passed:** {passed} / {total}")
        for severity in ("critical", "high", "medium", "low"):
            sev_failed = sum(1 for c in results if c.severity == severity and not c.passed)
            if sev_failed > 0:
                lines.append(f"- **{severity.upper()} failures:** {sev_failed}")
        lines.append("")

        return "\n".join(lines)

    def summary(self) -> dict:
        """Return counts of passed/failed checks by severity."""
        results = self.run_all_checks()
        total = len(results)
        passed = sum(1 for c in results if c.passed)
        failed = total - passed

        s: dict = {
            "total": total,
            "passed": passed,
            "failed": failed,
        }

        for severity in ("critical", "high", "medium", "low"):
            sev_checks = [c for c in results if c.severity == severity]
            s[f"{severity}_total"] = len(sev_checks)
            s[f"{severity}_passed"] = sum(1 for c in sev_checks if c.passed)
            s[f"{severity}_failed"] = sum(1 for c in sev_checks if not c.passed)

        return s
