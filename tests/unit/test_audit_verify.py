"""Tests for audit log verification."""

import json

import pytest

from lasso.config.defaults import evaluation_profile
from lasso.core.audit_verify import read_audit_entries, verify_audit_log
from lasso.core.sandbox import Sandbox


@pytest.fixture
def sandbox_with_audit(tmp_path):
    """Create a sandbox that generates an audit log."""
    profile = evaluation_profile(str(tmp_path), name="verify-test")
    profile.audit.log_dir = str(tmp_path / "audit")

    with Sandbox(profile) as sb:
        sb.exec("ls")
        sb.exec("cat file.txt")
        sb.exec("rm evil")  # blocked
        sb.exec("echo hello")
        yield sb, tmp_path / "audit"


class TestAuditVerification:
    def test_valid_log_passes(self, sandbox_with_audit):
        sb, audit_dir = sandbox_with_audit
        log_file = sb.audit.log_file

        result = verify_audit_log(log_file)
        assert result.valid
        assert result.total_entries > 0
        assert result.verified_entries == result.total_entries
        assert result.first_break_at is None
        assert len(result.errors) == 0

    def test_tampered_log_fails(self, sandbox_with_audit):
        sb, audit_dir = sandbox_with_audit
        log_file = sb.audit.log_file

        # Tamper with the log
        lines = log_file.read_text().strip().split("\n")
        if len(lines) > 2:
            entry = json.loads(lines[2])
            entry["action"] = "TAMPERED"
            lines[2] = json.dumps(entry, separators=(",", ":"), sort_keys=True)
            log_file.write_text("\n".join(lines) + "\n")

            result = verify_audit_log(log_file)
            assert not result.valid
            assert len(result.errors) > 0

    def test_missing_key_fails(self, sandbox_with_audit):
        sb, audit_dir = sandbox_with_audit
        log_file = sb.audit.log_file

        result = verify_audit_log(log_file, key_path="/nonexistent/key")
        assert not result.valid
        assert "not found" in result.errors[0].lower()

    def test_missing_log_fails(self):
        result = verify_audit_log("/nonexistent/audit.jsonl")
        assert not result.valid
        assert "not found" in result.errors[0].lower()


class TestReadAuditEntries:
    def test_read_all_entries(self, sandbox_with_audit):
        sb, audit_dir = sandbox_with_audit
        entries = read_audit_entries(sb.audit.log_file)
        assert len(entries) > 0

    def test_tail_entries(self, sandbox_with_audit):
        sb, audit_dir = sandbox_with_audit
        entries = read_audit_entries(sb.audit.log_file, tail=2)
        assert len(entries) <= 2

    def test_filter_by_type(self, sandbox_with_audit):
        sb, audit_dir = sandbox_with_audit
        commands = read_audit_entries(sb.audit.log_file, event_type="command")
        for e in commands:
            assert e["type"] == "command"

    def test_filter_blocked(self, sandbox_with_audit):
        sb, audit_dir = sandbox_with_audit
        all_entries = read_audit_entries(sb.audit.log_file)
        blocked = [e for e in all_entries if e.get("outcome") == "blocked"]
        assert len(blocked) >= 1  # rm was blocked

    def test_missing_file_returns_empty(self):
        entries = read_audit_entries("/nonexistent.jsonl")
        assert entries == []
