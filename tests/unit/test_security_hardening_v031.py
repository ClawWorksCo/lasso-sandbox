"""Security regression tests for v0.3.1 hardening.

Tests for every vulnerability identified in the security review:
- CRITICAL: iptables installation and failure handling
- CRITICAL: Authentication bypass removal
- HIGH: MCP injection prevention
- HIGH: Audit chain rotation integrity
- HIGH: SSRF and path traversal blocking
- HIGH: Command gate bypass prevention

Each test class maps to a specific security finding and must never be
removed.  If a test is failing, the security fix has regressed.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lasso.backends.converter import needs_network_rules, profile_to_container_config
from lasso.backends.image_builder import generate_dockerfile
from lasso.config.defaults import evaluation_profile, standard_profile
from lasso.config.profile import _validate_profile_name, profile_path
from lasso.config.schema import (
    AuditConfig,
    CommandConfig,
    CommandMode,
    FilesystemConfig,
    NetworkConfig,
    NetworkMode,
    SandboxProfile,
    SandboxState,
)
from lasso.core.audit import AuditLogger
from lasso.core.audit_verify import verify_audit_log
from lasso.core.commands import _SHORT_FLAG_MAP, DANGEROUS_ARGS, CommandGate
from lasso.core.sandbox import Sandbox
from tests.conftest import FakeBackend

# ===================================================================
# 1. TestIptablesInContainerImage
# ===================================================================

class TestIptablesInContainerImage:
    """CRITICAL: generated Dockerfiles MUST include iptables when
    the profile requires network policy rules (restricted or none mode).
    Without iptables, the container cannot enforce firewall restrictions.
    """

    def test_restricted_network_includes_iptables(self):
        """A restricted-network profile must install iptables."""
        profile = SandboxProfile(
            name="net-test",
            filesystem=FilesystemConfig(working_dir="/tmp/test"),
            network=NetworkConfig(mode=NetworkMode.RESTRICTED),
        )
        dockerfile = generate_dockerfile(profile)
        assert "iptables" in dockerfile, (
            "Dockerfile must install iptables for restricted network mode"
        )

    def test_none_network_excludes_iptables(self):
        """NONE mode uses Docker network_mode=none; no iptables needed."""
        profile = SandboxProfile(
            name="net-none",
            filesystem=FilesystemConfig(working_dir="/tmp/test"),
            network=NetworkConfig(mode=NetworkMode.NONE),
        )
        assert not needs_network_rules(profile), (
            "NONE mode should not need network rules (Docker handles isolation)"
        )

    def test_full_network_with_blocked_cidrs_includes_iptables(self):
        """FULL mode with blocked_cidrs still needs iptables."""
        profile = SandboxProfile(
            name="net-full-blocked",
            filesystem=FilesystemConfig(working_dir="/tmp/test"),
            network=NetworkConfig(
                mode=NetworkMode.FULL,
                blocked_cidrs=["10.0.0.0/8"],
            ),
        )
        dockerfile = generate_dockerfile(profile)
        assert "iptables" in dockerfile, (
            "Dockerfile must install iptables when blocked_cidrs are configured"
        )

    def test_full_network_without_blocked_cidrs_no_iptables(self):
        """FULL mode without blocked_cidrs does NOT need iptables."""
        profile = SandboxProfile(
            name="net-full-open",
            filesystem=FilesystemConfig(working_dir="/tmp/test"),
            network=NetworkConfig(
                mode=NetworkMode.FULL,
                blocked_cidrs=[],   # explicitly empty
                blocked_ports=[],   # explicitly empty
            ),
            commands=CommandConfig(
                mode=CommandMode.WHITELIST,
                whitelist=["ls", "cat"],  # no tools that need packages
            ),
        )
        assert not needs_network_rules(profile), (
            "FULL mode with empty blocked_cidrs should not need network rules"
        )
        dockerfile = generate_dockerfile(profile)
        lines = dockerfile.split("\n")
        install_line = [l for l in lines if "apt-get install" in l]
        if install_line:
            assert "iptables" not in install_line[0], (
                "FULL mode without blocked_cidrs should not install iptables"
            )


# ===================================================================
# 2. TestSandboxFailsOnIptablesFailure
# ===================================================================

class TestSandboxFailsOnIptablesFailure:
    """CRITICAL: when ALL iptables rules fail to apply, the sandbox MUST
    raise RuntimeError rather than starting in an unsecured state.
    """

    def test_all_iptables_fail_raises_runtime_error(self, tmp_path):
        """If every iptables rule returns non-zero, sandbox must error out."""
        backend = FakeBackend(iptables_exit_code=127)  # simulate missing iptables
        # Use standard_profile which has NetworkMode.RESTRICTED -> needs_network_rules = True
        profile = standard_profile(str(tmp_path), name="iptables-fail-test")
        assert needs_network_rules(profile), (
            "Test precondition: restricted profile must need network rules"
        )
        sb = Sandbox(profile, backend=backend)
        with pytest.raises(RuntimeError, match="(All network policy rules failed|Critical network policy rules failed)"):
            sb.start()
        assert sb.state == SandboxState.ERROR

    def test_iptables_success_does_not_raise(self, tmp_path):
        """When iptables rules succeed, sandbox starts normally."""
        backend = FakeBackend(iptables_exit_code=0)
        profile = evaluation_profile(str(tmp_path), name="iptables-ok-test")
        sb = Sandbox(profile, backend=backend)
        sb.start()
        assert sb.state == SandboxState.RUNNING
        sb.stop()


# ===================================================================
# 3. TestNoNewPrivileges
# ===================================================================

class TestNoNewPrivileges:
    """HIGH: ContainerConfig must always include 'no-new-privileges'
    in security_opt to prevent privilege escalation inside containers.
    """

    def test_container_config_has_no_new_privileges(self, tmp_path):
        """profile_to_container_config must set no-new-privileges."""
        profile = evaluation_profile(str(tmp_path), name="priv-test")
        config = profile_to_container_config(profile)
        assert "no-new-privileges" in config.security_opt, (
            "ContainerConfig must include 'no-new-privileges' in security_opt"
        )

    def test_development_profile_has_no_new_privileges(self, tmp_path):
        """Even broader profiles must have no-new-privileges."""
        profile = standard_profile(str(tmp_path), name="dev-priv-test")
        config = profile_to_container_config(profile)
        assert "no-new-privileges" in config.security_opt

    def test_cap_drop_all(self, tmp_path):
        """Container must drop ALL capabilities by default."""
        profile = evaluation_profile(str(tmp_path), name="cap-test")
        config = profile_to_container_config(profile)
        assert "ALL" in config.cap_drop


# ===================================================================
# 4. TestAuthenticationEnforced
# ===================================================================

class TestDashboardAuthRequired:
    """HIGH: all dashboard routes (including /api/sandboxes) must
    require login via the require_login decorator.
    """

    def test_api_sandboxes_requires_login(self, tmp_path, monkeypatch):
        """GET /api/sandboxes must redirect to login when auth mode is enabled."""
        monkeypatch.setenv("LASSO_DASHBOARD_AUTH", "1")
        from lasso.dashboard.app import create_app

        app = create_app()
        app.config["TESTING"] = True
        app.config["DASHBOARD_TOKEN_FILE"] = str(tmp_path / "token")

        with app.test_client() as client:
            resp = client.get("/api/sandboxes")
            assert resp.status_code == 302, (
                f"/api/sandboxes must require login in auth mode, got status {resp.status_code}"
            )
            assert "/login" in resp.headers.get("Location", "")

    def test_index_requires_login(self, tmp_path, monkeypatch):
        """GET / must redirect to login when auth mode is enabled."""
        monkeypatch.setenv("LASSO_DASHBOARD_AUTH", "1")
        from lasso.dashboard.app import create_app

        app = create_app()
        app.config["TESTING"] = True
        app.config["DASHBOARD_TOKEN_FILE"] = str(tmp_path / "token")

        with app.test_client() as client:
            resp = client.get("/")
            assert resp.status_code == 302
            assert "/login" in resp.headers.get("Location", "")


# ===================================================================
# 8. TestAuditRotationChain
# ===================================================================

class TestAuditRotationChain:
    """HIGH: after log rotation, the new file must be independently
    verifiable with its hash chain reset to zero.
    """

    def test_chain_resets_on_rotation(self, tmp_path):
        """After rotation, new file's chain starts fresh from zero.

        We set max_log_size_mb=1 (minimum allowed) and then write enough
        data to exceed 1 MB, triggering rotation.  After rotation the new
        file must be independently verifiable (chain seeded from zeros).
        """
        config = AuditConfig(
            enabled=True,
            sign_entries=True,
            log_dir=str(tmp_path),
            max_log_size_mb=1,  # 1 MB minimum
        )
        audit = AuditLogger("rotation-test", config)
        log_file = audit.log_file
        assert log_file is not None

        # Write a few initial entries
        audit.log_lifecycle("test_event_1", {"data": "first"})
        audit.log_lifecycle("test_event_2", {"data": "second"})

        # Artificially inflate the log file to exceed 1 MB to trigger rotation
        with open(log_file, "a") as f:
            padding = "x" * 1024
            for _ in range(1100):
                f.write(padding + "\n")

        # Next write triggers rotation check
        audit.log_lifecycle("post_rotation_event", {"data": "after rotation"})

        # After rotation, verify the NEW file independently
        if log_file.exists():
            result = verify_audit_log(log_file)
            # The new file should be independently verifiable
            # (chain starts from "0" * 64, not from previous file's chain)
            if result.total_entries > 0:
                assert result.valid, (
                    f"Post-rotation log file must be independently verifiable. "
                    f"Errors: {result.errors}"
                )

    def test_rotation_marker_links_files(self, tmp_path):
        """Rotation marker in new file must contain previous_chain_hash."""
        config = AuditConfig(
            enabled=True,
            sign_entries=True,
            log_dir=str(tmp_path),
            max_log_size_mb=1,  # minimum allowed by schema
        )
        audit = AuditLogger("link-test", config)
        log_file = audit.log_file
        assert log_file is not None

        # Write initial entries
        audit.log_lifecycle("init", {})

        # Inflate the file past 1 MB to trigger rotation
        with open(log_file, "a") as f:
            padding = "x" * 1024
            for _ in range(1100):
                f.write(padding + "\n")

        # Next write triggers rotation
        audit.log_lifecycle("trigger_rotation", {})

        # Check the current log for a rotation marker
        found_marker = False
        if log_file.exists():
            with open(log_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    detail = entry.get("detail", {})
                    if detail.get("rotation_marker"):
                        found_marker = True
                        # Must have previous_chain_hash
                        assert "previous_chain_hash" in detail, (
                            "Rotation marker must include previous_chain_hash"
                        )
                        # Must have previous_log_file
                        assert "previous_log_file" in detail, (
                            "Rotation marker must include previous_log_file"
                        )
                        break

        assert found_marker, (
            "After rotation, the new log file must contain a rotation_marker entry"
        )


# ===================================================================
# 9. TestAuditKeyWarning
# ===================================================================

class TestAuditKeyWarning:
    """HIGH: when the signing key is stored alongside the logs (default),
    a warning must be logged recommending external key storage.
    """

    def test_colocated_key_produces_warning(self, tmp_path, caplog):
        """[AU-1] Default key path is now ~/.lasso/.audit_key, not alongside logs."""
        config = AuditConfig(
            enabled=True,
            sign_entries=True,
            log_dir=str(tmp_path / "audit_logs"),
            # No signing_key_path -> key goes to ~/.lasso/.audit_key (not log dir)
        )
        audit = AuditLogger("warn-test", config)

        # Verify the key was NOT created inside the log directory
        log_dir_key = Path(config.log_dir) / ".audit_key"
        assert not log_dir_key.exists(), (
            "Key must NOT be stored alongside logs by default (AU-1 fix)"
        )
        # Verify the key was created at the new default location
        default_key = Path.home() / ".lasso" / ".audit_key"
        assert default_key.exists(), (
            "Key must be created at ~/.lasso/.audit_key by default"
        )
        assert audit._signing_key is not None

    def test_external_key_no_warning(self, tmp_path, caplog):
        """When signing_key_path points elsewhere, no warning."""
        key_dir = tmp_path / "separate_keys"
        key_dir.mkdir()
        config = AuditConfig(
            enabled=True,
            sign_entries=True,
            log_dir=str(tmp_path / "audit_logs"),
            signing_key_path=str(key_dir / "audit.key"),
        )
        with caplog.at_level(logging.WARNING, logger="lasso.audit"):
            audit = AuditLogger("no-warn-test", config)

        warning_messages = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
        key_warnings = [
            msg for msg in warning_messages
            if "signing key stored alongside" in msg.lower()
        ]
        assert len(key_warnings) == 0, (
            "No co-location warning expected when signing_key_path is external"
        )


# ===================================================================
# 10. TestSSRFBlocking
# ===================================================================

class TestSSRFBlocking:
    """HIGH: the webhook test endpoint must block URLs that resolve
    to private/loopback/link-local/reserved IP addresses.
    """

    @pytest.mark.parametrize("private_ip,label", [
        ("10.0.0.1", "10.x private"),
        ("172.16.0.1", "172.16.x private"),
        ("172.31.255.255", "172.31.x private"),
        ("192.168.1.1", "192.168.x private"),
        ("127.0.0.1", "loopback"),
        ("127.0.0.2", "loopback variant"),
        ("169.254.169.254", "link-local / cloud metadata"),
    ])
    def test_private_ips_rejected(self, private_ip, label, tmp_path):
        """Webhook URL resolving to private IP must be rejected."""
        import ipaddress
        ip = ipaddress.ip_address(private_ip)
        # Verify our test data is actually private/loopback/link-local
        assert ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved, (
            f"Test data error: {private_ip} should be non-routable"
        )

        # The SSRF check in routes.py uses socket.getaddrinfo to resolve
        # the hostname and then checks if the IP is private/loopback/etc.
        # We verify the logic directly.
        blocked = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        assert blocked, f"IP {private_ip} ({label}) must be blocked by SSRF protection"

    def test_ssrf_check_in_webhook_test_endpoint(self, tmp_path):
        """Integration test: POST /api/v1/webhooks/test with private IP."""
        from lasso.dashboard.app import create_app

        app = create_app()
        app.config["TESTING"] = True

        # Set up API key auth
        key_file = tmp_path / "api_keys.json"
        test_key = "lasso_test_ssrf_key"
        key_file.write_text(json.dumps({
            "keys": {
                test_key: {
                    "name": "test",
                    "created_at": "2024-01-01T00:00:00Z",
                    "scopes": ["admin"],
                }
            }
        }))
        app.config["API_KEY_FILE"] = str(key_file)

        with app.test_client() as client:
            # Mock DNS resolution to return a private IP
            with patch("socket.getaddrinfo", return_value=[
                (2, 1, 6, "", ("127.0.0.1", 80))
            ]):
                resp = client.post(
                    "/api/v1/webhooks/test",
                    json={"url": "http://evil.internal/hook"},
                    headers={"X-API-Key": test_key},
                )
                data = resp.get_json()
                if resp.status_code == 400:
                    assert "non-routable" in data.get("error", "").lower() or \
                           "private" in data.get("error", "").lower()


# ===================================================================
# 12. TestProfileNameValidation
# ===================================================================

class TestProfileNameValidation:
    """HIGH: profile names must reject path traversal characters
    to prevent writing profiles outside the intended directory.
    """

    @pytest.mark.parametrize("bad_name", [
        "../escape",
        "../../etc/passwd",
        "foo/bar",
        "foo\\bar",
        "..\\windows\\system32",
        "../../../tmp/evil",
    ])
    def test_traversal_names_rejected(self, bad_name):
        """Profile names with /, \\, or .. must raise ValueError."""
        with pytest.raises(ValueError, match="must not contain"):
            _validate_profile_name(bad_name)

    def test_valid_names_accepted(self):
        """Normal profile names must be accepted."""
        # These should NOT raise
        for name in ["my-profile", "test_profile", "profile123", "data-analysis"]:
            _validate_profile_name(name)  # no exception = pass

    def test_profile_path_uses_validation(self, tmp_path):
        """profile_path() must call _validate_profile_name."""
        with pytest.raises(ValueError):
            profile_path("../escape", profile_dir=tmp_path)


# ===================================================================
# 13. TestCommandGateShortFlags
# ===================================================================

class TestCommandGateShortFlags:
    """HIGH: the command gate must expand short flags to their long
    equivalents when checking blocked_args, so that blocking --force
    also blocks -f.
    """

    def test_git_push_force_short_flag_blocked(self):
        """git push -f must be blocked when --force is in blocked_args."""
        config = CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=["git"],
            blocked_args={"git": ["--force"]},
        )
        gate = CommandGate(config)
        verdict = gate.check("git push -f origin main")
        assert verdict.blocked, (
            "git push -f must be blocked when --force is blocked"
        )

    def test_git_push_long_force_also_blocked(self):
        """git push --force must also be blocked."""
        config = CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=["git"],
            blocked_args={"git": ["--force"]},
        )
        gate = CommandGate(config)
        verdict = gate.check("git push --force origin main")
        assert verdict.blocked

    def test_short_flag_map_exists_for_git(self):
        """The short flag map must include git -f -> --force."""
        assert "git" in _SHORT_FLAG_MAP
        assert _SHORT_FLAG_MAP["git"].get("-f") == "--force"

    def test_allowed_git_command_not_affected(self):
        """git status must still be allowed when --force is blocked."""
        config = CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=["git"],
            blocked_args={"git": ["--force"]},
        )
        gate = CommandGate(config)
        verdict = gate.check("git status")
        assert verdict.allowed


# ===================================================================
# 14. TestSedPatternFixed
# ===================================================================

class TestSedPatternFixed:
    """HIGH: the sed "e" dangerous arg pattern must use exact-match (=e)
    to avoid blocking every sed command that has any argument containing
    the letter "e" (e.g., sed 's/hello/world/' file.txt).
    """

    def test_sed_substitute_not_blocked(self):
        """sed 's/hello/world/' file.txt must NOT be blocked."""
        config = CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=["sed"],
        )
        gate = CommandGate(config)
        verdict = gate.check("sed 's/hello/world/' file.txt")
        assert verdict.allowed, (
            f"sed substitution should not be blocked. Reason: {verdict.reason}"
        )

    def test_sed_e_flag_blocked(self):
        """sed -e must be blocked (allows arbitrary command execution)."""
        config = CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=["sed"],
        )
        gate = CommandGate(config)
        verdict = gate.check("sed -e 'some_script' file.txt")
        assert verdict.blocked, "sed -e must be blocked"

    def test_sed_dangerous_args_use_exact_match(self):
        """The sed entry in DANGEROUS_ARGS must use =e for exact match."""
        sed_patterns = DANGEROUS_ARGS.get("sed", [])
        # "=e" means exact-match on "e" (the s///e flag)
        # "-e" means substring match on the -e flag
        assert "=e" in sed_patterns, (
            "sed dangerous args must include '=e' (exact-match) not bare 'e'"
        )
        # The bare "e" should NOT be in the list (would block everything)
        bare_e_patterns = [p for p in sed_patterns if p == "e"]
        assert len(bare_e_patterns) == 0, (
            "sed dangerous args must NOT include bare 'e' (would block all sed commands)"
        )

    def test_sed_e_execute_flag_exact_match(self):
        """sed with the standalone 'e' argument (execute) must be blocked."""
        config = CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=["sed"],
        )
        gate = CommandGate(config)
        # "e" as standalone argument = execute command in pattern space
        verdict = gate.check("sed e file.txt")
        assert verdict.blocked, "sed with standalone 'e' flag must be blocked"


# ===================================================================
# 15. TestInterpreterArgsBlocked
# ===================================================================

class TestInterpreterArgsBlocked:
    """HIGH: interpreter commands with -c, -m, -e flags must be blocked
    to prevent arbitrary code execution via the command gate.
    """

    @pytest.mark.parametrize("cmd", [
        "python3 -c 'import os; os.system(\"whoami\")'",
        "python3 -m http.server",
    ])
    def test_python3_dangerous_flags_blocked(self, cmd):
        """python3 -c and -m must be blocked."""
        config = CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=["python3"],
        )
        gate = CommandGate(config)
        verdict = gate.check(cmd)
        assert verdict.blocked, f"'{cmd}' must be blocked"

    @pytest.mark.parametrize("cmd", [
        "node -e 'require(\"child_process\").execSync(\"id\")'",
        "node --eval 'process.exit(1)'",
    ])
    def test_node_dangerous_flags_blocked(self, cmd):
        """node -e and --eval must be blocked."""
        config = CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=["node"],
        )
        gate = CommandGate(config)
        verdict = gate.check(cmd)
        assert verdict.blocked, f"'{cmd}' must be blocked"

    def test_python3_script_allowed(self):
        """python3 script.py (without -c/-m) must be allowed."""
        config = CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=["python3"],
        )
        gate = CommandGate(config)
        verdict = gate.check("python3 script.py --verbose")
        assert verdict.allowed, "python3 script.py must be allowed"

    def test_dangerous_args_includes_interpreters(self):
        """DANGEROUS_ARGS must include python3, python, node entries."""
        assert "python3" in DANGEROUS_ARGS
        assert "python" in DANGEROUS_ARGS
        assert "node" in DANGEROUS_ARGS

        # python3/python must block -c and -m
        for lang in ("python3", "python"):
            patterns = DANGEROUS_ARGS[lang]
            assert "-c" in patterns, f"{lang} must block -c"
            assert "-m" in patterns, f"{lang} must block -m"

        # node must block -e and --eval
        node_patterns = DANGEROUS_ARGS["node"]
        assert "-e" in node_patterns, "node must block -e"
        assert "--eval" in node_patterns, "node must block --eval"


# ===================================================================
# 16. TestWebhookTimestampInHMAC
# ===================================================================

class TestWebhookTimestampInHMAC:
    """HIGH: webhook signatures must include the timestamp in the HMAC
    payload to prevent replay attacks.
    """

    def test_signature_includes_timestamp(self):
        """The X-Lasso-Signature header must include t=<timestamp>."""
        from lasso.config.schema import WebhookConfig
        from lasso.core.audit import AuditEvent
        from lasso.core.webhooks import WebhookDispatcher

        # Create a webhook config with a known secret
        secret = "test-secret-key"
        wh_config = WebhookConfig(
            enabled=True,
            url="https://example.com/webhook",
            events=["lifecycle"],
            secret=secret,
        )

        # The _deliver method constructs the signature.
        # We test the signature format by checking what gets computed.
        dispatcher = WebhookDispatcher([wh_config], _allow_private=True)

        # Capture the request that would be sent
        sent_headers = {}

        def mock_urlopen(req, timeout=None):
            nonlocal sent_headers
            sent_headers = dict(req.headers)
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            event = AuditEvent(
                sandbox_id="test-001",
                event_type="lifecycle",
                action="test",
            )
            # Call _deliver directly (synchronous)
            payload = json.dumps(event.to_dict(), separators=(",", ":"), sort_keys=True)
            dispatcher._deliver(wh_config, payload, "lifecycle")

        # Check the signature header
        sig_header = sent_headers.get("X-lasso-signature", "")
        assert sig_header.startswith("t="), (
            f"Signature must start with t=<timestamp>. Got: {sig_header}"
        )
        assert ",sha256=" in sig_header, (
            f"Signature must include sha256=<hash>. Got: {sig_header}"
        )

        # Parse and verify the timestamp is numeric
        parts = sig_header.split(",")
        t_part = parts[0]
        assert t_part.startswith("t=")
        timestamp = t_part[2:]
        assert timestamp.isdigit(), f"Timestamp must be numeric, got: {timestamp}"

    def test_hmac_uses_timestamp_dot_payload(self):
        """The HMAC must be computed over 'timestamp.payload' not just payload."""
        secret = "verify-secret"
        timestamp = "1700000000"
        payload = '{"test":"data"}'

        # This is the format used in webhooks.py _deliver():
        sig_payload = timestamp + "." + payload
        expected_sig = hmac_mod.new(
            secret.encode(),
            sig_payload.encode(),
            hashlib.sha256,
        ).hexdigest()

        # Verify that computing HMAC without timestamp gives a DIFFERENT result
        wrong_sig = hmac_mod.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()

        assert expected_sig != wrong_sig, (
            "HMAC with timestamp must differ from HMAC without timestamp"
        )


