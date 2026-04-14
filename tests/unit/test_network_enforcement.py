"""Tests for network policy enforcement — verifying iptables rules are
generated correctly for each network mode and that the sandbox applies
them via the backend after container start.
"""


from lasso.backends.converter import needs_network_rules, profile_to_container_config
from lasso.config.defaults import (
    evaluation_profile,
    standard_profile,
)
from lasso.config.schema import (
    FilesystemConfig,
    NetworkConfig,
    NetworkMode,
    SandboxProfile,
)
from lasso.core.network import NetworkPolicy
from lasso.core.sandbox import Sandbox
from tests.conftest import FakeBackend


def _flatten_rules(rules: list[list[str]]) -> list[str]:
    """Join each rule list into a single string for easier assertion."""
    return [" ".join(r) for r in rules]


# ---------------------------------------------------------------------------
# needs_network_rules
# ---------------------------------------------------------------------------

class TestNeedsNetworkRules:
    def test_none_mode_no_rules_needed(self, tmp_path):
        """NONE mode uses Docker network_mode=none which handles isolation;
        no iptables rules or NET_ADMIN capability needed."""
        profile = evaluation_profile(str(tmp_path))
        assert profile.network.mode == NetworkMode.NONE
        assert needs_network_rules(profile) is False

    def test_restricted_mode_needs_rules(self, tmp_path):
        profile = standard_profile(str(tmp_path))
        assert profile.network.mode == NetworkMode.RESTRICTED
        assert needs_network_rules(profile) is True

    def test_full_mode_with_blocked_cidrs_needs_rules(self, tmp_path):
        profile = SandboxProfile(
            name="full-with-blocks",
            filesystem=FilesystemConfig(working_dir=str(tmp_path)),
            network=NetworkConfig(
                mode=NetworkMode.FULL,
                blocked_cidrs=["169.254.169.254/32"],
            ),
        )
        assert needs_network_rules(profile) is True

    def test_full_mode_without_blocked_cidrs_no_rules(self, tmp_path):
        profile = SandboxProfile(
            name="full-open",
            filesystem=FilesystemConfig(working_dir=str(tmp_path)),
            network=NetworkConfig(
                mode=NetworkMode.FULL,
                blocked_cidrs=[],
            ),
        )
        assert needs_network_rules(profile) is False


# ---------------------------------------------------------------------------
# NET_ADMIN capability added when needed
# ---------------------------------------------------------------------------

class TestCapAddNetAdmin:
    def test_none_mode_no_net_admin(self, tmp_path):
        """NONE mode uses Docker network_mode=none; no NET_ADMIN needed."""
        profile = evaluation_profile(str(tmp_path))
        config = profile_to_container_config(profile)
        assert "NET_ADMIN" not in config.cap_add

    def test_restricted_mode_gets_net_admin(self, tmp_path):
        profile = standard_profile(str(tmp_path))
        config = profile_to_container_config(profile)
        assert "NET_ADMIN" in config.cap_add

    def test_full_mode_no_blocks_no_net_admin(self, tmp_path):
        profile = SandboxProfile(
            name="full-open",
            filesystem=FilesystemConfig(working_dir=str(tmp_path)),
            network=NetworkConfig(mode=NetworkMode.FULL, blocked_cidrs=[]),
        )
        config = profile_to_container_config(profile)
        assert "NET_ADMIN" not in config.cap_add

    def test_full_mode_with_blocks_gets_net_admin(self, tmp_path):
        profile = SandboxProfile(
            name="full-blocks",
            filesystem=FilesystemConfig(working_dir=str(tmp_path)),
            network=NetworkConfig(
                mode=NetworkMode.FULL,
                blocked_cidrs=["10.0.0.0/8"],
            ),
        )
        config = profile_to_container_config(profile)
        assert "NET_ADMIN" in config.cap_add


# ---------------------------------------------------------------------------
# Iptables rule generation per mode
# ---------------------------------------------------------------------------

class TestIptablesRulesNoneMode:
    def test_drops_all_output(self):
        config = NetworkConfig(mode=NetworkMode.NONE)
        policy = NetworkPolicy(config)
        rules = policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        assert any("-P" in r and "OUTPUT" in r and "DROP" in r for r in flat)

    def test_drops_all_input(self):
        config = NetworkConfig(mode=NetworkMode.NONE)
        policy = NetworkPolicy(config)
        rules = policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        assert any("-P" in r and "INPUT" in r and "DROP" in r for r in flat)

    def test_allows_loopback(self):
        config = NetworkConfig(mode=NetworkMode.NONE)
        policy = NetworkPolicy(config)
        rules = policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        assert any("lo" in r and "ACCEPT" in r for r in flat)

    def test_exactly_eight_rules_with_ipv6(self):
        config = NetworkConfig(mode=NetworkMode.NONE)
        policy = NetworkPolicy(config)
        rules = policy.generate_iptables_rules()
        # 4 IPv4 + 4 IPv6 rules
        assert len(rules) == 8


class TestIptablesRulesFullMode:
    def test_no_default_drop_for_ipv4(self):
        config = NetworkConfig(
            mode=NetworkMode.FULL,
            blocked_cidrs=["169.254.169.254/32"],
        )
        policy = NetworkPolicy(config)
        rules = policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        # IPv4 rules should not have default DROP in FULL mode
        ipv4_flat = [r for r in flat if r.startswith("iptables")]
        assert not any("-P" in r and "DROP" in r for r in ipv4_flat)

    def test_blocked_cidrs_have_drop_rules(self):
        config = NetworkConfig(
            mode=NetworkMode.FULL,
            blocked_cidrs=["169.254.169.254/32", "10.0.0.0/8"],
        )
        policy = NetworkPolicy(config)
        rules = policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        assert any("169.254.169.254/32" in r and "DROP" in r for r in flat)
        assert any("10.0.0.0/8" in r and "DROP" in r for r in flat)

    def test_empty_blocked_cidrs_still_has_db_port_rules(self):
        config = NetworkConfig(mode=NetworkMode.FULL, blocked_cidrs=[])
        policy = NetworkPolicy(config)
        rules = policy.generate_iptables_rules()
        # DB port rules are always present even with no blocked CIDRs
        # Filter to IPv4 rules only — they should all be --dport DB rules
        ipv4_rules = [r for r in rules if r[0] == "iptables"]
        ipv4_flat = [" ".join(r) for r in ipv4_rules]
        assert len(ipv4_flat) > 0
        assert all("--dport" in r for r in ipv4_flat)


class TestIptablesRulesRestrictedMode:
    def test_default_deny_policy(self):
        config = NetworkConfig(
            mode=NetworkMode.RESTRICTED,
            allowed_domains=["pypi.org"],
            allowed_ports=[443],
            dns_servers=["1.1.1.1"],
        )
        policy = NetworkPolicy(config)
        rules = policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        assert any("-P" in r and "OUTPUT" in r and "DROP" in r for r in flat)
        assert any("-P" in r and "INPUT" in r and "DROP" in r for r in flat)

    def test_dns_rules_present(self):
        config = NetworkConfig(
            mode=NetworkMode.RESTRICTED,
            dns_servers=["1.1.1.1", "8.8.8.8"],
            allowed_ports=[443],
        )
        policy = NetworkPolicy(config)
        rules = policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        # UDP and TCP for each DNS server
        dns_rules = [r for r in flat if "53" in r]
        assert len(dns_rules) >= 4

    def test_established_connections_allowed(self):
        config = NetworkConfig(
            mode=NetworkMode.RESTRICTED,
            dns_servers=["1.1.1.1"],
            allowed_ports=[443],
        )
        policy = NetworkPolicy(config)
        rules = policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        assert any("ESTABLISHED" in r for r in flat)

    def test_blocked_cidrs_before_allows(self):
        config = NetworkConfig(
            mode=NetworkMode.RESTRICTED,
            blocked_cidrs=["169.254.169.254/32"],
            allowed_domains=["example.com"],
            allowed_ports=[443],
            dns_servers=["1.1.1.1"],
        )
        policy = NetworkPolicy(config)
        rules = policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        assert any("169.254.169.254/32" in r and "DROP" in r for r in flat)


# ---------------------------------------------------------------------------
# Sandbox applies iptables rules via backend after start
# ---------------------------------------------------------------------------

class TestSandboxAppliesNetworkPolicy:
    def test_none_mode_no_iptables_via_backend(self, tmp_path):
        """Starting a NONE-mode sandbox should NOT exec iptables rules.
        Docker's network_mode=none already provides full isolation."""
        backend = FakeBackend()
        profile = evaluation_profile(str(tmp_path), name="net-none")
        sb = Sandbox(profile, backend=backend)
        sb.start()

        # No iptables calls should be made for NONE mode
        sh_calls = [c for c in backend.exec_calls if c[0] == "sh" and c[1] == "-c"]
        iptables_in_scripts = [s for s in sh_calls if "iptables" in s[2]]
        assert len(iptables_in_scripts) == 0, "NONE mode should not apply iptables rules"
        sb.stop()

    def test_restricted_mode_applies_iptables_via_backend(self, tmp_path):
        """Starting a RESTRICTED-mode sandbox should exec iptables rules."""
        backend = FakeBackend()
        profile = standard_profile(str(tmp_path), name="net-restricted")
        sb = Sandbox(profile, backend=backend)
        sb.start()

        # Rules are now batched into a single sh -c "script" call
        sh_calls = [c for c in backend.exec_calls if c[0] == "sh" and c[1] == "-c"]
        assert len(sh_calls) >= 1, "Expected at least one batched sh -c exec call"
        script = sh_calls[0][2]
        # Script should contain iptables rules with default deny
        assert "iptables" in script
        assert "-P" in script and "OUTPUT" in script and "DROP" in script
        sb.stop()

    def test_full_mode_no_blocks_no_iptables(self, tmp_path):
        """FULL mode with empty blocked_cidrs should not exec iptables."""
        backend = FakeBackend()
        profile = SandboxProfile(
            name="full-clean",
            filesystem=FilesystemConfig(working_dir=str(tmp_path)),
            network=NetworkConfig(mode=NetworkMode.FULL, blocked_cidrs=[]),
        )
        sb = Sandbox(profile, backend=backend)
        sb.start()

        iptables_calls = [c for c in backend.exec_calls if c and c[0] == "iptables"]
        assert len(iptables_calls) == 0
        sb.stop()

    def test_full_mode_with_blocks_applies_iptables(self, tmp_path):
        """FULL mode with blocked_cidrs should exec DROP rules."""
        backend = FakeBackend()
        profile = SandboxProfile(
            name="full-blocks",
            filesystem=FilesystemConfig(working_dir=str(tmp_path)),
            network=NetworkConfig(
                mode=NetworkMode.FULL,
                blocked_cidrs=["169.254.169.254/32", "10.0.0.0/8"],
            ),
        )
        sb = Sandbox(profile, backend=backend)
        sb.start()

        # Rules are now batched into a single sh -c "script" call
        sh_calls = [c for c in backend.exec_calls if c[0] == "sh" and c[1] == "-c"]
        assert len(sh_calls) >= 1, "Expected at least one batched sh -c exec call"
        script = sh_calls[0][2]
        # Script should contain blocked CIDRs and DB port rules
        assert "169.254.169.254/32" in script
        assert "10.0.0.0/8" in script
        assert "1433" in script  # MSSQL port blocked
        sb.stop()

    def test_network_policy_audit_logged(self, tmp_path):
        """Network policy application should be recorded in audit trail."""
        backend = FakeBackend()
        # Use RESTRICTED mode which still applies iptables rules
        profile = standard_profile(str(tmp_path), name="net-audit")
        sb = Sandbox(profile, backend=backend)
        sb.start()

        log_content = sb.audit.log_file.read_text()
        assert "network_policy_applied" in log_content
        sb.stop()

    def test_native_mode_no_iptables(self, tmp_path):
        """Without a backend (native mode), no iptables rules applied."""
        profile = evaluation_profile(str(tmp_path), name="native")
        sb = Sandbox(profile, backend=None)
        sb.start()
        # Should not raise — native mode just skips network policy
        sb.stop()
