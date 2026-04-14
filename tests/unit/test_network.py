"""Tests for network policy — iptables rule generation and destination checks."""

import pytest

from lasso.config.schema import NetworkConfig, NetworkMode
from lasso.core.network import NetworkPolicy

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def none_policy():
    """Network policy with mode=NONE (no network access)."""
    config = NetworkConfig(mode=NetworkMode.NONE)
    return NetworkPolicy(config)


@pytest.fixture
def full_policy():
    """Network policy with mode=FULL (everything except blocked CIDRs)."""
    config = NetworkConfig(
        mode=NetworkMode.FULL,
        blocked_cidrs=["169.254.169.254/32", "10.0.0.0/8"],
    )
    return NetworkPolicy(config)


@pytest.fixture
def restricted_policy():
    """Network policy with mode=RESTRICTED (explicit allow only)."""
    config = NetworkConfig(
        mode=NetworkMode.RESTRICTED,
        allowed_domains=["pypi.org", "github.com"],
        blocked_cidrs=["169.254.169.254/32"],
        allowed_ports=[80, 443],
        dns_servers=["1.1.1.1", "8.8.8.8"],
    )
    return NetworkPolicy(config)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flatten_rules(rules: list[list[str]]) -> list[str]:
    """Join each rule list into a single string for easier assertion."""
    return [" ".join(r) for r in rules]


# ---------------------------------------------------------------------------
# generate_iptables_rules — NONE mode
# ---------------------------------------------------------------------------

class TestIptablesNoneMode:
    def test_has_output_drop(self, none_policy):
        rules = none_policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        assert any("OUTPUT" in r and "DROP" in r and "-P" in r for r in flat)

    def test_has_input_drop(self, none_policy):
        rules = none_policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        assert any("INPUT" in r and "DROP" in r and "-P" in r for r in flat)

    def test_has_loopback_accept(self, none_policy):
        rules = none_policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        assert any("lo" in r and "ACCEPT" in r for r in flat)

    def test_exactly_eight_rules(self, none_policy):
        rules = none_policy.generate_iptables_rules()
        # 4 IPv4 + 4 IPv6: OUTPUT DROP, INPUT DROP, OUTPUT lo ACCEPT, INPUT lo ACCEPT
        assert len(rules) == 8

    def test_loopback_output_and_input(self, none_policy):
        rules = none_policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        lo_rules = [r for r in flat if "lo" in r and "ACCEPT" in r]
        # 2 iptables + 2 ip6tables loopback rules
        assert len(lo_rules) == 4
        assert any("OUTPUT" in r for r in lo_rules)
        assert any("INPUT" in r for r in lo_rules)

    def test_has_ipv6_drop_policies(self, none_policy):
        rules = none_policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        assert any("ip6tables" in r and "OUTPUT" in r and "DROP" in r and "-P" in r for r in flat)
        assert any("ip6tables" in r and "INPUT" in r and "DROP" in r and "-P" in r for r in flat)


# ---------------------------------------------------------------------------
# generate_iptables_rules — FULL mode
# ---------------------------------------------------------------------------

class TestIptablesFullMode:
    def test_has_blocked_cidr_drop_rules(self, full_policy):
        rules = full_policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        assert any("169.254.169.254/32" in r and "DROP" in r for r in flat)
        assert any("10.0.0.0/8" in r and "DROP" in r for r in flat)

    def test_no_default_drop_policy_for_ipv4(self, full_policy):
        rules = full_policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        # Full mode should NOT set a default DROP policy for IPv4 iptables
        ipv4_rules = [r for r in flat if r.startswith("iptables")]
        assert not any("-P" in r and "DROP" in r for r in ipv4_rules)

    def test_no_ipv6_drop_policies_full_mode(self, full_policy):
        rules = full_policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        # IPv6 should NOT have default DROP in FULL mode (matches IPv4 permissive behavior)
        assert not any("ip6tables" in r and "-P" in r and "OUTPUT" in r and "DROP" in r for r in flat)
        assert not any("ip6tables" in r and "-P" in r and "INPUT" in r and "DROP" in r for r in flat)

    def test_rule_count_includes_db_ports_and_cidrs(self, full_policy):
        rules = full_policy.generate_iptables_rules()
        # DB port rules (11 default) + CIDR rules (2 in fixture)
        db_port_rules = [r for r in rules if "--dport" in r]
        cidr_rules = [r for r in rules if "-d" in r and "--dport" not in r]
        assert len(cidr_rules) == 2  # two blocked CIDRs
        assert len(db_port_rules) >= 11  # default blocked DB ports

    def test_no_blocked_cidrs_still_has_db_rules(self):
        config = NetworkConfig(mode=NetworkMode.FULL, blocked_cidrs=[])
        policy = NetworkPolicy(config)
        rules = policy.generate_iptables_rules()
        # Still has DB port blocking rules (IPv4) plus IPv6 rules
        assert len(rules) > 0
        # Filter to IPv4 rules only — they should all be --dport DB rules
        ipv4_rules = [r for r in rules if r[0] == "iptables"]
        assert len(ipv4_rules) > 0
        assert all("--dport" in " ".join(r) for r in ipv4_rules)


# ---------------------------------------------------------------------------
# generate_iptables_rules — RESTRICTED mode
# ---------------------------------------------------------------------------

class TestIptablesRestrictedMode:
    def test_has_default_drop_policies(self, restricted_policy):
        rules = restricted_policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        assert any("-P" in r and "OUTPUT" in r and "DROP" in r for r in flat)
        assert any("-P" in r and "INPUT" in r and "DROP" in r for r in flat)

    def test_has_dns_rules(self, restricted_policy):
        rules = restricted_policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        dns_rules = [r for r in flat if "53" in r]
        # Should have UDP and TCP rules for each DNS server
        assert len(dns_rules) >= 4  # 2 servers * 2 protocols

    def test_dns_rules_for_each_server(self, restricted_policy):
        rules = restricted_policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        assert any("1.1.1.1" in r and "53" in r for r in flat)
        assert any("8.8.8.8" in r and "53" in r for r in flat)

    def test_has_blocked_cidr_rules(self, restricted_policy):
        rules = restricted_policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        assert any("169.254.169.254/32" in r and "DROP" in r for r in flat)

    def test_has_loopback_rules(self, restricted_policy):
        rules = restricted_policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        lo_rules = [r for r in flat if "lo" in r and "ACCEPT" in r]
        # 2 iptables + at least 2 ip6tables loopback rules
        assert len(lo_rules) >= 4

    def test_has_established_connections_rule(self, restricted_policy):
        rules = restricted_policy.generate_iptables_rules()
        flat = _flatten_rules(rules)
        assert any("ESTABLISHED" in r for r in flat)


# ---------------------------------------------------------------------------
# generate_resolv_conf
# ---------------------------------------------------------------------------

class TestResolvConf:
    def test_contains_nameserver_lines(self, restricted_policy):
        conf = restricted_policy.generate_resolv_conf()
        assert "nameserver 1.1.1.1" in conf
        assert "nameserver 8.8.8.8" in conf

    def test_has_header_comment(self, restricted_policy):
        conf = restricted_policy.generate_resolv_conf()
        assert conf.startswith("# Generated by LASSO")

    def test_ends_with_newline(self, restricted_policy):
        conf = restricted_policy.generate_resolv_conf()
        assert conf.endswith("\n")

    def test_single_dns_server(self):
        config = NetworkConfig(
            mode=NetworkMode.RESTRICTED,
            dns_servers=["9.9.9.9"],
        )
        policy = NetworkPolicy(config)
        conf = policy.generate_resolv_conf()
        assert "nameserver 9.9.9.9" in conf
        assert conf.count("nameserver") == 1

    def test_no_dns_servers(self):
        config = NetworkConfig(
            mode=NetworkMode.RESTRICTED,
            dns_servers=[],
        )
        policy = NetworkPolicy(config)
        conf = policy.generate_resolv_conf()
        assert "nameserver" not in conf


# ---------------------------------------------------------------------------
# check_destination
# ---------------------------------------------------------------------------

class TestCheckDestination:
    def test_none_mode_always_returns_false(self, none_policy):
        allowed, reason = none_policy.check_destination("pypi.org", 443)
        assert allowed is False
        assert "disabled" in reason.lower()

    def test_none_mode_rejects_localhost(self, none_policy):
        allowed, _ = none_policy.check_destination("127.0.0.1", 80)
        assert allowed is False

    def test_restricted_allowed_domain_returns_true(self, restricted_policy):
        allowed, reason = restricted_policy.check_destination("pypi.org", 443)
        assert allowed is True
        assert reason == ""

    def test_restricted_unknown_domain_returns_false(self, restricted_policy):
        allowed, reason = restricted_policy.check_destination("evil.com", 443)
        assert allowed is False
        assert "not in allowed domains" in reason.lower()

    def test_restricted_blocked_port_returns_false(self, restricted_policy):
        allowed, reason = restricted_policy.check_destination("pypi.org", 22)
        assert allowed is False
        assert "port" in reason.lower()

    def test_full_mode_allowed_domain(self, full_policy):
        allowed, reason = full_policy.check_destination("example.com", 443)
        assert allowed is True
        assert reason == ""
