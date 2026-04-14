"""Network isolation — controls what the sandbox can reach over the network.

Uses iptables rules inside the sandbox's network namespace to enforce
allow/block policies for domains, CIDRs, and ports.
"""

from __future__ import annotations

import ipaddress
import socket
import threading

from lasso.config.schema import DATABASE_PORT_NAMES, NetworkConfig, NetworkMode

# Default timeout for DNS resolution (seconds).  DNS that takes longer
# than this is almost certainly broken or being abused.
_DNS_TIMEOUT_SECONDS = 5


def _getaddrinfo_with_timeout(
    host: str,
    port: int | None,
    family: int = socket.AF_UNSPEC,
    *,
    timeout: float = _DNS_TIMEOUT_SECONDS,
    **kwargs,
) -> list:
    """Wrapper around socket.getaddrinfo that enforces a timeout.

    stdlib getaddrinfo blocks indefinitely because it delegates to the
    OS resolver with no timeout parameter.  We run it in a daemon thread
    and raise socket.gaierror if it doesn't complete in *timeout* seconds.
    """
    result: list = []
    error: BaseException | None = None

    def _resolve():
        nonlocal result, error
        try:
            result = socket.getaddrinfo(host, port, family, **kwargs)
        except Exception as exc:
            error = exc

    t = threading.Thread(target=_resolve, daemon=True)
    t.start()
    t.join(timeout=timeout)

    if t.is_alive():
        raise socket.gaierror(f"DNS resolution for {host!r} timed out after {timeout}s")
    if error is not None:
        raise error  # type: ignore[misc]
    return result


class NetworkPolicy:
    """Translates NetworkConfig into enforceable network rules."""

    def __init__(self, config: NetworkConfig):
        self.config = config
        self._resolved_ips: dict[str, list[str]] = {}
        self._resolved_ipv6: dict[str, list[str]] = {}

    def resolve_domains(self) -> dict[str, list[str]]:
        """Resolve allowed domains to IP addresses for iptables rules.

        Returns only IPv4 addresses for use with iptables.  IPv6 addresses
        are stored separately in ``_resolved_ipv6`` so that
        ``_generate_ipv6_rules`` can emit the correct ip6tables ACCEPT
        entries.  Previously, AF_UNSPEC mixed both families into a single
        list which caused IPv6 addresses to be fed to iptables (invalid)
        and silently dropped from the firewall allowlist.
        """
        resolved: dict[str, list[str]] = {}
        resolved_v6: dict[str, list[str]] = {}
        for domain in self.config.allowed_domains:
            v4: list[str] = []
            v6: list[str] = []
            try:
                for info in _getaddrinfo_with_timeout(domain, None, socket.AF_UNSPEC):
                    family, _, _, _, sockaddr = info
                    addr = sockaddr[0]
                    if family == socket.AF_INET:
                        v4.append(addr)
                    elif family == socket.AF_INET6:
                        v6.append(addr)
            except socket.gaierror:
                pass
            resolved[domain] = list(set(v4))
            resolved_v6[domain] = list(set(v6))
        self._resolved_ips = resolved
        self._resolved_ipv6 = resolved_v6
        return resolved

    def generate_iptables_rules(self) -> list[list[str]]:
        """Generate iptables commands to enforce the network policy.

        These are applied inside the sandbox's network namespace.
        """
        rules: list[list[str]] = []

        if self.config.mode == NetworkMode.NONE:
            # Drop everything (IPv4)
            rules.append(["iptables", "-P", "OUTPUT", "DROP"])
            rules.append(["iptables", "-P", "INPUT", "DROP"])
            rules.append(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
            rules.append(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
            # Drop everything (IPv6)
            rules.append(["ip6tables", "-P", "OUTPUT", "DROP"])
            rules.append(["ip6tables", "-P", "INPUT", "DROP"])
            rules.append(["ip6tables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
            rules.append(["ip6tables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
            return rules

        # Block database ports in ALL modes (FULL and RESTRICTED)
        for port in self.config.blocked_ports:
            rules.append([
                "iptables", "-A", "OUTPUT", "-p", "tcp",
                "--dport", str(port), "-j", "DROP",
            ])

        if self.config.mode == NetworkMode.FULL:
            # Allow everything except blocked CIDRs
            for cidr in self.config.blocked_cidrs:
                rules.append([
                    "iptables", "-A", "OUTPUT", "-d", cidr, "-j", "DROP",
                ])
            # Add IPv6 equivalents — no default DROP in FULL mode (match IPv4 behavior)
            rules.extend(self._generate_ipv6_rules(rules, include_default_drop=False))
            return rules

        # RESTRICTED mode: default deny, explicit allow
        rules.append(["iptables", "-P", "OUTPUT", "DROP"])
        rules.append(["iptables", "-P", "INPUT", "DROP"])

        # Allow loopback
        rules.append(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
        rules.append(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])

        # Allow established connections
        rules.append([
            "iptables", "-A", "INPUT", "-m", "state",
            "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT",
        ])

        # Allow DNS (needed to resolve allowed domains)
        for dns in self.config.dns_servers:
            rules.append([
                "iptables", "-A", "OUTPUT", "-d", dns,
                "-p", "udp", "--dport", "53", "-j", "ACCEPT",
            ])
            rules.append([
                "iptables", "-A", "OUTPUT", "-d", dns,
                "-p", "tcp", "--dport", "53", "-j", "ACCEPT",
            ])

        # Block CIDRs first (takes precedence)
        for cidr in self.config.blocked_cidrs:
            rules.append([
                "iptables", "-A", "OUTPUT", "-d", cidr, "-j", "DROP",
            ])

        # Allow resolved domain IPs on allowed ports
        if not self._resolved_ips:
            self.resolve_domains()

        for domain, ips in self._resolved_ips.items():
            if domain in self.config.blocked_domains:
                continue
            for ip in ips:
                for port in self.config.allowed_ports:
                    rules.append([
                        "iptables", "-A", "OUTPUT",
                        "-d", ip, "-p", "tcp", "--dport", str(port),
                        "-j", "ACCEPT",
                    ])

        # Allow explicit CIDRs
        for cidr in self.config.allowed_cidrs:
            for port in self.config.allowed_ports:
                rules.append([
                    "iptables", "-A", "OUTPUT",
                    "-d", cidr, "-p", "tcp", "--dport", str(port),
                    "-j", "ACCEPT",
                ])

        # Add IPv6 equivalents to prevent IPv6 bypass
        rules.extend(self._generate_ipv6_rules(rules))

        return rules

    @staticmethod
    def _is_ipv4_specific(arg: str) -> bool:
        """Check if a rule argument is an IPv4-specific address or CIDR.

        Returns True for IPv4 literals (e.g. '192.168.1.1', '10.0.0.0/8')
        that should not be mirrored to ip6tables.
        """
        try:
            ipaddress.IPv4Address(arg.split("/")[0])
            return True
        except (ValueError, AttributeError):
            pass
        try:
            ipaddress.IPv4Network(arg, strict=False)
            return True
        except (ValueError, AttributeError):
            pass
        return False

    def _generate_ipv6_rules(
        self,
        ipv4_rules: list[list[str]],
        include_default_drop: bool = True,
    ) -> list[list[str]]:
        """Generate ip6tables equivalents for the given iptables rules.

        Skips rules that reference IPv4-specific addresses or CIDRs since
        those have no meaning in the IPv6 context.

        Also emits ACCEPT rules for resolved IPv6 domain addresses that
        are stored in ``_resolved_ipv6`` (populated by ``resolve_domains``).

        When *include_default_drop* is True (default), adds DROP policies and
        loopback ACCEPT for IPv6.  Set to False for FULL mode where IPv4
        behaviour is permissive (only specific blocks, no default DROP).
        """
        ipv6_rules: list[list[str]] = []
        if include_default_drop:
            ipv6_rules.extend([
                ["ip6tables", "-P", "OUTPUT", "DROP"],
                ["ip6tables", "-P", "INPUT", "DROP"],
                ["ip6tables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
                ["ip6tables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
            ])
        for rule in ipv4_rules:
            if rule[0] != "iptables":
                continue
            # Skip rules containing IPv4-specific addresses
            if any(self._is_ipv4_specific(arg) for arg in rule[1:]):
                continue
            ipv6_rules.append(["ip6tables"] + rule[1:])

        # Add ACCEPT rules for resolved IPv6 domain addresses
        resolved_v6 = getattr(self, "_resolved_ipv6", {})
        for domain, ips in resolved_v6.items():
            if domain in self.config.blocked_domains:
                continue
            for ip in ips:
                for port in self.config.allowed_ports:
                    ipv6_rules.append([
                        "ip6tables", "-A", "OUTPUT",
                        "-d", ip, "-p", "tcp", "--dport", str(port),
                        "-j", "ACCEPT",
                    ])

        return ipv6_rules

    def generate_resolv_conf(self) -> str:
        """Generate resolv.conf content for the sandbox."""
        lines = ["# Generated by LASSO - do not edit"]
        for dns in self.config.dns_servers:
            lines.append(f"nameserver {dns}")
        return "\n".join(lines) + "\n"

    def check_destination(self, host: str, port: int) -> tuple[bool, str]:
        """Pre-flight check: would a connection to host:port be allowed?

        This is a software-level check used by the command gate before
        execution. The iptables rules are the real enforcement.
        """
        if self.config.mode == NetworkMode.NONE:
            return False, "Network access is disabled."

        # Database ports are always blocked regardless of network mode
        if port in self.config.blocked_ports:
            db_name = DATABASE_PORT_NAMES.get(port, "database")
            return False, f"BLOCKED: Port {port} ({db_name}) — direct database access is not permitted."

        if port not in self.config.allowed_ports and self.config.mode == NetworkMode.RESTRICTED:
            return False, f"Port {port} is not in allowed ports."

        # Check blocked CIDRs (use getaddrinfo instead of deprecated gethostbyname)
        try:
            addrinfo = _getaddrinfo_with_timeout(host, None, socket.AF_INET)
            ip = addrinfo[0][4][0] if addrinfo else host
            ip_addr = ipaddress.ip_address(ip)
            for cidr in self.config.blocked_cidrs:
                if ip_addr in ipaddress.ip_network(cidr, strict=False):
                    return False, f"Destination {ip} is in blocked CIDR {cidr}."
        except (socket.gaierror, ValueError):
            pass

        if self.config.mode == NetworkMode.RESTRICTED:
            if host not in self.config.allowed_domains:
                # Check if it's an IP in allowed CIDRs
                try:
                    ip_addr = ipaddress.ip_address(host)
                    for cidr in self.config.allowed_cidrs:
                        if ip_addr in ipaddress.ip_network(cidr, strict=False):
                            return True, ""
                except ValueError:
                    pass
                return False, f"Host '{host}' is not in allowed domains."

        return True, ""

    def explain_policy(self) -> dict:
        """Human-readable summary of the network policy."""
        return {
            "mode": self.config.mode.value,
            "allowed_domains": self.config.allowed_domains or "(none)",
            "blocked_domains": self.config.blocked_domains or "(none)",
            "allowed_ports": self.config.allowed_ports,
            "blocked_ports_database": self.config.blocked_ports,
            "blocked_cidrs": self.config.blocked_cidrs,
            "dns_servers": self.config.dns_servers,
        }
