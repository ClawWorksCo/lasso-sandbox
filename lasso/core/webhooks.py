"""Webhook dispatcher — async delivery of audit events to external systems.

Sends sandbox audit events (violations, lifecycle changes, commands, etc.) to
configured webhook endpoints for SIEM/SOAR, Slack, and monitoring integration.

Design decisions:
- Uses stdlib ``urllib.request`` only (no external HTTP dependencies).
- Dispatches asynchronously via ``threading.Thread`` so webhook latency
  never blocks command execution inside the sandbox.
- Signs payloads with HMAC-SHA256 when a secret is configured, following
  the same pattern as GitHub webhook signatures (X-Hub-Signature-256).
- Retries with exponential backoff on transient failures.
- Pins resolved IPs to prevent DNS rebinding TOCTOU attacks (SSRF).
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

from lasso.core.network import _getaddrinfo_with_timeout

if TYPE_CHECKING:
    from lasso.config.schema import WebhookConfig
    from lasso.core.audit import AuditEvent

logger = logging.getLogger("lasso.webhooks")

# All event types that LASSO emits.
WEBHOOK_EVENT_TYPES: list[str] = [
    "command",
    "lifecycle",
    "violation",
    "file",
    "network",
]


def _validate_ip(ip_str: str) -> tuple[bool, str]:
    """Check a single resolved IP against SSRF blocklists.

    Returns (is_safe, reason).
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, f"Unparseable resolved IP: {ip_str}"

    _METADATA_ADDRS = {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("fd00:ec2::254"),
    }

    if ip in _METADATA_ADDRS:
        return False, f"Cloud metadata endpoint blocked: {ip}"
    if ip.is_private:
        return False, f"Private IP blocked: {ip}"
    if ip.is_loopback:
        return False, f"Loopback IP blocked: {ip}"
    if ip.is_link_local:
        return False, f"Link-local IP blocked: {ip}"
    if ip.is_reserved:
        return False, f"Reserved IP blocked: {ip}"
    if ip.is_multicast:
        return False, f"Multicast IP blocked: {ip}"
    if ip.is_unspecified:
        return False, f"Unspecified IP blocked: {ip}"

    # Detect IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) and validate
    # the embedded IPv4 address to prevent SSRF bypasses.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return _validate_ip(str(ip.ipv4_mapped))

    return True, ""


def _resolve_and_validate(url: str) -> tuple[str | None, str, str]:
    """Resolve a webhook URL hostname and validate the IP for SSRF safety.

    This is the core of the DNS-rebinding-safe webhook delivery: resolve once,
    validate, then return the pinned IP to connect to directly.

    Returns:
        (ip, hostname, reason) — *ip* is the validated IP string to connect to,
        or None if blocked.  *hostname* is the original hostname for Host/SNI.
        *reason* describes why it was blocked (empty on success).
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None, "", "Malformed URL"

    hostname = parsed.hostname
    if not hostname:
        return None, "", "No hostname in URL"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return None, "", f"Disallowed URL scheme: {scheme!r}"

    # Resolve hostname to IPs — pick the first valid one
    try:
        addrinfos = _getaddrinfo_with_timeout(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return None, "", f"DNS resolution failed for {hostname!r}: {exc}"

    if not addrinfos:
        return None, "", f"No DNS results for {hostname!r}"

    # Validate ALL resolved IPs (don't let a dual-stack response sneak in a
    # private IP on one family while a public IP on another).
    for _family, _type, _proto, _canonname, sockaddr in addrinfos:
        ip_str = sockaddr[0]
        is_safe, reason = _validate_ip(ip_str)
        if not is_safe:
            return None, "", reason

    # Use the first resolved IP for the actual connection
    pinned_ip = addrinfos[0][4][0]
    return pinned_ip, hostname, ""


class WebhookDispatcher:
    """Delivers audit events to one or more webhook endpoints.

    Each webhook is filtered by its ``events`` list — only matching event
    types are dispatched.  Delivery happens on a bounded thread pool so the
    caller is never blocked.
    """

    def __init__(
        self,
        webhooks: list[WebhookConfig],
        _allow_private: bool = False,
    ):
        self._webhooks = [wh for wh in webhooks if wh.enabled and wh.url]
        self._executor = ThreadPoolExecutor(max_workers=10)
        self._allow_private = _allow_private

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def dispatch(self, event: AuditEvent) -> None:
        """Send *event* to all matching webhooks (non-blocking)."""
        if not self._webhooks:
            return

        payload = json.dumps(event.to_dict(), separators=(",", ":"), sort_keys=True)

        for wh in self._webhooks:
            if event.event_type not in wh.events:
                continue
            self._executor.submit(self._deliver, wh, payload, event.event_type)

    def close(self) -> None:
        """Shut down the thread pool, waiting for pending deliveries."""
        self._executor.shutdown(wait=True)

    @property
    def active_webhooks(self) -> int:
        """Number of enabled+configured webhooks."""
        return len(self._webhooks)

    # ------------------------------------------------------------------
    # Internal delivery
    # ------------------------------------------------------------------

    def _deliver(
        self,
        wh: WebhookConfig,
        payload: str,
        event_type: str,
    ) -> None:
        """Deliver *payload* to a single webhook with retries.

        To prevent DNS rebinding TOCTOU attacks, we resolve the hostname once,
        validate the IP, and then connect directly to the resolved IP — passing
        the original hostname via the Host header and for TLS SNI/certificate
        verification.
        """
        parsed = urllib.parse.urlparse(wh.url)
        scheme = (parsed.scheme or "").lower()

        # SSRF protection: resolve, validate, and pin the IP
        if not self._allow_private:
            pinned_ip, hostname, reason = _resolve_and_validate(wh.url)
            if pinned_ip is None:
                logger.warning(
                    "Webhook delivery blocked (SSRF protection): %s -> %s — %s",
                    event_type, wh.url, reason,
                )
                return
        else:
            # In allow_private mode (testing), connect to the hostname directly
            pinned_ip = None
            hostname = parsed.hostname or ""

        delivery_id = uuid.uuid4().hex[:16]
        timestamp = str(int(time.time()))

        headers = {
            "Content-Type": "application/json",
            "X-Lasso-Event": event_type,
            "X-Lasso-Delivery": delivery_id,
            "X-Lasso-Timestamp": timestamp,
            "User-Agent": "LASSO-Webhook/1.0",
        }

        if wh.secret:
            sig_payload = timestamp + "." + payload
            sig = hmac.new(
                wh.secret.encode(),
                sig_payload.encode(),
                hashlib.sha256,
            ).hexdigest()
            headers["X-Lasso-Signature"] = f"t={timestamp},sha256={sig}"

        last_error: Exception | None = None
        attempts = 1 + wh.retry_count  # first attempt + retries

        for attempt in range(attempts):
            try:
                if pinned_ip is not None:
                    # IP-pinned request: connect to the resolved IP directly,
                    # use the original hostname for Host header and TLS SNI.
                    status = self._request_pinned(
                        pinned_ip=pinned_ip,
                        hostname=hostname,
                        port=parsed.port,
                        scheme=scheme,
                        path=parsed.path or "/",
                        query=parsed.query,
                        payload=payload,
                        headers=headers,
                        timeout=wh.timeout_seconds,
                    )
                else:
                    # _allow_private mode (tests): use urllib directly
                    req = urllib.request.Request(
                        wh.url,
                        data=payload.encode(),
                        headers=headers,
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=wh.timeout_seconds) as resp:
                        status = resp.status

                if 200 <= status < 300:
                    logger.debug(
                        "Webhook delivered: %s -> %s (status %d, delivery %s)",
                        event_type, wh.url, status, delivery_id,
                    )
                    return
                else:
                    last_error = RuntimeError(f"HTTP {status}")
            except (urllib.error.URLError, OSError, RuntimeError) as exc:
                last_error = exc

            # Exponential backoff before retry
            if attempt < attempts - 1:
                backoff = 0.5 * (2 ** attempt)
                time.sleep(backoff)

        logger.warning(
            "Webhook delivery failed after %d attempts: %s -> %s — %s",
            attempts, event_type, wh.url, last_error,
        )

    @staticmethod
    def _request_pinned(
        *,
        pinned_ip: str,
        hostname: str,
        port: int | None,
        scheme: str,
        path: str,
        query: str,
        payload: str,
        headers: dict[str, str],
        timeout: int,
    ) -> int:
        """Make an HTTP(S) request to a specific IP, using hostname for SNI.

        This prevents DNS rebinding by connecting to the already-validated IP
        while still sending the correct Host header and validating the TLS
        certificate against the original hostname.

        Returns the HTTP status code; raises on connection error.
        """
        request_path = path
        if query:
            request_path = f"{path}?{query}"

        default_port = 443 if scheme == "https" else 80
        connect_port = port or default_port

        # Build the connection to the pinned IP (not the hostname).
        # For HTTPS, we need the TLS handshake to use the original hostname
        # for SNI and certificate verification.  HTTPSConnection normally
        # derives server_hostname from self.host, but we need TCP to go to
        # the IP while TLS uses the hostname.  We achieve this by:
        #   1. Creating the connection with the IP as host
        #   2. Opening the raw TCP socket to the IP ourselves
        #   3. Wrapping it with TLS using server_hostname=hostname
        #   4. Assigning the wrapped socket back to the connection

        # Set the Host header to the original hostname (not the IP)
        host_header = hostname
        if port and port != default_port:
            host_header = f"{hostname}:{port}"
        headers = {**headers, "Host": host_header}

        if scheme == "https":
            ssl_ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(
                pinned_ip,
                port=connect_port,
                timeout=timeout,
                context=ssl_ctx,
            )
            # Manually connect: open TCP to IP, wrap TLS with hostname for SNI.
            # This avoids HTTPSConnection.connect() using self.host for both
            # the TCP destination and the TLS server_hostname.
            sock = socket.create_connection(
                (pinned_ip, connect_port), timeout=timeout,
            )
            try:
                conn.sock = ssl_ctx.wrap_socket(
                    sock, server_hostname=hostname,
                )
            except Exception:
                sock.close()
                raise
        else:
            conn = http.client.HTTPConnection(
                pinned_ip,
                port=connect_port,
                timeout=timeout,
            )

        try:
            conn.request("POST", request_path, body=payload.encode(), headers=headers)
            resp = conn.getresponse()
            resp.read()  # drain the response body
            return resp.status
        finally:
            conn.close()
