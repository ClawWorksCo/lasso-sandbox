"""Tests for the LASSO webhook dispatcher — delivery, signing, filtering, retries."""

from __future__ import annotations

import hashlib
import hmac
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

flask = pytest.importorskip("flask", reason="Flask is required for webhook API tests")

from lasso.config.schema import AuditConfig, WebhookConfig
from lasso.core.audit import AuditEvent, AuditLogger
from lasso.core.webhooks import (
    WEBHOOK_EVENT_TYPES,
    WebhookDispatcher,
    _resolve_and_validate,
    _validate_ip,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _public_mode(monkeypatch):
    """Disable dashboard auth for tests that import create_app."""
    monkeypatch.setenv("LASSO_DASHBOARD_PUBLIC", "1")


class _WebhookCapture:
    """HTTP server that captures incoming webhook requests."""

    def __init__(self, status_code: int = 200):
        self.requests: list[dict[str, Any]] = []
        self.status_code = status_code
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def start(self) -> str:
        """Start the server and return the base URL."""
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length) if length else b""
                with parent._lock:
                    parent.requests.append({
                        "path": self.path,
                        "headers": dict(self.headers),
                        "body": body.decode(),
                    })
                self.send_response(parent.status_code)
                self.end_headers()

            def log_message(self, format, *args):
                pass  # Silence HTTP logs in test output

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return f"http://127.0.0.1:{port}"

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    def wait_for_requests(self, count: int = 1, timeout: float = 5.0) -> None:
        """Block until *count* requests have been received or timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if len(self.requests) >= count:
                    return
            time.sleep(0.05)


@pytest.fixture
def capture():
    """Provide a fresh webhook capture server."""
    cap = _WebhookCapture()
    yield cap
    cap.stop()


@pytest.fixture
def failing_capture():
    """Provide a webhook capture server that returns 500."""
    cap = _WebhookCapture(status_code=500)
    yield cap
    cap.stop()


def _make_event(event_type: str = "violation") -> AuditEvent:
    return AuditEvent(
        sandbox_id="test-abc123",
        event_type=event_type,
        action="test_action",
        detail={"key": "value"},
    )


# ---------------------------------------------------------------------------
# Dispatcher tests
# ---------------------------------------------------------------------------

class TestWebhookDispatcher:
    """Core dispatcher behavior."""

    def test_sends_post_to_url(self, capture):
        url = capture.start()
        wh = WebhookConfig(enabled=True, url=url, events=["violation"])
        dispatcher = WebhookDispatcher([wh], _allow_private=True)

        event = _make_event("violation")
        dispatcher.dispatch(event)
        capture.wait_for_requests(1)

        assert len(capture.requests) == 1
        req = capture.requests[0]
        body = json.loads(req["body"])
        assert body["type"] == "violation"
        assert body["sandbox_id"] == "test-abc123"

    def test_hmac_signature_correct(self, capture):
        url = capture.start()
        secret = "my-webhook-secret"
        wh = WebhookConfig(enabled=True, url=url, events=["violation"], secret=secret)
        dispatcher = WebhookDispatcher([wh], _allow_private=True)

        event = _make_event("violation")
        dispatcher.dispatch(event)
        capture.wait_for_requests(1)

        req = capture.requests[0]
        sig_header = req["headers"].get("X-Lasso-Signature", "")
        assert "sha256=" in sig_header
        assert sig_header.startswith("t=")

        # Parse the signature header: t=<timestamp>,sha256=<hex>
        parts = dict(p.split("=", 1) for p in sig_header.split(","))
        timestamp = parts["t"]
        sig_hex = parts["sha256"]

        # Verify the HMAC independently (timestamp.payload)
        sig_payload = timestamp + "." + req["body"]
        expected = hmac.new(
            secret.encode(),
            sig_payload.encode(),
            hashlib.sha256,
        ).hexdigest()
        assert sig_hex == expected

    def test_no_signature_without_secret(self, capture):
        url = capture.start()
        wh = WebhookConfig(enabled=True, url=url, events=["violation"], secret=None)
        dispatcher = WebhookDispatcher([wh], _allow_private=True)

        dispatcher.dispatch(_make_event("violation"))
        capture.wait_for_requests(1)

        req = capture.requests[0]
        assert "X-Lasso-Signature" not in req["headers"]

    def test_event_filtering_only_matching(self, capture):
        url = capture.start()
        wh = WebhookConfig(enabled=True, url=url, events=["lifecycle"])
        dispatcher = WebhookDispatcher([wh], _allow_private=True)

        # This event should NOT be sent (violation != lifecycle)
        dispatcher.dispatch(_make_event("violation"))
        time.sleep(0.3)
        assert len(capture.requests) == 0

        # This event SHOULD be sent
        dispatcher.dispatch(_make_event("lifecycle"))
        capture.wait_for_requests(1)
        assert len(capture.requests) == 1

    def test_disabled_webhooks_dont_send(self, capture):
        url = capture.start()
        wh = WebhookConfig(enabled=False, url=url, events=["violation"])
        dispatcher = WebhookDispatcher([wh], _allow_private=True)

        dispatcher.dispatch(_make_event("violation"))
        time.sleep(0.3)
        assert len(capture.requests) == 0
        assert dispatcher.active_webhooks == 0

    def test_empty_url_webhooks_dont_send(self, capture):
        wh = WebhookConfig(enabled=True, url="", events=["violation"])
        dispatcher = WebhookDispatcher([wh], _allow_private=True)
        assert dispatcher.active_webhooks == 0

    def test_async_dispatch_does_not_block(self, capture):
        url = capture.start()
        wh = WebhookConfig(enabled=True, url=url, events=["violation"])
        dispatcher = WebhookDispatcher([wh], _allow_private=True)

        start = time.monotonic()
        dispatcher.dispatch(_make_event("violation"))
        elapsed = time.monotonic() - start

        # dispatch() should return almost immediately (< 100ms)
        assert elapsed < 0.1

        capture.wait_for_requests(1)
        assert len(capture.requests) == 1

    def test_retries_on_failure(self, failing_capture):
        url = failing_capture.start()
        wh = WebhookConfig(
            enabled=True, url=url, events=["violation"],
            retry_count=2, timeout_seconds=2,
        )
        dispatcher = WebhookDispatcher([wh], _allow_private=True)

        dispatcher.dispatch(_make_event("violation"))
        # 1 initial + 2 retries = 3 total attempts, with backoff
        failing_capture.wait_for_requests(3, timeout=10.0)
        assert len(failing_capture.requests) == 3

    def test_custom_headers_present(self, capture):
        url = capture.start()
        wh = WebhookConfig(enabled=True, url=url, events=["violation"])
        dispatcher = WebhookDispatcher([wh], _allow_private=True)

        dispatcher.dispatch(_make_event("violation"))
        capture.wait_for_requests(1)

        headers = capture.requests[0]["headers"]
        assert headers.get("X-Lasso-Event") == "violation"
        assert "X-Lasso-Delivery" in headers
        assert "X-Lasso-Timestamp" in headers
        assert headers.get("Content-Type") == "application/json"

    def test_multiple_webhooks(self, capture):
        url = capture.start()
        wh1 = WebhookConfig(enabled=True, url=url + "/hook1", events=["violation"])
        wh2 = WebhookConfig(enabled=True, url=url + "/hook2", events=["violation"])
        dispatcher = WebhookDispatcher([wh1, wh2], _allow_private=True)

        dispatcher.dispatch(_make_event("violation"))
        capture.wait_for_requests(2)
        assert len(capture.requests) == 2


class TestWebhookEventTypes:
    """Verify the event type constants."""

    def test_all_types_present(self):
        assert "command" in WEBHOOK_EVENT_TYPES
        assert "lifecycle" in WEBHOOK_EVENT_TYPES
        assert "violation" in WEBHOOK_EVENT_TYPES
        assert "file" in WEBHOOK_EVENT_TYPES
        assert "network" in WEBHOOK_EVENT_TYPES


# ---------------------------------------------------------------------------
# AuditLogger integration
# ---------------------------------------------------------------------------

class TestAuditLoggerWebhookIntegration:
    """Verify AuditLogger dispatches to webhooks."""

    def test_audit_logger_dispatches_to_webhook(self, tmp_path, capture):
        url = capture.start()
        config = AuditConfig(
            enabled=True,
            log_dir=str(tmp_path / "audit"),
            sign_entries=False,
            webhooks=[
                WebhookConfig(enabled=True, url=url, events=["violation"]),
            ],
        )
        dispatcher = WebhookDispatcher(config.webhooks, _allow_private=True)
        logger = AuditLogger("test-sb", config, webhook_dispatcher=dispatcher)

        logger.log_violation("TEST-001", "Test violation")
        capture.wait_for_requests(1)
        assert len(capture.requests) == 1

        body = json.loads(capture.requests[0]["body"])
        assert body["type"] == "violation"

    def test_audit_logger_no_webhook_by_default(self, tmp_path):
        config = AuditConfig(
            enabled=True,
            log_dir=str(tmp_path / "audit"),
            sign_entries=False,
        )
        # No webhook_dispatcher passed — should work fine without errors
        logger = AuditLogger("test-sb", config)
        logger.log_lifecycle("test_event")


# ---------------------------------------------------------------------------
# WebhookConfig in schema
# ---------------------------------------------------------------------------

class TestWebhookConfig:
    """Validate WebhookConfig Pydantic model."""

    def test_defaults(self):
        wh = WebhookConfig()
        assert wh.enabled is False
        assert wh.url == ""
        assert "violation" in wh.events
        assert "lifecycle" in wh.events
        assert wh.secret is None
        assert wh.timeout_seconds == 5
        assert wh.retry_count == 2

    def test_audit_config_webhooks_field(self):
        config = AuditConfig(
            webhooks=[
                WebhookConfig(enabled=True, url="https://example.com/hook"),
            ],
        )
        assert len(config.webhooks) == 1
        assert config.webhooks[0].url == "https://example.com/hook"

    def test_audit_config_empty_webhooks_by_default(self):
        config = AuditConfig()
        assert config.webhooks == []


# ---------------------------------------------------------------------------
# SSRF / DNS rebinding protection tests
# ---------------------------------------------------------------------------

class TestValidateIp:
    """Unit tests for the _validate_ip helper."""

    def test_public_ip_allowed(self):
        is_safe, reason = _validate_ip("8.8.8.8")
        assert is_safe
        assert reason == ""

    def test_loopback_blocked(self):
        is_safe, reason = _validate_ip("127.0.0.1")
        assert not is_safe
        assert "blocked" in reason.lower()

    def test_private_10_blocked(self):
        is_safe, reason = _validate_ip("10.0.0.1")
        assert not is_safe
        assert "Private" in reason

    def test_private_192_blocked(self):
        is_safe, reason = _validate_ip("192.168.1.1")
        assert not is_safe
        assert "Private" in reason

    def test_link_local_blocked(self):
        is_safe, reason = _validate_ip("169.254.1.1")
        assert not is_safe
        # link-local is a subset of private on some Python versions
        assert not is_safe

    def test_metadata_endpoint_blocked(self):
        is_safe, reason = _validate_ip("169.254.169.254")
        assert not is_safe

    def test_ipv6_loopback_blocked(self):
        is_safe, reason = _validate_ip("::1")
        assert not is_safe
        assert "blocked" in reason.lower()

    def test_unparseable_ip(self):
        is_safe, reason = _validate_ip("not-an-ip")
        assert not is_safe
        assert "Unparseable" in reason


class TestResolveAndValidate:
    """Tests for _resolve_and_validate (DNS resolve + IP validation)."""

    def test_rejects_private_hostname(self, monkeypatch):
        """If DNS resolves to a private IP, the URL is rejected."""
        monkeypatch.setattr(
            socket, "getaddrinfo",
            lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
        )
        ip, hostname, reason = _resolve_and_validate("https://evil.example.com/hook")
        assert ip is None
        assert "blocked" in reason.lower()

    def test_returns_pinned_ip_for_public(self, monkeypatch):
        """A public IP is returned for pinning."""
        monkeypatch.setattr(
            socket, "getaddrinfo",
            lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
        )
        ip, hostname, reason = _resolve_and_validate("https://example.com/hook")
        assert ip == "93.184.216.34"
        assert hostname == "example.com"
        assert reason == ""

    def test_rejects_dual_stack_with_private(self, monkeypatch):
        """If any resolved IP is private, the whole URL is rejected."""
        monkeypatch.setattr(
            socket, "getaddrinfo",
            lambda *a, **kw: [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443)),
            ],
        )
        ip, hostname, reason = _resolve_and_validate("https://example.com/hook")
        assert ip is None
        assert "Private" in reason

    def test_rejects_bad_scheme(self):
        ip, hostname, reason = _resolve_and_validate("ftp://example.com/hook")
        assert ip is None
        assert "scheme" in reason.lower()

    def test_rejects_no_hostname(self):
        ip, hostname, reason = _resolve_and_validate("https:///no-host")
        assert ip is None

    def test_dns_failure(self, monkeypatch):
        monkeypatch.setattr(
            socket, "getaddrinfo",
            lambda *a, **kw: (_ for _ in ()).throw(socket.gaierror("nope")),
        )
        ip, hostname, reason = _resolve_and_validate("https://nonexistent.invalid/hook")
        assert ip is None
        assert "DNS" in reason


class TestIpPinnedDelivery:
    """Verify that the dispatcher uses the pinned IP path when SSRF protection is on."""

    def test_pinned_delivery_to_http_server(self, capture, monkeypatch):
        """With _allow_private=False, the dispatcher resolves, validates, and
        connects to the pinned IP.  We monkeypatch DNS to return 127.0.0.1
        (which would normally be blocked) but also patch _validate_ip to allow
        it so we can test the IP-pinned HTTP path end-to-end."""
        url = capture.start()
        # Extract port from the capture URL
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        port = parsed.port

        # Patch getaddrinfo to return 127.0.0.1 (the capture server)
        monkeypatch.setattr(
            socket, "getaddrinfo",
            lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))],
        )
        # Patch _validate_ip to allow 127.0.0.1 for this test
        import lasso.core.webhooks as webhooks_mod
        original_validate = webhooks_mod._validate_ip
        monkeypatch.setattr(
            webhooks_mod, "_validate_ip",
            lambda ip_str: (True, "") if ip_str == "127.0.0.1" else original_validate(ip_str),
        )

        wh = WebhookConfig(
            enabled=True, url=f"http://test-webhook.example.com:{port}/hook",
            events=["violation"],
        )
        # _allow_private=False to exercise the IP-pinned code path
        dispatcher = WebhookDispatcher([wh], _allow_private=False)

        event = _make_event("violation")
        dispatcher.dispatch(event)
        capture.wait_for_requests(1)

        assert len(capture.requests) == 1
        req = capture.requests[0]
        # Verify the Host header was set to the original hostname, not the IP
        assert req["headers"].get("Host") == f"test-webhook.example.com:{port}"
        body = json.loads(req["body"])
        assert body["type"] == "violation"

    def test_ssrf_blocked_no_delivery(self, capture, monkeypatch):
        """When DNS resolves to a private IP, delivery is blocked entirely."""
        url = capture.start()
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        port = parsed.port

        # DNS resolves to a private IP
        monkeypatch.setattr(
            socket, "getaddrinfo",
            lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port))],
        )

        wh = WebhookConfig(
            enabled=True, url=f"http://evil.example.com:{port}/hook",
            events=["violation"],
        )
        dispatcher = WebhookDispatcher([wh], _allow_private=False)

        event = _make_event("violation")
        dispatcher.dispatch(event)
        dispatcher.close()  # wait for threads to finish

        # No request should have been made
        assert len(capture.requests) == 0


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------

