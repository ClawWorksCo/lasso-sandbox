"""Tests for the Flask web dashboard — routes, security headers, and API."""

import json

import pytest

flask = pytest.importorskip("flask", reason="Flask is required for dashboard tests")

from lasso.config.defaults import evaluation_profile
from lasso.dashboard.app import create_app

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TEST_CSRF_TOKEN = "test-csrf-token-for-dashboard-tests"


def _seed_csrf(client):
    """Seed a CSRF token into the session so POST requests pass validation."""
    with client.session_transaction() as sess:
        sess["csrf_token"] = _TEST_CSRF_TOKEN


def _post_with_csrf(client, url, data=None, **kwargs):
    """Make a POST request with a valid CSRF token."""
    _seed_csrf(client)
    if data is None:
        data = {}
    data["csrf_token"] = _TEST_CSRF_TOKEN
    return client.post(url, data=data, **kwargs)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _public_mode(monkeypatch):
    """Run all dashboard tests in public mode (auth tested separately)."""
    monkeypatch.setenv("LASSO_DASHBOARD_PUBLIC", "1")


@pytest.fixture
def app(tmp_path):
    """Create a Flask app in test mode."""
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def app_with_sandbox(tmp_path):
    """Flask app with a running sandbox already registered."""
    application = create_app()
    application.config["TESTING"] = True

    registry = application.config["REGISTRY"]
    profile = evaluation_profile(str(tmp_path), name="test-sandbox")
    profile.audit.log_dir = str(tmp_path / "audit")
    sb = registry.create(profile)
    sb.start()

    return application, sb


@pytest.fixture
def client_with_sandbox(app_with_sandbox):
    """Test client with a running sandbox."""
    application, sb = app_with_sandbox
    return application.test_client(), sb


# ---------------------------------------------------------------------------
# Basic route responses
# ---------------------------------------------------------------------------

class TestBasicRoutes:
    def test_index_returns_200(self, client):
        resp = client.get("/")
        assert resp.status_code == 200

    def test_profiles_returns_200(self, client):
        resp = client.get("/profiles")
        assert resp.status_code == 200

    def test_check_returns_200(self, client):
        resp = client.get("/check")
        assert resp.status_code == 200

    def test_nonexistent_sandbox_returns_404(self, client):
        resp = client.get("/sandbox/nonexistent")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Sandbox creation
# ---------------------------------------------------------------------------

class TestSandboxCreation:
    def test_create_sandbox_redirects(self, client, tmp_path):
        resp = _post_with_csrf(client, "/sandbox/create", data={
            "profile": "evaluation",
            "working_dir": str(tmp_path),
        })
        assert resp.status_code == 302  # redirect

    def test_create_sandbox_appears_in_registry(self, app, tmp_path):
        with app.test_client() as c:
            _post_with_csrf(c, "/sandbox/create", data={
                "profile": "evaluation",
                "working_dir": str(tmp_path),
            })
            registry = app.config["REGISTRY"]
            sandboxes = registry.list_all()
            assert len(sandboxes) >= 1

    def test_create_without_profile_redirects(self, client, tmp_path):
        resp = _post_with_csrf(client, "/sandbox/create", data={
            "profile": "",
            "working_dir": str(tmp_path),
        })
        assert resp.status_code == 302  # redirects to index


# ---------------------------------------------------------------------------
# Sandbox detail and audit pages
# ---------------------------------------------------------------------------

class TestSandboxDetail:
    def test_sandbox_detail_returns_200(self, client_with_sandbox):
        client, sb = client_with_sandbox
        resp = client.get(f"/sandbox/{sb.id}")
        assert resp.status_code == 200

    def test_sandbox_audit_returns_200(self, client_with_sandbox):
        client, sb = client_with_sandbox
        resp = client.get(f"/audit/{sb.id}")
        assert resp.status_code == 200

    def test_audit_for_nonexistent_returns_404(self, client):
        resp = client.get("/audit/does-not-exist")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Sandbox stop
# ---------------------------------------------------------------------------

class TestSandboxStop:
    def test_stop_sandbox_redirects(self, client_with_sandbox):
        client, sb = client_with_sandbox
        resp = _post_with_csrf(client, f"/sandbox/{sb.id}/stop")
        assert resp.status_code == 302

    def test_stop_nonexistent_returns_404(self, client):
        resp = _post_with_csrf(client, "/sandbox/nonexistent-id/stop")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------

class TestAPI:
    def test_api_sandboxes_returns_json_list(self, client):
        resp = client.get("/api/sandboxes")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert isinstance(data, list)

    def test_api_sandboxes_includes_created_sandbox(self, client_with_sandbox):
        client, sb = client_with_sandbox
        resp = client.get("/api/sandboxes")
        data = json.loads(resp.data)
        ids = [s["id"] for s in data]
        assert sb.id in ids

    def test_api_sandbox_status(self, client_with_sandbox):
        client, sb = client_with_sandbox
        resp = client.get(f"/api/sandbox/{sb.id}/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["id"] == sb.id

    def test_api_sandbox_status_not_found(self, client):
        resp = client.get("/api/sandbox/no-such-id/status")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

class TestSecurityHeaders:
    def test_x_content_type_options(self, client):
        resp = client.get("/")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options(self, client):
        resp = client.get("/")
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_security_headers_on_api(self, client):
        resp = client.get("/api/sandboxes")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_security_headers_on_profiles(self, client):
        resp = client.get("/profiles")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"


# ---------------------------------------------------------------------------
# Command length limit
# ---------------------------------------------------------------------------

class TestCommandLengthLimit:
    def test_exec_command_too_long(self, client_with_sandbox):
        client, sb = client_with_sandbox
        long_command = "a" * 4097
        resp = _post_with_csrf(client, f"/sandbox/{sb.id}/exec", data={
            "command": long_command,
        })
        assert resp.status_code == 200  # returns HTMX partial, not HTTP error
        text = resp.data.decode()
        assert "too long" in text.lower() or "4096" in text

    def test_exec_valid_length_command(self, client_with_sandbox):
        client, sb = client_with_sandbox
        resp = _post_with_csrf(client, f"/sandbox/{sb.id}/exec", data={
            "command": "ls",
        })
        assert resp.status_code == 200
        text = resp.data.decode()
        assert "too long" not in text.lower()
