"""Tests for dashboard authentication and CSRF protection."""

import os

import pytest

flask = pytest.importorskip("flask", reason="Flask is required for dashboard tests")

from lasso.dashboard.app import create_app
from lasso.dashboard.auth import DashboardAuth

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def token_file(tmp_path):
    """Path for a temporary token file."""
    return tmp_path / "dashboard_token"


@pytest.fixture
def auth(token_file):
    """A DashboardAuth instance with a temp token file."""
    return DashboardAuth(token_file=token_file)


@pytest.fixture
def app(tmp_path, token_file, monkeypatch):
    """Create a Flask app with dashboard auth enabled."""
    # Enable auth mode for these tests (default is public/no-auth)
    monkeypatch.setenv("LASSO_DASHBOARD_AUTH", "1")

    # Write a known token
    token_file.parent.mkdir(parents=True, exist_ok=True)
    token_file.write_text("test-secret-token-12345")

    application = create_app()
    application.config["TESTING"] = True
    application.config["DASHBOARD_TOKEN_FILE"] = str(token_file)
    # Re-init auth with the right token file
    from lasso.dashboard.auth import DashboardAuth
    application.config["DASHBOARD_AUTH"] = DashboardAuth(token_file=token_file)
    return application


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def known_token():
    """The token written to the token file."""
    return "test-secret-token-12345"


def _login(client, token):
    """Helper: perform login flow (GET to get CSRF, then POST)."""
    # GET login page to get a session with CSRF token
    resp = client.get("/login")
    assert resp.status_code == 200

    # Extract CSRF token from the response HTML
    html = resp.data.decode()
    import re
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "CSRF token not found in login page"
    csrf = match.group(1)

    return client.post("/login", data={
        "token": token,
        "csrf_token": csrf,
    })


# ---------------------------------------------------------------------------
# DashboardAuth unit tests
# ---------------------------------------------------------------------------

class TestDashboardAuth:
    def test_generates_token_on_first_run(self, auth, token_file):
        token = auth.token
        assert token
        assert len(token) > 20
        assert token_file.exists()
        assert token_file.read_text().strip() == token

    def test_loads_existing_token(self, token_file):
        token_file.write_text("my-preset-token")
        auth = DashboardAuth(token_file=token_file)
        assert auth.token == "my-preset-token"

    def test_validate_correct_token(self, token_file):
        token_file.write_text("correct-token")
        auth = DashboardAuth(token_file=token_file)
        assert auth.validate("correct-token") is True

    def test_validate_wrong_token(self, token_file):
        token_file.write_text("correct-token")
        auth = DashboardAuth(token_file=token_file)
        assert auth.validate("wrong-token") is False

    def test_validate_empty_token(self, token_file):
        token_file.write_text("correct-token")
        auth = DashboardAuth(token_file=token_file)
        assert auth.validate("") is False


# ---------------------------------------------------------------------------
# Login flow
# ---------------------------------------------------------------------------

class TestLogin:
    def test_login_page_returns_200(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200
        assert b"Access Token" in resp.data or b"token" in resp.data.lower()

    def test_login_with_correct_token_redirects(self, client, known_token):
        resp = _login(client, known_token)
        assert resp.status_code == 302
        assert "/login" not in resp.headers.get("Location", "")

    def test_login_with_wrong_token_returns_401(self, client):
        resp = _login(client, "wrong-token")
        assert resp.status_code == 401
        assert b"Invalid" in resp.data

    def test_authenticated_session_accesses_dashboard(self, client, known_token):
        _login(client, known_token)
        resp = client.get("/")
        assert resp.status_code == 200

    def test_logout_clears_session(self, client, known_token):
        _login(client, known_token)
        # Verify we can access dashboard
        resp = client.get("/")
        assert resp.status_code == 200

        # Logout via POST (GET is no longer accepted to prevent CSRF logout)
        # We need a CSRF token from the session; get it from a page
        import re
        page = client.get("/")
        html = page.data.decode()
        match = re.search(r'name="csrf_token" value="([^"]+)"', html)
        csrf = match.group(1) if match else ""

        resp = client.post("/logout", data={"csrf_token": csrf})
        assert resp.status_code == 302

        # Now dashboard should redirect to login
        resp = client.get("/")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_logout_get_not_allowed(self, client, known_token):
        """GET /logout should return 405 Method Not Allowed."""
        _login(client, known_token)
        resp = client.get("/logout")
        assert resp.status_code == 405


# ---------------------------------------------------------------------------
# Protected routes require login
# ---------------------------------------------------------------------------

class TestProtectedRoutes:
    def test_index_redirects_to_login(self, client):
        resp = client.get("/")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_profiles_redirects_to_login(self, client):
        resp = client.get("/profiles")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_check_redirects_to_login(self, client):
        resp = client.get("/check")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_partials_redirect_to_login(self, client):
        resp = client.get("/partials/sandbox-table")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# CSRF protection
# ---------------------------------------------------------------------------

class TestCSRF:
    def test_post_without_csrf_returns_403(self, client, known_token, tmp_path):
        """POST to a dashboard route without CSRF token is rejected."""
        _login(client, known_token)
        resp = client.post("/sandbox/create", data={
            "profile": "evaluation",
            "working_dir": str(tmp_path),
        })
        assert resp.status_code == 403

    def test_post_with_valid_csrf_succeeds(self, client, known_token, tmp_path):
        """POST with valid CSRF token is accepted."""
        _login(client, known_token)

        # GET a page to capture the CSRF token from the session
        resp = client.get("/")
        html = resp.data.decode()
        import re
        match = re.search(r'name="csrf_token" value="([^"]+)"', html)
        assert match, "CSRF token not found in page"
        csrf = match.group(1)

        resp = client.post("/sandbox/create", data={
            "profile": "evaluation",
            "working_dir": str(tmp_path),
            "csrf_token": csrf,
        })
        # Should redirect (302) on success, not 403
        assert resp.status_code == 302

    def test_post_with_wrong_csrf_returns_403(self, client, known_token, tmp_path):
        """POST with an invalid CSRF token is rejected."""
        _login(client, known_token)

        resp = client.post("/sandbox/create", data={
            "profile": "evaluation",
            "working_dir": str(tmp_path),
            "csrf_token": "totally-wrong-token",
        })
        assert resp.status_code == 403

    def test_stop_without_csrf_returns_403(self, client, known_token):
        """POST to stop endpoint without CSRF is rejected."""
        _login(client, known_token)
        resp = client.post("/sandbox/some-id/stop", data={})
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# API routes do NOT require dashboard auth
# ---------------------------------------------------------------------------

class TestAPIRoutesExempt:
    def test_api_sandboxes_requires_login(self, client):
        """Dashboard JSON API routes require login."""
        resp = client.get("/api/sandboxes")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_api_sandbox_status_requires_login(self, client):
        """Dashboard JSON API routes require login."""
        resp = client.get("/api/sandbox/nonexistent/status")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_api_sandboxes_json_requires_login(self, client):
        """Dashboard JSON API sandboxes list requires login."""
        resp = client.get("/api/sandboxes")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# Public mode (LASSO_DASHBOARD_PUBLIC=1)
# ---------------------------------------------------------------------------

class TestPublicMode:
    def test_public_mode_skips_auth(self, tmp_path, token_file):
        """When LASSO_DASHBOARD_PUBLIC=1, no login required."""
        token_file.write_text("some-token")
        os.environ["LASSO_DASHBOARD_PUBLIC"] = "1"
        try:
            application = create_app()
            application.config["TESTING"] = True
            application.config["DASHBOARD_TOKEN_FILE"] = str(token_file)
            application.config["DASHBOARD_AUTH"] = DashboardAuth(token_file=token_file)
            with application.test_client() as c:
                resp = c.get("/")
                assert resp.status_code == 200
        finally:
            os.environ.pop("LASSO_DASHBOARD_PUBLIC", None)

    def test_public_mode_enforces_csrf_on_post(self, tmp_path, token_file):
        """[API-1/API-2] CSRF must be enforced even in public mode."""
        token_file.write_text("some-token")
        os.environ["LASSO_DASHBOARD_PUBLIC"] = "1"
        try:
            application = create_app()
            application.config["TESTING"] = True
            application.config["DASHBOARD_TOKEN_FILE"] = str(token_file)
            application.config["DASHBOARD_AUTH"] = DashboardAuth(token_file=token_file)
            with application.test_client() as c:
                # POST without CSRF token should be rejected
                resp = c.post("/sandbox/create", data={
                    "profile": "evaluation",
                    "working_dir": str(tmp_path),
                })
                assert resp.status_code == 403

                # POST with valid CSRF token should succeed
                with c.session_transaction() as sess:
                    sess["csrf_token"] = "test-csrf-public"
                resp = c.post("/sandbox/create", data={
                    "profile": "evaluation",
                    "working_dir": str(tmp_path),
                    "csrf_token": "test-csrf-public",
                })
                assert resp.status_code != 403
        finally:
            os.environ.pop("LASSO_DASHBOARD_PUBLIC", None)
