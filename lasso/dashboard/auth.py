"""Dashboard authentication and CSRF protection.

Provides:
- Token-based login for the web dashboard
- Session management via Flask sessions
- CSRF protection for all POST requests to dashboard routes
- Public mode bypass when LASSO_DASHBOARD_AUTH is not set

The dashboard token is generated on first run and stored at
~/.lasso/dashboard_token.  It is printed to the console so the
operator can copy it into the login form.
"""

from __future__ import annotations

import functools
import logging
import os
import secrets
from pathlib import Path

from flask import (
    Blueprint,
    Flask,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup

from lasso.utils.paths import get_lasso_dir

logger = logging.getLogger("lasso.dashboard.auth")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_TOKEN_FILE = get_lasso_dir() / "dashboard_token"


# ---------------------------------------------------------------------------
# Dashboard auth manager
# ---------------------------------------------------------------------------

class DashboardAuth:
    """Manages a single dashboard access token stored on disk."""

    def __init__(self, token_file: Path | None = None):
        self._token_file = token_file or DEFAULT_TOKEN_FILE
        self._token: str | None = None

    @property
    def token(self) -> str:
        """Return the current token, generating one if needed."""
        if self._token is None:
            self._token = self._load_or_create()
        return self._token

    def _load_or_create(self) -> str:
        """Load existing token from disk or generate a new one."""
        if self._token_file.exists():
            stored = self._token_file.read_text().strip()
            if stored:
                return stored

        # Generate new token
        new_token = secrets.token_urlsafe(32)
        self._token_file.parent.mkdir(parents=True, exist_ok=True)
        self._token_file.write_text(new_token)
        # Restrict permissions (owner read/write only)
        try:
            self._token_file.chmod(0o600)
        except OSError:
            pass  # Windows may not support chmod
        logger.info("Generated new dashboard token at %s", self._token_file)
        return new_token

    def validate(self, candidate: str) -> bool:
        """Check if a candidate token matches the stored token.

        Uses constant-time comparison to prevent timing attacks.
        """
        return secrets.compare_digest(candidate, self.token)


# ---------------------------------------------------------------------------
# Public mode check
# ---------------------------------------------------------------------------

def is_public_mode() -> bool:
    """Return True if dashboard auth is not required.

    The dashboard binds to localhost by default and is only accessible
    from the developer's own machine, so authentication is off by default.
    Set LASSO_DASHBOARD_AUTH=1 to require token login (e.g., when
    exposing the dashboard through a reverse proxy).
    """
    if os.environ.get("LASSO_DASHBOARD_AUTH", "").strip() == "1":
        return False
    return True


# ---------------------------------------------------------------------------
# Login decorator
# ---------------------------------------------------------------------------

def require_login(f):
    """Decorator: redirect to /login if user is not authenticated.

    Skipped when LASSO_DASHBOARD_AUTH is not set (localhost-only mode).
    """

    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if is_public_mode():
            return f(*args, **kwargs)
        if not session.get("dashboard_authenticated"):
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)

    return decorated


# ---------------------------------------------------------------------------
# CSRF protection
# ---------------------------------------------------------------------------

def _generate_csrf_token() -> str:
    """Return the CSRF token for the current session, creating one if needed."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def csrf_token_html() -> Markup:
    """Return a hidden <input> containing the CSRF token for use in templates."""
    from markupsafe import escape
    token = escape(_generate_csrf_token())
    return Markup(  # nosec B704 — token is escaped via markupsafe.escape() above
        f'<input type="hidden" name="csrf_token" value="{token}">'
    )


def _is_api_route() -> bool:
    """Return True if the current request targets an API route.

    NOTE: As of v1.2.1 the REST API has been removed and there are no
    /api/ routes that need CSRF exemption.  This always returns False
    so that all POST routes go through CSRF validation.
    """
    return False


def validate_csrf() -> tuple | None:
    """Before-request handler: validate CSRF token on dashboard POST requests.

    Returns None to allow the request, or a (response, status_code) tuple
    to reject it.
    """
    if request.method != "POST":
        return None

    # API routes use their own auth (API keys), not CSRF
    if _is_api_route():
        return None

    # [API-1/API-2] CSRF validation is ALWAYS active, even in public mode.
    # Public mode only skips the login requirement (via require_login),
    # not CSRF protection. Without CSRF, an attacker can craft malicious
    # forms that trigger sandbox actions on behalf of a local user.

    # Login POST needs CSRF but not session auth
    expected = session.get("csrf_token", "")
    submitted = request.form.get("csrf_token", "")

    if not expected or not secrets.compare_digest(submitted, expected):
        return "CSRF token missing or invalid.", 403

    return None


# ---------------------------------------------------------------------------
# Auth blueprint (login/logout routes)
# ---------------------------------------------------------------------------

auth_bp = Blueprint(
    "auth",
    __name__,
    template_folder="templates",
)


def _github_oauth_available() -> bool:
    """Check if GitHub OAuth login is configured (client_id is set)."""
    return bool(os.environ.get("LASSO_GITHUB_CLIENT_ID", ""))


def _validate_github_token(token: str) -> bool:
    """Validate a GitHub token by calling the user API."""
    try:
        from lasso.auth.github import GitHubAuth
        auth = GitHubAuth()
        info = auth._http_get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {token}"},
        )
        return bool(info.get("login"))
    except Exception:
        return False


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Login page and form handler."""
    error = None
    github_available = _github_oauth_available()

    if request.method == "GET":
        # Ensure CSRF token exists for the login form
        _generate_csrf_token()
        if is_public_mode() or session.get("dashboard_authenticated"):
            return redirect(url_for("dashboard.index"))
        return render_template(
            "login.html",
            error=error,
            csrf_token=csrf_token_html,
            github_available=github_available,
        )

    # POST — validate CSRF first
    expected = session.get("csrf_token", "")
    submitted = request.form.get("csrf_token", "")
    if not expected or not secrets.compare_digest(submitted, expected):
        error = "Invalid request. Please try again."
        return render_template(
            "login.html", error=error, csrf_token=csrf_token_html,
            github_available=github_available,
        ), 403

    # Check if this is a GitHub token login
    login_method = request.form.get("login_method", "token")

    if login_method == "github":
        # Try to use the stored GitHub token from CLI auth
        try:
            from lasso.auth.github import GitHubAuth
            gh_auth = GitHubAuth()
            gh_token = gh_auth.get_token()
            if gh_token and _validate_github_token(gh_token):
                session["dashboard_authenticated"] = True
                session["auth_method"] = "github"
                session["csrf_token"] = secrets.token_hex(32)
                return redirect(url_for("dashboard.index"))
            else:
                error = "No valid GitHub token found. Run 'lasso auth login' first."
        except Exception:
            error = "GitHub authentication failed. Run 'lasso auth login' first."

        return render_template(
            "login.html", error=error, csrf_token=csrf_token_html,
            github_available=github_available,
        ), 401

    # Standard token-based login
    token = request.form.get("token", "").strip()
    auth = _get_dashboard_auth()

    if auth.validate(token):
        session["dashboard_authenticated"] = True
        session["auth_method"] = "token"
        # Rotate CSRF token on login
        session["csrf_token"] = secrets.token_hex(32)
        return redirect(url_for("dashboard.index"))

    error = "Invalid access token."
    return render_template(
        "login.html", error=error, csrf_token=csrf_token_html,
        github_available=github_available,
    ), 401


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Clear session and redirect to login.

    Uses POST to prevent CSRF logout attacks (a malicious page cannot
    trigger a POST with a valid CSRF token).
    """
    session.clear()
    return redirect(url_for("auth.login"))


# ---------------------------------------------------------------------------
# Flask app integration
# ---------------------------------------------------------------------------

def _get_dashboard_auth() -> DashboardAuth:
    """Get or create the DashboardAuth instance from the Flask app config."""
    from flask import current_app
    auth = current_app.config.get("DASHBOARD_AUTH")
    if auth is None:
        token_file = current_app.config.get("DASHBOARD_TOKEN_FILE")
        auth = DashboardAuth(token_file=Path(token_file) if token_file else None)
        current_app.config["DASHBOARD_AUTH"] = auth
    return auth


def init_dashboard_auth(app: Flask) -> None:
    """Register authentication and CSRF protection on a Flask app.

    Call this from the app factory after registering blueprints.
    """
    app.register_blueprint(auth_bp)

    # Make csrf_token() available in all templates
    app.jinja_env.globals["csrf_token"] = csrf_token_html

    # Register CSRF validation as before_request
    @app.before_request
    def _csrf_check():
        return validate_csrf()

    # Print dashboard token on startup (if not public mode)
    if not is_public_mode():
        auth = DashboardAuth(
            token_file=Path(app.config["DASHBOARD_TOKEN_FILE"])
            if app.config.get("DASHBOARD_TOKEN_FILE")
            else None
        )
        app.config["DASHBOARD_AUTH"] = auth
        token = auth.token
        logger.debug("Dashboard access token generated (ends ...%s)", token[-4:] if len(token) >= 4 else "****")
        print(f"\n  LASSO Dashboard access token: {token}")
        print("  Use this token to log in at /login\n")
