"""LASSO Dashboard -- Flask application factory.

Usage:
    from lasso.dashboard.app import create_app
    app = create_app(registry=my_registry, backend=my_backend)
    app.run(debug=True)

Requires: pip install flask
"""

from __future__ import annotations

import atexit
import os
import secrets
from pathlib import Path
from typing import Any

try:
    from flask import Flask
except ImportError:
    raise ImportError(
        "Flask is required for the dashboard. "
        "Install it with: pip install lasso-sandbox[dashboard]"
    )

from lasso.core.sandbox import SandboxRegistry
from lasso.dashboard.auth import init_dashboard_auth
from lasso.dashboard.filters import _register_filters
from lasso.dashboard.helpers import (  # noqa: F401 — re-export for backward compat
    _validate_working_dir,
    read_audit_log,
)
from lasso.dashboard.routes import dashboard_bp

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app(
    registry: SandboxRegistry | None = None,
    backend: Any | None = None,
) -> Flask:
    """Create and configure the LASSO dashboard Flask application.

    Args:
        registry: A SandboxRegistry instance for managing sandboxes.
                  A new empty registry is created if None.
        backend:  A ContainerBackend instance (Docker, Podman, etc.).
                  Native subprocess mode is used if None.

    Returns:
        A configured Flask application.

    Example:
        app = create_app()
        app.run(host="127.0.0.1", port=5000, debug=True)
    """
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
    )

    app.config["REGISTRY"] = registry or SandboxRegistry(backend=backend)
    app.config["BACKEND"] = backend
    app.config["SECRET_KEY"] = os.environ.get("LASSO_SECRET_KEY", secrets.token_hex(32))

    app.register_blueprint(dashboard_bp)

    # Dashboard authentication + CSRF
    init_dashboard_auth(app)

    _register_filters(app)

    # Session cookie hardening
    app.config["SESSION_COOKIE_SECURE"] = not app.debug
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["PERMANENT_SESSION_LIFETIME"] = 3600

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"

        # CORS -- no cross-origin access (omit Access-Control-Allow-Origin
        # entirely; Flask's default is to not set CORS headers, which
        # causes browsers to block all cross-origin requests).
        # Do NOT set Access-Control-Allow-Origin to "null" -- that value
        # is exploitable via sandboxed iframes and data: URIs.

        # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )

        return response

    # Register atexit handler to gracefully shut down registry when Flask stops
    reg = app.config["REGISTRY"]
    atexit.register(reg.shutdown)

    return app


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Auto-detect container backend for standalone mode so that
    # existing sandboxes can be reconnected from the state store.
    _backend = None
    try:
        from lasso.backends.detect import detect_backend
        _backend = detect_backend()
        if _backend:
            info = _backend.get_info()
            print(f"Backend: {info.get('runtime', 'container')} {info.get('version', '')}")
    except Exception:
        pass
    app = create_app(backend=_backend)
    print("LASSO Dashboard starting on http://127.0.0.1:5000")
    print("Note: pip install flask  (if not already installed)")
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG", "0") == "1")
