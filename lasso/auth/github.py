"""GitHub OAuth Device Flow authentication.

Used for GitHub token acquisition. Opens a browser for the user to
authorize, then stores the token for use with OpenCode and LASSO
dashboard.

Device Flow (RFC 8628):
  1. POST https://github.com/login/device/code  -> user_code + device_code
  2. User visits verification_uri and enters user_code
  3. Poll https://github.com/login/oauth/access_token until authorized
  4. Store token securely on disk

References:
  - https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#device-flow
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.parse
import urllib.request
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lasso.utils.paths import get_lasso_dir

logger = logging.getLogger("lasso.auth.github")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEVICE_CODE_URL = "https://github.com/login/device/code"
TOKEN_URL = "https://github.com/login/oauth/access_token"
USER_API_URL = "https://api.github.com/user"

DEFAULT_SCOPES = "read:user read:org"

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AuthError(Exception):
    """Base class for authentication errors."""


class DeviceFlowError(AuthError):
    """Error during the device flow process."""


class TokenExpiredError(AuthError):
    """The stored token has expired or been revoked.

    Note: GitHub OAuth tokens do not have a built-in expiry field, so
    this exception is provided for callers that implement their own
    expiration logic (e.g., token age checks or API 401 detection).
    LASSO itself does not currently raise this exception.
    """


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class DeviceCodeResponse:
    """Response from the device code request."""
    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    interval: int


@dataclass
class TokenInfo:
    """Stored token information."""
    access_token: str
    token_type: str
    scope: str
    created_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "scope": self.scope,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TokenInfo:
        return cls(
            access_token=data["access_token"],
            token_type=data.get("token_type", "bearer"),
            scope=data.get("scope", ""),
            created_at=data.get("created_at", 0.0),
        )


# ---------------------------------------------------------------------------
# HTTP helper (injectable for testing)
# ---------------------------------------------------------------------------


def _default_http_post(url: str, data: dict[str, str], headers: dict[str, str] | None = None) -> dict[str, Any]:
    """POST to a URL with form data, return parsed JSON response.

    Uses urllib.request so we have zero external dependencies.
    """
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    req_headers = {"Accept": "application/json"}
    if headers:
        req_headers.update(headers)

    request_obj = urllib.request.Request(url, data=encoded, headers=req_headers, method="POST")
    with urllib.request.urlopen(request_obj, timeout=30) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body)


def _default_http_get(url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    """GET a URL, return parsed JSON response."""
    req_headers = {"Accept": "application/json"}
    if headers:
        req_headers.update(headers)

    request_obj = urllib.request.Request(url, headers=req_headers, method="GET")
    with urllib.request.urlopen(request_obj, timeout=30) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body)


# ---------------------------------------------------------------------------
# GitHubAuth
# ---------------------------------------------------------------------------


class GitHubAuth:
    """GitHub OAuth Device Flow authentication.

    Used for GitHub token acquisition.
    Opens a browser for the user to authorize, then stores
    the token for use with OpenCode and LASSO.
    """

    CLIENT_ID_ENV = "LASSO_GITHUB_CLIENT_ID"

    def __init__(
        self,
        client_id: str | None = None,
        token_path: Path | None = None,
        scopes: str = DEFAULT_SCOPES,
        http_post: Callable | None = None,
        http_get: Callable | None = None,
        open_browser: Callable | None = None,
    ):
        self.client_id = client_id or os.environ.get(self.CLIENT_ID_ENV, "")
        self.token_path = Path(token_path) if token_path else (get_lasso_dir() / "github_token.json")
        self.scopes = scopes

        # Injectable dependencies for testing
        self._http_post = http_post or _default_http_post
        self._http_get = http_get or _default_http_get
        self._open_browser = open_browser or webbrowser.open

    # ------------------------------------------------------------------
    # Device Flow
    # ------------------------------------------------------------------

    def request_device_code(self) -> DeviceCodeResponse:
        """Step 1: Request a device code from GitHub.

        Returns a DeviceCodeResponse with the user_code to display
        and device_code for polling.
        """
        if not self.client_id:
            raise DeviceFlowError(
                f"No GitHub OAuth client ID configured. "
                f"Set {self.CLIENT_ID_ENV} environment variable or pass client_id."
            )

        data = {
            "client_id": self.client_id,
            "scope": self.scopes,
        }

        resp = self._http_post(DEVICE_CODE_URL, data)

        if "error" in resp:
            raise DeviceFlowError(
                f"Device code request failed: {resp.get('error_description', resp['error'])}"
            )

        return DeviceCodeResponse(
            device_code=resp["device_code"],
            user_code=resp["user_code"],
            verification_uri=resp["verification_uri"],
            expires_in=resp.get("expires_in", 900),
            interval=resp.get("interval", 5),
        )

    def poll_for_token(self, device_code: str, interval: int = 5, expires_in: int = 900) -> TokenInfo:
        """Step 3: Poll GitHub until the user authorizes (or timeout).

        Handles slow_down responses by increasing the interval.
        """
        if not self.client_id:
            raise DeviceFlowError("No client_id configured.")

        deadline = time.monotonic() + expires_in
        poll_interval = interval

        while time.monotonic() < deadline:
            time.sleep(poll_interval)

            data = {
                "client_id": self.client_id,
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            }

            resp = self._http_post(TOKEN_URL, data)

            if "access_token" in resp:
                token_info = TokenInfo(
                    access_token=resp["access_token"],
                    token_type=resp.get("token_type", "bearer"),
                    scope=resp.get("scope", ""),
                    created_at=time.time(),
                )
                return token_info

            error = resp.get("error", "")

            if error == "authorization_pending":
                continue
            elif error == "slow_down":
                poll_interval += 5
                continue
            elif error == "expired_token":
                raise DeviceFlowError("Device code expired. Please try again.")
            elif error == "access_denied":
                raise DeviceFlowError("Authorization was denied by the user.")
            else:
                raise DeviceFlowError(
                    f"Token poll error: {resp.get('error_description', error)}"
                )

        raise DeviceFlowError("Device code expired (timeout). Please try again.")

    def login(self) -> TokenInfo:
        """Start the full device flow login.

        1. Request device code
        2. Display code and open browser
        3. Poll for token
        4. Save token to disk

        Returns the TokenInfo on success.
        """
        # Check for GITHUB_TOKEN env var override
        env_token = os.environ.get("GITHUB_TOKEN")
        if env_token:
            logger.info("Using GITHUB_TOKEN from environment (skipping device flow).")
            token_info = TokenInfo(
                access_token=env_token,
                token_type="bearer",
                scope="env_override",
                created_at=time.time(),
            )
            # Don't persist env-sourced tokens to disk — the env var is
            # the source of truth and the user did not consent to storage.
            return token_info

        # Full device flow
        device = self.request_device_code()

        # Open browser
        try:
            self._open_browser(device.verification_uri)
        except Exception:
            pass  # Browser open is best-effort

        # Poll
        token_info = self.poll_for_token(
            device.device_code,
            interval=device.interval,
            expires_in=device.expires_in,
        )

        self._save_token(token_info)
        return token_info

    # ------------------------------------------------------------------
    # Token storage
    # ------------------------------------------------------------------

    def _save_token(self, token_info: TokenInfo) -> None:
        """Save token to OS keyring (preferred) or disk with restricted permissions."""
        data = json.dumps(token_info.to_dict())

        # Try OS keyring first
        try:
            import keyring
            keyring.set_password("lasso", "github_token", data)
            logger.debug("Token saved to OS keyring")
            return
        except Exception:
            pass  # Fall through to file-based storage

        # Fallback: file with restrictive permissions.
        # Set permissions BEFORE writing to avoid a window where the file
        # is world-readable.  Use os.open + os.fdopen for atomic create
        # with mode 0o600; fall back to write-then-chmod on Windows.
        self.token_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(
                str(self.token_path),
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            with os.fdopen(fd, "w") as f:
                f.write(data)
        except OSError:
            # Windows may not support POSIX mode bits on os.open;
            # fall back to write-then-chmod.
            self.token_path.write_text(data)
            try:
                self.token_path.chmod(0o600)
            except OSError:
                pass

        logger.info("Token saved to %s", self.token_path)

    def _load_token(self) -> TokenInfo | None:
        """Load token from OS keyring (preferred) or disk."""
        # Try OS keyring first
        try:
            import keyring
            data = keyring.get_password("lasso", "github_token")
            if data:
                return TokenInfo.from_dict(json.loads(data))
        except Exception:
            pass

        # Fallback: file-based
        if self.token_path.exists():
            try:
                data = json.loads(self.token_path.read_text())
                return TokenInfo.from_dict(data)
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                logger.warning("Failed to load token from %s: %s", self.token_path, e)
        return None

    def get_token(self) -> str | None:
        """Get the stored GitHub token, or None if not logged in.

        Checks GITHUB_TOKEN env var first, then falls back to stored token.
        """
        # Env var override always takes priority
        env_token = os.environ.get("GITHUB_TOKEN")
        if env_token:
            return env_token

        token_info = self._load_token()
        if token_info:
            return token_info.access_token
        return None

    def logout(self) -> bool:
        """Remove stored token from both keyring and file. Returns True if a token was removed."""
        removed = False

        # Clear from OS keyring
        try:
            import keyring
            keyring.delete_password("lasso", "github_token")
            logger.info("Token removed from OS keyring")
            removed = True
        except Exception:
            pass  # Keyring not available or no token stored

        # Clear from file
        if self.token_path.exists():
            self.token_path.unlink()
            logger.info("Token removed from %s", self.token_path)
            removed = True

        return removed

    def is_authenticated(self) -> bool:
        """Check if a valid token exists (env var or stored)."""
        return self.get_token() is not None

    # ------------------------------------------------------------------
    # User info
    # ------------------------------------------------------------------

    def get_user_info(self) -> dict[str, Any] | None:
        """Fetch GitHub user info using stored token.

        Returns a dict with keys like login, name, email, etc.
        Returns None if not authenticated or API call fails.
        """
        token = self.get_token()
        if not token:
            return None

        try:
            return self._http_get(
                USER_API_URL,
                headers={"Authorization": f"Bearer {token}"},
            )
        except Exception as e:
            logger.warning("Failed to fetch user info: %s", e)
            return None

    # ------------------------------------------------------------------
    # Device code response (for CLI to use)
    # ------------------------------------------------------------------

    @property
    def has_client_id(self) -> bool:
        """Check if a client ID is configured."""
        return bool(self.client_id)
