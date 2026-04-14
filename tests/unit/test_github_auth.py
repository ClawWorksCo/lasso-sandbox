"""Tests for GitHub Device Flow authentication.

Tests token storage, retrieval, permissions, device flow HTTP formatting,
user info fetch, env var override, and CLI auth commands.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from lasso.auth.github import (
    DeviceFlowError,
    GitHubAuth,
    TokenInfo,
)
from lasso.cli.main import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def token_path(tmp_path):
    """Temporary token file path."""
    return tmp_path / "github_token.json"


@pytest.fixture
def sample_token_info():
    """A sample TokenInfo for testing."""
    return TokenInfo(
        access_token="ghp_test1234567890abcdef",
        token_type="bearer",
        scope="read:user read:org",
        created_at=1700000000.0,
    )


@pytest.fixture
def mock_http_post():
    """A mock HTTP POST function."""
    return MagicMock()


@pytest.fixture
def mock_http_get():
    """A mock HTTP GET function."""
    return MagicMock()


@pytest.fixture
def auth(token_path, mock_http_post, mock_http_get):
    """A GitHubAuth instance with mocked HTTP and test token path."""
    return GitHubAuth(
        client_id="test-client-id",
        token_path=token_path,
        http_post=mock_http_post,
        http_get=mock_http_get,
        open_browser=MagicMock(),
    )


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Remove GITHUB_TOKEN from environment for clean tests."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("LASSO_GITHUB_CLIENT_ID", raising=False)


@pytest.fixture(autouse=True)
def _disable_keyring(monkeypatch):
    """Disable keyring so tests exercise file-based token storage."""
    import builtins
    _real_import = builtins.__import__

    def _no_keyring(name, *args, **kwargs):
        if name == "keyring":
            raise ImportError("keyring disabled for tests")
        return _real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_keyring)


@pytest.fixture(autouse=True)
def _reset_cli_registry():
    """Reset the global CLI registry between tests."""
    import lasso.cli.helpers as cli_helpers
    old = cli_helpers._registry
    cli_helpers._registry = None
    yield
    cli_helpers._registry = old


# ---------------------------------------------------------------------------
# TokenInfo serialization
# ---------------------------------------------------------------------------

class TestTokenInfo:

    def test_to_dict(self, sample_token_info):
        d = sample_token_info.to_dict()
        assert d["access_token"] == "ghp_test1234567890abcdef"
        assert d["token_type"] == "bearer"
        assert d["scope"] == "read:user read:org"
        assert d["created_at"] == 1700000000.0

    def test_from_dict(self):
        data = {
            "access_token": "ghp_abc",
            "token_type": "bearer",
            "scope": "read:user",
            "created_at": 1700000000.0,
        }
        info = TokenInfo.from_dict(data)
        assert info.access_token == "ghp_abc"
        assert info.token_type == "bearer"

    def test_from_dict_defaults(self):
        data = {"access_token": "ghp_minimal"}
        info = TokenInfo.from_dict(data)
        assert info.access_token == "ghp_minimal"
        assert info.token_type == "bearer"
        assert info.scope == ""
        assert info.created_at == 0.0


# ---------------------------------------------------------------------------
# Token storage and retrieval
# ---------------------------------------------------------------------------

class TestTokenStorage:

    def test_save_and_load_token(self, auth, sample_token_info, token_path):
        auth._save_token(sample_token_info)

        assert token_path.exists()
        data = json.loads(token_path.read_text())
        assert data["access_token"] == sample_token_info.access_token

        loaded = auth._load_token()
        assert loaded is not None
        assert loaded.access_token == sample_token_info.access_token
        assert loaded.scope == sample_token_info.scope

    def test_load_token_missing_file(self, auth):
        assert auth._load_token() is None

    def test_load_token_corrupt_json(self, auth, token_path):
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text("not json at all{{{")
        assert auth._load_token() is None

    def test_load_token_missing_keys(self, auth, token_path):
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text('{"foo": "bar"}')
        assert auth._load_token() is None

    def test_get_token_from_file(self, auth, sample_token_info):
        auth._save_token(sample_token_info)
        assert auth.get_token() == sample_token_info.access_token

    def test_get_token_returns_none_when_no_token(self, auth):
        assert auth.get_token() is None

    def test_save_creates_parent_directory(self, tmp_path, sample_token_info):
        deep_path = tmp_path / "a" / "b" / "c" / "token.json"
        a = GitHubAuth(client_id="x", token_path=deep_path)
        a._save_token(sample_token_info)
        assert deep_path.exists()


# ---------------------------------------------------------------------------
# Token file permissions
# ---------------------------------------------------------------------------

class TestTokenPermissions:

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permissions not on Windows")
    def test_token_file_permissions_0600(self, auth, sample_token_info, token_path):
        auth._save_token(sample_token_info)
        mode = token_path.stat().st_mode
        assert mode & 0o777 == 0o600


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

class TestLogout:

    def test_logout_removes_token(self, auth, sample_token_info, token_path):
        auth._save_token(sample_token_info)
        assert token_path.exists()

        result = auth.logout()
        assert result is True
        assert not token_path.exists()

    def test_logout_when_no_token(self, auth):
        result = auth.logout()
        assert result is False


# ---------------------------------------------------------------------------
# is_authenticated
# ---------------------------------------------------------------------------

class TestIsAuthenticated:

    def test_not_authenticated_initially(self, auth):
        assert auth.is_authenticated() is False

    def test_authenticated_after_save(self, auth, sample_token_info):
        auth._save_token(sample_token_info)
        assert auth.is_authenticated() is True

    def test_authenticated_via_env_var(self, auth, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_from_env")
        assert auth.is_authenticated() is True

    def test_not_authenticated_after_logout(self, auth, sample_token_info):
        auth._save_token(sample_token_info)
        auth.logout()
        assert auth.is_authenticated() is False


# ---------------------------------------------------------------------------
# GITHUB_TOKEN env var override
# ---------------------------------------------------------------------------

class TestEnvVarOverride:

    def test_get_token_prefers_env_var(self, auth, sample_token_info, monkeypatch):
        auth._save_token(sample_token_info)
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_env_override")
        assert auth.get_token() == "ghp_env_override"

    def test_login_uses_env_var(self, auth, monkeypatch, token_path):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_env_login")
        token_info = auth.login()
        assert token_info.access_token == "ghp_env_login"
        assert token_info.scope == "env_override"
        # Env-sourced tokens should NOT be persisted to disk (N22)
        assert not token_path.exists()


# ---------------------------------------------------------------------------
# Device flow request formatting
# ---------------------------------------------------------------------------

class TestDeviceFlowRequests:

    def test_request_device_code_sends_correct_data(self, auth, mock_http_post):
        mock_http_post.return_value = {
            "device_code": "dc_123",
            "user_code": "ABCD-1234",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 900,
            "interval": 5,
        }

        result = auth.request_device_code()

        mock_http_post.assert_called_once_with(
            "https://github.com/login/device/code",
            {"client_id": "test-client-id", "scope": "read:user read:org"},
        )
        assert result.user_code == "ABCD-1234"
        assert result.device_code == "dc_123"
        assert result.verification_uri == "https://github.com/login/device"
        assert result.expires_in == 900
        assert result.interval == 5

    def test_request_device_code_no_client_id(self, token_path):
        auth = GitHubAuth(client_id="", token_path=token_path)
        with pytest.raises(DeviceFlowError, match="No GitHub OAuth client ID"):
            auth.request_device_code()

    def test_request_device_code_api_error(self, auth, mock_http_post):
        mock_http_post.return_value = {
            "error": "unauthorized_client",
            "error_description": "The client is not authorized.",
        }
        with pytest.raises(DeviceFlowError, match="not authorized"):
            auth.request_device_code()

    def test_poll_for_token_success(self, auth, mock_http_post):
        # First call: pending, second call: success
        mock_http_post.side_effect = [
            {"error": "authorization_pending"},
            {
                "access_token": "ghp_polled",
                "token_type": "bearer",
                "scope": "read:user",
            },
        ]

        result = auth.poll_for_token("dc_123", interval=0, expires_in=10)
        assert result.access_token == "ghp_polled"
        assert mock_http_post.call_count == 2

    def test_poll_for_token_slow_down(self, auth, mock_http_post):
        mock_http_post.side_effect = [
            {"error": "slow_down"},
            {
                "access_token": "ghp_slow",
                "token_type": "bearer",
                "scope": "read:user",
            },
        ]

        result = auth.poll_for_token("dc_123", interval=0, expires_in=30)
        assert result.access_token == "ghp_slow"

    def test_poll_for_token_access_denied(self, auth, mock_http_post):
        mock_http_post.return_value = {"error": "access_denied"}
        with pytest.raises(DeviceFlowError, match="denied"):
            auth.poll_for_token("dc_123", interval=0, expires_in=10)

    def test_poll_for_token_expired(self, auth, mock_http_post):
        mock_http_post.return_value = {"error": "expired_token"}
        with pytest.raises(DeviceFlowError, match="expired"):
            auth.poll_for_token("dc_123", interval=0, expires_in=10)

    def test_poll_sends_correct_grant_type(self, auth, mock_http_post):
        mock_http_post.return_value = {
            "access_token": "ghp_grant",
            "token_type": "bearer",
            "scope": "",
        }

        auth.poll_for_token("dc_456", interval=0, expires_in=10)

        call_args = mock_http_post.call_args
        assert call_args[0][0] == "https://github.com/login/oauth/access_token"
        data = call_args[0][1]
        assert data["grant_type"] == "urn:ietf:params:oauth:grant-type:device_code"
        assert data["device_code"] == "dc_456"
        assert data["client_id"] == "test-client-id"


# ---------------------------------------------------------------------------
# User info fetch
# ---------------------------------------------------------------------------

class TestUserInfo:

    def test_get_user_info_success(self, auth, mock_http_get, sample_token_info):
        auth._save_token(sample_token_info)
        mock_http_get.return_value = {
            "login": "testuser",
            "name": "Test User",
            "email": "test@example.com",
        }

        info = auth.get_user_info()
        assert info["login"] == "testuser"
        assert info["name"] == "Test User"

        # Verify auth header was sent
        call_args = mock_http_get.call_args
        headers = call_args[1].get("headers") or call_args[0][1]
        assert "Bearer" in headers["Authorization"]

    def test_get_user_info_not_authenticated(self, auth):
        assert auth.get_user_info() is None

    def test_get_user_info_api_failure(self, auth, mock_http_get, sample_token_info):
        auth._save_token(sample_token_info)
        mock_http_get.side_effect = Exception("Network error")
        assert auth.get_user_info() is None


# ---------------------------------------------------------------------------
# Full login flow
# ---------------------------------------------------------------------------

class TestLoginFlow:

    def test_full_login_flow(self, auth, mock_http_post, token_path):
        # request_device_code
        mock_http_post.side_effect = [
            {
                "device_code": "dc_full",
                "user_code": "WXYZ-9876",
                "verification_uri": "https://github.com/login/device",
                "expires_in": 900,
                "interval": 0,
            },
            # poll (first attempt succeeds)
            {
                "access_token": "ghp_full_flow",
                "token_type": "bearer",
                "scope": "read:user read:org",
            },
        ]

        token_info = auth.login()
        assert token_info.access_token == "ghp_full_flow"
        assert token_path.exists()

        # Browser should have been opened
        auth._open_browser.assert_called_once_with("https://github.com/login/device")


# ---------------------------------------------------------------------------
# has_client_id
# ---------------------------------------------------------------------------

class TestHasClientId:

    def test_has_client_id_true(self, auth):
        assert auth.has_client_id is True

    def test_has_client_id_false(self, token_path):
        a = GitHubAuth(client_id="", token_path=token_path)
        assert a.has_client_id is False

    def test_client_id_from_env(self, token_path, monkeypatch):
        monkeypatch.setenv("LASSO_GITHUB_CLIENT_ID", "env-client-id")
        a = GitHubAuth(token_path=token_path)
        assert a.has_client_id is True
        assert a.client_id == "env-client-id"


# ---------------------------------------------------------------------------
# CLI auth commands
# ---------------------------------------------------------------------------

class TestCLIAuthCommands:

    def test_auth_status_not_authenticated(self):
        """lasso auth status when not logged in."""
        result = runner.invoke(app, ["auth", "status"])
        assert result.exit_code == 0
        # Should mention not authenticated or show status
        assert "Not authenticated" in result.output or "Authenticated" in result.output

    def test_auth_logout_no_token(self):
        """lasso auth logout when no token exists."""
        result = runner.invoke(app, ["auth", "logout"])
        assert result.exit_code == 0
        assert "No stored token" in result.output or "Logged out" in result.output

    def test_auth_token_not_authenticated(self):
        """lasso auth token when not logged in should fail."""
        result = runner.invoke(app, ["auth", "token"])
        assert result.exit_code == 1
        assert "Not authenticated" in result.output

    def test_auth_token_with_env_var(self, monkeypatch):
        """lasso auth token should return GITHUB_TOKEN from env."""
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_cli_test_token")
        result = runner.invoke(app, ["auth", "token"])
        assert result.exit_code == 0
        assert "ghp_cli_test_token" in result.output

    def test_auth_login_no_client_id(self):
        """lasso auth login without client_id should fail."""
        result = runner.invoke(app, ["auth", "login"])
        assert result.exit_code == 1
        assert "client ID" in result.output or "LASSO_GITHUB_CLIENT_ID" in result.output

    def test_auth_login_with_env_token(self, monkeypatch, tmp_path):
        """lasso auth login with GITHUB_TOKEN should skip device flow."""
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_env_cli")
        # Need to set client_id too so it doesn't fail on that check
        monkeypatch.setenv("LASSO_GITHUB_CLIENT_ID", "test-id")
        result = runner.invoke(app, ["auth", "login"])
        assert result.exit_code == 0
        assert "environment" in result.output or "Token saved" in result.output
        # Clean up the token file saved to ~/.lasso/ by the login command
        default_token = Path.home() / ".lasso" / "github_token.json"
        if default_token.exists():
            default_token.unlink()


# ---------------------------------------------------------------------------
# Sandbox GitHub token injection
# ---------------------------------------------------------------------------

class TestSandboxTokenInjection:

    def test_inject_github_token_into_sandbox_env(self, tmp_path, monkeypatch):
        """Sandbox._inject_github_token adds token to env dict when available."""
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_sandbox_inject")

        from lasso.config.schema import AgentAuthConfig, SandboxProfile
        from lasso.core.sandbox import Sandbox

        profile = SandboxProfile(
            name="test-inject",
            filesystem={"working_dir": str(tmp_path)},
            agent_auth=AgentAuthConfig(github_token_env="GITHUB_TOKEN"),
            audit={"enabled": False},
        )

        sb = Sandbox(profile)
        env = {}
        sb._inject_github_token(env)
        assert env.get("GITHUB_TOKEN") == "ghp_sandbox_inject"

    def test_inject_github_token_skipped_without_agent_auth(self, tmp_path):
        """Sandbox._inject_github_token does nothing if agent_auth is None."""
        from lasso.config.schema import SandboxProfile
        from lasso.core.sandbox import Sandbox

        profile = SandboxProfile(
            name="test-no-auth",
            filesystem={"working_dir": str(tmp_path)},
            agent_auth=None,
            audit={"enabled": False},
        )

        sb = Sandbox(profile)
        env = {}
        sb._inject_github_token(env)
        assert "GITHUB_TOKEN" not in env

    def test_inject_github_token_no_token_available(self, tmp_path, monkeypatch):
        """Sandbox._inject_github_token does nothing if no token is stored."""
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)

        from lasso.config.schema import AgentAuthConfig, SandboxProfile
        from lasso.core.sandbox import Sandbox

        profile = SandboxProfile(
            name="test-no-token",
            filesystem={"working_dir": str(tmp_path)},
            agent_auth=AgentAuthConfig(github_token_env="GITHUB_TOKEN"),
            audit={"enabled": False},
        )

        sb = Sandbox(profile)
        env = {}
        sb._inject_github_token(env)
        # Should not add anything if no token is available
        # (the stored token file won't exist in tmp context)
        assert "GITHUB_TOKEN" not in env or env.get("GITHUB_TOKEN") is None
