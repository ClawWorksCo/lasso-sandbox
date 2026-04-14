"""Tests for graceful shutdown — signal handlers, registry shutdown, state persistence."""

import json
import signal

import pytest

from lasso.config.defaults import evaluation_profile
from lasso.config.schema import SandboxState
from lasso.core.sandbox import SandboxRegistry

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def registry(tmp_path):
    """Create a SandboxRegistry with a temp state directory."""
    return SandboxRegistry(backend=None, state_dir=str(tmp_path / "state"))


@pytest.fixture
def running_sandbox(registry, tmp_path):
    """Create and start a sandbox in the registry."""
    profile = evaluation_profile(str(tmp_path / "workdir"))
    profile.audit.log_dir = str(tmp_path / "audit")
    sb = registry.create(profile)
    sb.start()
    return sb


# ---------------------------------------------------------------------------
# Registry.shutdown() tests
# ---------------------------------------------------------------------------

class TestRegistryShutdown:
    """Test SandboxRegistry.shutdown() behaviour."""

    def test_shutdown_stops_all_sandboxes(self, registry, running_sandbox):
        """shutdown() should stop all running sandboxes."""
        assert running_sandbox.state == SandboxState.RUNNING
        registry.shutdown()
        assert running_sandbox.state == SandboxState.STOPPED

    def test_shutdown_saves_state(self, registry, running_sandbox, tmp_path):
        """shutdown() should persist state to disk."""
        registry.shutdown()
        state_file = tmp_path / "state" / "state.json"
        assert state_file.exists()
        data = json.loads(state_file.read_text())
        assert running_sandbox.id in data["sandboxes"]
        assert data["sandboxes"][running_sandbox.id]["state"] == "stopped"

    def test_shutdown_logs_lifecycle_events(self, registry, running_sandbox):
        """shutdown() should log shutdown_initiated and shutdown_complete."""
        registry.shutdown()
        log_file = running_sandbox.audit.log_file
        assert log_file.exists()

        entries = []
        for line in log_file.read_text().splitlines():
            if line.strip():
                entries.append(json.loads(line))

        lifecycle_actions = [
            e["action"] for e in entries if e.get("type") == "lifecycle"
        ]
        assert "shutdown_initiated" in lifecycle_actions
        assert "shutdown_complete" in lifecycle_actions

    def test_shutdown_with_no_sandboxes(self, registry):
        """shutdown() on empty registry should not raise."""
        registry.shutdown()  # Should not raise

    def test_shutdown_with_already_stopped_sandbox(self, registry, running_sandbox):
        """shutdown() should handle already-stopped sandboxes gracefully."""
        running_sandbox.stop()
        assert running_sandbox.state == SandboxState.STOPPED
        registry.shutdown()  # Should not raise

    def test_shutdown_multiple_sandboxes(self, registry, tmp_path):
        """shutdown() should stop all running sandboxes when multiple exist."""
        sandboxes = []
        for i in range(3):
            profile = evaluation_profile(str(tmp_path / f"workdir{i}"))
            profile.audit.log_dir = str(tmp_path / "audit")
            sb = registry.create(profile)
            sb.start()
            sandboxes.append(sb)

        registry.shutdown()

        for sb in sandboxes:
            assert sb.state == SandboxState.STOPPED


# ---------------------------------------------------------------------------
# Signal handler registration tests
# ---------------------------------------------------------------------------

class TestSignalHandlers:
    """Test signal handler registration from CLI."""

    def test_register_signal_handlers(self):
        """_register_signal_handlers should install handlers for SIGINT/SIGTERM."""
        from lasso.cli.main import _register_signal_handlers

        _register_signal_handlers()

        # On all platforms, SIGINT should be handled
        handler = signal.getsignal(signal.SIGINT)
        assert handler is not None
        assert callable(handler)
        assert handler is not signal.SIG_DFL

    def test_shutdown_handler_calls_registry_shutdown(self, registry, running_sandbox, monkeypatch):
        """_shutdown_handler should call registry.shutdown()."""
        import lasso.cli.helpers as cli_module

        monkeypatch.setattr(cli_module, "_registry", registry)

        assert running_sandbox.state == SandboxState.RUNNING

        with pytest.raises(SystemExit) as exc_info:
            cli_module._shutdown_handler(signal.SIGINT, None)

        assert exc_info.value.code == 0
        assert running_sandbox.state == SandboxState.STOPPED

    def test_shutdown_handler_no_registry(self):
        """_shutdown_handler should not raise when no registry exists."""
        import lasso.cli.helpers as cli_module

        original = cli_module._registry
        try:
            cli_module._registry = None
            with pytest.raises(SystemExit) as exc_info:
                cli_module._shutdown_handler(signal.SIGINT, None)
            assert exc_info.value.code == 0
        finally:
            cli_module._registry = original

    def test_sigbreak_registered_on_windows(self, monkeypatch):
        """On Windows, SIGBREAK should also be registered."""
        # We can test the logic even on Linux by checking the hasattr branch
        from lasso.cli.main import _register_signal_handlers

        if hasattr(signal, "SIGBREAK"):
            _register_signal_handlers()
            handler = signal.getsignal(signal.SIGBREAK)
            assert handler is not signal.SIG_DFL


# ---------------------------------------------------------------------------
# Dashboard atexit tests
# ---------------------------------------------------------------------------

class TestDashboardShutdown:
    """Test atexit handler in dashboard create_app."""

    @pytest.fixture(autouse=True)
    def _public_mode(self, monkeypatch):
        """Run dashboard tests in public mode."""
        monkeypatch.setenv("LASSO_DASHBOARD_PUBLIC", "1")

    def test_atexit_registered(self, tmp_path, monkeypatch):
        """create_app should register an atexit handler for registry shutdown."""
        import atexit
        flask = pytest.importorskip("flask")
        from lasso.dashboard.app import create_app

        registry = SandboxRegistry(backend=None, state_dir=str(tmp_path / "state"))

        # Track atexit registrations
        registered = []
        original_register = atexit.register
        monkeypatch.setattr(atexit, "register", lambda fn, *a, **kw: registered.append(fn))

        create_app(registry=registry)

        # Verify a shutdown method was registered (bound method of a SandboxRegistry)
        assert len(registered) >= 1
        shutdown_fns = [
            fn for fn in registered
            if hasattr(fn, "__self__") and isinstance(fn.__self__, SandboxRegistry)
            and fn.__func__ is SandboxRegistry.shutdown
        ]
        assert len(shutdown_fns) == 1
