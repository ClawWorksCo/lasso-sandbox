"""Tests for reconnecting to stopped containers."""


from lasso.backends.base import ContainerState
from lasso.config.schema import SandboxState
from lasso.core.sandbox import SandboxRegistry
from lasso.core.state import StateStore
from tests.conftest import FakeBackend


class TestStoppedContainerReconnect:
    """Tests for _reconnect() handling of stopped containers."""

    def test_reconnect_stopped_container_returns_sandbox(self, tmp_path):
        """_reconnect returns a sandbox for stopped containers (not None)."""
        backend = FakeBackend()
        # Manually add a stopped container to the fake backend
        backend.containers["cid-001"] = {"state": ContainerState.STOPPED, "config": type("C", (), {"name": "lasso-sb-001", "image": "test"})()}

        store = StateStore(state_dir=str(tmp_path))
        store.record_create(
            "sb-001", "standard", "cid-001",
            agent="opencode", working_dir="/home/user/project",
        )

        registry = SandboxRegistry(backend=backend, state_dir=str(tmp_path))
        result = registry._reconnect("sb-001")

        assert result is not None
        assert result.state == SandboxState.STOPPED
        assert result._container_id == "cid-001"

    def test_reconnect_running_container_returns_running(self, tmp_path):
        """_reconnect returns RUNNING state for running containers."""
        backend = FakeBackend()
        backend.containers["cid-002"] = {"state": ContainerState.RUNNING, "config": type("C", (), {"name": "lasso-sb-002", "image": "test"})()}

        store = StateStore(state_dir=str(tmp_path))
        store.record_create(
            "sb-002", "standard", "cid-002",
            agent="opencode", working_dir="/home/user/project",
        )

        registry = SandboxRegistry(backend=backend, state_dir=str(tmp_path))
        result = registry._reconnect("sb-002")

        assert result is not None
        assert result.state == SandboxState.RUNNING

    def test_find_existing_stopped_returns_sandbox(self, tmp_path):
        """find_existing returns a stopped sandbox that can be restarted."""
        backend = FakeBackend()
        backend.containers["cid-001"] = {"state": ContainerState.STOPPED, "config": type("C", (), {"name": "lasso-sb-001", "image": "test"})()}

        store = StateStore(state_dir=str(tmp_path))
        store.record_create(
            "sb-001", "standard", "cid-001",
            agent="opencode", working_dir="/home/user/project",
        )
        store.record_stop("sb-001")

        registry = SandboxRegistry(backend=backend, state_dir=str(tmp_path))
        result = registry.find_existing("/home/user/project")

        assert result is not None
        assert result.state == SandboxState.STOPPED

    def test_restart_stopped_sandbox(self, tmp_path):
        """A stopped sandbox can be restarted via registry.start()."""
        backend = FakeBackend()
        backend.containers["cid-001"] = {"state": ContainerState.STOPPED, "config": type("C", (), {"name": "lasso-sb-001", "image": "test"})()}

        store = StateStore(state_dir=str(tmp_path))
        store.record_create(
            "sb-001", "standard", "cid-001",
            agent="opencode", working_dir="/home/user/project",
        )
        store.record_stop("sb-001")

        registry = SandboxRegistry(backend=backend, state_dir=str(tmp_path))
        sb = registry.find_existing("/home/user/project")
        assert sb is not None
        assert sb.state == SandboxState.STOPPED

        # Restart the sandbox
        registry.start(sb)
        assert sb.state == SandboxState.RUNNING

    def test_reconnect_exited_container_returns_none(self, tmp_path):
        """Containers in states other than RUNNING/PAUSED/STOPPED return None."""
        backend = FakeBackend()
        # Container that's been removed (inspect will raise)
        store = StateStore(state_dir=str(tmp_path))
        store.record_create(
            "sb-gone", "standard", "cid-gone",
            agent="opencode", working_dir="/home/user/project",
        )

        registry = SandboxRegistry(backend=backend, state_dir=str(tmp_path))
        result = registry._reconnect("sb-gone")

        # FakeBackend raises ValueError for unknown containers
        assert result is None
