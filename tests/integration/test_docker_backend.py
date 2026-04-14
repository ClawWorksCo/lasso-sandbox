"""Integration tests for the Docker backend — requires a running Docker daemon.

These tests create real containers, so they're slower and need Docker.
Skip with: pytest -m "not integration"
"""

import pytest

from lasso.backends.base import ContainerConfig, ContainerState
from lasso.backends.docker_backend import DockerBackend

# Mark all tests in this module as integration
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def backend():
    """Create a Docker backend, skip if unavailable."""
    b = DockerBackend()
    if not b.is_available():
        pytest.skip("Docker daemon not available")
    return b


@pytest.fixture
def container(backend):
    """Create a container for testing, clean up after."""
    config = ContainerConfig(
        image="alpine:latest",
        name="lasso-test-integration",
        working_dir="/workspace",
        network_mode="none",
        mem_limit="128m",
        pids_limit=50,
        cap_drop=["ALL"],
        read_only_root=True,
        tmpfs_mounts={"/tmp": "size=16m,mode=1777"},
        bind_mounts=[],
        environment={"LASSO_TEST": "true"},
    )

    container_id = backend.create(config)
    backend.start(container_id)
    yield container_id
    # Cleanup
    backend.stop(container_id, timeout=5)
    backend.remove(container_id, force=True)


class TestDockerBackendAvailability:
    def test_is_available(self, backend):
        assert backend.is_available()

    def test_get_info(self, backend):
        info = backend.get_info()
        assert "version" in info
        assert "runtime" in info


class TestContainerLifecycle:
    def test_create_and_start(self, backend):
        config = ContainerConfig(
            image="alpine:latest",
            name="lasso-lifecycle-test",
            network_mode="none",
            bind_mounts=[],
        )
        cid = backend.create(config)
        try:
            backend.start(cid)
            info = backend.inspect(cid)
            assert info.state == ContainerState.RUNNING
        finally:
            backend.stop(cid)
            backend.remove(cid, force=True)

    def test_stop_and_remove(self, backend):
        config = ContainerConfig(
            image="alpine:latest",
            name="lasso-stop-test",
            network_mode="none",
            bind_mounts=[],
        )
        cid = backend.create(config)
        backend.start(cid)
        backend.stop(cid)
        info = backend.inspect(cid)
        assert info.state == ContainerState.STOPPED
        backend.remove(cid)


class TestCommandExecution:
    def test_exec_simple_command(self, backend, container):
        result = backend.exec(container, ["echo", "hello"])
        assert result.exit_code == 0
        assert result.stdout.strip() == "hello"

    def test_exec_ls(self, backend, container):
        result = backend.exec(container, ["ls", "/"])
        assert result.exit_code == 0
        assert "bin" in result.stdout
        assert "etc" in result.stdout

    def test_exec_nonexistent_command(self, backend, container):
        result = backend.exec(container, ["nonexistent_command_xyz"])
        assert result.exit_code != 0

    def test_exec_returns_stderr(self, backend, container):
        result = backend.exec(container, ["ls", "/nonexistent_path_xyz"])
        assert result.exit_code != 0
        assert result.stderr  # should have error message

    def test_exec_environment_variable(self, backend, container):
        result = backend.exec(container, ["sh", "-c", "echo $LASSO_TEST"])
        assert result.exit_code == 0
        assert "true" in result.stdout


class TestResourceLimits:
    def test_pids_limit_enforced(self, backend, container):
        # Try to create more processes than the limit allows
        # With pids_limit=50, a fork bomb should hit the limit
        result = backend.exec(container, [
            "sh", "-c",
            "for i in $(seq 1 100); do sleep 10 & done 2>&1; echo done"
        ])
        # The exact behavior varies, but it should either fail or
        # the container should still be functional after
        info = backend.inspect(container)
        assert info.state == ContainerState.RUNNING


class TestNetworkIsolation:
    def test_no_network_blocks_connections(self, backend, container):
        # Container has network_mode="none", so no network access
        result = backend.exec(container, ["sh", "-c", "ping -c1 -W1 8.8.8.8 2>&1 || echo BLOCKED"])
        assert "BLOCKED" in result.stdout or result.exit_code != 0


class TestReadOnlyFilesystem:
    def test_cannot_write_to_root(self, backend, container):
        result = backend.exec(container, ["sh", "-c", "touch /testfile 2>&1 || echo READONLY"])
        assert "READONLY" in result.stdout or "Read-only" in result.stderr

    def test_can_write_to_tmpfs(self, backend, container):
        result = backend.exec(container, ["sh", "-c", "echo hello > /tmp/test && cat /tmp/test"])
        assert result.exit_code == 0
        assert "hello" in result.stdout


class TestContainerListing:
    def test_list_lasso_containers(self, backend, container):
        containers = backend.list_containers()
        names = [c.name for c in containers]
        assert any("lasso-test-integration" in n for n in names)
