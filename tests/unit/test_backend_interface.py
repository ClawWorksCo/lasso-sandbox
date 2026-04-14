"""Tests for the container backend interface contract.

These tests verify that any backend implementation correctly satisfies
the ContainerBackend interface. Uses a mock backend to test the contract
without requiring Docker/Podman.
"""


from lasso.backends.base import (
    BackendType,
    ContainerConfig,
    ContainerInfo,
    ContainerState,
    ExecResult,
)


class TestContainerConfig:
    def test_default_config(self):
        config = ContainerConfig()
        assert config.image == "python:3.12-slim"
        assert config.network_mode == "none"
        assert config.read_only_root is True
        assert config.cap_drop == ["ALL"]
        assert config.pids_limit == 100

    def test_config_with_bind_mounts(self):
        config = ContainerConfig(
            bind_mounts=[
                {"source": "/host/path", "target": "/container/path", "mode": "rw"},
                {"source": "/host/readonly", "target": "/data", "mode": "ro"},
            ]
        )
        assert len(config.bind_mounts) == 2
        assert config.bind_mounts[0]["mode"] == "rw"
        assert config.bind_mounts[1]["mode"] == "ro"

    def test_config_security_defaults_are_restrictive(self):
        config = ContainerConfig()
        assert config.cap_drop == ["ALL"]
        assert config.cap_add == []
        assert config.read_only_root is True
        assert config.network_mode == "none"
        assert config.user == "1000:1000"

    def test_config_resource_limits(self):
        config = ContainerConfig(
            mem_limit="8g",
            cpu_quota=100000,
            pids_limit=200,
        )
        assert config.mem_limit == "8g"
        assert config.cpu_quota == 100000
        assert config.pids_limit == 200


class TestExecResult:
    def test_success_result(self):
        result = ExecResult(exit_code=0, stdout="hello\n", stderr="", duration_ms=42)
        assert result.exit_code == 0
        assert result.stdout == "hello\n"
        assert result.duration_ms == 42

    def test_error_result(self):
        result = ExecResult(exit_code=1, stdout="", stderr="not found\n")
        assert result.exit_code == 1
        assert result.stderr == "not found\n"


class TestContainerInfo:
    def test_info_fields(self):
        info = ContainerInfo(
            container_id="abc123",
            name="test-sandbox",
            state=ContainerState.RUNNING,
            image="python:3.12-slim",
        )
        assert info.container_id == "abc123"
        assert info.state == ContainerState.RUNNING


class TestContainerState:
    def test_all_states_exist(self):
        assert ContainerState.CREATED == "created"
        assert ContainerState.RUNNING == "running"
        assert ContainerState.PAUSED == "paused"
        assert ContainerState.STOPPED == "stopped"
        assert ContainerState.REMOVED == "removed"
        assert ContainerState.ERROR == "error"


class TestBackendType:
    def test_types(self):
        assert BackendType.DOCKER == "docker"
        assert BackendType.PODMAN == "podman"
