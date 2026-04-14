"""Shared test fixtures for LASSO unit and integration tests.

Provides a canonical FakeBackend implementation that all test files
should use instead of defining their own.  The FakeBackend implements
every method of ContainerBackend, tracks all calls for assertion, and
supports configurable iptables exit codes for network policy testing.
"""

from __future__ import annotations

import pytest

from lasso.backends.base import (
    ContainerBackend,
    ContainerConfig,
    ContainerInfo,
    ContainerState,
    ExecResult,
)


class FakeBackend(ContainerBackend):
    """In-memory fake backend for testing sandbox orchestration.

    Features:
    - Implements all 15 ContainerBackend abstract methods
    - Tracks every method call in ``self.calls`` for assertion
    - Tracks exec commands separately in ``self.exec_calls``
    - Configurable availability (``available`` param)
    - Configurable iptables exit code for network policy tests
    - Simulates basic command output for ``ls`` and ``python3``
    - Handles batched ``sh -c`` iptables scripts
    """

    def __init__(
        self,
        available: bool = True,
        iptables_exit_code: int = 0,
    ):
        self._available = available
        self._iptables_exit_code = iptables_exit_code
        self.containers: dict[str, dict] = {}
        self._next_id = 0
        self.calls: list[tuple[str, tuple]] = []
        self.exec_calls: list[list[str]] = []

    def _record(self, method: str, *args):
        self.calls.append((method, args))

    def is_available(self) -> bool:
        return self._available

    def get_info(self) -> dict:
        return {"runtime": "fake", "version": "0.0.0"}

    def create(self, config: ContainerConfig) -> str:
        self._record("create", config)
        self._next_id += 1
        cid = f"fake-{self._next_id:04d}"
        self.containers[cid] = {
            "config": config,
            "state": ContainerState.CREATED,
        }
        return cid

    def start(self, container_id: str) -> None:
        self._record("start", container_id)
        self.containers[container_id]["state"] = ContainerState.RUNNING

    def stop(self, container_id: str, timeout: int = 10) -> None:
        self._record("stop", container_id)
        if container_id in self.containers:
            self.containers[container_id]["state"] = ContainerState.STOPPED

    def remove(self, container_id: str, force: bool = False) -> None:
        self._record("remove", container_id)
        self.containers.pop(container_id, None)

    def exec(
        self,
        container_id: str,
        command: list[str],
        timeout: int = 300,
        user: str | None = None,
    ) -> ExecResult:
        self._record("exec", container_id, command)
        self.exec_calls.append(command)

        cmd_name = command[0] if command else ""

        # Handle batched iptables scripts (sh -c "iptables ...")
        if cmd_name == "sh" and len(command) >= 3 and command[1] == "-c":
            script = command[2]
            if ("iptables" in script or "ip6tables" in script):
                if self._iptables_exit_code != 0:
                    return ExecResult(
                        exit_code=self._iptables_exit_code,
                        stdout="",
                        stderr="iptables: command not found",
                    )
                return ExecResult(
                    exit_code=0,
                    stdout="CRITICAL_FAILED=0 FAILED=0",
                    stderr="",
                )

        # Handle direct iptables/ip6tables calls
        if cmd_name in ("iptables", "ip6tables"):
            return ExecResult(
                exit_code=self._iptables_exit_code,
                stdout="",
                stderr=(
                    f"{cmd_name}: command not found"
                    if self._iptables_exit_code != 0
                    else ""
                ),
            )

        # Simulate common commands
        if cmd_name == "ls":
            return ExecResult(
                exit_code=0, stdout="file1.txt\nfile2.py\n", stderr=""
            )
        if cmd_name == "python3":
            return ExecResult(
                exit_code=0, stdout="Python 3.12.0\n", stderr=""
            )

        return ExecResult(exit_code=0, stdout="", stderr="")

    def inspect(self, container_id: str) -> ContainerInfo:
        c = self.containers.get(container_id)
        if c is None:
            raise ValueError(f"Container {container_id} not found")
        # Support both dict format (from create()) and direct ContainerState
        # (for tests that manually set backend.containers[id] = ContainerState.X)
        if isinstance(c, ContainerState):
            return ContainerInfo(
                container_id=container_id,
                name=f"lasso-{container_id}",
                state=c,
                image="python:3.12-slim",
            )
        return ContainerInfo(
            container_id=container_id,
            name=c["config"].name,
            state=c["state"],
            image=c["config"].image,
        )

    def logs(self, container_id: str, tail: int = 100) -> str:
        return ""

    def list_containers(
        self, label_filter: str = "lasso"
    ) -> list[ContainerInfo]:
        return [self.inspect(cid) for cid in self.containers]

    def create_network(
        self,
        name: str,
        internal: bool = True,
        allowed_cidrs: list[str] | None = None,
    ) -> str:
        self._record("create_network", name)
        return f"net-{name}"

    def remove_network(self, name: str) -> None:
        self._record("remove_network", name)

    def build_image(self, dockerfile_content: str, tag: str) -> str:
        self._record("build_image", tag)
        return f"sha256:fake-{tag}"

    def image_exists(self, tag: str) -> bool:
        return True


@pytest.fixture
def fake_backend():
    """Provide a fresh FakeBackend instance."""
    return FakeBackend()
