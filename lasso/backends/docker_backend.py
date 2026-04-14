"""Container backend implementation for Podman and Docker.

Uses the Docker SDK which is compatible with both runtimes.
On Windows, Podman Desktop is recommended (free for enterprise).
For Podman: set DOCKER_HOST=unix:///run/user/$UID/podman/podman.sock
"""

from __future__ import annotations

import io
import logging
import threading
import time
from typing import Any

logger = logging.getLogger("lasso.docker")

try:
    import docker
    from docker.errors import APIError, ImageNotFound, NotFound
    _HAS_DOCKER = True
except ImportError:
    docker = None  # type: ignore[assignment]
    APIError = Exception  # type: ignore[misc,assignment]
    ImageNotFound = Exception  # type: ignore[misc,assignment]
    NotFound = Exception  # type: ignore[misc,assignment]
    _HAS_DOCKER = False

from lasso.backends.base import (
    ContainerBackend,
    ContainerConfig,
    ContainerInfo,
    ContainerState,
    ExecResult,
)

# Pinned Docker socket proxy image.  Using a specific tag (not :latest) for
# reproducible builds and to avoid silent behaviour changes.  To update:
#   1. Check https://github.com/Tecnativa/docker-socket-proxy/releases
#   2. Pull the new tag and verify: docker pull ghcr.io/tecnativa/docker-socket-proxy:<tag>
#   3. Update the tag below.
SOCKET_PROXY_IMAGE = "ghcr.io/tecnativa/docker-socket-proxy:0.2"


def _state_from_docker(status: str) -> ContainerState:
    """Map Docker container status string to ContainerState."""
    mapping = {
        "created": ContainerState.CREATED,
        "running": ContainerState.RUNNING,
        "paused": ContainerState.PAUSED,
        "restarting": ContainerState.RUNNING,
        "removing": ContainerState.STOPPED,
        "exited": ContainerState.STOPPED,
        "dead": ContainerState.ERROR,
    }
    return mapping.get(status, ContainerState.ERROR)


class DockerBackend(ContainerBackend):
    """Docker/Podman backend via the Docker SDK.

    Works with:
    - Docker Engine (Linux/macOS/Windows)
    - Docker Desktop (Windows/macOS)
    - Podman with Docker-compatible socket
    """

    def __init__(self, base_url: str | None = None):
        if not _HAS_DOCKER:
            raise ImportError(
                "Docker SDK is required for container operations. "
                "Install it with: pip install lasso-sandbox[containers]"
            )
        self._base_url = base_url
        self._client: docker.DockerClient | None = None

    def _get_client(self) -> docker.DockerClient:
        if self._client is None:
            if self._base_url:
                self._client = docker.DockerClient(base_url=self._base_url)
            else:
                self._client = docker.from_env()
        return self._client

    def is_available(self) -> bool:
        try:
            client = self._get_client()
            client.ping()
            return True
        except Exception as e:
            logger.debug("Docker backend not available: %s", e)
            return False

    def get_info(self) -> dict[str, Any]:
        try:
            client = self._get_client()
            info = client.info()
            return {
                "runtime": info.get("Name", "docker"),
                "version": client.version().get("Version", "unknown"),
                "os": info.get("OperatingSystem", "unknown"),
                "arch": info.get("Architecture", "unknown"),
                "storage_driver": info.get("Driver", "unknown"),
                "cgroup_driver": info.get("CgroupDriver", "unknown"),
            }
        except Exception as e:
            return {"error": str(e)}

    def create(self, config: ContainerConfig) -> str:
        client = self._get_client()

        # Ensure image exists
        try:
            client.images.get(config.image)
        except ImageNotFound:
            client.images.pull(config.image)

        # Build mount list
        binds = []
        for mount in config.bind_mounts:
            mode = mount.get("mode", "rw")
            source = mount["source"]
            target = mount["target"]
            binds.append(f"{source}:{target}:{mode}")

        # Named volumes (for session persistence etc.)
        for vol in config.volumes:
            vol_name = vol["name"]
            vol_target = vol["target"]
            vol_mode = vol.get("mode", "rw")
            # Ensure the named volume exists
            try:
                client.volumes.get(vol_name)
            except NotFound:
                client.volumes.create(name=vol_name, labels={"managed-by": "lasso"})
            binds.append(f"{vol_name}:{vol_target}:{vol_mode}")

        # Build tmpfs
        tmpfs = config.tmpfs_mounts if config.tmpfs_mounts else {}

        # Host config
        host_config = {
            "binds": binds,
            "tmpfs": tmpfs,
            "mem_limit": config.mem_limit,
            "cpu_quota": config.cpu_quota,
            "cpu_period": config.cpu_period,
            "pids_limit": config.pids_limit,
            "network_mode": config.network_mode,
            "dns": config.dns if config.dns else None,
            "security_opt": config.security_opt if config.security_opt else None,
            "cap_drop": config.cap_drop,
            "cap_add": config.cap_add if config.cap_add else None,
            "read_only": config.read_only_root,
        }
        if config.runtime:
            host_config["runtime"] = config.runtime

        container = client.api.create_container(
            image=config.image,
            name=config.name,
            hostname=config.hostname,
            working_dir=config.working_dir,
            environment=config.environment,
            user=config.user,
            labels={"managed-by": "lasso", "lasso-profile": config.name},
            stdin_open=True,
            tty=False,
            host_config=client.api.create_host_config(**host_config),
            # Keep the container running with a sleep process
            command=["sleep", "infinity"],
        )

        return container["Id"]

    def start(self, container_id: str) -> None:
        client = self._get_client()
        client.api.start(container_id)

    def stop(self, container_id: str, timeout: int = 10) -> None:
        client = self._get_client()
        try:
            client.api.stop(container_id, timeout=timeout)
        except (NotFound, APIError):
            pass

    def remove(self, container_id: str, force: bool = False) -> None:
        client = self._get_client()
        try:
            client.api.remove_container(container_id, force=force)
        except (NotFound, APIError):
            pass

    def exec(self, container_id: str, command: list[str],
             timeout: int = 300, user: str | None = None) -> ExecResult:
        client = self._get_client()
        start = time.monotonic_ns()

        try:
            exec_kwargs: dict = {
                "container": container_id,
                "cmd": command,
                "stdout": True,
                "stderr": True,
                "workdir": "/workspace",
            }
            if user:
                exec_kwargs["user"] = user
            exec_id = client.api.exec_create(**exec_kwargs)

            # Run exec_start in a thread to enforce timeout
            output_holder: list = [None]
            error_holder: list = [None]

            def _run_exec():
                try:
                    output_holder[0] = client.api.exec_start(exec_id["Id"], demux=True)
                except Exception as e:
                    error_holder[0] = e

            thread = threading.Thread(target=_run_exec, daemon=True)
            thread.start()
            thread.join(timeout=timeout)

            if thread.is_alive():
                # Timeout — the command exceeded the allowed time.
                # NOTE: Docker API has no exec kill/cancel endpoint, so the
                # exec process may continue running inside the container.
                # The container's PID limit (pids_limit) prevents runaway
                # accumulation.  The process will be cleaned up when the
                # container is stopped/removed.
                duration_ms = (time.monotonic_ns() - start) // 1_000_000
                return ExecResult(
                    exit_code=-1,
                    stdout="",
                    stderr=f"Command timed out after {timeout}s",
                    duration_ms=duration_ms,
                )

            if error_holder[0] is not None:
                raise error_holder[0]

            output = output_holder[0]

            # output is (stdout_bytes, stderr_bytes) when demux=True
            stdout_bytes = output[0] if output[0] else b""
            stderr_bytes = output[1] if output[1] else b""

            inspect = client.api.exec_inspect(exec_id["Id"])
            exit_code = inspect.get("ExitCode", -1)

            duration_ms = (time.monotonic_ns() - start) // 1_000_000

            return ExecResult(
                exit_code=exit_code,
                stdout=stdout_bytes.decode(errors="replace"),
                stderr=stderr_bytes.decode(errors="replace"),
                duration_ms=duration_ms,
            )
        except APIError as e:
            duration_ms = (time.monotonic_ns() - start) // 1_000_000
            return ExecResult(
                exit_code=-1,
                stdout="",
                stderr=f"Docker API error: {e}",
                duration_ms=duration_ms,
            )

    def inspect(self, container_id: str) -> ContainerInfo:
        client = self._get_client()
        data = client.api.inspect_container(container_id)
        state_str = data.get("State", {}).get("Status", "unknown")

        return ContainerInfo(
            container_id=container_id,
            name=data.get("Name", "").lstrip("/"),
            state=_state_from_docker(state_str),
            image=data.get("Config", {}).get("Image", ""),
            created_at=data.get("Created", ""),
            pid=data.get("State", {}).get("Pid", 0),
            network_mode=data.get("HostConfig", {}).get("NetworkMode", ""),
        )

    def logs(self, container_id: str, tail: int = 100) -> str:
        client = self._get_client()
        return client.api.logs(
            container_id, tail=tail, stdout=True, stderr=True
        ).decode(errors="replace")

    def list_containers(self, label_filter: str = "lasso") -> list[ContainerInfo]:
        client = self._get_client()
        containers = client.api.containers(
            all=True,
            filters={"label": f"managed-by={label_filter}"},
        )
        results = []
        for c in containers:
            results.append(ContainerInfo(
                container_id=c["Id"],
                name=c.get("Names", [""])[0].lstrip("/"),
                state=_state_from_docker(c.get("State", "unknown")),
                image=c.get("Image", ""),
                created_at=str(c.get("Created", "")),
            ))
        return results

    def create_network(self, name: str, internal: bool = True,
                       allowed_cidrs: list[str] | None = None) -> str:
        client = self._get_client()

        if allowed_cidrs:
            logger.warning(
                "allowed_cidrs=%r requested but not implemented in Docker "
                "bridge networks — use iptables-based network policy instead. "
                "The network will be created without CIDR restrictions.",
                allowed_cidrs,
            )

        network = client.api.create_network(
            name=name,
            driver="bridge",
            internal=internal,
            labels={"managed-by": "lasso"},
        )
        return network["Id"]

    def remove_network(self, name: str) -> None:
        client = self._get_client()
        try:
            client.api.remove_network(name)
        except (NotFound, APIError):
            pass

    def build_image(self, dockerfile_content: str, tag: str) -> str:
        client = self._get_client()
        fileobj = io.BytesIO(dockerfile_content.encode())

        # Stream build output for progress feedback
        import sys
        image_id = None
        for chunk in client.api.build(fileobj=fileobj, tag=tag, rm=True, decode=True):
            if "stream" in chunk:
                line = chunk["stream"].strip()
                if line and not line.startswith("---"):
                    sys.stderr.write(f"\r  {line[:80]}")
                    sys.stderr.flush()
            if "aux" in chunk and "ID" in chunk["aux"]:
                image_id = chunk["aux"]["ID"]
            if "error" in chunk:
                sys.stderr.write("\n")
                raise RuntimeError(f"Image build failed: {chunk['error'].strip()}")
        sys.stderr.write("\r" + " " * 80 + "\r")  # clear progress line

        if image_id:
            return image_id
        # Fallback: fetch the image by tag to get the ID
        image = client.images.get(tag)
        return image.id

    def image_exists(self, tag: str) -> bool:
        client = self._get_client()
        try:
            client.images.get(tag)
            return True
        except ImageNotFound:
            return False

    # ------------------------------------------------------------------
    # Docker-from-Docker socket proxy
    # ------------------------------------------------------------------

    _PROXY_NAME = "lasso-socket-proxy"
    _PROXY_NETWORK = "lasso-sandbox-net"
    _PROXY_IMAGE = SOCKET_PROXY_IMAGE

    def _ensure_socket_proxy(self) -> None:
        """Ensure the Docker socket proxy container and network are running.

        Creates the ``lasso-sandbox-net`` bridge network (if missing),
        starts the ``lasso-socket-proxy`` container with a read-only
        Docker socket mount and limited API permissions, and connects
        the proxy to the bridge network.
        """
        client = self._get_client()

        # 1. Ensure bridge network exists
        try:
            client.api.inspect_network(self._PROXY_NETWORK)
        except NotFound:
            client.api.create_network(
                self._PROXY_NETWORK,
                driver="bridge",
                labels={"managed-by": "lasso"},
            )
            logger.info("Created network %s", self._PROXY_NETWORK)

        # 2. Check if proxy container already exists and is running
        try:
            info = client.api.inspect_container(self._PROXY_NAME)
            state = info.get("State", {}).get("Status", "")
            if state == "running":
                # Ensure it's connected to the sandbox network
                networks = info.get("NetworkSettings", {}).get("Networks", {})
                if self._PROXY_NETWORK not in networks:
                    client.api.connect_container_to_network(
                        self._PROXY_NAME, self._PROXY_NETWORK,
                    )
                return
            # Exists but not running -- remove and recreate
            client.api.remove_container(self._PROXY_NAME, force=True)
        except NotFound:
            pass

        # 3. Pull image if needed
        try:
            client.images.get(self._PROXY_IMAGE)
        except ImageNotFound:
            logger.info("Pulling %s ...", self._PROXY_IMAGE)
            client.images.pull(self._PROXY_IMAGE)

        # 4. Create and start the proxy container
        proxy_env = {
            "CONTAINERS": "1",
            "IMAGES": "1",
            "BUILD": "1",
            "POST": "1",
            "NETWORKS": "1",
            "INFO": "1",
            "VERSION": "1",
            "VOLUMES": "0",
            "EXEC": "0",
            "AUTH": "0",
        }

        host_config = client.api.create_host_config(
            binds=["/var/run/docker.sock:/var/run/docker.sock:ro"],
            network_mode=self._PROXY_NETWORK,
        )

        container = client.api.create_container(
            image=self._PROXY_IMAGE,
            name=self._PROXY_NAME,
            environment=proxy_env,
            labels={"managed-by": "lasso", "lasso-role": "socket-proxy"},
            host_config=host_config,
        )
        client.api.start(container["Id"])
        logger.info("Started socket proxy %s", self._PROXY_NAME)

    def _cleanup_socket_proxy(self) -> None:
        """Stop the socket proxy if no docker_from_docker sandboxes remain.

        Inspects all running lasso-managed containers. If none of them
        are docker_from_docker sandboxes (i.e. connected to the proxy
        network), the proxy container and network are removed.
        """
        client = self._get_client()

        # Check if any sandbox containers are still on the proxy network
        try:
            net_info = client.api.inspect_network(self._PROXY_NETWORK)
            connected = net_info.get("Containers", {})
            # Filter out the proxy container itself
            sandbox_containers = {
                cid: c for cid, c in connected.items()
                if c.get("Name", "") != self._PROXY_NAME
            }
            if sandbox_containers:
                return  # Other DfD sandboxes still running
        except NotFound:
            return  # Network already gone

        # No remaining sandbox containers -- tear down the proxy
        try:
            client.api.stop(self._PROXY_NAME, timeout=5)
            client.api.remove_container(self._PROXY_NAME, force=True)
            logger.info("Removed socket proxy %s", self._PROXY_NAME)
        except (NotFound, APIError):
            pass

        try:
            client.api.remove_network(self._PROXY_NETWORK)
            logger.info("Removed network %s", self._PROXY_NETWORK)
        except (NotFound, APIError):
            pass

    def get_native_client(self):
        """Return the underlying docker.DockerClient for runtime inspection."""
        return self._get_client()
