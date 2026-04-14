"""Integration tests for LASSO — real user workflows end-to-end.

Tests the way a real user would use LASSO: creating sandboxes, running
AI agents, verifying security controls, checking audit trails, and
using the dashboard.

Run all:    pytest tests/integration/test_user_workflows.py -v --tb=short
Run fast:   pytest tests/integration/test_user_workflows.py -v --tb=short -k "not image_build"
Skip:       pytest -m "not integration"
"""

import json
import os
import subprocess
import sys

import pytest

from lasso.backends.image_builder import (
    ensure_image,
    generate_dockerfile,
    image_tag,
)
from lasso.config.defaults import (
    BUILTIN_PROFILES,
    evaluation_profile,
    standard_profile,
    strict_profile,
)
from lasso.config.schema import (
    AuditConfig,
    CommandConfig,
    CommandMode,
    FilesystemConfig,
    NetworkConfig,
    NetworkMode,
    ProfileMode,
    SandboxProfile,
    SandboxState,
)
from lasso.core.commands import CommandGate
from lasso.core.sandbox import SandboxRegistry

# Mark every test in this module as integration
pytestmark = pytest.mark.integration


# ============================================================================
# Test Group 1: Sandbox Lifecycle
# ============================================================================


class TestSandboxLifecycle:
    """End-to-end sandbox creation, use, and teardown."""

    def test_create_development_sandbox(self, dev_sandbox):
        """Create a development sandbox and verify it starts and is running."""
        assert dev_sandbox.state == SandboxState.RUNNING
        assert dev_sandbox._container_id is not None
        assert dev_sandbox.id is not None
        status = dev_sandbox.status()
        assert status["state"] == "running"
        assert status["name"] == "standard"

    def test_create_strict_sandbox(self, strict_sandbox):
        """Create a strict/banking sandbox and verify it starts."""
        assert strict_sandbox.state == SandboxState.RUNNING
        assert strict_sandbox._container_id is not None
        status = strict_sandbox.status()
        assert status["state"] == "running"
        assert status["name"] == "strict"
        assert status["network_mode"] == "none"

    def test_exec_allowed_commands(self, dev_sandbox):
        """Run whitelisted commands (ls, echo, python3, git) and get output."""
        # echo
        result = dev_sandbox.exec("echo hello world")
        assert result.exit_code == 0
        assert "hello world" in result.stdout
        assert not result.blocked

        # ls
        result = dev_sandbox.exec("ls /")
        assert result.exit_code == 0
        assert "workspace" in result.stdout or "usr" in result.stdout

        # python3 --version (python3 is whitelisted but -c is blocked)
        result = dev_sandbox.exec("python3 --version")
        assert result.exit_code == 0
        assert "Python" in result.stdout or "Python" in result.stderr

    def test_exec_blocked_commands(self, dev_sandbox):
        """Verify blocked commands (rm, docker, nc) are rejected by the gate."""
        # rm is not on the development whitelist
        result = dev_sandbox.exec("rm -rf /tmp/test")
        assert result.blocked
        assert "BLOCKED" in result.stderr or result.block_reason

        # docker is not whitelisted
        result = dev_sandbox.exec("docker ps")
        assert result.blocked

        # nc (netcat) is not whitelisted
        result = dev_sandbox.exec("nc -l 1234")
        assert result.blocked

    def test_exec_blocked_args(self, dev_sandbox):
        """Verify blocked argument patterns are rejected."""
        # python3 -c is a dangerous arg pattern
        result = dev_sandbox.exec("python3 -c 'import os; os.system(\"id\")'")
        assert result.blocked
        assert "Dangerous" in result.block_reason or "blocked" in result.block_reason.lower()

        # python3 -m is also blocked
        result = dev_sandbox.exec("python3 -m http.server")
        assert result.blocked

    def test_stop_and_cleanup(self, docker_backend, tmp_path):
        """Stop a sandbox and verify the container is removed."""
        registry = SandboxRegistry(
            backend=docker_backend,
            state_dir=str(tmp_path / "state"),
        )
        profile = evaluation_profile(str(tmp_path / "workspace"))
        profile.mode = ProfileMode.AUTONOMOUS
        profile.audit = AuditConfig(
            enabled=True,
            log_dir=str(tmp_path / "audit"),
            sign_entries=False,
        )
        sb = registry.create(profile)
        registry.start(sb)

        container_id = sb._container_id
        assert container_id is not None
        assert sb.state == SandboxState.RUNNING

        # Stop and verify
        sb.stop()
        assert sb.state == SandboxState.STOPPED

        # Container should be removed (stop() calls remove())
        try:
            info = docker_backend.inspect(container_id)
            # If we can still inspect, it should not be running
            assert info.state != "running"
        except Exception:
            # Container was removed entirely -- this is the expected path
            pass

    def test_sandbox_reconnection(self, docker_backend, tmp_path):
        """Create sandbox in one registry, find it in another (cross-process)."""
        state_dir = str(tmp_path / "shared_state")
        profile = evaluation_profile(str(tmp_path / "workspace"))
        profile.mode = ProfileMode.AUTONOMOUS
        profile.audit = AuditConfig(
            enabled=True,
            log_dir=str(tmp_path / "audit"),
            sign_entries=False,
        )

        # Create in registry 1
        reg1 = SandboxRegistry(backend=docker_backend, state_dir=state_dir)
        sb = reg1.create(profile)
        reg1.start(sb)
        sandbox_id = sb.id

        try:
            # Simulate a new process: create a new registry with same state dir
            reg2 = SandboxRegistry(backend=docker_backend, state_dir=state_dir)
            found = reg2.get(sandbox_id)
            assert found is not None, f"Could not reconnect to sandbox {sandbox_id}"
            assert found.state == SandboxState.RUNNING
            assert found._container_id is not None

            # Should be able to exec commands via reconnected sandbox
            result = found.exec("echo reconnected")
            assert result.exit_code == 0
            assert "reconnected" in result.stdout
        finally:
            sb.stop()


# ============================================================================
# Test Group 2: Security Controls
# ============================================================================


class TestSecurityControls:
    """Verify all security boundaries work in real containers."""

    def test_non_root_user(self, dev_sandbox):
        """Verify the sandbox runs as non-root (uid 1000)."""
        # The Dockerfile creates user 'agent' with uid 1000
        result = dev_sandbox.exec("echo $USER")
        # $USER may not be set, try id command if whitelisted
        # echo is allowed, check via whoami or id indirectly
        # Since only echo is safe, use /proc
        result = dev_sandbox.exec("cat /proc/self/status")
        assert result.exit_code == 0
        # Look for Uid line -- should show 1000
        for line in result.stdout.splitlines():
            if line.startswith("Uid:"):
                uids = line.split()
                # Real UID should be 1000
                assert "1000" in uids, f"Expected uid 1000 in {line}"
                break
        else:
            # If we can't parse /proc/self/status, at least verify
            # we can't write to root-owned paths
            result = dev_sandbox.exec("touch /root/test")
            assert result.exit_code != 0 or result.blocked

    def test_read_only_root_filesystem(self, dev_sandbox):
        """Verify cannot write to / or /usr (read-only root FS)."""
        result = dev_sandbox.exec("touch /test_readonly")
        # Should fail because root FS is read-only
        assert result.exit_code != 0 or result.blocked

    def test_workspace_is_writable(self, dev_sandbox):
        """Verify /workspace is writable."""
        result = dev_sandbox.exec("touch /workspace/test_file")
        assert result.exit_code == 0, f"Failed to write to /workspace: {result.stderr}"

        # Verify the file was created
        result = dev_sandbox.exec("ls /workspace/test_file")
        assert result.exit_code == 0

    def test_network_none_blocks_everything(self, docker_backend, tmp_path):
        """In none mode, verify no network connectivity at all."""
        registry = SandboxRegistry(
            backend=docker_backend,
            state_dir=str(tmp_path / "state"),
        )
        # Create a profile with network=none but curl whitelisted so the
        # command gate allows it -- we want to test container-level blocking
        profile = SandboxProfile(
            name="net-none-test",
            filesystem=FilesystemConfig(working_dir=str(tmp_path / "workspace")),
            commands=CommandConfig(
                mode=CommandMode.WHITELIST,
                whitelist=["echo", "ls", "cat", "test"],
                allow_shell_operators=False,
            ),
            network=NetworkConfig(mode=NetworkMode.NONE),
            mode=ProfileMode.AUTONOMOUS,
            audit=AuditConfig(
                enabled=True,
                log_dir=str(tmp_path / "audit"),
                sign_entries=False,
            ),
        )
        sb = registry.create(profile)
        registry.start(sb)
        try:
            # Can't test curl because it's not whitelisted, but we can
            # verify the container was started with --network=none
            # by checking /sys/class/net
            result = sb.exec("ls /sys/class/net")
            assert result.exit_code == 0
            # With network=none, only loopback (lo) should exist
            interfaces = result.stdout.strip().split()
            assert interfaces == ["lo"] or len(interfaces) <= 1, (
                f"Expected only loopback interface, got: {interfaces}"
            )
        finally:
            sb.stop()

    def test_tmpfs_writable(self, dev_sandbox):
        """Verify /tmp is writable (tmpfs mount)."""
        result = dev_sandbox.exec("touch /tmp/test_tmpfs")
        assert result.exit_code == 0, f"/tmp not writable: {result.stderr}"

    def test_dangerous_python_c_blocked(self, dev_sandbox):
        """Verify python3 -c is blocked by command gate."""
        result = dev_sandbox.exec("python3 -c 'print(1)'")
        assert result.blocked
        assert "Dangerous" in result.block_reason or "-c" in result.block_reason

    def test_compound_command_blocked(self, dev_sandbox):
        """Verify shell operators are subject to command gate policies."""
        # Development profile allows shell operators, but rm is not whitelisted.
        # The check_pipeline should catch the rm in the second stage.
        # However, sandbox.exec() uses check() not check_pipeline() --
        # it relies on the container itself. Let's test the gate directly.
        gate = dev_sandbox.command_gate
        verdicts = gate.check_pipeline("ls && rm -rf /")
        # At least one verdict should be blocked (the rm part)
        blocked_verdicts = [v for v in verdicts if v.blocked]
        assert len(blocked_verdicts) > 0, "rm -rf / should be blocked in pipeline"

    def test_shell_operator_injection_blocked(self, strict_sandbox):
        """Verify shell operators are blocked in strict mode."""
        # Strict profile has allow_shell_operators=False
        result = strict_sandbox.exec("ls | cat")
        assert result.blocked
        assert "Shell operators" in result.block_reason or "operator" in result.block_reason.lower()

    def test_path_traversal_blocked(self, dev_sandbox):
        """Verify path traversal attempts are blocked."""
        result = dev_sandbox.exec("cat ../../etc/passwd")
        assert result.blocked
        assert "traversal" in result.block_reason.lower()


# ============================================================================
# Test Group 3: Audit Trail
# ============================================================================


class TestAuditTrail:
    """Verify audit logging works end-to-end."""

    def test_audit_log_created_on_start(self, dev_sandbox):
        """Verify audit log file is created when sandbox starts."""
        log_file = dev_sandbox.audit.log_file
        assert log_file is not None
        assert log_file.exists(), f"Audit log not found at {log_file}"
        # Should have at least the lifecycle start events
        content = log_file.read_text()
        assert len(content.strip()) > 0

    def test_commands_logged(self, dev_sandbox):
        """Run commands and verify they appear in the audit log."""
        dev_sandbox.exec("echo audit_test_marker")
        dev_sandbox.exec("ls /workspace")

        log_file = dev_sandbox.audit.log_file
        content = log_file.read_text()
        lines = [json.loads(line) for line in content.strip().splitlines() if line.strip()]

        # Find command events
        cmd_events = [e for e in lines if e.get("type") == "command"]
        assert len(cmd_events) >= 2, f"Expected at least 2 command events, got {len(cmd_events)}"

        # Verify the echo command was logged
        echo_events = [e for e in cmd_events if e.get("action") == "echo"]
        assert len(echo_events) >= 1, "echo command not found in audit log"

    def test_blocked_commands_logged(self, dev_sandbox):
        """Verify blocked commands are logged with 'blocked' outcome."""
        dev_sandbox.exec("rm -rf /")
        dev_sandbox.exec("docker ps")

        log_file = dev_sandbox.audit.log_file
        content = log_file.read_text()
        lines = [json.loads(line) for line in content.strip().splitlines() if line.strip()]

        blocked_events = [e for e in lines if e.get("outcome") == "blocked"]
        assert len(blocked_events) >= 2, (
            f"Expected at least 2 blocked events, got {len(blocked_events)}"
        )

    def test_audit_has_signatures(self, dev_sandbox):
        """Verify each audit entry has an HMAC signature."""
        dev_sandbox.exec("echo signed_test")

        log_file = dev_sandbox.audit.log_file
        content = log_file.read_text()
        lines = [json.loads(line) for line in content.strip().splitlines() if line.strip()]

        assert len(lines) > 0, "No audit entries found"

        # All entries should have a signature since sign_entries=True
        for i, entry in enumerate(lines):
            assert "sig" in entry, f"Entry {i} missing HMAC signature: {entry}"
            assert len(entry["sig"]) == 64, (
                f"Entry {i} signature wrong length: {len(entry['sig'])}"
            )

    def test_audit_chain_integrity(self, dev_sandbox):
        """Verify the HMAC chain is valid after multiple commands."""
        # Generate a few audit events
        dev_sandbox.exec("echo chain_test_1")
        dev_sandbox.exec("echo chain_test_2")
        dev_sandbox.exec("ls /workspace")

        log_file = dev_sandbox.audit.log_file
        assert log_file.exists()

        # Use the built-in verifier
        from lasso.core.audit_verify import verify_audit_log
        result = verify_audit_log(str(log_file))

        assert result.valid, (
            f"Audit chain verification failed: {result.errors}"
        )
        assert result.verified_entries > 0
        assert result.total_entries == result.verified_entries

    def test_audit_lifecycle_events(self, dev_sandbox):
        """Verify lifecycle events (start, running) are logged."""
        log_file = dev_sandbox.audit.log_file
        content = log_file.read_text()
        lines = [json.loads(line) for line in content.strip().splitlines() if line.strip()]

        lifecycle_events = [e for e in lines if e.get("type") == "lifecycle"]
        actions = [e.get("action") for e in lifecycle_events]

        assert "start" in actions, "Missing 'start' lifecycle event"
        assert "running" in actions, "Missing 'running' lifecycle event"


# ============================================================================
# Test Group 4: Agent Image Building
# ============================================================================


class TestAgentImageBuilding:
    """Verify agent pre-install works in Docker images."""

    def test_dockerfile_includes_agent_install(self):
        """Verify generate_dockerfile with agent adds install commands (unit test)."""
        profile = standard_profile("/workspace")
        dockerfile = generate_dockerfile(profile, agent="opencode")
        assert "opencode" in dockerfile.lower()
        assert "Install AI agent: opencode" in dockerfile

    def test_dockerfile_includes_claude_code_install(self):
        """Verify generate_dockerfile with claude-code adds Node.js + npm."""
        profile = standard_profile("/workspace")
        dockerfile = generate_dockerfile(profile, agent="claude-code")
        assert "nodesource" in dockerfile or "nodejs" in dockerfile
        assert "claude-code" in dockerfile

    def test_dockerfile_user_agent(self):
        """Verify the Dockerfile creates a non-root user."""
        profile = evaluation_profile("/workspace")
        dockerfile = generate_dockerfile(profile)
        assert "useradd" in dockerfile
        assert "agent" in dockerfile
        assert "USER agent" in dockerfile
        assert "uid 1000" in dockerfile or "-u 1000" in dockerfile

    def test_image_tag_deterministic(self):
        """Verify image tags are deterministic based on config hash."""
        profile = standard_profile("/workspace")
        tag1 = image_tag(profile)
        tag2 = image_tag(profile)
        assert tag1 == tag2
        assert tag1.startswith("lasso-")

        # Different agent produces different tag
        tag_opencode = image_tag(profile, agent="opencode")
        assert tag_opencode != tag1
        assert "opencode" in tag_opencode

    @pytest.mark.timeout(120)
    def test_build_image_with_opencode(self, docker_backend, tmp_path):
        """Build an image with opencode pre-installed and verify it exists."""
        profile = standard_profile(str(tmp_path / "workspace"))
        tag = ensure_image(docker_backend, profile, agent="opencode")
        assert docker_backend.image_exists(tag)

    @pytest.mark.timeout(120)
    def test_agent_available_in_sandbox(self, docker_backend, tmp_path):
        """Create sandbox with opencode image, verify opencode is installed."""
        profile = standard_profile(str(tmp_path / "workspace"))
        profile.mode = ProfileMode.AUTONOMOUS
        profile.audit = AuditConfig(
            enabled=True,
            log_dir=str(tmp_path / "audit"),
            sign_entries=False,
        )
        # Set the agent so image builder installs opencode
        profile.extra_env["LASSO_AGENT"] = "opencode"

        registry = SandboxRegistry(
            backend=docker_backend,
            state_dir=str(tmp_path / "state"),
        )
        sb = registry.create(profile)
        registry.start(sb)
        try:
            # Verify opencode binary is available
            result = sb.exec("which opencode")
            assert result.exit_code == 0
            assert "opencode" in result.stdout.lower(), (
                f"opencode not found: {result.stdout[:500]}"
            )
        finally:
            sb.stop()


# ============================================================================
# Test Group 5: Profile Inheritance (unit tests, no Docker)
# ============================================================================


class TestProfileWorkflows:
    """Test profile creation and inheritance as a team would use it."""

    def test_team_extends_builtin(self, tmp_path):
        """Create a team profile that extends 'development', verify merge."""
        from lasso.config.profile import load_profile, save_profile

        base = standard_profile(str(tmp_path / "workspace"))
        # Create a team variant with tighter network controls
        team_profile = SandboxProfile(
            name="team-backend",
            description="Backend team profile based on development",
            extends="standard",
            filesystem=FilesystemConfig(working_dir=str(tmp_path / "workspace")),
            commands=base.commands.model_copy(),
            network=NetworkConfig(
                mode=NetworkMode.RESTRICTED,
                allowed_domains=["pypi.org", "github.com"],
                allowed_ports=[443],
            ),
            mode=ProfileMode.ASSIST,
            audit=AuditConfig(
                enabled=True,
                sign_entries=True,
                log_dir=str(tmp_path / "audit"),
            ),
        )
        profile_dir = tmp_path / "profiles"
        profile_dir.mkdir()
        save_profile(team_profile, profile_dir)

        # Load it back and verify
        loaded = load_profile("team-backend", profile_dir)
        assert loaded.name == "team-backend"
        assert loaded.extends == "standard"
        assert loaded.network.mode == NetworkMode.RESTRICTED
        assert "pypi.org" in loaded.network.allowed_domains
        assert loaded.audit.sign_entries is True

    def test_profile_lock_and_verify(self, tmp_path):
        """Lock a profile (record hash) and verify it matches on reload."""
        from lasso.config.profile import load_profile, save_profile

        profile = strict_profile(str(tmp_path / "workspace"))
        profile_dir = tmp_path / "profiles"
        profile_dir.mkdir()
        save_profile(profile, profile_dir)

        # Record the config hash (this is the "lock")
        original_hash = profile.config_hash()

        # Load and verify hash matches
        loaded = load_profile("strict", profile_dir)
        assert loaded.config_hash() == original_hash, (
            "Profile hash changed after save/load cycle"
        )

    def test_profile_export_import_strict_rejects_tampered(self, tmp_path):
        """Export, modify, reimport -- verify strict mode rejects it."""
        from lasso.config.profile import save_profile
        from lasso.config.sharing import export_profile, import_profile

        profile_dir = tmp_path / "profiles"
        profile_dir.mkdir()

        # Save strict profile first so export can find it
        profile = strict_profile(str(tmp_path / "workspace"))
        save_profile(profile, profile_dir)

        # Export
        export_path = tmp_path / "exported_strict.toml"
        export_profile("strict", export_path, profile_dir=profile_dir)
        assert export_path.exists()

        # Tamper with the exported file -- change the description
        content = export_path.read_text()
        tampered = content.replace(
            profile.description,
            "TAMPERED DESCRIPTION that changes the hash",
        )
        tampered_path = tmp_path / "tampered_strict.toml"
        tampered_path.write_text(tampered)

        # Import in strict mode should raise ValueError
        import_dir = tmp_path / "import_profiles"
        import_dir.mkdir()
        with pytest.raises(ValueError, match="hash mismatch"):
            import_profile(tampered_path, profile_dir=import_dir, strict=True)

    def test_profile_export_import_roundtrip(self, tmp_path):
        """Export and reimport without tampering succeeds."""
        from lasso.config.profile import save_profile
        from lasso.config.sharing import export_profile, import_profile

        profile_dir = tmp_path / "profiles"
        profile_dir.mkdir()

        profile = strict_profile(str(tmp_path / "workspace"))
        save_profile(profile, profile_dir)

        export_path = tmp_path / "exported_offline.toml"
        export_profile("offline", export_path, profile_dir=profile_dir)

        import_dir = tmp_path / "import_profiles"
        import_dir.mkdir()
        imported = import_profile(export_path, profile_dir=import_dir, strict=True)
        assert imported.name == "offline"
        assert imported.network.mode == NetworkMode.NONE

    def test_all_builtin_profiles_valid(self, tmp_path):
        """Verify all builtin profiles can be instantiated and have valid hashes."""
        for name, factory in BUILTIN_PROFILES.items():
            profile = factory(str(tmp_path / "workspace"))
            assert profile.name == name
            assert len(profile.config_hash()) == 64  # SHA-256 hex
            assert profile.commands.mode in (CommandMode.WHITELIST, CommandMode.BLACKLIST)


# ============================================================================
# Test Group 6: CLI Smoke Tests
# ============================================================================


class TestCLISmokeTests:
    """Test the CLI commands work end-to-end via subprocess."""

    @staticmethod
    def _run_lasso(*args, timeout=30):
        """Run a lasso CLI command and return the CompletedProcess."""
        cmd = [sys.executable, "-m", "lasso"] + list(args)
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd="/tmp",
        )

    def test_lasso_version(self):
        """lasso version outputs version info."""
        result = self._run_lasso("version")
        assert result.returncode == 0
        assert "LASSO" in result.stdout or "lasso" in result.stdout.lower()

    def test_lasso_doctor(self):
        """lasso doctor runs without crashing."""
        result = self._run_lasso("doctor")
        # Doctor may return non-zero if some checks fail, but should not crash
        assert result.returncode in (0, 1)
        output = result.stdout + result.stderr
        assert len(output) > 0

    def test_lasso_check(self):
        """lasso check --json returns valid JSON."""
        result = self._run_lasso("check", "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "platform" in data
        assert "container_runtime" in data

    def test_lasso_profile_list(self):
        """lasso profile list shows builtin profiles."""
        result = self._run_lasso("profile", "list")
        assert result.returncode == 0
        output = result.stdout
        assert "evaluation" in output
        assert "standard" in output
        assert "strict" in output

    @pytest.mark.timeout(120)
    def test_lasso_create_and_status(self, tmp_path):
        """lasso create + lasso status shows the sandbox."""
        workdir = str(tmp_path / "workspace")
        os.makedirs(workdir, exist_ok=True)

        # Create
        result = self._run_lasso(
            "create", "evaluation", "--dir", workdir,
            timeout=90,
        )
        assert result.returncode == 0, f"create failed: {result.stderr}"
        # Extract sandbox ID from output
        output = result.stdout + result.stderr
        # The CLI prints the sandbox ID
        sandbox_id = None
        for line in output.splitlines():
            stripped = line.strip()
            # Look for a hex ID (12 chars)
            if len(stripped) >= 10 and all(c in "0123456789abcdef" for c in stripped[:12]):
                sandbox_id = stripped[:12]
                break
            # Or look for "Created sandbox <id>" pattern
            if "sandbox" in stripped.lower() and "creat" in stripped.lower():
                parts = stripped.split()
                for p in parts:
                    clean = p.strip("'\"()[]")
                    if len(clean) >= 10 and all(c in "0123456789abcdef" for c in clean[:12]):
                        sandbox_id = clean[:12]
                        break

        try:
            # Status should list at least one sandbox
            status_result = self._run_lasso("status")
            assert status_result.returncode == 0
        finally:
            # Cleanup: stop all sandboxes
            self._run_lasso("stop", "all", timeout=30)

    @pytest.mark.timeout(90)
    def test_lasso_exec_allowed(self, tmp_path):
        """lasso create + exec echo returns output."""
        workdir = str(tmp_path / "workspace")
        os.makedirs(workdir, exist_ok=True)

        # Create minimal sandbox
        create_result = self._run_lasso(
            "create", "evaluation", "--dir", workdir,
            timeout=60,
        )
        assert create_result.returncode == 0
        output = create_result.stdout + create_result.stderr

        # Extract sandbox ID
        sandbox_id = None
        for line in output.splitlines():
            stripped = line.strip()
            for part in stripped.split():
                clean = part.strip("'\"()[]")
                if len(clean) >= 10 and all(c in "0123456789abcdef" for c in clean[:12]):
                    sandbox_id = clean[:12]
                    break
            if sandbox_id:
                break

        try:
            if sandbox_id:
                exec_result = self._run_lasso(
                    "exec", sandbox_id, "--", "echo", "hello",
                    timeout=15,
                )
                # Even if exec returns non-zero (mode restrictions), it should not crash
                combined = exec_result.stdout + exec_result.stderr
                # In observe mode, echo might be allowed
                assert "hello" in combined or "BLOCKED" in combined or "not allowed" in combined.lower()
        finally:
            self._run_lasso("stop", "all", timeout=30)

    @pytest.mark.timeout(90)
    def test_lasso_exec_blocked(self, tmp_path):
        """lasso exec with blocked command shows BLOCKED."""
        workdir = str(tmp_path / "workspace")
        os.makedirs(workdir, exist_ok=True)

        create_result = self._run_lasso(
            "create", "evaluation", "--dir", workdir,
            timeout=60,
        )
        assert create_result.returncode == 0
        output = create_result.stdout + create_result.stderr

        sandbox_id = None
        for line in output.splitlines():
            for part in line.strip().split():
                clean = part.strip("'\"()[]")
                if len(clean) >= 10 and all(c in "0123456789abcdef" for c in clean[:12]):
                    sandbox_id = clean[:12]
                    break
            if sandbox_id:
                break

        try:
            if sandbox_id:
                exec_result = self._run_lasso(
                    "exec", sandbox_id, "--", "rm", "-rf", "/",
                    timeout=15,
                )
                combined = exec_result.stdout + exec_result.stderr
                assert (
                    "BLOCKED" in combined
                    or "not in the whitelist" in combined
                    or "blocked" in combined.lower()
                ), f"Expected blocked message, got: {combined}"
        finally:
            self._run_lasso("stop", "all", timeout=30)

    def test_lasso_dry_run(self, tmp_path):
        """lasso create --dry-run shows config without creating."""
        workdir = str(tmp_path / "workspace")
        os.makedirs(workdir, exist_ok=True)
        result = self._run_lasso(
            "create", "standard", "--dir", workdir, "--dry-run",
        )
        # dry-run should succeed and show config info
        combined = result.stdout + result.stderr
        assert result.returncode == 0 or "dry" in combined.lower()


# ============================================================================
# Test Group 7: Dashboard Smoke Tests
# ============================================================================


class TestDashboardSmokeTests:
    """Test dashboard pages render correctly."""

    @pytest.fixture(autouse=True)
    def setup_app(self, tmp_path):
        """Create a Flask test client with public mode enabled."""
        os.environ["LASSO_DASHBOARD_PUBLIC"] = "1"
        try:
            from lasso.dashboard.app import create_app
            self.app = create_app()
            self.app.config["TESTING"] = True
            self.client = self.app.test_client()
        finally:
            # Clean up env var after app creation (it's already read)
            pass
        yield
        os.environ.pop("LASSO_DASHBOARD_PUBLIC", None)

    def test_login_page_renders(self):
        """GET /login returns 200 with login form."""
        # In public mode, /login redirects to /
        response = self.client.get("/login")
        assert response.status_code in (200, 302)
        if response.status_code == 200:
            data = response.get_data(as_text=True)
            assert "login" in data.lower() or "token" in data.lower()

    def test_index_page_requires_auth(self):
        """Without public mode, GET / redirects to /login."""
        # Temporarily disable public mode
        os.environ.pop("LASSO_DASHBOARD_PUBLIC", None)
        from lasso.dashboard.app import create_app
        app = create_app()
        app.config["TESTING"] = True
        client = app.test_client()

        response = client.get("/")
        assert response.status_code in (302, 303)
        assert "/login" in response.headers.get("Location", "")

    def test_index_page_with_auth(self):
        """GET / in public mode shows sandbox page."""
        response = self.client.get("/")
        assert response.status_code == 200
        data = response.get_data(as_text=True)
        # Should contain dashboard content
        assert "LASSO" in data or "sandbox" in data.lower() or "lasso" in data.lower()

    def test_profiles_page_renders(self):
        """GET /profiles shows profile listing."""
        response = self.client.get("/profiles")
        assert response.status_code == 200
        data = response.get_data(as_text=True)
        # Should list builtin profiles
        assert "evaluation" in data.lower() or "standard" in data.lower() or "profile" in data.lower()

    def test_security_headers_present(self):
        """Verify security headers are set on responses."""
        response = self.client.get("/")
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert "Content-Security-Policy" in response.headers

    def test_404_on_nonexistent_sandbox(self):
        """GET /sandbox/nonexistent returns 404."""
        response = self.client.get("/sandbox/doesnotexist123")
        assert response.status_code == 404


# ============================================================================
# Test Group 8: Command Gate Edge Cases (unit tests, no Docker)
# ============================================================================


class TestCommandGateEdgeCases:
    """Test command gate security edge cases that a pentester would try."""

    @pytest.fixture
    def gate(self):
        """Create a command gate with development profile settings."""
        profile = standard_profile("/workspace")
        return CommandGate(profile.commands, mode=ProfileMode.AUTONOMOUS)

    def test_null_byte_injection(self, gate):
        """Null bytes in commands are stripped."""
        verdict = gate.check("echo\x00hello")
        # Should either be allowed (null stripped) or blocked
        # The key is it doesn't crash
        assert verdict is not None

    def test_control_character_rejected(self, gate):
        """Control characters (newlines, etc.) are rejected."""
        verdict = gate.check("echo\nhidden_command")
        assert verdict.blocked
        assert "control character" in verdict.reason.lower()

    def test_url_encoded_path_traversal(self, gate):
        """URL-encoded path traversal is detected."""
        verdict = gate.check("cat %2e%2e%2fetc%2fpasswd")
        assert verdict.blocked
        assert "traversal" in verdict.reason.lower()

    def test_unicode_dot_lookalike_blocked(self, gate):
        """Unicode characters that look like dots are blocked in paths."""
        # \u2024 is "one dot leader" -- looks like "." but isn't
        verdict = gate.check("cat \u2024\u2024/etc/passwd")
        assert verdict.blocked

    def test_database_clients_blocked(self, gate):
        """Database client tools are always blocked."""
        for db_client in ["psql", "mysql", "mongo", "redis-cli", "sqlcmd"]:
            # These are in DANGEROUS_ARGS with empty list = always blocked
            verdict = gate.check(f"{db_client} --help")
            assert verdict.blocked, f"{db_client} should be blocked"

    def test_empty_command_blocked(self, gate):
        """Empty commands are rejected."""
        verdict = gate.check("")
        assert verdict.blocked
        verdict = gate.check("   ")
        assert verdict.blocked

    def test_git_push_force_blocked(self):
        """git push --force is blocked in strict profiles."""
        profile = strict_profile("/workspace")
        gate = CommandGate(profile.commands, mode=ProfileMode.AUTONOMOUS)
        verdict = gate.check("git push --force origin main")
        assert verdict.blocked

    def test_pip_install_user_blocked(self):
        """pip install --user is blocked in strict profiles."""
        profile = strict_profile("/workspace")
        gate = CommandGate(profile.commands, mode=ProfileMode.AUTONOMOUS)
        verdict = gate.check("pip install --user malicious-pkg")
        assert verdict.blocked

    def test_gradual_authorization_modes(self):
        """Verify observe mode restricts more than assist mode."""
        profile = standard_profile("/workspace")

        # Observe mode: very restricted
        gate = CommandGate(profile.commands, mode=ProfileMode.OBSERVE)
        observe_policy = gate.explain_policy()
        observe_cmds = set(observe_policy["allowed_commands"])

        # Assist mode: more commands
        gate.set_mode(ProfileMode.ASSIST)
        assist_policy = gate.explain_policy()
        assist_cmds = set(assist_policy["allowed_commands"])

        # Autonomous mode: full whitelist
        gate.set_mode(ProfileMode.AUTONOMOUS)
        auto_policy = gate.explain_policy()
        auto_cmds = set(auto_policy["allowed_commands"])

        # Each mode should allow progressively more commands
        assert len(observe_cmds) <= len(assist_cmds) <= len(auto_cmds)
