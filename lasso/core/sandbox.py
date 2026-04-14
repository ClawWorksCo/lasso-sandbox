"""Sandbox — the main orchestrator that ties all isolation layers together.

Lifecycle: create → configure → start → exec → stop → cleanup

Supports two execution modes:
1. Container backend (Docker/Podman) — primary, cross-platform
2. Native backend (Linux namespaces) — fallback for lightweight use
"""

from __future__ import annotations

import logging
import platform
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("lasso.sandbox")

from lasso.agents.registry import AGENT_CLI_COMMANDS
from lasso.backends.base import ContainerBackend, ContainerState
from lasso.backends.converter import needs_network_rules, profile_to_container_config
from lasso.config.schema import DATABASE_PORT_NAMES, ProfileMode, SandboxProfile, SandboxState
from lasso.core.audit import AuditLogger
from lasso.core.commands import CommandGate
from lasso.core.network import NetworkPolicy


@dataclass
class SandboxExecResult:
    """Result of a command execution inside the sandbox."""
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int = 0
    blocked: bool = False
    block_reason: str = ""


# Backward-compat alias (prefer SandboxExecResult in new code)
ExecResult = SandboxExecResult


class Sandbox:
    """A single isolated execution environment.

    Each Sandbox instance represents one agent's sandboxed workspace with
    its own filesystem view, command policy, network rules, resource limits,
    and audit trail.

    When a `backend` is provided, commands execute inside a container.
    When no backend is provided, falls back to direct subprocess execution
    with software-level isolation (command gate + env sanitization).
    """

    def __init__(
        self,
        profile: SandboxProfile,
        backend: ContainerBackend | None = None,
        sandbox_id: str | None = None,
    ):
        self.id = sandbox_id or uuid.uuid4().hex[:12]
        self.profile = profile.model_copy(deep=True)
        self._mode = self.profile.mode
        self.state = SandboxState.CREATED
        self.created_at = datetime.now(timezone.utc)

        # Pluggable backend
        self._backend = backend
        self._container_id: str | None = None

        # If Docker-from-Docker is enabled, allow docker/podman commands
        if self.profile.docker_from_docker:
            for cmd in ("docker", "podman"):
                if cmd in self.profile.commands.blacklist:
                    self.profile.commands.blacklist.remove(cmd)

        # If an AI agent is selected, configure the sandbox for it:
        # - Add CLI command to whitelists
        # Agent API domains are now included directly in profiles so no
        # dynamic domain injection is needed here.
        agent = self.profile.extra_env.get("LASSO_AGENT", "")
        if agent and agent in AGENT_CLI_COMMANDS:
            for cmd in AGENT_CLI_COMMANDS[agent]:
                # For whitelist mode: add to allowed lists
                if cmd not in self.profile.commands.whitelist:
                    self.profile.commands.whitelist.append(cmd)
                if cmd not in self.profile.commands.assist_whitelist:
                    self.profile.commands.assist_whitelist.append(cmd)
                if cmd not in self.profile.commands.observe_whitelist:
                    self.profile.commands.observe_whitelist.append(cmd)
                # For blacklist mode: ensure agent CLI is not blocked
                if cmd in self.profile.commands.blacklist:
                    self.profile.commands.blacklist.remove(cmd)

        # Core subsystems (always active regardless of backend)
        self.command_gate = CommandGate(self.profile.commands, mode=self._mode)

        # Set up webhook dispatcher if any webhooks are configured
        webhook_dispatcher = None
        if self.profile.audit.webhooks:
            from lasso.core.webhooks import WebhookDispatcher
            webhook_dispatcher = WebhookDispatcher(self.profile.audit.webhooks)

        self.audit = AuditLogger(self.id, self.profile.audit, profile_name=self.profile.name, webhook_dispatcher=webhook_dispatcher)

        # Runtime counters
        self._exec_count = 0
        self._blocked_count = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the sandbox environment."""
        if self.state not in (SandboxState.CREATED, SandboxState.STOPPED):
            raise RuntimeError(f"Cannot start sandbox in state: {self.state.value}")

        self.state = SandboxState.CONFIGURING
        self.audit.log_lifecycle("start", {
            "profile": self.profile.name,
            "config_hash": self.profile.config_hash(),
            "backend": self._backend.__class__.__name__ if self._backend else "native",
        })

        if self._backend:
            # If we already have a container (e.g. stopped sandbox being
            # restarted), just restart it instead of creating a new one.
            if self._container_id:
                self._restart_existing_container()
            else:
                self._start_with_backend()
        else:
            self._start_native()

        self.state = SandboxState.RUNNING
        self.audit.log_lifecycle("running")

    def _restart_existing_container(self) -> None:
        """Restart a stopped container that already exists."""
        try:
            self._backend.start(self._container_id)
        except Exception as e:
            self.state = SandboxState.ERROR
            self.audit.log_lifecycle("restart_failed", {"error": str(e)})
            raise

        # Re-apply network policy since iptables rules are lost on restart
        self._apply_network_policy()

    def _start_with_backend(self) -> None:
        """Start using a container backend."""
        if not self._backend.is_available():
            self.state = SandboxState.ERROR
            raise RuntimeError(
                f"Container backend {self._backend.__class__.__name__} is not available. "
                "Is the runtime installed and running?"
            )
        from lasso.backends.image_builder import ensure_image
        from lasso.config.operational import load_config
        agent = self.profile.extra_env.get("LASSO_AGENT")
        op_config = load_config()
        image_tag = ensure_image(
            self._backend, self.profile, agent=agent,
            ca_cert_path=op_config.containers.ca_cert_path,
        )

        # Ensure the Docker socket proxy is running for DfD sandboxes
        if self.profile.docker_from_docker:
            from lasso.backends.docker_backend import DockerBackend
            if isinstance(self._backend, DockerBackend):
                self._backend._ensure_socket_proxy()

        container_config = profile_to_container_config(self.profile)
        container_config.name = f"lasso-{self.id}"
        container_config.image = image_tag

        try:
            self._container_id = self._backend.create(container_config)
            self._backend.start(self._container_id)
        except Exception as e:
            self.state = SandboxState.ERROR
            self.audit.log_lifecycle("start_failed", {"error": str(e)})
            raise

        # Apply network policy rules inside the container
        self._apply_network_policy()

    def _apply_network_policy(self) -> None:
        """Generate and apply iptables rules inside the container.

        Creates a NetworkPolicy from the profile's network config, generates
        iptables commands, and executes each one inside the container via the
        backend. Results are logged to the audit trail.
        """
        if not self._backend or not self._container_id:
            return

        if not needs_network_rules(self.profile):
            return

        policy = NetworkPolicy(self.profile.network)
        rules = policy.generate_iptables_rules()

        if not rules:
            return

        # Batch all rules into a single shell script for speed.
        # Running 96 individual docker exec calls takes ~10s;
        # a single batched exec takes ~0.5s.
        script_lines = ["#!/bin/sh", "set -e", "FAILED=0", "CRITICAL_FAILED=0"]
        critical_rules = []
        for rule in rules:
            rule_str = " ".join(rule)
            is_critical = " -P " in f" {rule_str} "
            if is_critical:
                # Critical rules must succeed — fail immediately
                script_lines.append(f"{rule_str} || CRITICAL_FAILED=$((CRITICAL_FAILED+1))")
                critical_rules.append(rule_str)
            else:
                # Supplementary rules — log failure but continue
                script_lines.append(f"{rule_str} 2>/dev/null || FAILED=$((FAILED+1))")

        script_lines.append('echo "CRITICAL_FAILED=$CRITICAL_FAILED FAILED=$FAILED"')
        script = "\n".join(script_lines)

        try:
            result = self._backend.exec(
                self._container_id,
                ["sh", "-c", script],
                timeout=30,
                user="root",
            )
        except Exception as e:
            self.state = SandboxState.ERROR
            raise RuntimeError(f"Network policy script failed: {e}")

        # Parse results from script output
        critical_failed = 0
        supplementary_failed = 0
        parsed = False
        if result.stdout:
            for part in result.stdout.strip().split():
                if part.startswith("CRITICAL_FAILED="):
                    critical_failed = int(part.split("=")[1])
                    parsed = True
                elif part.startswith("FAILED="):
                    supplementary_failed = int(part.split("=")[1])
                    parsed = True

        # If the script failed entirely (non-zero exit, no parseable output),
        # treat all rules as failed
        if result.exit_code != 0 and not parsed:
            critical_failed = len([r for r in rules if " -P " in f" {' '.join(r)} "])
            supplementary_failed = len(rules) - critical_failed

        applied = len(rules) - critical_failed - supplementary_failed
        failed = critical_failed + supplementary_failed

        self.audit.log_lifecycle("network_policy_applied", {
            "mode": self.profile.network.mode.value,
            "rules_total": len(rules),
            "rules_applied": applied,
            "rules_failed": failed,
            "critical_failed": critical_failed,
            "supplementary_failed": supplementary_failed,
        })

        if critical_failed > 0:
            self.state = SandboxState.ERROR
            raise RuntimeError(
                f"Critical network policy rules failed ({critical_failed} policy rules). "
                "Container is not safely isolated."
            )

        if failed == len(rules) and len(rules) > 0:
            self.state = SandboxState.ERROR
            raise RuntimeError(
                "All network policy rules failed to apply. "
                "Is iptables installed in the container image?"
            )

        # Remove iptables binaries so a root process inside the container
        # cannot flush the firewall rules we just applied.
        try:
            self._backend.exec(
                self._container_id,
                ["sh", "-c",
                 "rm -f /usr/sbin/iptables /usr/sbin/ip6tables "
                 "/usr/sbin/iptables-save /usr/sbin/iptables-restore "
                 "/usr/sbin/ip6tables-save /usr/sbin/ip6tables-restore "
                 "2>/dev/null; true"],
                timeout=10,
                user="root",
            )
            self.audit.log_lifecycle("iptables_binaries_removed")
        except Exception as e:
            logger.warning("Failed to remove iptables binaries: %s", e)

        if supplementary_failed > 0:
            logger.warning(
                "Network policy: %d/%d rules succeeded "
                "(%d supplementary rules failed, default policies OK)",
                applied, len(rules), supplementary_failed,
            )

    def _inject_github_token(self, env: dict[str, str]) -> None:
        """Inject GitHub token into sandbox environment if available.

        Only injects if the profile has agent_auth.github_token_env configured.
        Token is sourced from GitHubAuth (which checks GITHUB_TOKEN env var
        and ~/.lasso/github_token.json).
        """
        if not self.profile.agent_auth:
            return

        token_env_name = self.profile.agent_auth.github_token_env
        if not token_env_name:
            return

        try:
            from lasso.auth.github import GitHubAuth
            auth = GitHubAuth()
            token = auth.get_token()
            if token:
                env[token_env_name] = token
                self.audit.log_lifecycle("github_token_injected", {
                    "env_var": token_env_name,
                })
        except Exception as e:
            logger.debug("Could not inject GitHub token: %s", e)

    def _start_native(self) -> None:
        """Start with native (subprocess) isolation — no container runtime needed."""
        # Native mode just validates the working directory exists
        from pathlib import Path
        workdir = Path(self.profile.filesystem.working_dir)
        if not workdir.exists():
            workdir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Profile mode (gradual authorization)
    # ------------------------------------------------------------------

    @property
    def mode(self) -> ProfileMode:
        """Current profile mode controlling command access level."""
        return self._mode

    def set_mode(self, new_mode: ProfileMode) -> None:
        """Change the sandbox profile mode (gradual authorization).

        Validates the transition, updates the command gate, and logs
        the mode change to the audit trail.

        Raises:
            RuntimeError: If the sandbox is not in RUNNING state.
        """
        if self.state != SandboxState.RUNNING:
            raise RuntimeError(
                f"Cannot change mode on sandbox in state: {self.state.value}. "
                "Sandbox must be running."
            )

        old_mode = self._mode
        if old_mode == new_mode:
            return

        self._mode = new_mode
        self.command_gate.set_mode(new_mode)

        self.audit.log_lifecycle("mode_changed", {
            "old_mode": old_mode.value,
            "new_mode": new_mode.value,
        })

        logger.info(
            "Sandbox %s mode changed: %s -> %s",
            self.id, old_mode.value, new_mode.value,
        )

    def exec(self, raw_command: str) -> SandboxExecResult:
        """Execute a command inside the sandbox with full policy enforcement.

        1. Validate command against the command gate
        2. If allowed, execute via backend or native subprocess
        3. Log everything to audit trail
        4. Return structured result
        """
        if self.state != SandboxState.RUNNING:
            return SandboxExecResult(
                command=raw_command,
                exit_code=-1,
                stdout="",
                stderr=f"Sandbox is not running (state: {self.state.value})",
                duration_ms=0,
                blocked=True,
                block_reason="Sandbox not running",
            )

        self._exec_count += 1

        # --- Step 1: Command validation (always, regardless of backend) ---
        verdict = self.command_gate.check(raw_command)

        if verdict.blocked:
            self._blocked_count += 1
            self.audit.log_command_blocked(raw_command, verdict.reason)
            return SandboxExecResult(
                command=raw_command,
                exit_code=-1,
                stdout="",
                stderr=f"BLOCKED: {verdict.reason}",
                duration_ms=0,
                blocked=True,
                block_reason=verdict.reason,
            )

        # --- Step 2: Execute ---
        start_time = time.monotonic_ns()
        cmd_list = [verdict.command] + verdict.args

        if self._backend and self._container_id:
            result = self._exec_with_backend(cmd_list)
        else:
            result = self._exec_native(cmd_list)

        duration_ms = (time.monotonic_ns() - start_time) // 1_000_000

        # --- Step 3: Audit ---
        detail = {"duration_ms": duration_ms, "exit_code": result.exit_code}
        if self.profile.audit.include_command_output:
            detail["stdout_head"] = result.stdout[:2000]
            detail["stderr_head"] = result.stderr[:2000]

        self.audit.log_command(
            verdict.command,
            verdict.args,
            outcome="success" if result.exit_code == 0 else "error",
            detail=detail,
        )

        return SandboxExecResult(
            command=raw_command,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_ms=duration_ms,
        )

    def _exec_with_backend(self, cmd: list[str]) -> SandboxExecResult:
        """Execute a command via the container backend."""
        try:
            backend_result = self._backend.exec(
                self._container_id,
                cmd,
                timeout=self.profile.commands.max_execution_seconds,
            )
            return SandboxExecResult(
                command=" ".join(cmd),
                exit_code=backend_result.exit_code,
                stdout=backend_result.stdout,
                stderr=backend_result.stderr,
                duration_ms=backend_result.duration_ms,
            )
        except Exception as e:
            return SandboxExecResult(
                command=" ".join(cmd),
                exit_code=-1,
                stdout="",
                stderr=str(e),
                duration_ms=0,
            )

    def _exec_native(self, cmd: list[str]) -> SandboxExecResult:
        """Execute a command as a subprocess with env sanitization."""
        if platform.system() == "Windows":
            default_path = r"C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem"
        else:
            default_path = "/usr/local/bin:/usr/bin:/bin"

        env = {
            "PATH": default_path,
            "HOME": self.profile.filesystem.working_dir,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TERM": "dumb",
            "LASSO_SANDBOX_ID": self.id,
            "LASSO_SANDBOX_NAME": self.profile.name,
        }

        # Inject GitHub token if available and configured
        self._inject_github_token(env)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.profile.commands.max_execution_seconds,
                env=env,
                cwd=self.profile.filesystem.working_dir,
            )
            return SandboxExecResult(
                command=" ".join(cmd),
                exit_code=proc.returncode,
                stdout=proc.stdout.decode(errors="replace"),
                stderr=proc.stderr.decode(errors="replace"),
            )
        except subprocess.TimeoutExpired:
            return SandboxExecResult(
                command=" ".join(cmd),
                exit_code=-1,
                stdout="",
                stderr=f"Command timed out after {self.profile.commands.max_execution_seconds}s",
            )
        except Exception as e:
            return SandboxExecResult(
                command=" ".join(cmd),
                exit_code=-1,
                stdout="",
                stderr=str(e),
            )

    def stop(self) -> None:
        """Stop the sandbox and clean up."""
        if self.state == SandboxState.STOPPED:
            return

        prev_state = self.state
        self.state = SandboxState.STOPPED

        if self._backend and self._container_id:
            try:
                self._backend.stop(self._container_id)
                self._backend.remove(self._container_id)
            except Exception as e:
                logger.warning("Container cleanup failed for %s: %s", self._container_id[:12], e)

            # Clean up the socket proxy if no DfD sandboxes remain
            if self.profile.docker_from_docker:
                from lasso.backends.docker_backend import DockerBackend
                if isinstance(self._backend, DockerBackend):
                    try:
                        self._backend._cleanup_socket_proxy()
                    except Exception as e:
                        logger.warning("Socket proxy cleanup failed: %s", e)

        # Emit the "stopped" lifecycle event BEFORE closing the audit
        # dispatcher, so the webhook for this final event actually fires.
        self.audit.log_lifecycle("stopped", {
            "prev_state": prev_state.value,
            "total_execs": self._exec_count,
            "total_blocked": self._blocked_count,
        })

        # Close the webhook dispatcher to flush queued events and free threads
        self.audit.close()

    # ------------------------------------------------------------------
    # Status / introspection
    # ------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Return current sandbox status including full security posture."""
        net = self.profile.network
        fs = self.profile.filesystem
        audit_cfg = self.profile.audit

        return {
            "id": self.id,
            "name": self.profile.name,
            "state": self.state.value,
            "mode": self._mode.value,
            "created_at": self.created_at.isoformat(),
            "working_dir": fs.working_dir,
            "exec_count": self._exec_count,
            "blocked_count": self._blocked_count,
            "config_hash": self.profile.config_hash()[:12],
            "audit_log": str(self.audit.log_file) if self.audit.log_file else None,
            "network_mode": net.mode.value,
            "command_mode": self.profile.commands.mode.value,
            "backend": self._backend.__class__.__name__ if self._backend else "native",
            "container_id": self._container_id,
            # Network policy details
            "network": {
                "mode": net.mode.value,
                "allowed_domains": net.allowed_domains,
                "blocked_ports": net.blocked_ports,
                "blocked_ports_named": {
                    port: DATABASE_PORT_NAMES.get(port, f"port {port}")
                    for port in net.blocked_ports
                },
                "blocked_cidrs": net.blocked_cidrs,
                "allowed_ports": net.allowed_ports,
                "dns_servers": net.dns_servers,
            },
            # Filesystem isolation details
            "filesystem": {
                "working_dir": fs.working_dir,
                "read_only_paths": fs.read_only_paths,
                "hidden_paths": fs.hidden_paths,
                "writable_paths": fs.writable_paths,
                "max_disk_mb": fs.max_disk_mb,
                "temp_dir_mb": fs.temp_dir_mb,
            },
            # Audit configuration
            "audit_config": {
                "enabled": audit_cfg.enabled,
                "sign_entries": audit_cfg.sign_entries,
                "log_dir": audit_cfg.log_dir,
                "include_command_output": audit_cfg.include_command_output,
                "include_file_diffs": audit_cfg.include_file_diffs,
                "max_log_size_mb": audit_cfg.max_log_size_mb,
                "webhooks_count": len(audit_cfg.webhooks),
            },
        }

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False

    def __repr__(self) -> str:
        return f"<Sandbox id={self.id} name={self.profile.name!r} state={self.state.value}>"


# ---------------------------------------------------------------------------
# Multi-sandbox registry
# ---------------------------------------------------------------------------

class SandboxRegistry:
    """Manages multiple running sandboxes with optional persistent state.

    When a ``state_dir`` is provided (or defaults to ``~/.lasso``),
    sandbox metadata is persisted to disk so that LASSO can recover
    after crashes.  On construction the store is loaded automatically;
    call :meth:`reconcile` after init to prune stale entries.
    """

    def __init__(
        self,
        backend: ContainerBackend | None = None,
        state_dir: str | None = None,
    ):
        self._sandboxes: dict[str, Sandbox] = {}
        self._backend = backend

        # Persistent state
        from lasso.core.state import StateStore
        self._store = StateStore(state_dir=state_dir)
        self._store.load()

        # Reconcile persisted state with actual container status
        if self._backend:
            try:
                self._store.reconcile(self._backend)
            except Exception as e:
                logger.warning("Reconcile failed during startup: %s", e)

    def create(self, profile: SandboxProfile) -> Sandbox:
        """Create and register a new sandbox.

        Returns a Sandbox instance (not yet started -- caller must call
        ``sandbox.start()``).
        """
        sb = Sandbox(profile, backend=self._backend)
        self._sandboxes[sb.id] = sb
        self._store.record_create(
            sandbox_id=sb.id,
            profile_name=profile.name,
            container_id=sb._container_id,
            mode=profile.mode.value,
            agent=profile.extra_env.get("LASSO_AGENT"),
            working_dir=profile.filesystem.working_dir,
        )
        return sb

    def start(self, sandbox: Sandbox) -> None:
        """Start a sandbox and update the state store with the container ID."""
        sandbox.start()
        if sandbox._container_id:
            self._store.update_container_id(sandbox.id, sandbox._container_id)

    def get(self, sandbox_id: str) -> Sandbox | None:
        sb = self._sandboxes.get(sandbox_id)
        if sb is not None:
            return sb

        # Try to reconnect from state store + running container
        return self._reconnect(sandbox_id)

    def _reconnect(self, sandbox_id: str) -> Sandbox | None:
        """Rebuild a Sandbox object from the state store and Docker.

        When the CLI runs as a new process, the in-memory registry is
        empty.  This method checks the persisted state file, verifies
        the container still exists via the backend, and rebuilds a
        usable Sandbox instance.

        If the state file is corrupt or empty (e.g. after a Windows
        ``os.replace()`` failure), falls back to discovering the container
        by its Docker name convention (``lasso-{sandbox_id}``).
        """
        self._store.load()  # refresh from disk
        # Check all records (not just running) so we can reconnect to
        # stopped containers that still exist in Docker.
        records = self._store.get_all_records()
        rec = records.get(sandbox_id)

        if not self._backend:
            return None

        if rec is None:
            # State file has no record for this sandbox — may be corrupt
            # or empty.  Try to discover the container by Docker name as
            # a last resort so "Open Terminal" / "lasso attach" still works.
            return self._reconnect_by_container_name(sandbox_id)

        # Find the container: first try stored ID, then search by name
        container_id = rec.container_id
        if not container_id:
            # Look up by Docker container name convention: lasso-{sandbox_id}
            try:
                info = self._backend.inspect(f"lasso-{sandbox_id}")
                container_id = f"lasso-{sandbox_id}"
            except Exception:
                return None
        else:
            try:
                info = self._backend.inspect(container_id)
            except Exception:
                return None

        if info.state not in (ContainerState.RUNNING, ContainerState.PAUSED, ContainerState.STOPPED):
            return None

        # Rebuild a minimal Sandbox that can exec commands (or be restarted)
        from lasso.config.defaults import BUILTIN_PROFILES
        factory = BUILTIN_PROFILES.get(rec.profile_name)
        if factory:
            profile = factory("/workspace")
        else:
            # Try loading a saved profile
            try:
                from lasso.config.profile import load_profile
                profile = load_profile(rec.profile_name)
            except Exception:
                # SECURITY: Original profile not found. Fall back to the most
                # restrictive builtin profile to avoid privilege escalation.
                # A sandbox created with a strict/custom profile must never
                # silently resume under a permissive profile.
                logger.warning(
                    "Reconnecting sandbox %s: profile '%s' not found. "
                    "Falling back to 'strict' profile to prevent "
                    "security downgrade. Restore the original profile "
                    "or stop and recreate the sandbox.",
                    sandbox_id,
                    rec.profile_name,
                )
                from lasso.config.defaults import strict_profile
                profile = strict_profile("/workspace")

        # Restore the agent so the CLI is whitelisted
        if rec.agent:
            profile.extra_env["LASSO_AGENT"] = rec.agent

        sb = Sandbox(profile, backend=self._backend, sandbox_id=sandbox_id)
        sb._container_id = container_id

        # Set the sandbox state to match the container state
        if info.state == ContainerState.STOPPED:
            sb.state = SandboxState.STOPPED
        else:
            sb.state = SandboxState.RUNNING

        try:
            sb._mode = ProfileMode(rec.mode)
        except ValueError:
            sb._mode = profile.mode

        self._sandboxes[sandbox_id] = sb
        return sb

    def _reconnect_by_container_name(self, sandbox_id: str) -> Sandbox | None:
        """Last-resort reconnection when the state file has no record.

        Attempts to find a running container named ``lasso-{sandbox_id}``
        and rebuilds a Sandbox with the strict profile (safest default).
        This handles the case where the state file was corrupted (e.g. by
        a Windows file-locking race) but the container is still running.
        """
        container_name = f"lasso-{sandbox_id}"
        try:
            info = self._backend.inspect(container_name)
        except Exception:
            return None

        if info.state not in (ContainerState.RUNNING, ContainerState.PAUSED, ContainerState.STOPPED):
            return None

        logger.warning(
            "Sandbox %s not found in state file but container '%s' exists. "
            "Reconnecting with strict profile (state file may be corrupt).",
            sandbox_id,
            container_name,
        )

        # SECURITY: No state record means we don't know the original profile.
        # Use strict as the safest default.
        from lasso.config.defaults import strict_profile
        profile = strict_profile("/workspace")

        sb = Sandbox(profile, backend=self._backend, sandbox_id=sandbox_id)
        sb._container_id = container_name

        if info.state == ContainerState.STOPPED:
            sb.state = SandboxState.STOPPED
        else:
            sb.state = SandboxState.RUNNING

        self._sandboxes[sandbox_id] = sb

        # Re-persist the record so subsequent lookups don't hit the fallback
        self._store.record_create(
            sandbox_id=sandbox_id,
            profile_name="strict",
            container_id=container_name,
            mode=profile.mode.value,
        )

        return sb

    def find_existing(self, working_dir: str, agent: str | None = None) -> Sandbox | None:
        """Find an existing sandbox matching the given working directory.

        Searches through all persisted sandbox records (running or stopped)
        for one whose working_dir matches. If ``agent`` is provided, only
        matches sandboxes with that agent.

        Returns the Sandbox if found and reconnectable, None otherwise.
        Running sandboxes are preferred over stopped ones.
        """
        from pathlib import Path
        target = str(Path(working_dir).resolve())

        self._store.load()
        all_records = self._store.get_all_records()

        # Prefer running sandboxes, then stopped
        best_match_id: str | None = None
        best_is_running = False

        for sid, rec in all_records.items():
            # Match working_dir
            if rec.working_dir != target:
                continue

            # Match agent if specified
            if agent is not None and rec.agent != agent:
                continue

            is_running = rec.state == "running"

            # Prefer running over stopped
            if best_match_id is None or (is_running and not best_is_running):
                best_match_id = sid
                best_is_running = is_running

        if best_match_id is None:
            return None

        # Try to reconnect (will return None if container is truly gone)
        if best_is_running:
            return self.get(best_match_id)

        # For stopped sandboxes, return a reconnected instance if possible
        return self._reconnect(best_match_id)

    def get_by_name(self, name: str) -> Sandbox | None:
        for sb in self._sandboxes.values():
            if sb.profile.name == name:
                return sb
        return None

    def list_all(self) -> list[dict[str, Any]]:
        # Reconnect any running sandboxes from the state store
        self._store.load()
        for sid in self._store.get_running_records():
            if sid not in self._sandboxes:
                self._reconnect(sid)
        return [sb.status() for sb in self._sandboxes.values()]

    def set_mode(self, sandbox_id: str, mode: ProfileMode) -> bool:
        """Change the profile mode for a running sandbox.

        Returns True if the sandbox was found and mode updated.
        """
        sb = self._sandboxes.get(sandbox_id) or self._reconnect(sandbox_id)
        if sb:
            sb.set_mode(mode)
            self._store.record_mode_change(sandbox_id, mode.value)
            return True
        return False

    def stop(self, sandbox_id: str) -> bool:
        sb = self._sandboxes.get(sandbox_id) or self._reconnect(sandbox_id)
        if sb:
            sb.stop()
            self._store.record_stop(sandbox_id)
            return True
        return False

    def stop_all(self) -> int:
        count = 0
        for sb in self._sandboxes.values():
            if sb.state == SandboxState.RUNNING:
                sb.stop()
                self._store.record_stop(sb.id)
                count += 1
        return count

    def remove(self, sandbox_id: str) -> bool:
        sb = self._sandboxes.pop(sandbox_id, None)
        if sb is None:
            sb = self._reconnect(sandbox_id)
            if sb:
                self._sandboxes.pop(sandbox_id, None)
        if sb:
            sb.stop()
            self._store.record_remove(sandbox_id)
            return True
        return False

    def reconcile(self) -> dict[str, str]:
        """Reconcile persisted state against actual containers.

        Checks which containers from previous runs still exist and updates
        the state store accordingly.  Returns a dict mapping sandbox_id to
        the action taken (``"alive"``, ``"stopped"``, or ``"gone"``).
        """
        return self._store.reconcile(self._backend)

    def shutdown(self) -> None:
        """Gracefully shut down all sandboxes, save state, and log events.

        Called by signal handlers and atexit hooks to ensure clean teardown.
        Logs lifecycle events for audit trail compliance.
        """
        # Use a dedicated audit logger for registry-level events

        audit = None
        # Borrow an audit logger from any existing sandbox, or create a minimal one
        for sb in self._sandboxes.values():
            if sb.audit and sb.audit.config.enabled:
                audit = sb.audit
                break

        if audit:
            audit.log_lifecycle("shutdown_initiated", {
                "sandbox_count": len(self._sandboxes),
                "running_count": sum(
                    1 for sb in self._sandboxes.values()
                    if sb.state == SandboxState.RUNNING
                ),
            })

        # Stop all running sandboxes
        stopped = self.stop_all()

        # Save state to disk
        self._store.save()

        if audit:
            audit.log_lifecycle("shutdown_complete", {
                "sandboxes_stopped": stopped,
            })

        logger.info("Shutdown complete: %d sandbox(es) stopped, state saved.", stopped)

    @property
    def store(self):
        """Access the underlying StateStore (for inspection / testing)."""
        return self._store

    def __len__(self) -> int:
        return len(self._sandboxes)
