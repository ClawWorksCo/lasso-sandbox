"""Audit logger — tamper-evident, structured logging of every sandbox action.

Every command execution, file modification, network request, and policy
violation is recorded with timestamps, sandbox ID, and optional HMAC
signatures for tamper detection.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import logging.handlers
import os
import secrets
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lasso.config.schema import AuditConfig
from lasso.utils.paths import get_lasso_dir

logger = logging.getLogger("lasso.audit")


class AuditEvent:
    """A single auditable event."""

    __slots__ = (
        "event_id", "timestamp", "sandbox_id", "event_type",
        "actor", "action", "target", "detail", "outcome", "signature",
    )

    def __init__(
        self,
        sandbox_id: str,
        event_type: str,
        action: str,
        target: str = "",
        detail: dict[str, Any] | None = None,
        outcome: str = "success",
        actor: str = "agent",
    ):
        self.event_id = uuid.uuid4().hex
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.sandbox_id = sandbox_id
        self.event_type = event_type
        self.actor = actor
        self.action = action
        self.target = target
        self.detail = detail or {}
        self.outcome = outcome
        self.signature: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "event_id": self.event_id,
            "ts": self.timestamp,
            "sandbox_id": self.sandbox_id,
            "type": self.event_type,
            "actor": self.actor,
            "action": self.action,
            "target": self.target,
            "outcome": self.outcome,
        }
        if self.detail:
            d["detail"] = self.detail
        if self.signature:
            d["sig"] = self.signature
        return d


class AuditLogger:
    """Append-only, optionally HMAC-signed audit log."""

    def __init__(
        self,
        sandbox_id: str,
        config: AuditConfig,
        profile_name: str = "",
        webhook_dispatcher: Any | None = None,
    ):
        self.sandbox_id = sandbox_id
        self.config = config
        self._profile_name = profile_name
        self._signing_key: bytes | None = None
        self._log_path: Path | None = None
        self._chain_hash: str = "0" * 64  # hash chain seed
        self._lock = threading.Lock()
        self._webhook_dispatcher = webhook_dispatcher
        self._syslog_handler: logging.handlers.SysLogHandler | None = None

        if config.enabled:
            self._setup_log_dir()
        if config.sign_entries:
            self._load_or_create_signing_key()
        if config.syslog_address:
            self._setup_syslog()

    def _setup_log_dir(self) -> None:
        log_dir = Path(self.config.log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"{self.sandbox_id}_{ts}.jsonl"
        self._log_path = log_dir / filename

    def _load_or_create_signing_key(self) -> None:
        if self.config.signing_key_path:
            key_path = Path(self.config.signing_key_path)
        else:
            key_path = get_lasso_dir() / ".audit_key"

        # [AU-1] Reject key paths co-located with logs in non-dev profiles.
        # An attacker who gains access to the log directory should not also
        # be able to read or replace the signing key.
        log_dir = Path(self.config.log_dir).resolve()
        resolved_key = key_path.resolve() if key_path.exists() else key_path.parent.resolve() / key_path.name
        try:
            resolved_key.relative_to(log_dir)
            key_inside_log_dir = True
        except ValueError:
            key_inside_log_dir = False

        if key_inside_log_dir:
            profile_name = getattr(self, '_profile_name', None) or ''
            # Allow co-located key only for low-security builtin profiles.
            _RELAXED_PROFILES = ('standard', 'open', '')
            if profile_name.lower() not in _RELAXED_PROFILES:
                raise RuntimeError(
                    f"[AU-1] Signing key '{resolved_key}' is inside the log "
                    f"directory '{log_dir}'. Move it to a separate location "
                    f"(e.g. ~/.lasso/.audit_key) or set signing_key_path in "
                    f"the audit config."
                )
            else:
                logger.warning(
                    "Audit signing key is inside the log directory at %s. "
                    "This is only acceptable for standard/open profiles. "
                    "For production, configure signing_key_path to an external location.",
                    resolved_key,
                )

        if key_path.exists():
            self._signing_key = key_path.read_bytes()
        else:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            self._signing_key = secrets.token_bytes(32)
            key_path.write_bytes(self._signing_key)
            try:
                os.chmod(str(key_path), 0o600)
            except OSError:
                logger.warning(
                    "Could not set permissions on %s (Windows?)", key_path
                )

    # Mapping from syslog facility name to SysLogHandler constant.
    _SYSLOG_FACILITY_MAP: dict[str, int] = {
        "local0": logging.handlers.SysLogHandler.LOG_LOCAL0,
        "local1": logging.handlers.SysLogHandler.LOG_LOCAL1,
        "local2": logging.handlers.SysLogHandler.LOG_LOCAL2,
        "local3": logging.handlers.SysLogHandler.LOG_LOCAL3,
        "local4": logging.handlers.SysLogHandler.LOG_LOCAL4,
        "local5": logging.handlers.SysLogHandler.LOG_LOCAL5,
        "local6": logging.handlers.SysLogHandler.LOG_LOCAL6,
        "local7": logging.handlers.SysLogHandler.LOG_LOCAL7,
        "auth": logging.handlers.SysLogHandler.LOG_AUTH,
        "daemon": logging.handlers.SysLogHandler.LOG_DAEMON,
        "user": logging.handlers.SysLogHandler.LOG_USER,
    }

    def _setup_syslog(self) -> None:
        """Configure syslog forwarding if ``syslog_address`` is set.

        Supports Unix socket paths (e.g. ``/dev/log``) and network
        addresses in the form ``udp://host:port`` or ``tcp://host:port``.
        Errors during setup are logged but never crash the process.
        """
        address = self.config.syslog_address
        if not address:
            return

        facility = self._SYSLOG_FACILITY_MAP.get(
            self.config.syslog_facility.lower(),
            logging.handlers.SysLogHandler.LOG_LOCAL0,
        )

        try:
            socktype = None  # default (UDP for network)
            if address.startswith("udp://"):
                host_port = address[len("udp://"):]
                host, _, port_str = host_port.rpartition(":")
                resolved_address: str | tuple[str, int] = (host, int(port_str or 514))
            elif address.startswith("tcp://"):
                import socket as _socket
                host_port = address[len("tcp://"):]
                host, _, port_str = host_port.rpartition(":")
                resolved_address = (host, int(port_str or 514))
                socktype = _socket.SOCK_STREAM
            else:
                # Unix domain socket path (e.g. /dev/log)
                resolved_address = address

            handler = logging.handlers.SysLogHandler(
                address=resolved_address,
                facility=facility,
                **({"socktype": socktype} if socktype is not None else {}),
            )
            handler.setFormatter(logging.Formatter("lasso-audit: %(message)s"))
            self._syslog_handler = handler
            logger.info("Syslog forwarding configured: %s (facility=%s)", address, self.config.syslog_facility)
        except Exception as exc:
            logger.warning("Failed to configure syslog forwarding to %s: %s", address, exc)

    def _forward_to_syslog(self, json_line: str) -> None:
        """Send a single audit entry to syslog. Errors are logged, never raised."""
        if self._syslog_handler is None:
            return
        try:
            record = logging.LogRecord(
                name="lasso.audit",
                level=logging.INFO,
                pathname="",
                lineno=0,
                msg=json_line,
                args=(),
                exc_info=None,
            )
            self._syslog_handler.emit(record)
        except Exception as exc:
            logger.warning("Syslog forwarding failed: %s", exc)

    def _sign(self, payload: str) -> str:
        """HMAC-SHA256 of payload chained with previous hash for tamper detection."""
        if not self._signing_key:
            return ""
        chain_input = f"{self._chain_hash}:{payload}"
        sig = hmac.new(self._signing_key, chain_input.encode(), hashlib.sha256).hexdigest()
        self._chain_hash = sig
        return sig

    def _check_rotation(self) -> None:
        """Rotate the log file if it exceeds the configured max size.

        Rotation scheme: current.jsonl -> current.jsonl.1, .1 -> .2, etc.
        Files beyond rotation_count are deleted.
        """
        if not self._log_path:
            return

        try:
            if not self._log_path.exists():
                return
            size_bytes = self._log_path.stat().st_size
        except OSError:
            return

        max_bytes = self.config.max_log_size_mb * 1024 * 1024
        if size_bytes < max_bytes:
            return

        # Rotate: shift existing numbered files up
        base = self._log_path
        for i in range(self.config.rotation_count, 0, -1):
            src = Path(f"{base}.{i}")
            dst = Path(f"{base}.{i + 1}")
            if src.exists():
                if i >= self.config.rotation_count:
                    # Delete files beyond rotation_count
                    try:
                        src.unlink()
                    except OSError as e:
                        logger.warning("Failed to delete rotated log %s: %s", src, e)
                else:
                    try:
                        src.rename(dst)
                    except OSError as e:
                        logger.warning("Failed to rotate log %s -> %s: %s", src, dst, e)

        # Move current log to .1
        rotated_path = Path(f"{base}.1")
        try:
            self._log_path.rename(rotated_path)
        except OSError as e:
            logger.warning("Failed to rotate current log to .1: %s", e)

        # Reset the hash chain so the new file is independently verifiable.
        # Preserve the old chain hash so the rotation marker can link files.
        prev_chain_hash = self._chain_hash
        self._chain_hash = "0" * 64

        # The next write will create a fresh file automatically.
        # Log a lifecycle event about the rotation (written to the new file).
        self._log_rotation_event(
            previous_log_file=str(rotated_path),
            previous_chain_hash=prev_chain_hash,
        )

    def _sign_and_write(self, event: AuditEvent) -> None:
        """Sign an event (if configured) and write it to the log file and syslog.

        This is the shared write path used by both :meth:`log` and
        :meth:`_log_rotation_event`.  Caller must already hold ``self._lock``
        when thread-safety is required.
        """
        payload = json.dumps(event.to_dict(), separators=(",", ":"), sort_keys=True)
        if self.config.sign_entries:
            event.signature = self._sign(payload)
        line = json.dumps(event.to_dict(), separators=(",", ":"), sort_keys=True)
        if self._log_path:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        self._forward_to_syslog(line)
        logger.debug("audit: %s", line)

    def _log_rotation_event(
        self,
        previous_log_file: str = "",
        previous_chain_hash: str = "",
    ) -> None:
        """Write a lifecycle event noting that log rotation occurred.

        The ``rotation_marker`` detail fields link the new file back to the
        previous one so that a full-chain verifier can confirm continuity
        across rotated files.

        Note: caller must already hold ``self._lock``.
        """
        detail: dict[str, Any] = {
            "max_log_size_mb": self.config.max_log_size_mb,
            "rotation_count": self.config.rotation_count,
            "rotation_marker": True,
        }
        if previous_log_file:
            detail["previous_log_file"] = previous_log_file
        if previous_chain_hash:
            detail["previous_chain_hash"] = previous_chain_hash

        event = AuditEvent(
            sandbox_id=self.sandbox_id,
            event_type="lifecycle",
            action="log_rotated",
            actor="system",
            detail=detail,
        )
        # Write directly to avoid infinite recursion (don't call self.log)
        self._sign_and_write(event)
        # Dispatch rotation events to webhooks (same as regular events in self.log)
        if self._webhook_dispatcher:
            try:
                self._webhook_dispatcher.dispatch(event)
            except Exception:
                logger.debug("Webhook dispatch failed for rotation event %s", event.event_id)

    def log(self, event: AuditEvent) -> None:
        """Write an event to the audit log."""
        if not self.config.enabled:
            return

        with self._lock:
            # Check if rotation is needed before writing
            self._check_rotation()

            self._sign_and_write(event)

        # Dispatch to webhooks (non-blocking, on background threads) — outside lock
        if self._webhook_dispatcher is not None:
            try:
                self._webhook_dispatcher.dispatch(event)
            except Exception:
                logger.debug("Webhook dispatch failed for event %s", event.event_id)

    # --- Convenience methods ---

    def log_command(
        self,
        command: str,
        args: list[str],
        outcome: str = "success",
        detail: dict[str, Any] | None = None,
    ) -> None:
        self.log(AuditEvent(
            sandbox_id=self.sandbox_id,
            event_type="command",
            action=command,
            target=" ".join(args),
            outcome=outcome,
            detail=detail or {},
        ))

    def log_command_blocked(self, command: str, reason: str) -> None:
        self.log(AuditEvent(
            sandbox_id=self.sandbox_id,
            event_type="command",
            action=command,
            outcome="blocked",
            detail={"reason": reason},
        ))

    def log_file_access(
        self, path: str, operation: str, outcome: str = "success"
    ) -> None:
        self.log(AuditEvent(
            sandbox_id=self.sandbox_id,
            event_type="file",
            action=operation,
            target=path,
            outcome=outcome,
        ))

    def log_network(
        self, host: str, port: int, outcome: str = "success"
    ) -> None:
        self.log(AuditEvent(
            sandbox_id=self.sandbox_id,
            event_type="network",
            action="connect",
            target=f"{host}:{port}",
            outcome=outcome,
        ))

    def log_lifecycle(self, action: str, detail: dict[str, Any] | None = None) -> None:
        self.log(AuditEvent(
            sandbox_id=self.sandbox_id,
            event_type="lifecycle",
            action=action,
            actor="system",
            detail=detail or {},
        ))

    def log_violation(self, rule_id: str, description: str, severity: str = "error") -> None:
        self.log(AuditEvent(
            sandbox_id=self.sandbox_id,
            event_type="violation",
            action=rule_id,
            outcome="blocked",
            detail={"description": description, "severity": severity},
        ))

    def close(self) -> None:
        """Close the webhook dispatcher and release resources."""
        if self._webhook_dispatcher is not None:
            try:
                self._webhook_dispatcher.close()
            except Exception:
                logger.debug("Failed to close webhook dispatcher")

    @property
    def log_file(self) -> Path | None:
        return self._log_path
