"""Persistent state store for sandbox registry.

Saves sandbox metadata to ~/.lasso/state.json so that LASSO can recover
after crashes. On startup, reconciles persisted state against actual
container status from the backend.

Uses file locking for safe concurrent access via
:mod:`lasso.utils.filelock` (fcntl on Linux/macOS, msvcrt on Windows).
"""

from __future__ import annotations

import json
import logging
import os
import platform
import tempfile as _tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lasso.utils.filelock import locked_file
from lasso.utils.paths import get_lasso_dir

logger = logging.getLogger("lasso.state")


@dataclass
class SandboxRecord:
    """Persisted metadata for a single sandbox."""
    sandbox_id: str
    profile_name: str
    container_id: str | None = None
    state: str = "created"
    mode: str = "observe"
    agent: str | None = None
    working_dir: str | None = None
    created_at: str = ""
    stopped_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SandboxRecord:
        return cls(
            sandbox_id=data["sandbox_id"],
            profile_name=data["profile_name"],
            container_id=data.get("container_id"),
            state=data.get("state", "created"),
            mode=data.get("mode", "observe"),
            agent=data.get("agent"),
            working_dir=data.get("working_dir"),
            created_at=data.get("created_at", ""),
            stopped_at=data.get("stopped_at"),
        )


@dataclass
class RegistryState:
    """Top-level persisted state document."""
    version: int = 1
    updated_at: str = ""
    sandboxes: dict[str, SandboxRecord] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "updated_at": self.updated_at,
            "sandboxes": {
                sid: rec.to_dict() for sid, rec in self.sandboxes.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RegistryState:
        sandboxes = {}
        for sid, rec_data in data.get("sandboxes", {}).items():
            sandboxes[sid] = SandboxRecord.from_dict(rec_data)
        return cls(
            version=data.get("version", 1),
            updated_at=data.get("updated_at", ""),
            sandboxes=sandboxes,
        )


_VALID_MODES = {"observe", "assist", "autonomous"}



class StateStore:
    """Persistent state store backed by a JSON file with file locking."""

    def __init__(self, state_dir: str | None = None):
        if state_dir:
            self._state_dir = Path(state_dir)
        else:
            self._state_dir = get_lasso_dir()
        self._state_file = self._state_dir / "state.json"
        self._state: RegistryState = RegistryState()

    @property
    def state_file(self) -> Path:
        return self._state_file

    def load(self) -> RegistryState:
        """Load state from disk. Returns empty state if file doesn't exist.

        Handles corrupt or empty state files gracefully by starting fresh
        rather than crashing.
        """
        if not self._state_file.exists():
            self._state = RegistryState()
            return self._state

        try:
            # Check for empty/zero-byte file before attempting JSON parse
            if self._state_file.stat().st_size == 0:
                logger.warning("Empty state file %s, starting fresh.", self._state_file)
                self._state = RegistryState()
                return self._state

            with locked_file(self._state_file, "r") as f:
                raw = f.read()
            if not raw or not raw.strip():
                logger.warning("Blank state file %s, starting fresh.", self._state_file)
                self._state = RegistryState()
                return self._state

            data = json.loads(raw)
            self._state = RegistryState.from_dict(data)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            logger.warning("Corrupt state file %s, starting fresh: %s", self._state_file, e)
            self._state = RegistryState()
        except OSError as e:
            logger.warning("Cannot read state file %s, starting fresh: %s", self._state_file, e)
            self._state = RegistryState()

        return self._state

    def save(self) -> None:
        """Write current state to disk with file locking.

        Uses atomic write (tempfile + rename) with a Windows-specific retry
        loop for ``os.replace()``, which can fail with ``[WinError 5] Access
        is denied`` when another process has the target file open.  After
        retries are exhausted, falls back to a direct (non-atomic) write so
        the state is never silently lost.

        On PermissionError the directory is self-healed (re-created with
        correct ownership) and the write is retried once before giving up.
        """
        try:
            self._state_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            logger.warning(
                "PermissionError creating %s — attempting self-heal",
                self._state_dir,
            )
            self._self_heal_dir()

        self._state.updated_at = datetime.now(timezone.utc).isoformat()

        # Restrict directory permissions (owner-only)
        try:
            self._state_dir.chmod(0o700)
        except OSError:
            pass  # Windows or permission error — best effort

        payload = json.dumps(self._state.to_dict(), indent=2)

        if platform.system() == "Windows":
            self._save_windows(payload)
        else:
            self._save_posix(payload)

    def _self_heal_dir(self) -> None:
        """Attempt to re-create the state directory after a PermissionError."""
        try:
            import shutil
            if self._state_dir.exists():
                shutil.rmtree(self._state_dir, ignore_errors=True)
            self._state_dir.mkdir(parents=True, exist_ok=True)
            self._state_dir.chmod(0o700)
            logger.info("Self-healed state directory: %s", self._state_dir)
        except OSError as e:
            logger.error("Self-heal failed for %s: %s", self._state_dir, e)

    def _save_windows(self, payload: str) -> None:
        """Windows save path: retry os.replace with back-off, then direct write fallback."""
        tmp_fd, tmp_path = _tempfile.mkstemp(dir=self._state_dir, suffix=".tmp")
        tmp_file = Path(tmp_path)
        try:
            os.close(tmp_fd)
            with open(tmp_file, "w") as f:
                f.write(payload)

            replaced = False
            for attempt in range(5):
                try:
                    tmp_file.replace(self._state_file)
                    replaced = True
                    break
                except PermissionError:
                    if attempt < 4:
                        time.sleep(0.1 * (attempt + 1))
                    else:
                        logger.warning(
                            "Atomic replace failed after retries; "
                            "falling back to direct write for %s",
                            self._state_file,
                        )

            if not replaced:
                try:
                    with open(self._state_file, "w") as f:
                        f.write(payload)
                except OSError as e:
                    logger.error("Direct write fallback also failed for %s: %s", self._state_file, e)

            if tmp_file.exists():
                try:
                    tmp_file.unlink()
                except OSError:
                    pass

            try:
                self._state_file.chmod(0o600)
            except OSError:
                pass
        except OSError as e:
            logger.error("Failed to save state to %s: %s", self._state_file, e)
            if tmp_file.exists():
                try:
                    tmp_file.unlink()
                except OSError:
                    pass

    def _save_posix(self, payload: str) -> None:
        """POSIX save path: atomic tempfile + rename."""
        tmp_fd, tmp_path = _tempfile.mkstemp(dir=self._state_dir, suffix=".tmp")
        tmp_file = Path(tmp_path)
        try:
            os.close(tmp_fd)
            with open(tmp_file, "w") as f:
                f.write(payload)

            tmp_file.replace(self._state_file)

            try:
                self._state_file.chmod(0o600)
            except OSError:
                pass
        except OSError as e:
            logger.error("Failed to save state to %s: %s", self._state_file, e)
            if tmp_file.exists():
                try:
                    tmp_file.unlink()
                except OSError:
                    pass

    def record_create(self, sandbox_id: str, profile_name: str,
                      container_id: str | None = None,
                      mode: str = "observe",
                      agent: str | None = None,
                      working_dir: str | None = None) -> None:
        """Record that a sandbox was created.

        Raises:
            ValueError: If mode is not one of "observe", "assist", "autonomous".
        """
        if mode not in _VALID_MODES:
            raise ValueError(
                f"Invalid mode '{mode}'. Must be one of: {', '.join(sorted(_VALID_MODES))}"
            )
        self._state.sandboxes[sandbox_id] = SandboxRecord(
            sandbox_id=sandbox_id,
            profile_name=profile_name,
            container_id=container_id,
            state="running",
            mode=mode,
            agent=agent,
            working_dir=working_dir,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.save()

    def update_container_id(self, sandbox_id: str, container_id: str) -> None:
        """Update the container ID for a sandbox after it has been started."""
        rec = self._state.sandboxes.get(sandbox_id)
        if rec:
            rec.container_id = container_id
            self.save()

    def record_mode_change(self, sandbox_id: str, mode: str) -> None:
        """Record a sandbox mode change.

        Raises:
            ValueError: If mode is not one of "observe", "assist", "autonomous".
        """
        if mode not in _VALID_MODES:
            raise ValueError(
                f"Invalid mode '{mode}'. Must be one of: {', '.join(sorted(_VALID_MODES))}"
            )
        record = self._state.sandboxes.get(sandbox_id)
        if record:
            record.mode = mode
            self.save()

    def record_stop(self, sandbox_id: str) -> None:
        """Record that a sandbox was stopped."""
        record = self._state.sandboxes.get(sandbox_id)
        if record:
            record.state = "stopped"
            record.stopped_at = datetime.now(timezone.utc).isoformat()
            self.save()

    def record_remove(self, sandbox_id: str) -> None:
        """Remove a sandbox from persisted state."""
        if sandbox_id in self._state.sandboxes:
            del self._state.sandboxes[sandbox_id]
            self.save()

    def get_all_records(self) -> dict[str, SandboxRecord]:
        """Return all persisted sandbox records."""
        return dict(self._state.sandboxes)

    def get_running_records(self) -> dict[str, SandboxRecord]:
        """Return records for sandboxes believed to be running."""
        return {
            sid: rec for sid, rec in self._state.sandboxes.items()
            if rec.state == "running"
        }

    def reconcile(self, backend) -> dict[str, str]:
        """Reconcile persisted state against actual container status.

        Checks which containers still exist via the backend. Updates state
        for containers that have disappeared or stopped.

        Args:
            backend: A ContainerBackend instance (or None for native mode).

        Returns:
            Dict mapping sandbox_id to action taken: "alive", "stopped", "gone".
        """
        results: dict[str, str] = {}

        if backend is None:
            # In native mode, mark all as gone since we can't verify
            for sid, rec in list(self._state.sandboxes.items()):
                if rec.state == "running":
                    rec.state = "stopped"
                    rec.stopped_at = datetime.now(timezone.utc).isoformat()
                    results[sid] = "gone"
                else:
                    results[sid] = "stopped"
            self.save()
            return results

        for sid, rec in list(self._state.sandboxes.items()):
            if rec.state != "running" or not rec.container_id:
                results[sid] = "stopped"
                continue

            try:
                info = backend.inspect(rec.container_id)
                from lasso.backends.base import ContainerState
                if info.state == ContainerState.RUNNING:
                    results[sid] = "alive"
                else:
                    rec.state = "stopped"
                    rec.stopped_at = datetime.now(timezone.utc).isoformat()
                    results[sid] = "stopped"
            except Exception:
                # Container no longer exists
                rec.state = "stopped"
                rec.stopped_at = datetime.now(timezone.utc).isoformat()
                results[sid] = "gone"

        self.save()
        return results
