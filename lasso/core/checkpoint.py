"""Checkpoint versioning for LASSO releases.

Tracks verified release checkpoints so that teams can pin to a known-good
version and receive warnings when a newer checkpoint is available.

Persistence follows the StateStore pattern: file-locked JSON with atomic
writes to ``~/.lasso/checkpoints.json``.

Each checkpoint entry carries an HMAC-SHA256 signature (in the ``sha256``
field) computed over ``tag:version:released_at`` using the audit signing
key.  Use :func:`verify_checkpoint` to validate entries independently.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lasso.utils.crypto import sign_config, verify_config
from lasso.utils.filelock import locked_file
from lasso.utils.paths import get_lasso_dir

logger = logging.getLogger("lasso.checkpoint")

# When a remote manifest endpoint is configured, CheckpointStore can
# fetch the canonical list of checkpoints from this URL.  For now we
# operate in local-only mode.
CHECKPOINT_MANIFEST_URL: str = ""

# Default name for the checkpoint signing key (co-located with checkpoints.json).
_CHECKPOINT_KEY_FILE = ".checkpoint_key"


def _parse_version(version: str) -> tuple[int, ...]:
    """Parse a semver-ish string into a comparable tuple of ints.

    Strips leading 'v' and handles pre-release suffixes.  A pre-release
    version sorts *before* the corresponding release:
    ``(0, 3, 0, 0)`` for ``"0.3.0-beta1"`` vs ``(0, 3, 0, 1)`` for
    ``"0.3.0"``.

    Falls back to ``(0,)`` on parse errors so comparisons never crash.
    """
    v = version.strip().lstrip("v")
    is_prerelease = False
    if "-" in v:
        v = v.split("-", 1)[0]
        is_prerelease = True
    try:
        parts = tuple(int(part) for part in v.split("."))
        # Append a release indicator: 0 = pre-release, 1 = release.
        return parts + (0 if is_prerelease else 1,)
    except (ValueError, AttributeError):
        return (0,)


def _load_or_create_key(state_dir: Path) -> bytes:
    """Load (or generate) the HMAC signing key for checkpoints.

    The key lives at ``<state_dir>/.checkpoint_key``.  If it does not
    exist yet a fresh 32-byte key is created with restricted permissions.
    """
    key_path = state_dir / _CHECKPOINT_KEY_FILE
    if key_path.exists():
        return key_path.read_bytes()

    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    key_path.write_bytes(key)
    try:
        os.chmod(str(key_path), 0o600)
    except OSError:
        logger.debug("Could not set permissions on %s (Windows?)", key_path)
    return key


def _sign_checkpoint(tag: str, version: str, released_at: str, key: bytes) -> str:
    """Compute HMAC-SHA256 over the canonical checkpoint fields."""
    payload = f"{tag}:{version}:{released_at}"
    return sign_config(payload, key)


def verify_checkpoint(checkpoint: CheckpointInfo, key: bytes) -> bool:
    """Verify the HMAC signature stored in *checkpoint.sha256*.

    Returns ``True`` when the signature matches.
    """
    payload = f"{checkpoint.tag}:{checkpoint.version}:{checkpoint.released_at}"
    return verify_config(payload, checkpoint.sha256, key)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CheckpointInfo:
    """Metadata for a single verified release checkpoint."""

    tag: str
    version: str
    released_at: str = ""
    sha256: str = ""
    notes: str = ""
    reviewed_by: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Keep reviewed_by even when empty (it's always a list)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CheckpointInfo:
        return cls(
            tag=data["tag"],
            version=data["version"],
            released_at=data.get("released_at", ""),
            sha256=data.get("sha256", ""),
            notes=data.get("notes", ""),
            reviewed_by=data.get("reviewed_by", []),
        )


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class CheckpointStore:
    """Persistent store for checkpoint metadata.

    Backed by ``~/.lasso/checkpoints.json`` using file locking and atomic
    writes, identical to :class:`lasso.core.state.StateStore`.
    """

    _thread_lock = threading.Lock()  # In-process mutex for concurrent threads

    def __init__(self, state_dir: str | None = None):
        if state_dir:
            self._state_dir = Path(state_dir)
        else:
            self._state_dir = get_lasso_dir()
        self._checkpoint_file = self._state_dir / "checkpoints.json"

    @property
    def checkpoint_file(self) -> Path:
        return self._checkpoint_file

    # -- signing key -------------------------------------------------------

    def _get_signing_key(self) -> bytes:
        """Return the HMAC signing key, creating it on first access."""
        return _load_or_create_key(self._state_dir)

    # -- manifest ----------------------------------------------------------

    def load_manifest(self) -> list[CheckpointInfo]:
        """Load all checkpoints from disk.

        Returns an empty list if the file does not exist or is corrupt.
        """
        if not self._checkpoint_file.exists():
            return []

        try:
            with locked_file(self._checkpoint_file, "r") as f:
                data = json.load(f)

            checkpoints_raw = data.get("checkpoints", [])
            return [CheckpointInfo.from_dict(c) for c in checkpoints_raw]
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.warning(
                "Corrupt checkpoint file %s, returning empty: %s",
                self._checkpoint_file,
                e,
            )
            return []

    def save_manifest(self, checkpoints: list[CheckpointInfo]) -> None:
        """Write the full checkpoint list to disk atomically."""
        self._state_dir.mkdir(parents=True, exist_ok=True)

        doc = {
            "version": 1,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "checkpoints": [c.to_dict() for c in checkpoints],
            "pinned_version": self.get_pinned_version(),
        }

        tmp_file = self._checkpoint_file.with_suffix(".tmp")
        try:
            with locked_file(tmp_file, "w") as f:
                json.dump(doc, f, indent=2)
            tmp_file.replace(self._checkpoint_file)
        except OSError as e:
            logger.error(
                "Failed to save checkpoints to %s: %s",
                self._checkpoint_file,
                e,
            )
            if tmp_file.exists():
                tmp_file.unlink()

    # -- queries -----------------------------------------------------------

    def latest_checkpoint(self) -> CheckpointInfo | None:
        """Return the checkpoint with the highest version, or None."""
        checkpoints = self.load_manifest()
        if not checkpoints:
            return None
        return max(checkpoints, key=lambda c: _parse_version(c.version))

    def check_for_update(self, current_version: str) -> CheckpointInfo | None:
        """Return the latest checkpoint if its version exceeds *current_version*.

        Returns ``None`` when there is no newer checkpoint available.
        """
        latest = self.latest_checkpoint()
        if latest is None:
            return None
        if _parse_version(latest.version) > _parse_version(current_version):
            return latest
        return None

    # -- pinning -----------------------------------------------------------

    def pin_version(self, version: str) -> None:
        """Pin the current installation to *version*.

        Writes the pin into the checkpoint JSON document so that it
        persists across sessions.
        """
        self._state_dir.mkdir(parents=True, exist_ok=True)

        # Load existing doc (or start fresh)
        doc: dict[str, Any] = {"version": 1, "checkpoints": []}
        if self._checkpoint_file.exists():
            try:
                with locked_file(self._checkpoint_file, "r") as f:
                    doc = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass

        doc["pinned_version"] = version
        doc["updated_at"] = datetime.now(timezone.utc).isoformat()

        tmp_file = self._checkpoint_file.with_suffix(".tmp")
        try:
            with locked_file(tmp_file, "w") as f:
                json.dump(doc, f, indent=2)
            tmp_file.replace(self._checkpoint_file)
        except OSError as e:
            logger.error("Failed to pin version: %s", e)
            if tmp_file.exists():
                tmp_file.unlink()

    def get_pinned_version(self) -> str | None:
        """Return the pinned version string, or None if not pinned."""
        if not self._checkpoint_file.exists():
            return None

        try:
            with locked_file(self._checkpoint_file, "r") as f:
                data = json.load(f)
            pinned = data.get("pinned_version")
            return pinned if pinned else None
        except (json.JSONDecodeError, OSError):
            return None

    # -- registration ------------------------------------------------------

    def register_checkpoint(
        self,
        tag: str,
        version: str,
        notes: str = "",
        reviewed_by: list[str] | None = None,
    ) -> CheckpointInfo:
        """Add a new checkpoint entry and persist it.

        The operation is atomic: the file lock is held across the entire
        read-modify-write cycle to prevent TOCTOU races.  Duplicate tags
        are rejected -- if *tag* already exists the existing entry is
        returned unchanged.

        Each entry is HMAC-SHA256 signed using the checkpoint signing
        key for tamper detection.

        Returns the :class:`CheckpointInfo` (newly created or existing).
        """
        self._state_dir.mkdir(parents=True, exist_ok=True)
        key = self._get_signing_key()
        released_at = datetime.now(timezone.utc).isoformat()
        signature = _sign_checkpoint(tag, version, released_at, key)

        checkpoint = CheckpointInfo(
            tag=tag,
            version=version,
            released_at=released_at,
            sha256=signature,
            notes=notes,
            reviewed_by=reviewed_by or [],
        )

        # --- atomic read-modify-write under thread + file lock ---
        # The threading.Lock serializes in-process threads (flock only
        # works across processes, not threads sharing the same process).
        # The file lock ("a+") serializes across processes and creates
        # the file atomically if it doesn't exist.
        with self._thread_lock:
            try:
                with locked_file(self._checkpoint_file, "a+") as f:
                    f.seek(0)
                    content = f.read()
                    if content.strip():
                        try:
                            existing_doc = json.loads(content)
                        except (json.JSONDecodeError, ValueError):
                            existing_doc = {"version": 1, "checkpoints": [], "pinned_version": None}
                    else:
                        existing_doc = {"version": 1, "checkpoints": [], "pinned_version": None}

                    checkpoints_raw = existing_doc.get("checkpoints", [])

                    # Duplicate detection -- reject if tag already exists.
                    for raw in checkpoints_raw:
                        if raw.get("tag") == tag:
                            logger.info("Checkpoint %s already registered, skipping", tag)
                            return CheckpointInfo.from_dict(raw)

                    checkpoints_raw.append(checkpoint.to_dict())
                    existing_doc["checkpoints"] = checkpoints_raw
                    existing_doc["updated_at"] = datetime.now(timezone.utc).isoformat()

                    # Seek to beginning, truncate, and write updated doc
                    f.seek(0)
                    f.truncate()
                    json.dump(existing_doc, f, indent=2)
            except OSError as e:
                logger.error(
                    "Failed to save checkpoint to %s: %s",
                    self._checkpoint_file,
                    e,
                )

        return checkpoint
