"""Audit log verification — independently verify the integrity of audit trails.

Replays the HMAC hash chain to detect tampering, deletion, or reordering
of audit entries.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path

from lasso.utils.paths import get_lasso_dir


@dataclass
class VerificationResult:
    """Result of verifying an audit log."""
    valid: bool
    total_entries: int
    verified_entries: int
    first_break_at: int | None = None  # line number of first chain break
    errors: list[str] = None
    final_chain_hash: str = ""  # chain hash after last entry (for cross-file linking)

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


def verify_audit_log(
    log_path: str | Path,
    key_path: str | Path | None = None,
) -> VerificationResult:
    """Verify the HMAC hash chain of an audit log file.

    Replays the exact chain logic from AuditLogger:
    - chain starts at "0" * 64
    - each entry is signed as HMAC(key, f"{prev_chain_hash}:{payload_without_sig}")
    - the signature of entry N becomes the chain input for entry N+1
    """
    log_path = Path(log_path)
    if not log_path.exists():
        return VerificationResult(
            valid=False, total_entries=0, verified_entries=0,
            errors=[f"Log file not found: {log_path}"],
        )

    # Find the signing key
    if key_path:
        key_file = Path(key_path)
    else:
        # Check the new default location first, then fall back to legacy
        # (co-located with logs) for backward compatibility.
        default_key = get_lasso_dir() / ".audit_key"
        legacy_key = log_path.parent / ".audit_key"
        if default_key.exists():
            key_file = default_key
        else:
            key_file = legacy_key

    if not key_file.exists():
        return VerificationResult(
            valid=False, total_entries=0, verified_entries=0,
            errors=[f"Signing key not found at {key_file}. Cannot verify signatures."],
        )

    signing_key = key_file.read_bytes()

    # Read and verify entries
    chain_hash = "0" * 64
    entries = []
    errors = []
    verified = 0
    first_break = None

    with open(log_path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                errors.append(f"Line {line_num}: invalid JSON: {e}")
                if first_break is None:
                    first_break = line_num
                continue

            stored_sig = entry.get("sig", "")
            if not stored_sig:
                errors.append(f"Line {line_num}: no signature found")
                if first_break is None:
                    first_break = line_num
                entries.append(entry)
                continue

            # Reconstruct the payload WITHOUT the signature (as the logger does)
            entry_no_sig = {k: v for k, v in entry.items() if k != "sig"}
            payload = json.dumps(entry_no_sig, separators=(",", ":"), sort_keys=True)

            # Compute expected signature
            chain_input = f"{chain_hash}:{payload}"
            expected_sig = hmac.new(
                signing_key, chain_input.encode(), hashlib.sha256
            ).hexdigest()

            if hmac.compare_digest(expected_sig, stored_sig):
                verified += 1
                chain_hash = stored_sig  # advance chain
            else:
                errors.append(
                    f"Line {line_num}: signature mismatch "
                    f"(expected {expected_sig[:16]}..., got {stored_sig[:16]}...)"
                )
                if first_break is None:
                    first_break = line_num
                # Still advance chain with stored sig to check remaining entries
                chain_hash = stored_sig

            entries.append(entry)

    total = len(entries)
    return VerificationResult(
        valid=(verified == total and total > 0),
        total_entries=total,
        verified_entries=verified,
        first_break_at=first_break,
        errors=errors,
        final_chain_hash=chain_hash,
    )


def read_audit_entries(
    log_path: str | Path,
    tail: int = 0,
    event_type: str | None = None,
) -> list[dict]:
    """Read audit log entries with optional filtering.

    Args:
        log_path: Path to JSONL audit log.
        tail: If > 0, return only the last N entries.
        event_type: Filter by event type (command, lifecycle, violation, etc.)
    """
    log_path = Path(log_path)
    if not log_path.exists():
        return []

    entries = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if event_type and entry.get("type") != event_type:
                    continue
                entries.append(entry)
            except json.JSONDecodeError:
                continue

    if tail > 0:
        return entries[-tail:]
    return entries


def verify_chain(
    log_paths: list[str | Path],
    key_path: str | Path | None = None,
) -> VerificationResult:
    """Verify a sequence of rotated audit log files as a single chain.

    Each individual file is verified independently (chain seeded from
    ``"0" * 64``).  Then the rotation markers that link adjacent files are
    checked: the ``previous_chain_hash`` recorded in file N must equal the
    final chain hash of file N-1.

    Args:
        log_paths: Log files in **chronological** order (oldest first).
        key_path: Optional explicit path to the signing key.

    Returns:
        A single :class:`VerificationResult` that aggregates all files.
    """
    if not log_paths:
        return VerificationResult(
            valid=False, total_entries=0, verified_entries=0,
            errors=["No log files provided."],
        )

    all_errors: list[str] = []
    total_entries = 0
    total_verified = 0
    first_break: int | None = None
    entry_offset = 0  # running line-number offset across files
    prev_final_hash: str | None = None
    final_hash = ""

    for idx, path in enumerate(log_paths):
        result = verify_audit_log(path, key_path=key_path)

        # Accumulate counts
        total_entries += result.total_entries
        total_verified += result.verified_entries

        # Prefix file name to per-file errors for clarity
        fname = Path(path).name
        for err in result.errors:
            all_errors.append(f"[{fname}] {err}")
            if first_break is None and result.first_break_at is not None:
                first_break = entry_offset + result.first_break_at

        # Cross-file linkage check: the rotation marker in file N should
        # reference the final chain hash of file N-1.
        if idx > 0 and prev_final_hash is not None:
            marker_hash = _extract_rotation_marker_hash(path)
            if marker_hash is None:
                err = (
                    f"[{fname}] Missing rotation_marker entry; "
                    f"cannot verify linkage from previous file."
                )
                all_errors.append(err)
                if first_break is None:
                    first_break = entry_offset + 1
            elif marker_hash != prev_final_hash:
                err = (
                    f"[{fname}] Rotation marker previous_chain_hash "
                    f"({marker_hash[:16]}...) does not match previous "
                    f"file's final chain hash ({prev_final_hash[:16]}...)."
                )
                all_errors.append(err)
                if first_break is None:
                    first_break = entry_offset + 1

        prev_final_hash = result.final_chain_hash
        final_hash = result.final_chain_hash
        entry_offset += result.total_entries

    return VerificationResult(
        valid=(total_verified == total_entries and total_entries > 0 and not all_errors),
        total_entries=total_entries,
        verified_entries=total_verified,
        first_break_at=first_break,
        errors=all_errors,
        final_chain_hash=final_hash,
    )


def _extract_rotation_marker_hash(log_path: str | Path) -> str | None:
    """Read the first entry of *log_path* and return its ``previous_chain_hash``.

    Returns ``None`` if the first entry is not a rotation marker or the
    field is missing.
    """
    log_path = Path(log_path)
    if not log_path.exists():
        return None

    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return None

            detail = entry.get("detail", {})
            if detail.get("rotation_marker"):
                return detail.get("previous_chain_hash")
            # First non-empty line is not a rotation marker
            return None

    return None
