"""Profile sharing — export, import, versioning, and diff for team collaboration.

Supports:
- Export/import profiles as standalone TOML files with integrity hashes
- Team profile directories via LASSO_PROFILE_DIR environment variable
- Automatic version tracking with history stored in ~/.lasso/profiles/.history/
- Human-readable profile diffs for review
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path

import tomli
import tomli_w

from lasso.config.profile import (
    DEFAULT_PROFILE_DIR,
    _ensure_dir,
    _strip_none,
    load_profile,
    load_profile_from_path,
    save_profile,
)
from lasso.config.schema import SandboxProfile
from lasso.utils.filelock import locked_file

logger = logging.getLogger("lasso.sharing")


# ---------------------------------------------------------------------------
# Profile directories (personal + team)
# ---------------------------------------------------------------------------

def get_profile_dirs(working_dir: str | None = None) -> list[Path]:
    """Return all profile directories, ordered by priority (highest first).

    Precedence:
    1. <working_dir>/.lasso/profiles/ (project profiles)
    2. LASSO_PROFILE_DIR directories
    3. ~/.lasso/profiles/ (user profiles)
    """
    dirs: list[Path] = []

    # Project-level profiles (highest priority after explicit --file)
    if working_dir:
        project_profiles = Path(working_dir) / ".lasso" / "profiles"
        if project_profiles.is_dir():
            dirs.append(project_profiles)

    # LASSO_PROFILE_DIR
    env_dir = os.environ.get("LASSO_PROFILE_DIR", "")
    if env_dir:
        for part in env_dir.split(os.pathsep):
            part = part.strip()
            if part:
                p = Path(part)
                if p not in dirs:
                    dirs.append(p)

    # Default user profiles
    if DEFAULT_PROFILE_DIR not in dirs:
        dirs.append(DEFAULT_PROFILE_DIR)

    return dirs


def find_profile(name: str, working_dir: str | None = None) -> Path | None:
    """Search all profile directories for a named profile.

    Returns the path to the first match, or None.
    """
    for profile_dir in get_profile_dirs(working_dir=working_dir):
        candidate = profile_dir / f"{name}.toml"
        if candidate.exists():
            return candidate
    return None


# ---------------------------------------------------------------------------
# Export / Import
# ---------------------------------------------------------------------------

def export_profile(
    name: str,
    output_path: str | Path,
    profile_dir: Path = DEFAULT_PROFILE_DIR,
) -> Path:
    """Export a profile as a standalone TOML file with metadata.

    The exported file includes a [lasso_metadata] section with:
    - config_hash: SHA-256 of the profile for integrity verification
    - exported_at: ISO timestamp of export
    - source: where the profile was loaded from

    Args:
        name: Profile name (builtin or saved).
        output_path: Destination file path.
        profile_dir: Directory to search for saved profiles.

    Returns:
        Path to the written file.
    """
    output_path = Path(output_path)

    # Try loading from saved profiles first, then builtins
    profile: SandboxProfile | None = None
    source = "unknown"

    try:
        profile = load_profile(name, profile_dir)
        source = str(profile_dir / f"{name}.toml")
    except FileNotFoundError:
        from lasso.config.defaults import BUILTIN_PROFILES
        if name in BUILTIN_PROFILES:
            profile = BUILTIN_PROFILES[name](".")
            source = f"builtin:{name}"

    if profile is None:
        raise FileNotFoundError(f"Profile '{name}' not found in saved or builtin profiles.")

    # Build export data
    data = _strip_none(profile.model_dump(mode="json"))
    data["lasso_metadata"] = {
        "config_hash": profile.config_hash(),
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(tomli_w.dumps(data).encode())
    logger.info("Exported profile '%s' to %s", name, output_path)
    return output_path


def import_profile(
    path: str | Path,
    name: str | None = None,
    profile_dir: Path = DEFAULT_PROFILE_DIR,
    strict: bool = True,
) -> SandboxProfile:
    """Import a profile from a TOML file.

    Validates the profile structure and optionally verifies the config hash
    if lasso_metadata is present. Saves to the profile directory.

    Args:
        path: Source TOML file.
        name: Override the profile name. Uses the name from the file if None.
        profile_dir: Directory to save the imported profile.

    Returns:
        The imported SandboxProfile.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Import file not found: {path}")

    with open(path, "rb") as f:
        data = tomli.load(f)

    # Extract and remove metadata before validation
    metadata = data.pop("lasso_metadata", None)

    # Override name if provided
    if name:
        data["name"] = name

    # Validate the profile
    try:
        profile = SandboxProfile(**data)
    except Exception as e:
        raise ValueError(f"Invalid profile data in '{path}': {e}") from e

    # Verify integrity hash if metadata is present.
    # Skip verification when the name was overridden — the name is part of the
    # hash, so a rename always causes a legitimate mismatch.
    if metadata and "config_hash" in metadata and not name:
        actual_hash = profile.config_hash()
        expected_hash = metadata["config_hash"]
        if actual_hash != expected_hash:
            msg = (
                f"Config hash mismatch for imported profile '{profile.name}': "
                f"expected {expected_hash[:12]}, got {actual_hash[:12]}. "
                "The profile may have been modified since export."
            )
            if strict:
                raise ValueError(msg)
            logger.warning(msg)

    # Update timestamp
    profile.updated_at = datetime.now(timezone.utc).isoformat()

    # Save to profile directory
    save_profile(profile, profile_dir)
    logger.info("Imported profile '%s' from %s", profile.name, path)
    return profile


# ---------------------------------------------------------------------------
# Versioning
# ---------------------------------------------------------------------------

def _history_dir(name: str) -> Path:
    """Return the history directory for a profile."""
    return DEFAULT_PROFILE_DIR / ".history" / name


def save_profile_versioned(
    profile: SandboxProfile,
    profile_dir: Path = DEFAULT_PROFILE_DIR,
) -> Path:
    """Save a profile with automatic version increment and history.

    If the profile already exists:
    1. Archives the current version to .history/<name>/
    2. Increments the profile_version
    3. Saves the new version

    Returns the path to the saved profile.
    """
    _ensure_dir(profile_dir)
    dest = profile_dir / f"{profile.name}.toml"

    if dest.exists():
        # Archive the current version
        try:
            with open(dest, "rb") as f:
                old_data = tomli.load(f)
            old_profile = SandboxProfile(**old_data)
            _archive_version(old_profile)

            # Auto-increment version
            profile.profile_version = old_profile.profile_version + 1
        except Exception as e:
            logger.warning("Could not archive previous version of '%s': %s", profile.name, e)
            # Still save the new version

    # Update timestamp
    profile.updated_at = datetime.now(timezone.utc).isoformat()

    return save_profile(profile, profile_dir)


def _archive_version(profile: SandboxProfile) -> Path:
    """Archive a profile version to the history directory."""
    history = _history_dir(profile.name)
    _ensure_dir(history)

    filename = f"v{profile.profile_version}_{profile.updated_at[:19].replace(':', '-')}.toml"
    dest = history / filename

    data = _strip_none(profile.model_dump(mode="json"))
    dest.write_bytes(tomli_w.dumps(data).encode())
    logger.debug("Archived %s v%d to %s", profile.name, profile.profile_version, dest)
    return dest


def list_profile_versions(name: str) -> list[dict]:
    """List all archived versions of a profile.

    Returns a list of dicts with 'version', 'timestamp', and 'path'.
    """
    history = _history_dir(name)
    if not history.exists():
        return []

    versions = []
    for toml_file in sorted(history.glob("*.toml")):
        try:
            with open(toml_file, "rb") as f:
                data = tomli.load(f)
            p = SandboxProfile(**data)
            versions.append({
                "version": p.profile_version,
                "timestamp": p.updated_at,
                "path": str(toml_file),
                "config_hash": p.config_hash()[:12],
            })
        except Exception as e:
            versions.append({
                "version": 0,
                "timestamp": "",
                "path": str(toml_file),
                "error": str(e),
            })

    return versions


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

def diff_profiles(
    a: SandboxProfile,
    b: SandboxProfile,
) -> str:
    """Return a human-readable diff between two profiles.

    Compares all fields recursively and reports additions, removals,
    and changes.

    Args:
        a: First profile (treated as the 'old' version).
        b: Second profile (treated as the 'new' version).

    Returns:
        Multi-line string describing differences, or "No differences." if equal.
    """
    a_data = a.model_dump(mode="json", exclude={"created_at", "updated_at"})
    b_data = b.model_dump(mode="json", exclude={"created_at", "updated_at"})

    lines: list[str] = []
    lines.append(f"--- {a.name} (v{a.profile_version})")
    lines.append(f"+++ {b.name} (v{b.profile_version})")
    lines.append("")

    _diff_dicts(a_data, b_data, "", lines)

    if len(lines) == 3:  # only headers
        lines.append("No differences.")

    return "\n".join(lines)


def _diff_dicts(
    a: dict,
    b: dict,
    prefix: str,
    lines: list[str],
) -> None:
    """Recursively diff two dicts and append human-readable lines."""
    all_keys = sorted(set(list(a.keys()) + list(b.keys())))

    for key in all_keys:
        path = f"{prefix}.{key}" if prefix else key
        a_val = a.get(key)
        b_val = b.get(key)

        if key not in a:
            lines.append(f"  + {path}: {_format_value(b_val)}")
        elif key not in b:
            lines.append(f"  - {path}: {_format_value(a_val)}")
        elif a_val != b_val:
            if isinstance(a_val, dict) and isinstance(b_val, dict):
                _diff_dicts(a_val, b_val, path, lines)
            elif isinstance(a_val, list) and isinstance(b_val, list):
                _diff_lists(a_val, b_val, path, lines)
            else:
                lines.append(f"  ~ {path}: {_format_value(a_val)} -> {_format_value(b_val)}")


def _diff_lists(
    a: list,
    b: list,
    path: str,
    lines: list[str],
) -> None:
    """Diff two lists and append human-readable lines."""
    import json as _json

    def _item_key(x):
        """Stable string representation for set comparison."""
        if isinstance(x, (dict, list)):
            return _json.dumps(x, sort_keys=True)
        return str(x)

    a_set = set(_item_key(x) for x in a)
    b_set = set(_item_key(x) for x in b)

    added = b_set - a_set
    removed = a_set - b_set

    if added:
        lines.append(f"  + {path}: added {sorted(added)}")
    if removed:
        lines.append(f"  - {path}: removed {sorted(removed)}")

    # If items are the same set but different order, note that
    if not added and not removed and a != b:
        lines.append(f"  ~ {path}: order changed")


def _format_value(v) -> str:
    """Format a value for display in a diff."""
    if isinstance(v, str):
        return f'"{v}"'
    if isinstance(v, list) and len(v) > 5:
        return f"[{len(v)} items]"
    return str(v)


# ---------------------------------------------------------------------------
# Profile locking / approval hash
# ---------------------------------------------------------------------------

def _resolve_profile_for_lock(name: str, working_dir: str = ".") -> SandboxProfile:
    """Resolve a profile by name for locking purposes.

    Searches project profiles, LASSO_PROFILE_DIR, saved profiles, and builtins.
    """
    from lasso.config.defaults import BUILTIN_PROFILES

    # 1. Project-level profiles
    project_path = Path(working_dir) / ".lasso" / "profiles" / f"{name}.toml"
    if project_path.exists():
        return load_profile_from_path(project_path)

    # 2. find_profile (LASSO_PROFILE_DIR + default dir)
    found = find_profile(name, working_dir=working_dir)
    if found:
        return load_profile_from_path(found)

    # 3. Builtins
    if name in BUILTIN_PROFILES:
        return BUILTIN_PROFILES[name](working_dir)

    raise FileNotFoundError(f"Profile '{name}' not found.")


def lock_profile(name: str, working_dir: str = ".") -> dict:
    """Lock a profile's current config hash.

    Creates or updates .lasso/profile.lock with the profile's hash,
    version, and timestamp. Multiple profiles can be locked simultaneously.

    Returns the lock data dict for the profile.
    """
    import json as _json

    profile = _resolve_profile_for_lock(name, working_dir)
    lock_data = {
        "name": name,
        "config_hash": profile.config_hash(),
        "locked_at": datetime.now(timezone.utc).isoformat(),
        "profile_version": profile.profile_version,
    }

    lock_path = Path(working_dir) / ".lasso" / "profile.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    locks: dict = {}

    # Use file locking for the entire read-modify-write cycle to prevent
    # TOCTOU races when multiple processes lock profiles concurrently.
    # Open in "a+" so the file is created if it doesn't exist, then
    # seek to the start to read existing content.
    with locked_file(lock_path, "a+") as f:
        f.seek(0)
        content = f.read()
        if content:
            parsed = _json.loads(content)
            if isinstance(parsed, dict):
                locks = parsed
        locks[name] = lock_data
        f.seek(0)
        f.truncate()
        f.write(_json.dumps(locks, indent=2))
    logger.info("Locked profile '%s' (hash: %s)", name, lock_data["config_hash"][:12])
    return lock_data


def verify_profile_locks(working_dir: str = ".") -> list[dict]:
    """Verify all locked profiles match their expected hashes.

    Returns a list of dicts with match status for each locked profile.
    An empty list is returned if no lock file exists.
    """
    import json as _json

    lock_path = Path(working_dir) / ".lasso" / "profile.lock"
    if not lock_path.exists():
        return []

    with locked_file(lock_path, "r") as f:
        parsed = _json.loads(f.read())
    if not isinstance(parsed, dict):
        return []
    locks = parsed
    results = []
    for name, lock_data in locks.items():
        try:
            profile = _resolve_profile_for_lock(name, working_dir)
            actual_hash = profile.config_hash()
            expected_hash = lock_data["config_hash"]
            results.append({
                "name": name,
                "expected_hash": expected_hash[:12],
                "actual_hash": actual_hash[:12],
                "match": actual_hash == expected_hash,
                "locked_at": lock_data.get("locked_at", ""),
            })
        except Exception as e:
            results.append({"name": name, "error": str(e), "match": False})
    return results
