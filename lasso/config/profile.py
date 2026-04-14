"""Profile persistence — save / load / list / delete sandbox profiles."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import tomli
import tomli_w

from lasso.config.schema import FilesystemConfig, SandboxProfile
from lasso.utils.paths import get_lasso_dir

logger = logging.getLogger("lasso.profile")

DEFAULT_PROFILE_DIR = get_lasso_dir() / "profiles"


def _ensure_dir(profile_dir: Path) -> None:
    profile_dir.mkdir(parents=True, exist_ok=True)


def _validate_profile_name(name: str) -> None:
    """Reject profile names that could escape the profile directory."""
    if "/" in name or "\\" in name or ".." in name:
        raise ValueError(
            f"Invalid profile name '{name}': must not contain '/', '\\', or '..'"
        )


def profile_path(name: str, profile_dir: Path = DEFAULT_PROFILE_DIR) -> Path:
    _validate_profile_name(name)
    return profile_dir / f"{name}.toml"


def _strip_none(obj):
    """Recursively remove None values from dicts (TOML can't serialize None)."""
    if isinstance(obj, dict):
        return {k: _strip_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_strip_none(i) for i in obj]
    return obj


def save_profile(profile: SandboxProfile, profile_dir: Path = DEFAULT_PROFILE_DIR) -> Path:
    """Serialize a SandboxProfile to a TOML file. Returns the path written."""
    _validate_profile_name(profile.name)
    _ensure_dir(profile_dir)
    dest = profile_path(profile.name, profile_dir)
    data = _strip_none(profile.model_dump(mode="json"))
    dest.write_bytes(tomli_w.dumps(data).encode())
    return dest


def load_profile(name: str, profile_dir: Path = DEFAULT_PROFILE_DIR) -> SandboxProfile:
    """Load a named profile from disk."""
    path = profile_path(name, profile_dir)
    if not path.exists():
        raise FileNotFoundError(f"Profile '{name}' not found at {path}")
    try:
        with open(path, "rb") as f:
            data = tomli.load(f)
    except tomli.TOMLDecodeError as e:
        logger.error("Failed to parse profile %s: %s", path, e)
        raise ValueError(f"Profile '{name}' has invalid TOML syntax: {e}") from e
    try:
        return SandboxProfile(**data)
    except Exception as e:
        logger.error("Invalid profile data in %s: %s", path, e)
        raise ValueError(f"Profile '{name}' has invalid configuration: {e}") from e


def load_profile_from_path(path: str | Path) -> SandboxProfile:
    """Load a profile from an arbitrary TOML file path."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Profile file not found: {path}")
    try:
        with open(path, "rb") as f:
            data = tomli.load(f)
    except tomli.TOMLDecodeError as e:
        logger.error("Failed to parse profile %s: %s", path, e)
        raise ValueError(f"Profile at '{path}' has invalid TOML syntax: {e}") from e
    try:
        return SandboxProfile(**data)
    except Exception as e:
        logger.error("Invalid profile data in %s: %s", path, e)
        raise ValueError(f"Profile at '{path}' has invalid configuration: {e}") from e


def list_profiles(profile_dir: Path = DEFAULT_PROFILE_DIR) -> list[dict]:
    """Return summary dicts for all saved profiles."""
    _ensure_dir(profile_dir)
    results = []
    for toml_file in sorted(profile_dir.glob("*.toml")):
        try:
            with open(toml_file, "rb") as f:
                data = tomli.load(f)
            p = SandboxProfile(**data)
            summary = p.summary()
            summary["path"] = str(toml_file)
            results.append(summary)
        except Exception as e:
            results.append({"name": toml_file.stem, "error": str(e)})
    return results


def delete_profile(name: str, profile_dir: Path = DEFAULT_PROFILE_DIR) -> bool:
    """Delete a profile. Returns True if it existed."""
    _validate_profile_name(name)
    path = profile_path(name, profile_dir)
    if path.exists():
        path.unlink()
        return True
    return False


# ---------------------------------------------------------------------------
# Profile inheritance resolution
# ---------------------------------------------------------------------------

# Fields that use list-append merge (union, deduplicated).
_LIST_FIELDS = {
    "whitelist", "blacklist", "observe_whitelist", "assist_whitelist",
    "allowed_domains", "blocked_domains", "allowed_ports", "blocked_ports",
    "allowed_cidrs", "blocked_cidrs", "dns_servers",
    "read_only_paths", "writable_paths", "hidden_paths",
    "tags", "allowed_repos", "allowed_servers", "blocked_servers",
    "rules", "webhooks", "profiles",
}


def _extract_overrides(child: dict, default: dict) -> dict:
    """Return only the fields where *child* differs from *default*.

    This lets us distinguish values the child profile explicitly set
    from values that are merely Pydantic defaults, so that parent
    values are not silently overwritten.
    """
    overrides: dict = {}
    for key, child_val in child.items():
        default_val = default.get(key)
        if isinstance(child_val, dict) and isinstance(default_val, dict):
            nested = _extract_overrides(child_val, default_val)
            if nested:
                overrides[key] = nested
        elif child_val != default_val:
            overrides[key] = child_val
    return overrides


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep-merge two dicts. Override wins for scalars, lists are appended
    (deduplicated), nested dicts are recursively merged."""
    from lasso.utils.merge import deep_merge
    return deep_merge(base, override, list_strategy="append")


def _load_profile_by_name(
    name: str,
    working_dir: str = ".",
    profile_dirs: list[Path] | None = None,
) -> SandboxProfile:
    """Load a profile by name from builtins, saved profiles, or profile dirs."""
    from lasso.config.defaults import BUILTIN_PROFILES

    # 1. Builtins
    if name in BUILTIN_PROFILES:
        return BUILTIN_PROFILES[name](working_dir)

    # 2. Saved profiles in default dir
    try:
        return load_profile(name)
    except FileNotFoundError:
        pass

    # 3. Extra profile dirs (LASSO_PROFILE_DIR)
    if profile_dirs:
        for pdir in profile_dirs:
            candidate = pdir / f"{name}.toml"
            if candidate.exists():
                return load_profile_from_path(candidate)

    # 4. LASSO_PROFILE_DIR from environment
    env_dir = os.environ.get("LASSO_PROFILE_DIR", "")
    if env_dir:
        for part in env_dir.split(os.pathsep):
            part = part.strip()
            if part:
                candidate = Path(part) / f"{name}.toml"
                if candidate.exists():
                    return load_profile_from_path(candidate)

    raise FileNotFoundError(f"Profile '{name}' not found in builtins, saved profiles, or profile directories.")


def resolve_profile(
    name: str,
    working_dir: str = ".",
    profile_dirs: list[Path] | None = None,
    _seen: list[str] | None = None,
) -> SandboxProfile:
    """Load a profile and resolve its inheritance chain.

    If the profile has an ``extends`` field, the base profile is loaded
    first (recursively) and merged with the child.

    Merge rules:
    - Scalar fields (str, int, bool): child overrides parent.
    - List fields: child items appended to parent (union, deduplicated).
    - Nested dicts (blocked_args, extra_env): deep merge, child wins.
    - ``name`` always comes from the child (never inherited).

    Raises ``ValueError`` on circular inheritance.
    """
    if _seen is None:
        _seen = []

    if name in _seen:
        chain = " -> ".join(_seen) + f" -> {name}"
        raise ValueError(f"Circular profile inheritance detected: {chain}")

    _seen.append(name)

    profile = _load_profile_by_name(name, working_dir, profile_dirs)

    if not profile.extends:
        # No inheritance — return as-is (clear extends just in case)
        profile.extends = None
        return profile

    # Recursively resolve the base
    base = resolve_profile(
        profile.extends,
        working_dir=working_dir,
        profile_dirs=profile_dirs,
        _seen=_seen,
    )

    # Merge: base data + child overrides only (not child defaults)
    base_data = base.model_dump(mode="json")

    # Build a fresh default profile to compare against.  This lets us
    # distinguish fields the child *explicitly set* from fields that are
    # merely Pydantic defaults.
    default_profile = SandboxProfile(
        name="__default__",
        filesystem=FilesystemConfig(working_dir=working_dir or "."),
    )
    default_data = default_profile.model_dump(mode="json")
    child_data = profile.model_dump(mode="json")

    # Extract only the overrides (fields where child differs from default)
    child_overrides = _extract_overrides(child_data, default_data)

    # name always comes from the child
    child_overrides["name"] = profile.name

    # Merge: base + child overrides
    merged_data = _deep_merge(base_data, child_overrides)

    # Clear extends — the profile is fully resolved
    merged_data["extends"] = None

    return SandboxProfile(**merged_data)
