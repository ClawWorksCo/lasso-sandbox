"""Utility functions for deep-merging dictionaries."""

from __future__ import annotations


def deep_merge(
    base: dict,
    override: dict,
    list_strategy: str = "replace",
) -> dict:
    """Deep merge two dicts. Override values win for scalars.

    Args:
        base: The base dictionary.
        override: The override dictionary (values take precedence).
        list_strategy: ``"replace"`` (default) -- override list replaces base.
                       ``"append"`` -- append override items to base, deduplicate.

    Returns:
        A new merged dictionary.
    """
    merged = dict(base)
    for key, child_val in override.items():
        if key not in merged:
            merged[key] = child_val
            continue

        parent_val = merged[key]

        # Both dicts -> recurse
        if isinstance(parent_val, dict) and isinstance(child_val, dict):
            merged[key] = deep_merge(parent_val, child_val, list_strategy=list_strategy)
        # Both lists -> strategy decides
        elif isinstance(parent_val, list) and isinstance(child_val, list):
            if list_strategy == "append":
                seen: set = set()
                combined: list = []
                for item in parent_val + child_val:
                    # For unhashable items (dicts), use repr as key
                    try:
                        item_key = item
                        hash(item_key)
                    except TypeError:
                        item_key = repr(item)
                    if item_key not in seen:
                        seen.add(item_key)
                        combined.append(item)
                merged[key] = combined
            else:
                # "replace" -- override list wins
                merged[key] = child_val
        else:
            # Scalar: child overrides
            merged[key] = child_val

    return merged
