"""Cross-platform path utilities for LASSO's user-level data directory."""
from __future__ import annotations

import os
import platform
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def get_lasso_dir() -> Path:
    if platform.system() == "Windows":
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        if local_app_data:
            return Path(local_app_data) / "lasso"
    return Path.home() / ".lasso"

LASSO_DIR = get_lasso_dir()
