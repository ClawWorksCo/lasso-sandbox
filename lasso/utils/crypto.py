"""Cryptographic utilities — config signing and integrity verification."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from pathlib import Path


def generate_key(length: int = 32) -> bytes:
    """Generate a cryptographically secure random key."""
    return secrets.token_bytes(length)


def sign_config(config_json: str, key: bytes) -> str:
    """HMAC-SHA256 sign a config string."""
    return hmac.new(key, config_json.encode(), hashlib.sha256).hexdigest()


def verify_config(config_json: str, signature: str, key: bytes) -> bool:
    """Verify an HMAC-SHA256 signature."""
    expected = hmac.new(key, config_json.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def hash_file(path: str | Path) -> str:
    """SHA-256 hash of a file's contents."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()
