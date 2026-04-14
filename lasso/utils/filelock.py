"""Cross-platform file locking utilities.

Provides exclusive file locking that works on both POSIX (fcntl) and
Windows (msvcrt).  Shared by :mod:`lasso.core.checkpoint` and
:mod:`lasso.core.state` to avoid duplicated lock logic.

The Windows implementation locks 1 MB (``1 << 20`` bytes) rather than a
single byte so that mutual exclusion actually covers the full file
content for any realistic config / state file.
"""

from __future__ import annotations

import platform
from contextlib import contextmanager
from typing import IO

# 1 MB -- more than sufficient for any LASSO config/state file.
_LOCK_SIZE = 1 << 20


def lock_file(f: IO) -> None:
    """Acquire an exclusive lock on an open file object.

    .. note:: Platform behaviour difference

       On **Windows**, ``msvcrt.locking(LK_LOCK)`` retries for approximately
       10 seconds before raising ``OSError``.  On **POSIX**, ``fcntl.flock``
       with ``LOCK_EX`` blocks indefinitely until the lock is available.
       If you need a bounded wait on POSIX, use :func:`lock_file_timeout`.
    """
    if platform.system() == "Windows":
        import msvcrt

        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, _LOCK_SIZE)
    else:
        import fcntl

        fcntl.flock(f.fileno(), fcntl.LOCK_EX)


def unlock_file(f: IO) -> None:
    """Release an exclusive lock on an open file object."""
    if platform.system() == "Windows":
        import msvcrt

        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, _LOCK_SIZE)
    else:
        import fcntl

        fcntl.flock(f.fileno(), fcntl.LOCK_UN)


@contextmanager
def locked_file(path, mode: str = "r"):
    """Context manager that opens *path* and holds an exclusive lock.

    The lock is held for the entire duration of the ``with`` block,
    which eliminates TOCTOU races on load-modify-save cycles.

    Yields the open file handle.
    """
    f = open(path, mode, encoding="utf-8")  # noqa: SIM115
    try:
        lock_file(f)
        yield f
    finally:
        try:
            unlock_file(f)
        finally:
            f.close()
