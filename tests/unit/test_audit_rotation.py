"""Tests for audit log rotation — size-based rotation with configurable count."""

import json
from pathlib import Path

import pytest

from lasso.config.schema import AuditConfig
from lasso.core.audit import AuditLogger

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def audit_dir(tmp_path):
    """Return a temporary audit log directory."""
    d = tmp_path / "audit"
    d.mkdir()
    return d


@pytest.fixture
def small_config(audit_dir):
    """AuditConfig with a very small max_log_size_mb for testing rotation."""
    return AuditConfig(
        enabled=True,
        log_dir=str(audit_dir),
        max_log_size_mb=1,  # minimum allowed by schema, we'll use tiny files
        rotation_count=3,
        sign_entries=False,
    )


def _make_logger(sandbox_id: str, config: AuditConfig) -> AuditLogger:
    """Create an AuditLogger with a given config."""
    return AuditLogger(sandbox_id, config)


def _write_bytes_to_log(logger: AuditLogger, size_bytes: int) -> None:
    """Write enough events to the log to exceed size_bytes."""
    # Each event line is roughly 200 bytes
    while logger.log_file and (
        not logger.log_file.exists() or logger.log_file.stat().st_size < size_bytes
    ):
        logger.log_command("test-cmd", ["arg1", "arg2"])


# ---------------------------------------------------------------------------
# Rotation trigger tests
# ---------------------------------------------------------------------------

class TestRotationTrigger:
    """Test that rotation triggers at the right time."""

    def test_no_rotation_under_limit(self, audit_dir):
        """Log should not rotate when under max size."""
        config = AuditConfig(
            enabled=True,
            log_dir=str(audit_dir),
            max_log_size_mb=100,  # 100 MB — we'll never hit this
            rotation_count=3,
            sign_entries=False,
        )
        logger = _make_logger("test-no-rotate", config)

        # Write a few events
        for _ in range(5):
            logger.log_command("ls", ["-la"])

        # Only the original log file should exist
        log_file = logger.log_file
        assert log_file.exists()
        assert not Path(f"{log_file}.1").exists()

    def test_rotation_when_exceeding_max_size(self, audit_dir):
        """Log should rotate when file exceeds max_log_size_mb."""
        # Use a tiny max size (0.001 MB = ~1024 bytes)
        config = AuditConfig(
            enabled=True,
            log_dir=str(audit_dir),
            max_log_size_mb=1,  # schema minimum is 1
            rotation_count=3,
            sign_entries=False,
        )
        logger = _make_logger("test-rotate", config)

        # Manually set a very small threshold for testing by patching
        # We'll write to the log until it's big enough, then force rotation
        # by writing a file that exceeds threshold

        # Write enough data to exceed 1 MB
        log_file = logger.log_file
        # Write a large payload to the log file directly to exceed 1 MB
        with open(log_file, "w") as f:
            f.write("x" * (1024 * 1024 + 100) + "\n")

        # Now the next log() call should trigger rotation
        logger.log_command("post-rotation", ["cmd"])

        # The original file should exist (new, small)
        assert log_file.exists()
        assert log_file.stat().st_size < 1024 * 1024  # new file is small

        # The rotated file should exist
        rotated = Path(f"{log_file}.1")
        assert rotated.exists()

    def test_very_small_max_size(self, audit_dir):
        """Rotation should work with max_log_size_mb=1 (the schema minimum)."""
        config = AuditConfig(
            enabled=True,
            log_dir=str(audit_dir),
            max_log_size_mb=1,
            rotation_count=2,
            sign_entries=False,
        )
        logger = _make_logger("test-tiny", config)
        log_file = logger.log_file

        # Write enough to exceed 1 MB
        with open(log_file, "w") as f:
            f.write("x" * (1024 * 1024 + 10) + "\n")

        # This should trigger rotation
        logger.log_command("trigger", [])

        assert log_file.exists()
        assert Path(f"{log_file}.1").exists()


# ---------------------------------------------------------------------------
# Rotation count tests
# ---------------------------------------------------------------------------

class TestRotationCount:
    """Test that rotation_count is respected."""

    def test_old_files_deleted_beyond_rotation_count(self, audit_dir):
        """Files beyond rotation_count should be deleted."""
        config = AuditConfig(
            enabled=True,
            log_dir=str(audit_dir),
            max_log_size_mb=1,
            rotation_count=2,
            sign_entries=False,
        )
        logger = _make_logger("test-count", config)
        log_file = logger.log_file

        # Simulate 3 rotations
        for i in range(3):
            with open(log_file, "w") as f:
                f.write("x" * (1024 * 1024 + 10) + "\n")
            logger.log_command(f"rotation-{i}", [])

        # With rotation_count=2, we should have:
        # log_file (current), log_file.1, log_file.2
        # log_file.3 should NOT exist
        assert log_file.exists()
        assert Path(f"{log_file}.1").exists()
        assert Path(f"{log_file}.2").exists()
        assert not Path(f"{log_file}.3").exists()

    def test_rotation_count_of_one(self, audit_dir):
        """With rotation_count=1, only one backup should be kept."""
        config = AuditConfig(
            enabled=True,
            log_dir=str(audit_dir),
            max_log_size_mb=1,
            rotation_count=1,
            sign_entries=False,
        )
        logger = _make_logger("test-one", config)
        log_file = logger.log_file

        # First rotation
        with open(log_file, "w") as f:
            f.write("x" * (1024 * 1024 + 10) + "\n")
        logger.log_command("first", [])

        # Second rotation
        with open(log_file, "w") as f:
            f.write("x" * (1024 * 1024 + 10) + "\n")
        logger.log_command("second", [])

        assert log_file.exists()
        assert Path(f"{log_file}.1").exists()
        assert not Path(f"{log_file}.2").exists()


# ---------------------------------------------------------------------------
# New file creation tests
# ---------------------------------------------------------------------------

class TestNewFileAfterRotation:
    """Test that a new log file is created after rotation."""

    def test_new_file_created_after_rotation(self, audit_dir):
        """After rotation, the new log file should contain the latest event."""
        config = AuditConfig(
            enabled=True,
            log_dir=str(audit_dir),
            max_log_size_mb=1,
            rotation_count=3,
            sign_entries=False,
        )
        logger = _make_logger("test-newfile", config)
        log_file = logger.log_file

        # Fill the log past max size
        with open(log_file, "w") as f:
            f.write("x" * (1024 * 1024 + 10) + "\n")

        # This write triggers rotation and writes to new file
        logger.log_command("after-rotation", ["arg"])

        # New file should exist and contain the rotation event + our command
        assert log_file.exists()
        lines = log_file.read_text().strip().splitlines()
        assert len(lines) >= 1  # At least rotation event + command

        # Verify last line is our command
        last_entry = json.loads(lines[-1])
        assert last_entry["action"] == "after-rotation"


# ---------------------------------------------------------------------------
# Lifecycle event tests
# ---------------------------------------------------------------------------

class TestRotationLifecycleEvent:
    """Test that a log_rotated lifecycle event is written."""

    def test_log_rotated_event_written(self, audit_dir):
        """Rotation should log a lifecycle event with action 'log_rotated'."""
        config = AuditConfig(
            enabled=True,
            log_dir=str(audit_dir),
            max_log_size_mb=1,
            rotation_count=3,
            sign_entries=False,
        )
        logger = _make_logger("test-event", config)
        log_file = logger.log_file

        # Trigger rotation
        with open(log_file, "w") as f:
            f.write("x" * (1024 * 1024 + 10) + "\n")
        logger.log_command("trigger", [])

        # Read new file, first entry should be log_rotated
        lines = log_file.read_text().strip().splitlines()
        first_entry = json.loads(lines[0])
        assert first_entry["type"] == "lifecycle"
        assert first_entry["action"] == "log_rotated"
        assert first_entry["detail"]["max_log_size_mb"] == 1
        assert first_entry["detail"]["rotation_count"] == 3


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestRotationEdgeCases:
    """Test edge cases for log rotation."""

    def test_works_when_log_file_does_not_exist(self, audit_dir):
        """Rotation check should handle missing log file gracefully."""
        config = AuditConfig(
            enabled=True,
            log_dir=str(audit_dir),
            max_log_size_mb=1,
            rotation_count=3,
            sign_entries=False,
        )
        logger = _make_logger("test-missing", config)

        # Delete the log file if it was created during setup
        if logger.log_file and logger.log_file.exists():
            logger.log_file.unlink()

        # This should not raise
        logger.log_command("first-write", [])
        assert logger.log_file.exists()

    def test_rotation_with_signing_enabled(self, audit_dir):
        """Rotation should work with HMAC signing enabled."""
        config = AuditConfig(
            enabled=True,
            log_dir=str(audit_dir),
            max_log_size_mb=1,
            rotation_count=2,
            sign_entries=True,
        )
        logger = _make_logger("test-signed", config)
        log_file = logger.log_file

        # Trigger rotation
        with open(log_file, "w") as f:
            f.write("x" * (1024 * 1024 + 10) + "\n")
        logger.log_command("signed-cmd", [])

        assert log_file.exists()
        assert Path(f"{log_file}.1").exists()

        # Verify new entries have signatures
        lines = log_file.read_text().strip().splitlines()
        for line in lines:
            entry = json.loads(line)
            assert "sig" in entry

    def test_disabled_audit_skips_rotation(self, audit_dir):
        """With audit disabled, no rotation should happen."""
        config = AuditConfig(
            enabled=False,
            log_dir=str(audit_dir),
            max_log_size_mb=1,
            rotation_count=3,
            sign_entries=False,
        )
        logger = _make_logger("test-disabled", config)

        # Log should be a no-op
        logger.log_command("test", [])

        # No log file should be created
        assert logger.log_file is None
