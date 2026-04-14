"""Tests for checkpoint versioning — store, CLI commands, and update warnings.

Covers:
- CheckpointStore load/save/pin round-trips
- check_for_update with mock manifests
- register_checkpoint (HMAC signing, duplicate detection, atomicity)
- Shared filelock utility (Windows 1 MB lock size, context manager)
- HMAC-signed checkpoint verification
- Pre-release version ordering
- Removal of dead pinned_lasso_version from state.py
- CLI version/checkpoint commands with CliRunner
- create command update warning
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from lasso.cli.main import app
from lasso.core.checkpoint import (
    CHECKPOINT_MANIFEST_URL,
    CheckpointInfo,
    CheckpointStore,
    _parse_version,
    _sign_checkpoint,
    verify_checkpoint,
)

runner = CliRunner()


@pytest.fixture(autouse=True)
def _reset_cli_registry():
    """Reset the global CLI registry between tests to avoid state leaks."""
    import lasso.cli.helpers as cli_helpers
    old = cli_helpers._registry
    cli_helpers._registry = None
    yield
    cli_helpers._registry = old


def _invoke(*args: str, input: str | None = None):
    """Invoke the CLI with the given arguments."""
    return runner.invoke(app, list(args), input=input)


# ---------------------------------------------------------------------------
# _parse_version helper
# ---------------------------------------------------------------------------

class TestParseVersion:
    def test_simple_semver(self):
        # Release: last element is 1
        assert _parse_version("0.2.0") == (0, 2, 0, 1)

    def test_leading_v(self):
        assert _parse_version("v1.3.5") == (1, 3, 5, 1)

    def test_prerelease_stripped(self):
        # Pre-release: last element is 0
        assert _parse_version("0.3.0-beta1") == (0, 3, 0, 0)

    def test_two_part_version(self):
        assert _parse_version("1.0") == (1, 0, 1)

    def test_empty_returns_zero(self):
        assert _parse_version("") == (0,)

    def test_garbage_returns_zero(self):
        assert _parse_version("not-a-version") == (0,)

    def test_comparison_works(self):
        assert _parse_version("0.3.0") > _parse_version("0.2.0")
        assert _parse_version("1.0.0") > _parse_version("0.99.99")
        assert _parse_version("0.2.0") == _parse_version("0.2.0")

    def test_prerelease_sorts_before_release(self):
        """Pre-release '0.3.0-beta1' must sort strictly before release '0.3.0'."""
        assert _parse_version("0.3.0-beta1") < _parse_version("0.3.0")

    def test_prerelease_not_equal_to_release(self):
        """Pre-release and release with the same base version must not be equal."""
        assert _parse_version("0.3.0-beta1") != _parse_version("0.3.0")

    def test_prerelease_sorts_after_previous_release(self):
        """0.3.0-beta1 is newer than 0.2.0 even though it's a pre-release."""
        assert _parse_version("0.3.0-beta1") > _parse_version("0.2.0")

    def test_two_prereleases_of_same_base_are_equal(self):
        """Two different pre-release tags on the same base compare equally.

        Since we strip the suffix entirely, -beta1 and -rc2 both become
        (0, 3, 0, 0).  This is a known limitation.
        """
        assert _parse_version("0.3.0-beta1") == _parse_version("0.3.0-rc2")


# ---------------------------------------------------------------------------
# CheckpointInfo
# ---------------------------------------------------------------------------

class TestCheckpointInfo:
    def test_to_dict_round_trip(self):
        cp = CheckpointInfo(
            tag="v0.2.0",
            version="0.2.0",
            released_at="2026-01-01T00:00:00Z",
            sha256="abc123",
            notes="First release",
            reviewed_by=["Alice", "Bob"],
        )
        d = cp.to_dict()
        cp2 = CheckpointInfo.from_dict(d)
        assert cp2.tag == cp.tag
        assert cp2.version == cp.version
        assert cp2.reviewed_by == ["Alice", "Bob"]

    def test_from_dict_missing_optional_fields(self):
        d = {"tag": "v0.1.0", "version": "0.1.0"}
        cp = CheckpointInfo.from_dict(d)
        assert cp.notes == ""
        assert cp.reviewed_by == []
        assert cp.sha256 == ""

    def test_to_dict_includes_empty_reviewed_by(self):
        cp = CheckpointInfo(tag="v0.1.0", version="0.1.0")
        d = cp.to_dict()
        assert "reviewed_by" in d
        assert d["reviewed_by"] == []


# ---------------------------------------------------------------------------
# Shared filelock utility
# ---------------------------------------------------------------------------

class TestFilelockUtility:
    """Verify the shared filelock module is correctly configured."""

    def test_lock_size_is_1mb(self):
        """Windows lock must cover 1 MB, not just 1 byte."""
        from lasso.utils.filelock import _LOCK_SIZE
        assert _LOCK_SIZE == 1 << 20  # 1,048,576

    def test_lock_file_calls_msvcrt_with_correct_size(self):
        """On Windows, lock_file must pass _LOCK_SIZE to msvcrt.locking."""
        from lasso.utils import filelock

        mock_msvcrt = MagicMock()
        mock_msvcrt.LK_LOCK = 1  # typical msvcrt constant value

        mock_file = MagicMock()
        mock_file.fileno.return_value = 42

        with patch.object(filelock, "platform") as mock_platform:
            mock_platform.system.return_value = "Windows"
            with patch.dict("sys.modules", {"msvcrt": mock_msvcrt}):
                filelock.lock_file(mock_file)

        mock_msvcrt.locking.assert_called_once_with(42, mock_msvcrt.LK_LOCK, 1 << 20)

    def test_unlock_file_calls_msvcrt_with_correct_size(self):
        """On Windows, unlock_file must pass _LOCK_SIZE to msvcrt.locking."""
        from lasso.utils import filelock

        mock_msvcrt = MagicMock()
        mock_msvcrt.LK_UNLCK = 2

        mock_file = MagicMock()
        mock_file.fileno.return_value = 42

        with patch.object(filelock, "platform") as mock_platform:
            mock_platform.system.return_value = "Windows"
            with patch.dict("sys.modules", {"msvcrt": mock_msvcrt}):
                filelock.unlock_file(mock_file)

        mock_msvcrt.locking.assert_called_once_with(42, mock_msvcrt.LK_UNLCK, 1 << 20)

    def test_locked_file_context_manager(self, tmp_path):
        """locked_file opens, locks, yields, unlocks, and closes."""
        from lasso.utils.filelock import locked_file

        test_file = tmp_path / "test.txt"
        test_file.write_text("hello")

        with locked_file(test_file, "r") as f:
            content = f.read()
        assert content == "hello"

        # After the context manager exits, the file handle should be closed
        assert f.closed

    def test_checkpoint_uses_shared_lock(self):
        """checkpoint.py must import from lasso.utils.filelock, not define its own."""
        import lasso.core.checkpoint as cp_mod
        assert not hasattr(cp_mod, "_lock_file"), (
            "checkpoint.py should not have its own _lock_file; use lasso.utils.filelock"
        )
        assert not hasattr(cp_mod, "_unlock_file"), (
            "checkpoint.py should not have its own _unlock_file; use lasso.utils.filelock"
        )

    def test_state_uses_shared_lock(self):
        """state.py must import from lasso.utils.filelock, not define its own."""
        import lasso.core.state as st_mod
        assert not hasattr(st_mod, "_lock_file"), (
            "state.py should not have its own _lock_file; use lasso.utils.filelock"
        )
        assert not hasattr(st_mod, "_unlock_file"), (
            "state.py should not have its own _unlock_file; use lasso.utils.filelock"
        )


# ---------------------------------------------------------------------------
# HMAC-signed checkpoint verification
# ---------------------------------------------------------------------------

class TestCheckpointHMAC:
    def test_register_creates_hmac_signature(self, tmp_path):
        """register_checkpoint must produce an HMAC, not a bare SHA-256."""
        store = CheckpointStore(state_dir=str(tmp_path))
        cp = store.register_checkpoint(tag="v0.2.0", version="0.2.0")

        # The sha256 field should be a 64-char hex HMAC digest
        assert len(cp.sha256) == 64

        # Verify it's a real HMAC, not just hash(tag:version:date)
        key = store._get_signing_key()
        assert verify_checkpoint(cp, key)

    def test_verify_checkpoint_valid(self, tmp_path):
        """verify_checkpoint returns True for a correctly signed entry."""
        store = CheckpointStore(state_dir=str(tmp_path))
        cp = store.register_checkpoint(tag="v1.0.0", version="1.0.0")
        key = store._get_signing_key()

        assert verify_checkpoint(cp, key) is True

    def test_verify_checkpoint_tampered_tag(self, tmp_path):
        """Changing the tag must invalidate the HMAC signature."""
        store = CheckpointStore(state_dir=str(tmp_path))
        cp = store.register_checkpoint(tag="v1.0.0", version="1.0.0")
        key = store._get_signing_key()

        # Tamper with the tag
        cp.tag = "v1.0.0-TAMPERED"
        assert verify_checkpoint(cp, key) is False

    def test_verify_checkpoint_tampered_version(self, tmp_path):
        """Changing the version must invalidate the HMAC signature."""
        store = CheckpointStore(state_dir=str(tmp_path))
        cp = store.register_checkpoint(tag="v1.0.0", version="1.0.0")
        key = store._get_signing_key()

        cp.version = "9.9.9"
        assert verify_checkpoint(cp, key) is False

    def test_verify_checkpoint_tampered_released_at(self, tmp_path):
        """Changing released_at must invalidate the HMAC signature."""
        store = CheckpointStore(state_dir=str(tmp_path))
        cp = store.register_checkpoint(tag="v1.0.0", version="1.0.0")
        key = store._get_signing_key()

        cp.released_at = "2099-01-01T00:00:00Z"
        assert verify_checkpoint(cp, key) is False

    def test_verify_checkpoint_wrong_key(self, tmp_path):
        """A different key must not validate the signature."""
        store = CheckpointStore(state_dir=str(tmp_path))
        cp = store.register_checkpoint(tag="v1.0.0", version="1.0.0")

        wrong_key = b"wrong-key-that-is-32-bytes-long!"
        assert verify_checkpoint(cp, wrong_key) is False

    def test_sign_checkpoint_function(self):
        """_sign_checkpoint produces a consistent HMAC for fixed inputs."""
        key = b"test-key-32-bytes-padding-here!!"
        sig1 = _sign_checkpoint("v1.0", "1.0", "2026-01-01T00:00:00Z", key)
        sig2 = _sign_checkpoint("v1.0", "1.0", "2026-01-01T00:00:00Z", key)
        assert sig1 == sig2
        assert len(sig1) == 64

    def test_signing_key_persists_across_instances(self, tmp_path):
        """The signing key should be created once and reused."""
        store1 = CheckpointStore(state_dir=str(tmp_path))
        key1 = store1._get_signing_key()

        store2 = CheckpointStore(state_dir=str(tmp_path))
        key2 = store2._get_signing_key()

        assert key1 == key2


# ---------------------------------------------------------------------------
# CheckpointStore — load / save
# ---------------------------------------------------------------------------

class TestCheckpointStoreLoadSave:
    def test_load_empty_dir_returns_empty_list(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        assert store.load_manifest() == []

    def test_save_creates_file(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        cp = CheckpointInfo(tag="v0.1.0", version="0.1.0")
        store.save_manifest([cp])
        assert store.checkpoint_file.exists()

    def test_save_and_load_round_trip(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        checkpoints = [
            CheckpointInfo(tag="v0.1.0", version="0.1.0", notes="Alpha"),
            CheckpointInfo(tag="v0.2.0", version="0.2.0", notes="Beta"),
        ]
        store.save_manifest(checkpoints)

        store2 = CheckpointStore(state_dir=str(tmp_path))
        loaded = store2.load_manifest()
        assert len(loaded) == 2
        assert loaded[0].tag == "v0.1.0"
        assert loaded[1].tag == "v0.2.0"

    def test_corrupt_file_returns_empty(self, tmp_path):
        cp_file = tmp_path / "checkpoints.json"
        cp_file.write_text("{{not valid json")
        store = CheckpointStore(state_dir=str(tmp_path))
        assert store.load_manifest() == []

    def test_file_has_version_and_updated_at(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        store.save_manifest([CheckpointInfo(tag="v1", version="1.0")])
        data = json.loads(store.checkpoint_file.read_text())
        assert data["version"] == 1
        assert "updated_at" in data

    def test_state_dir_created_if_missing(self, tmp_path):
        nested = tmp_path / "deep" / "nested"
        store = CheckpointStore(state_dir=str(nested))
        store.save_manifest([CheckpointInfo(tag="v1", version="1.0")])
        assert store.checkpoint_file.exists()


# ---------------------------------------------------------------------------
# CheckpointStore — latest / check_for_update
# ---------------------------------------------------------------------------

class TestCheckpointStoreQueries:
    def test_latest_checkpoint_empty(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        assert store.latest_checkpoint() is None

    def test_latest_checkpoint_returns_highest(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        store.save_manifest([
            CheckpointInfo(tag="v0.1.0", version="0.1.0"),
            CheckpointInfo(tag="v0.3.0", version="0.3.0"),
            CheckpointInfo(tag="v0.2.0", version="0.2.0"),
        ])
        latest = store.latest_checkpoint()
        assert latest is not None
        assert latest.version == "0.3.0"

    def test_check_for_update_returns_newer(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        store.save_manifest([
            CheckpointInfo(tag="v0.3.0", version="0.3.0", notes="New"),
        ])
        update = store.check_for_update("0.2.0")
        assert update is not None
        assert update.version == "0.3.0"

    def test_check_for_update_returns_none_when_current(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        store.save_manifest([
            CheckpointInfo(tag="v0.2.0", version="0.2.0"),
        ])
        assert store.check_for_update("0.2.0") is None

    def test_check_for_update_returns_none_when_ahead(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        store.save_manifest([
            CheckpointInfo(tag="v0.1.0", version="0.1.0"),
        ])
        assert store.check_for_update("0.2.0") is None

    def test_check_for_update_empty_manifest(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        assert store.check_for_update("0.2.0") is None


# ---------------------------------------------------------------------------
# CheckpointStore — pinning
# ---------------------------------------------------------------------------

class TestCheckpointStorePin:
    def test_pin_creates_file(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        store.pin_version("0.2.0")
        assert store.checkpoint_file.exists()

    def test_pin_and_read_back(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        store.pin_version("0.2.0")

        store2 = CheckpointStore(state_dir=str(tmp_path))
        assert store2.get_pinned_version() == "0.2.0"

    def test_pin_preserves_existing_checkpoints(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        store.save_manifest([
            CheckpointInfo(tag="v0.1.0", version="0.1.0"),
        ])
        store.pin_version("0.1.0")

        store2 = CheckpointStore(state_dir=str(tmp_path))
        assert store2.get_pinned_version() == "0.1.0"
        assert len(store2.load_manifest()) == 1

    def test_get_pinned_version_no_file(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        assert store.get_pinned_version() is None

    def test_get_pinned_version_no_pin_set(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        store.save_manifest([])
        assert store.get_pinned_version() is None

    def test_pin_overwrites_previous_pin(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        store.pin_version("0.1.0")
        store.pin_version("0.2.0")
        assert store.get_pinned_version() == "0.2.0"

    def test_pin_creates_nested_dir(self, tmp_path):
        nested = tmp_path / "deep" / "dir"
        store = CheckpointStore(state_dir=str(nested))
        store.pin_version("1.0.0")
        assert store.get_pinned_version() == "1.0.0"


# ---------------------------------------------------------------------------
# CheckpointStore — register_checkpoint
# ---------------------------------------------------------------------------

class TestRegisterCheckpoint:
    def test_register_creates_entry(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        cp = store.register_checkpoint(
            tag="v0.2.0",
            version="0.2.0",
            notes="Stable release",
            reviewed_by=["Alice"],
        )
        assert cp.tag == "v0.2.0"
        assert cp.version == "0.2.0"
        assert cp.notes == "Stable release"
        assert cp.reviewed_by == ["Alice"]
        assert len(cp.sha256) == 64  # SHA-256 hex digest
        assert cp.released_at != ""

    def test_register_appends_to_existing(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        store.register_checkpoint(tag="v0.1.0", version="0.1.0")
        store.register_checkpoint(tag="v0.2.0", version="0.2.0")

        loaded = store.load_manifest()
        assert len(loaded) == 2
        assert loaded[0].tag == "v0.1.0"
        assert loaded[1].tag == "v0.2.0"

    def test_register_default_reviewed_by(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        cp = store.register_checkpoint(tag="v0.1.0", version="0.1.0")
        assert cp.reviewed_by == []

    def test_register_persists_to_disk(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        store.register_checkpoint(tag="v0.1.0", version="0.1.0")

        # Read with a new instance
        store2 = CheckpointStore(state_dir=str(tmp_path))
        loaded = store2.load_manifest()
        assert len(loaded) == 1
        assert loaded[0].tag == "v0.1.0"

    def test_register_duplicate_tag_rejected(self, tmp_path):
        """Registering the same tag twice must not create a duplicate entry."""
        store = CheckpointStore(state_dir=str(tmp_path))
        cp1 = store.register_checkpoint(tag="v0.1.0", version="0.1.0", notes="First")
        cp2 = store.register_checkpoint(tag="v0.1.0", version="0.1.0", notes="Duplicate")

        loaded = store.load_manifest()
        assert len(loaded) == 1, "Duplicate tag must not be appended"
        # The returned checkpoint should be the original one
        assert cp2.tag == "v0.1.0"
        assert cp2.notes == "First"

    def test_register_different_tags_both_kept(self, tmp_path):
        """Different tags must both be kept."""
        store = CheckpointStore(state_dir=str(tmp_path))
        store.register_checkpoint(tag="v0.1.0", version="0.1.0")
        store.register_checkpoint(tag="v0.2.0", version="0.2.0")
        store.register_checkpoint(tag="v0.1.0", version="0.1.0")  # duplicate

        loaded = store.load_manifest()
        assert len(loaded) == 2

    def test_register_checkpoint_atomic_read_modify_write(self, tmp_path):
        """register_checkpoint must not produce duplicates even when called rapidly."""
        store = CheckpointStore(state_dir=str(tmp_path))

        # Register several distinct checkpoints
        for i in range(5):
            store.register_checkpoint(tag=f"v0.{i}.0", version=f"0.{i}.0")

        loaded = store.load_manifest()
        tags = [cp.tag for cp in loaded]
        assert len(tags) == len(set(tags)), "No duplicate tags should exist"
        assert len(loaded) == 5


# ---------------------------------------------------------------------------
# Dead pinned_lasso_version removed from state.py
# ---------------------------------------------------------------------------

class TestPinnedLassoVersionRemoved:
    """Verify that the dead pinned_lasso_version field is no longer in RegistryState."""

    def test_registry_state_has_no_pinned_lasso_version(self):
        from lasso.core.state import RegistryState
        state = RegistryState()
        assert not hasattr(state, "pinned_lasso_version"), (
            "pinned_lasso_version should be removed from RegistryState"
        )

    def test_registry_state_to_dict_no_pinned_lasso_version(self):
        from lasso.core.state import RegistryState
        state = RegistryState()
        d = state.to_dict()
        assert "pinned_lasso_version" not in d

    def test_registry_state_from_dict_ignores_legacy_field(self):
        """from_dict should tolerate the old field in JSON without crashing."""
        from lasso.core.state import RegistryState
        data = {
            "version": 1,
            "updated_at": "",
            "sandboxes": {},
            "pinned_lasso_version": "0.2.0",  # legacy
        }
        state = RegistryState.from_dict(data)
        assert not hasattr(state, "pinned_lasso_version")
        assert state.version == 1


# ---------------------------------------------------------------------------
# CHECKPOINT_MANIFEST_URL constant
# ---------------------------------------------------------------------------

class TestManifestURL:
    def test_default_is_empty(self):
        assert CHECKPOINT_MANIFEST_URL == ""


# ---------------------------------------------------------------------------
# CLI — lasso version
# ---------------------------------------------------------------------------

class TestCLIVersion:
    def test_version_shows_current(self):
        result = _invoke("version")
        assert result.exit_code == 0
        assert "LASSO v" in result.output

    def test_version_json(self):
        result = _invoke("version", "--json")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "current_version" in data
        assert "pinned_version" in data
        assert "latest_checkpoint" in data
        assert "update_available" in data

    def test_version_shows_pinned(self, tmp_path):
        """When a version is pinned, 'lasso version' mentions it."""
        store = CheckpointStore(state_dir=str(tmp_path))
        store.pin_version("0.2.0")

        with patch("lasso.core.checkpoint.CheckpointStore", return_value=store):
            result = _invoke("version")
        assert result.exit_code == 0
        assert "Pinned to" in result.output or "0.2.0" in result.output

    def test_version_shows_update_available(self, tmp_path):
        """When a newer checkpoint exists, 'lasso version' warns about it."""
        store = CheckpointStore(state_dir=str(tmp_path))
        store.register_checkpoint(tag="v99.0.0", version="99.0.0", notes="Future")

        with patch("lasso.core.checkpoint.CheckpointStore", return_value=store):
            result = _invoke("version")
        assert result.exit_code == 0
        assert "Update available" in result.output or "99.0.0" in result.output


# ---------------------------------------------------------------------------
# CLI — lasso checkpoint list / create / pin
# ---------------------------------------------------------------------------

class TestCLICheckpointList:
    def test_list_empty(self):
        result = _invoke("checkpoint", "list")
        assert result.exit_code == 0
        assert "No checkpoints" in result.output

    def test_list_json_empty(self):
        result = _invoke("checkpoint", "list", "--json")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 0

    def test_list_with_checkpoints(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        store.register_checkpoint(
            tag="v0.1.0", version="0.1.0", notes="Alpha",
        )
        store.register_checkpoint(
            tag="v0.2.0", version="0.2.0", notes="Beta",
            reviewed_by=["Alice"],
        )

        with patch("lasso.core.checkpoint.CheckpointStore", return_value=store):
            result = _invoke("checkpoint", "list")
        assert result.exit_code == 0
        assert "v0.1.0" in result.output
        assert "v0.2.0" in result.output
        assert "Alpha" in result.output
        assert "Beta" in result.output

    def test_list_json_with_checkpoints(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        store.register_checkpoint(tag="v0.1.0", version="0.1.0")

        with patch("lasso.core.checkpoint.CheckpointStore", return_value=store):
            result = _invoke("checkpoint", "list", "--json")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["tag"] == "v0.1.0"


class TestCLICheckpointCreate:
    def test_create_checkpoint(self, tmp_path):
        with patch("lasso.core.checkpoint.CheckpointStore",
                   return_value=CheckpointStore(state_dir=str(tmp_path))):
            result = _invoke(
                "checkpoint", "create", "v0.3.0",
                "--notes", "Test release",
                "--reviewer", "Alice",
            )
        assert result.exit_code == 0
        assert "Checkpoint registered" in result.output
        assert "v0.3.0" in result.output
        assert "0.3.0" in result.output

    def test_create_strips_v_for_version(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        with patch("lasso.core.checkpoint.CheckpointStore", return_value=store):
            _invoke("checkpoint", "create", "v1.2.3", "--notes", "test")

        loaded = store.load_manifest()
        assert len(loaded) == 1
        assert loaded[0].tag == "v1.2.3"
        assert loaded[0].version == "1.2.3"


class TestCLICheckpointPin:
    def test_pin_version(self, tmp_path):
        store = CheckpointStore(state_dir=str(tmp_path))
        with patch("lasso.core.checkpoint.CheckpointStore", return_value=store):
            result = _invoke("checkpoint", "pin", "0.2.0")
        assert result.exit_code == 0
        assert "Pinned to version 0.2.0" in result.output
        assert store.get_pinned_version() == "0.2.0"


# ---------------------------------------------------------------------------
# CLI — create warns about updates
# ---------------------------------------------------------------------------

class TestCreateUpdateWarning:
    def test_create_warns_when_update_available(self, tmp_path):
        """Non-quiet create should print a yellow warning if newer checkpoint exists."""
        store = CheckpointStore(state_dir=str(tmp_path))
        store.register_checkpoint(tag="v99.0.0", version="99.0.0")

        with patch("lasso.core.checkpoint.CheckpointStore", return_value=store):
            result = _invoke(
                "create", "evaluation",
                "--dir", str(tmp_path),
                "--native",
            )
        assert result.exit_code == 0
        assert "99.0.0" in result.output
        assert "available" in result.output.lower()

    def test_create_quiet_no_update_warning(self, tmp_path):
        """--quiet create should NOT show update warnings."""
        store = CheckpointStore(state_dir=str(tmp_path))
        store.register_checkpoint(tag="v99.0.0", version="99.0.0")

        with patch("lasso.core.checkpoint.CheckpointStore", return_value=store):
            result = _invoke(
                "create", "evaluation",
                "--dir", str(tmp_path),
                "--native",
                "--quiet",
            )
        assert result.exit_code == 0
        # In quiet mode, output should just be the sandbox ID
        output = result.output.strip()
        assert "available" not in output.lower()

    def test_create_no_warning_when_current(self, tmp_path):
        """No warning when there's no newer checkpoint."""
        result = _invoke(
            "create", "evaluation",
            "--dir", str(tmp_path),
            "--native",
        )
        assert result.exit_code == 0
        assert "update available" not in result.output.lower()


# ---------------------------------------------------------------------------
# CLI — check includes version info
# ---------------------------------------------------------------------------

class TestCheckIncludesVersion:
    def test_check_json_has_version_section(self):
        result = _invoke("check", "--json")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "version" in data
        assert "current" in data["version"]
        assert "pinned_version" in data["version"]
        assert "latest_checkpoint" in data["version"]

    def test_check_shows_version_row(self):
        result = _invoke("check")
        assert result.exit_code == 0
        assert "Version" in result.output
