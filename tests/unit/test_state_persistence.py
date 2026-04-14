"""Tests for sandbox registry state persistence — save, load, reconcile."""

import json

from lasso.backends.base import ContainerState
from lasso.config.defaults import evaluation_profile
from lasso.core.sandbox import SandboxRegistry
from lasso.core.state import RegistryState, SandboxRecord, StateStore
from tests.conftest import FakeBackend

# ---------------------------------------------------------------------------
# StateStore — save / load
# ---------------------------------------------------------------------------

class TestStateStoreSaveLoad:
    def test_save_creates_state_file(self, tmp_path):
        store = StateStore(state_dir=str(tmp_path))
        store.record_create("sb-001", "test-profile", "cid-001")
        assert store.state_file.exists()

    def test_load_empty_dir_returns_empty_state(self, tmp_path):
        store = StateStore(state_dir=str(tmp_path))
        state = store.load()
        assert len(state.sandboxes) == 0

    def test_save_and_load_round_trip(self, tmp_path):
        store = StateStore(state_dir=str(tmp_path))
        store.record_create("sb-001", "profile-a", "cid-001")
        store.record_create("sb-002", "profile-b", "cid-002")

        # Load in a new store instance
        store2 = StateStore(state_dir=str(tmp_path))
        state = store2.load()
        assert len(state.sandboxes) == 2
        assert state.sandboxes["sb-001"].profile_name == "profile-a"
        assert state.sandboxes["sb-002"].profile_name == "profile-b"

    def test_record_stop_updates_state(self, tmp_path):
        store = StateStore(state_dir=str(tmp_path))
        store.record_create("sb-001", "test", "cid-001")
        store.record_stop("sb-001")

        store2 = StateStore(state_dir=str(tmp_path))
        state = store2.load()
        assert state.sandboxes["sb-001"].state == "stopped"
        assert state.sandboxes["sb-001"].stopped_at is not None

    def test_record_remove_deletes_entry(self, tmp_path):
        store = StateStore(state_dir=str(tmp_path))
        store.record_create("sb-001", "test", "cid-001")
        store.record_remove("sb-001")

        store2 = StateStore(state_dir=str(tmp_path))
        state = store2.load()
        assert "sb-001" not in state.sandboxes

    def test_get_running_records(self, tmp_path):
        store = StateStore(state_dir=str(tmp_path))
        store.record_create("sb-001", "a", "cid-001")
        store.record_create("sb-002", "b", "cid-002")
        store.record_stop("sb-001")

        running = store.get_running_records()
        assert "sb-001" not in running
        assert "sb-002" in running

    def test_corrupt_file_handled_gracefully(self, tmp_path):
        state_file = tmp_path / "state.json"
        state_file.write_text("not valid json {{{")

        store = StateStore(state_dir=str(tmp_path))
        state = store.load()
        assert len(state.sandboxes) == 0

    def test_state_file_has_version(self, tmp_path):
        store = StateStore(state_dir=str(tmp_path))
        store.record_create("sb-001", "test", "cid-001")

        data = json.loads(store.state_file.read_text())
        assert data["version"] == 1
        assert "updated_at" in data

    def test_state_dir_created_if_missing(self, tmp_path):
        nested = tmp_path / "deep" / "nested"
        store = StateStore(state_dir=str(nested))
        store.record_create("sb-001", "test", "cid-001")
        assert (nested / "state.json").exists()


# ---------------------------------------------------------------------------
# StateStore — reconcile
# ---------------------------------------------------------------------------

class TestStateStoreReconcile:
    def test_reconcile_marks_running_container_as_alive(self, tmp_path):
        backend = FakeBackend()
        backend.containers["cid-001"] = ContainerState.RUNNING

        store = StateStore(state_dir=str(tmp_path))
        store.record_create("sb-001", "test", "cid-001")

        results = store.reconcile(backend)
        assert results["sb-001"] == "alive"
        assert store.get_running_records()["sb-001"].state == "running"

    def test_reconcile_marks_stopped_container(self, tmp_path):
        backend = FakeBackend()
        backend.containers["cid-001"] = ContainerState.STOPPED

        store = StateStore(state_dir=str(tmp_path))
        store.record_create("sb-001", "test", "cid-001")

        results = store.reconcile(backend)
        assert results["sb-001"] == "stopped"
        assert store.get_running_records() == {}

    def test_reconcile_marks_gone_container(self, tmp_path):
        backend = FakeBackend()
        # Container not in backend at all

        store = StateStore(state_dir=str(tmp_path))
        store.record_create("sb-001", "test", "cid-001")

        results = store.reconcile(backend)
        assert results["sb-001"] == "gone"

    def test_reconcile_without_backend_marks_all_gone(self, tmp_path):
        store = StateStore(state_dir=str(tmp_path))
        store.record_create("sb-001", "test", "cid-001")

        results = store.reconcile(None)
        assert results["sb-001"] == "gone"

    def test_reconcile_skips_already_stopped(self, tmp_path):
        backend = FakeBackend()

        store = StateStore(state_dir=str(tmp_path))
        store.record_create("sb-001", "test", "cid-001")
        store.record_stop("sb-001")

        results = store.reconcile(backend)
        assert results["sb-001"] == "stopped"

    def test_reconcile_persists_updates(self, tmp_path):
        backend = FakeBackend()
        # Container gone

        store = StateStore(state_dir=str(tmp_path))
        store.record_create("sb-001", "test", "cid-001")
        store.reconcile(backend)

        # Reload and verify
        store2 = StateStore(state_dir=str(tmp_path))
        state = store2.load()
        assert state.sandboxes["sb-001"].state == "stopped"


# ---------------------------------------------------------------------------
# SandboxRecord serialization
# ---------------------------------------------------------------------------

class TestSandboxRecord:
    def test_to_dict_excludes_none(self):
        rec = SandboxRecord(
            sandbox_id="sb-001",
            profile_name="test",
            state="running",
            created_at="2024-01-01T00:00:00Z",
        )
        d = rec.to_dict()
        assert "stopped_at" not in d
        assert d["sandbox_id"] == "sb-001"

    def test_from_dict_round_trip(self):
        rec = SandboxRecord(
            sandbox_id="sb-001",
            profile_name="test",
            container_id="cid-001",
            state="running",
            created_at="2024-01-01T00:00:00Z",
        )
        d = rec.to_dict()
        rec2 = SandboxRecord.from_dict(d)
        assert rec2.sandbox_id == rec.sandbox_id
        assert rec2.container_id == rec.container_id
        assert rec2.profile_name == rec.profile_name

    def test_from_dict_missing_optional_fields(self):
        d = {"sandbox_id": "sb-001", "profile_name": "test"}
        rec = SandboxRecord.from_dict(d)
        assert rec.state == "created"
        assert rec.container_id is None


# ---------------------------------------------------------------------------
# RegistryState serialization
# ---------------------------------------------------------------------------

class TestRegistryState:
    def test_empty_state(self):
        state = RegistryState()
        d = state.to_dict()
        assert d["version"] == 1
        assert d["sandboxes"] == {}

    def test_round_trip(self):
        state = RegistryState()
        state.sandboxes["sb-001"] = SandboxRecord(
            sandbox_id="sb-001",
            profile_name="test",
            state="running",
        )
        d = state.to_dict()
        state2 = RegistryState.from_dict(d)
        assert "sb-001" in state2.sandboxes
        assert state2.sandboxes["sb-001"].profile_name == "test"


# ---------------------------------------------------------------------------
# SandboxRegistry integration with StateStore
# ---------------------------------------------------------------------------

class TestRegistryPersistence:
    def test_create_persists_to_state(self, tmp_path):
        backend = FakeBackend()
        registry = SandboxRegistry(backend=backend, state_dir=str(tmp_path))
        profile = evaluation_profile(str(tmp_path), name="persist-test")

        sb = registry.create(profile)

        # Verify state file exists with the sandbox
        store2 = StateStore(state_dir=str(tmp_path))
        state = store2.load()
        assert sb.id in state.sandboxes
        assert state.sandboxes[sb.id].profile_name == "persist-test"

    def test_stop_updates_persisted_state(self, tmp_path):
        backend = FakeBackend()
        registry = SandboxRegistry(backend=backend, state_dir=str(tmp_path))
        profile = evaluation_profile(str(tmp_path), name="stop-test")

        sb = registry.create(profile)
        sb.start()
        registry.stop(sb.id)

        store2 = StateStore(state_dir=str(tmp_path))
        state = store2.load()
        assert state.sandboxes[sb.id].state == "stopped"

    def test_stop_all_updates_persisted_state(self, tmp_path):
        backend = FakeBackend()
        registry = SandboxRegistry(backend=backend, state_dir=str(tmp_path))

        profile1 = evaluation_profile(str(tmp_path), name="stop-all-1")
        profile2 = evaluation_profile(str(tmp_path), name="stop-all-2")

        sb1 = registry.create(profile1)
        sb2 = registry.create(profile2)
        sb1.start()
        sb2.start()

        registry.stop_all()

        store2 = StateStore(state_dir=str(tmp_path))
        state = store2.load()
        assert state.sandboxes[sb1.id].state == "stopped"
        assert state.sandboxes[sb2.id].state == "stopped"

    def test_remove_deletes_from_persisted_state(self, tmp_path):
        backend = FakeBackend()
        registry = SandboxRegistry(backend=backend, state_dir=str(tmp_path))
        profile = evaluation_profile(str(tmp_path), name="remove-test")

        sb = registry.create(profile)
        registry.remove(sb.id)

        store2 = StateStore(state_dir=str(tmp_path))
        state = store2.load()
        assert sb.id not in state.sandboxes

    def test_reconcile_via_registry(self, tmp_path):
        backend = FakeBackend()

        # Seed state file with a "running" sandbox whose container is gone
        store = StateStore(state_dir=str(tmp_path))
        store.record_create("old-sb", "old-profile", "gone-container")
        del store

        # SandboxRegistry now auto-reconciles on __init__, so the stale
        # sandbox is already cleaned up before we call reconcile() explicitly.
        registry = SandboxRegistry(backend=backend, state_dir=str(tmp_path))
        results = registry.reconcile()
        # After auto-reconcile at init, the sandbox is already stopped,
        # so a second reconcile reports it as "stopped".
        assert results["old-sb"] == "stopped"
