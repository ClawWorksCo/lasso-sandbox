"""Tests for team bootstrap (lasso init --from-config) and related features.

Covers:
- B2: Project-level .lasso/profiles/ auto-discovery
- B3: Profile locking / approval hash
- F1: Team bootstrap via lasso init --from-config
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import tomli

from lasso.config.defaults import evaluation_profile, standard_profile
from lasso.config.profile import load_profile_from_path, save_profile
from lasso.config.sharing import (
    find_profile,
    get_profile_dirs,
    lock_profile,
    verify_profile_locks,
)

# ---------------------------------------------------------------------------
# B2: Project-level .lasso/profiles/ auto-discovery
# ---------------------------------------------------------------------------

class TestProjectProfileDiscovery:
    """Tests for get_profile_dirs() and find_profile() with working_dir."""

    def test_project_profiles_dir_highest_priority(self, tmp_path):
        """Project .lasso/profiles/ should be first in the directory list."""
        project_profiles = tmp_path / ".lasso" / "profiles"
        project_profiles.mkdir(parents=True)

        dirs = get_profile_dirs(working_dir=str(tmp_path))
        assert dirs[0] == project_profiles

    def test_project_profiles_dir_not_included_if_missing(self, tmp_path):
        """If .lasso/profiles/ doesn't exist, it should not appear in dirs."""
        dirs = get_profile_dirs(working_dir=str(tmp_path))
        project_profiles = tmp_path / ".lasso" / "profiles"
        assert project_profiles not in dirs

    def test_working_dir_none_skips_project(self):
        """get_profile_dirs(working_dir=None) should skip project profiles."""
        dirs = get_profile_dirs(working_dir=None)
        from lasso.config.profile import DEFAULT_PROFILE_DIR
        assert DEFAULT_PROFILE_DIR in dirs

    def test_find_profile_in_project_dir(self, tmp_path):
        """find_profile() should find profiles in .lasso/profiles/."""
        project_profiles = tmp_path / ".lasso" / "profiles"
        project_profiles.mkdir(parents=True)

        p = evaluation_profile(str(tmp_path), name="team-secure")
        save_profile(p, profile_dir=project_profiles)

        result = find_profile("team-secure", working_dir=str(tmp_path))
        assert result is not None
        assert "team-secure.toml" in str(result)

    def test_project_profile_overrides_env_dir(self, tmp_path, monkeypatch):
        """Project profiles should take priority over LASSO_PROFILE_DIR."""
        project_profiles = tmp_path / ".lasso" / "profiles"
        project_profiles.mkdir(parents=True)

        env_profiles = tmp_path / "env-profiles"
        env_profiles.mkdir()
        monkeypatch.setenv("LASSO_PROFILE_DIR", str(env_profiles))

        # Create same-named profile in both dirs with different descriptions
        p1 = evaluation_profile(str(tmp_path), name="shared")
        p1.description = "project version"
        save_profile(p1, profile_dir=project_profiles)

        p2 = evaluation_profile(str(tmp_path), name="shared")
        p2.description = "env version"
        save_profile(p2, profile_dir=env_profiles)

        result = find_profile("shared", working_dir=str(tmp_path))
        assert result is not None
        loaded = load_profile_from_path(result)
        assert loaded.description == "project version"

    def test_backward_compat_no_working_dir(self):
        """get_profile_dirs() without arguments should still work."""
        dirs = get_profile_dirs()
        from lasso.config.profile import DEFAULT_PROFILE_DIR
        assert DEFAULT_PROFILE_DIR in dirs

    def test_env_dir_deduplication(self, tmp_path, monkeypatch):
        """Duplicate paths in LASSO_PROFILE_DIR should be deduplicated."""
        team_dir = tmp_path / "team"
        team_dir.mkdir()
        monkeypatch.setenv("LASSO_PROFILE_DIR", f"{team_dir}{os.pathsep}{team_dir}")

        dirs = get_profile_dirs()
        assert dirs.count(team_dir) == 1


# ---------------------------------------------------------------------------
# B3: Profile locking / approval hash
# ---------------------------------------------------------------------------

class TestProfileLocking:
    """Tests for lock_profile() and verify_profile_locks()."""

    def test_lock_creates_lock_file(self, tmp_path):
        """lock_profile() should create .lasso/profile.lock."""
        project_profiles = tmp_path / ".lasso" / "profiles"
        project_profiles.mkdir(parents=True)

        p = evaluation_profile(str(tmp_path), name="lockme")
        save_profile(p, profile_dir=project_profiles)

        lock_data = lock_profile("lockme", working_dir=str(tmp_path))

        lock_file = tmp_path / ".lasso" / "profile.lock"
        assert lock_file.exists()
        assert "config_hash" in lock_data
        assert lock_data["name"] == "lockme"
        assert "locked_at" in lock_data
        assert "profile_version" in lock_data

    def test_lock_file_is_valid_json(self, tmp_path):
        """The lock file should be valid JSON with the profile entry."""
        project_profiles = tmp_path / ".lasso" / "profiles"
        project_profiles.mkdir(parents=True)

        p = evaluation_profile(str(tmp_path), name="jsontest")
        save_profile(p, profile_dir=project_profiles)
        lock_profile("jsontest", working_dir=str(tmp_path))

        lock_file = tmp_path / ".lasso" / "profile.lock"
        locks = json.loads(lock_file.read_text())
        assert "jsontest" in locks
        assert locks["jsontest"]["config_hash"]

    def test_lock_multiple_profiles(self, tmp_path):
        """Multiple profiles can be locked in the same file."""
        project_profiles = tmp_path / ".lasso" / "profiles"
        project_profiles.mkdir(parents=True)

        for name in ["alpha", "beta"]:
            p = evaluation_profile(str(tmp_path), name=name)
            save_profile(p, profile_dir=project_profiles)
            lock_profile(name, working_dir=str(tmp_path))

        lock_file = tmp_path / ".lasso" / "profile.lock"
        locks = json.loads(lock_file.read_text())
        assert "alpha" in locks
        assert "beta" in locks

    def test_verify_matching_profiles(self, tmp_path):
        """verify_profile_locks() should report match=True for unchanged profiles."""
        project_profiles = tmp_path / ".lasso" / "profiles"
        project_profiles.mkdir(parents=True)

        p = evaluation_profile(str(tmp_path), name="stable")
        save_profile(p, profile_dir=project_profiles)
        lock_profile("stable", working_dir=str(tmp_path))

        results = verify_profile_locks(working_dir=str(tmp_path))
        assert len(results) == 1
        assert results[0]["match"] is True
        assert results[0]["name"] == "stable"

    def test_verify_detects_tampered_profile(self, tmp_path):
        """verify_profile_locks() should detect when a profile has been modified."""
        project_profiles = tmp_path / ".lasso" / "profiles"
        project_profiles.mkdir(parents=True)

        p = evaluation_profile(str(tmp_path), name="tampered")
        save_profile(p, profile_dir=project_profiles)
        lock_profile("tampered", working_dir=str(tmp_path))

        # Modify the profile after locking
        p.description = "I was changed after locking"
        save_profile(p, profile_dir=project_profiles)

        results = verify_profile_locks(working_dir=str(tmp_path))
        assert len(results) == 1
        assert results[0]["match"] is False

    def test_verify_no_lock_file_returns_empty(self, tmp_path):
        """verify_profile_locks() should return [] if no lock file exists."""
        results = verify_profile_locks(working_dir=str(tmp_path))
        assert results == []

    def test_verify_missing_profile_reports_error(self, tmp_path):
        """verify_profile_locks() should handle a deleted profile gracefully."""
        project_profiles = tmp_path / ".lasso" / "profiles"
        project_profiles.mkdir(parents=True)

        p = evaluation_profile(str(tmp_path), name="deleted")
        save_profile(p, profile_dir=project_profiles)
        lock_profile("deleted", working_dir=str(tmp_path))

        # Remove the profile
        (project_profiles / "deleted.toml").unlink()

        results = verify_profile_locks(working_dir=str(tmp_path))
        assert len(results) == 1
        assert results[0]["match"] is False
        assert "error" in results[0]

    def test_lock_builtin_profile(self, tmp_path):
        """Locking a builtin profile should work."""
        lock_data = lock_profile("evaluation", working_dir=str(tmp_path))
        assert lock_data["name"] == "evaluation"
        assert lock_data["config_hash"]

    def test_lock_nonexistent_profile_raises(self, tmp_path):
        """Locking a non-existent profile should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            lock_profile("nonexistent-xyz-profile", working_dir=str(tmp_path))


# ---------------------------------------------------------------------------
# F1: Team bootstrap: lasso init --from-config
# ---------------------------------------------------------------------------

class TestInitFromConfig:
    """Tests for _init_from_config (the --from-config codepath)."""

    def _make_team_config(self, tmp_path) -> Path:
        """Create a mock team config directory."""
        team_dir = tmp_path / "team-config"
        team_dir.mkdir()

        # lasso-config.toml
        (team_dir / "lasso-config.toml").write_text(
            '[lasso]\ndefault_profile = "secure"\n'
        )

        # profiles/
        profiles_dir = team_dir / "profiles"
        profiles_dir.mkdir()
        p = evaluation_profile(str(tmp_path), name="secure")
        p.description = "Team secure profile"
        save_profile(p, profile_dir=profiles_dir)

        p2 = standard_profile(str(tmp_path), name="dev")
        save_profile(p2, profile_dir=profiles_dir)

        # templates/
        templates_dir = team_dir / "templates"
        templates_dir.mkdir()
        (templates_dir / "agent.md").write_text("# Agent template\n")

        return team_dir

    def test_init_from_config_copies_profiles(self, tmp_path):
        """--from-config should copy profiles/ to .lasso/profiles/."""
        team_dir = self._make_team_config(tmp_path)
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        from lasso.cli.main import _init_from_config

        lasso_dir = project_dir / ".lasso"
        _init_from_config(str(team_dir), str(project_dir), lasso_dir, output_json=False)

        profiles_dest = lasso_dir / "profiles"
        assert profiles_dest.is_dir()
        assert (profiles_dest / "secure.toml").exists()
        assert (profiles_dest / "dev.toml").exists()

    def test_init_from_config_copies_config(self, tmp_path):
        """--from-config should copy lasso-config.toml to .lasso/config.toml."""
        team_dir = self._make_team_config(tmp_path)
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        from lasso.cli.main import _init_from_config

        lasso_dir = project_dir / ".lasso"
        _init_from_config(str(team_dir), str(project_dir), lasso_dir, output_json=False)

        config_dest = lasso_dir / "config.toml"
        assert config_dest.exists()
        with open(config_dest, "rb") as f:
            data = tomli.load(f)
        assert data["lasso"]["default_profile"] == "secure"

    def test_init_from_config_copies_templates(self, tmp_path):
        """--from-config should copy templates/ to .lasso/templates/."""
        team_dir = self._make_team_config(tmp_path)
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        from lasso.cli.main import _init_from_config

        lasso_dir = project_dir / ".lasso"
        _init_from_config(str(team_dir), str(project_dir), lasso_dir, output_json=False)

        templates_dest = lasso_dir / "templates"
        assert templates_dest.is_dir()
        assert (templates_dest / "agent.md").exists()

    def test_init_from_config_missing_dir_raises(self, tmp_path):
        """--from-config with a non-existent directory should exit with error."""
        from lasso.cli.main import _init_from_config

        project_dir = tmp_path / "my-project"
        project_dir.mkdir()
        lasso_dir = project_dir / ".lasso"

        from click.exceptions import Exit as ClickExit

        with pytest.raises((SystemExit, ClickExit)):
            _init_from_config(
                str(tmp_path / "nonexistent"),
                str(project_dir),
                lasso_dir,
                output_json=False,
            )

    def test_init_from_config_creates_audit_dir(self, tmp_path):
        """--from-config should create .lasso/audit/ directory."""
        team_dir = self._make_team_config(tmp_path)
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        from lasso.cli.main import _init_from_config

        lasso_dir = project_dir / ".lasso"
        _init_from_config(str(team_dir), str(project_dir), lasso_dir, output_json=False)

        assert (lasso_dir / "audit").is_dir()

    def test_init_from_config_partial_source(self, tmp_path):
        """--from-config with only profiles/ (no config or templates) should work."""
        team_dir = tmp_path / "partial-config"
        team_dir.mkdir()
        profiles_dir = team_dir / "profiles"
        profiles_dir.mkdir()
        p = evaluation_profile(str(tmp_path), name="only-profile")
        save_profile(p, profile_dir=profiles_dir)

        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        from lasso.cli.main import _init_from_config

        lasso_dir = project_dir / ".lasso"
        _init_from_config(str(team_dir), str(project_dir), lasso_dir, output_json=False)

        assert (lasso_dir / "profiles" / "only-profile.toml").exists()
        assert not (lasso_dir / "config.toml").exists()
        assert not (lasso_dir / "templates").exists()

    def test_init_from_config_empty_source(self, tmp_path):
        """--from-config with an empty directory should succeed gracefully."""
        empty_dir = tmp_path / "empty-config"
        empty_dir.mkdir()

        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        from lasso.cli.main import _init_from_config

        lasso_dir = project_dir / ".lasso"
        _init_from_config(str(empty_dir), str(project_dir), lasso_dir, output_json=False)

        # Should at least create the .lasso and audit dirs
        assert lasso_dir.is_dir()
        assert (lasso_dir / "audit").is_dir()
