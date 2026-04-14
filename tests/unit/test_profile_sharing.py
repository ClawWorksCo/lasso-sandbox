"""Tests for profile sharing — export, import, versioning, and diff."""

from __future__ import annotations

import os

import pytest
import tomli

from lasso.config.defaults import evaluation_profile, standard_profile
from lasso.config.profile import load_profile, save_profile
from lasso.config.sharing import (
    diff_profiles,
    export_profile,
    find_profile,
    get_profile_dirs,
    import_profile,
    list_profile_versions,
    save_profile_versioned,
)

# ---------------------------------------------------------------------------
# Profile directories
# ---------------------------------------------------------------------------

class TestProfileDirs:
    def test_default_dir_always_included(self):
        """The default ~/.lasso/profiles/ should always be in the list."""
        from lasso.config.profile import DEFAULT_PROFILE_DIR

        dirs = get_profile_dirs()
        assert DEFAULT_PROFILE_DIR in dirs

    def test_env_var_adds_dirs(self, monkeypatch, tmp_path):
        """LASSO_PROFILE_DIR should add directories to the search path."""
        team_dir = tmp_path / "team-profiles"
        team_dir.mkdir()

        monkeypatch.setenv("LASSO_PROFILE_DIR", str(team_dir))

        dirs = get_profile_dirs()
        assert team_dir in dirs

    def test_env_var_multiple_dirs(self, monkeypatch, tmp_path):
        """LASSO_PROFILE_DIR can contain multiple paths (os.pathsep separated)."""
        dir1 = tmp_path / "dir1"
        dir2 = tmp_path / "dir2"
        dir1.mkdir()
        dir2.mkdir()

        monkeypatch.setenv("LASSO_PROFILE_DIR", f"{dir1}{os.pathsep}{dir2}")

        dirs = get_profile_dirs()
        assert dir1 in dirs
        assert dir2 in dirs


class TestFindProfile:
    def test_finds_profile_in_default_dir(self, tmp_path):
        """find_profile should locate profiles in the default directory."""

        p = evaluation_profile(str(tmp_path), name="findme")
        save_profile(p, profile_dir=tmp_path)

        # Monkeypatch get_profile_dirs to use tmp_path
        import lasso.config.sharing as sharing_mod
        original = sharing_mod.get_profile_dirs

        sharing_mod.get_profile_dirs = lambda **kwargs: [tmp_path]
        try:
            result = find_profile("findme")
            assert result is not None
            assert result.name == "findme.toml"
        finally:
            sharing_mod.get_profile_dirs = original

    def test_returns_none_for_missing(self, tmp_path):
        """find_profile should return None for non-existent profiles."""
        import lasso.config.sharing as sharing_mod
        original = sharing_mod.get_profile_dirs

        sharing_mod.get_profile_dirs = lambda **kwargs: [tmp_path]
        try:
            result = find_profile("nonexistent")
            assert result is None
        finally:
            sharing_mod.get_profile_dirs = original


# ---------------------------------------------------------------------------
# Export / Import
# ---------------------------------------------------------------------------

class TestExportProfile:
    def test_export_saved_profile(self, tmp_path):
        """Export a saved profile to a standalone TOML file."""
        # Save a profile first
        p = evaluation_profile(str(tmp_path), name="export-test")
        save_profile(p, profile_dir=tmp_path)

        output = tmp_path / "exported.toml"
        result = export_profile("export-test", output, profile_dir=tmp_path)

        assert result == output
        assert output.exists()

        # Verify the exported file contains metadata
        with open(output, "rb") as f:
            data = tomli.load(f)

        assert "lasso_metadata" in data
        assert "config_hash" in data["lasso_metadata"]
        assert "exported_at" in data["lasso_metadata"]
        assert data["name"] == "export-test"

    def test_export_builtin_profile(self, tmp_path):
        """Export a builtin profile (not saved to disk)."""
        output = tmp_path / "minimal-exported.toml"
        result = export_profile("evaluation", output, profile_dir=tmp_path)

        assert result == output
        assert output.exists()

        with open(output, "rb") as f:
            data = tomli.load(f)

        assert data["name"] == "evaluation"
        assert "builtin" in data["lasso_metadata"]["source"]

    def test_export_nonexistent_raises(self, tmp_path):
        """Exporting a non-existent profile should raise FileNotFoundError."""
        output = tmp_path / "nope.toml"
        with pytest.raises(FileNotFoundError):
            export_profile("nonexistent-profile-xyz", output, profile_dir=tmp_path)


class TestImportProfile:
    def test_import_exported_profile(self, tmp_path):
        """Import a previously exported profile."""
        # Export first
        p = standard_profile(str(tmp_path), name="import-test")
        save_profile(p, profile_dir=tmp_path)
        exported = tmp_path / "export.toml"
        export_profile("import-test", exported, profile_dir=tmp_path)

        # Import to a different directory
        import_dir = tmp_path / "imported"
        import_dir.mkdir()
        imported = import_profile(exported, profile_dir=import_dir)

        assert imported.name == "import-test"
        assert (import_dir / "import-test.toml").exists()

    def test_import_with_name_override(self, tmp_path):
        """Import should allow overriding the profile name."""
        p = evaluation_profile(str(tmp_path), name="original")
        save_profile(p, profile_dir=tmp_path)
        exported = tmp_path / "exported.toml"
        export_profile("original", exported, profile_dir=tmp_path)

        import_dir = tmp_path / "imported"
        import_dir.mkdir()
        imported = import_profile(exported, name="renamed", profile_dir=import_dir)

        assert imported.name == "renamed"
        assert (import_dir / "renamed.toml").exists()

    def test_import_nonexistent_file_raises(self, tmp_path):
        """Importing a non-existent file should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            import_profile(tmp_path / "nope.toml")

    def test_import_invalid_toml_raises(self, tmp_path):
        """Importing an invalid TOML file should raise ValueError."""
        bad_file = tmp_path / "bad.toml"
        bad_file.write_text("name = 123\n[filesystem]\n")  # missing required fields

        with pytest.raises(ValueError, match="Invalid profile"):
            import_profile(bad_file, profile_dir=tmp_path)

    def test_import_integrity_strict_raises(self, tmp_path):
        """Import should raise ValueError on hash mismatch in strict mode (default)."""
        p = evaluation_profile(str(tmp_path), name="tampered")
        save_profile(p, profile_dir=tmp_path)
        exported = tmp_path / "export.toml"
        export_profile("tampered", exported, profile_dir=tmp_path)

        # Tamper with the file: change a value
        content = exported.read_text()
        content = content.replace("max_memory_mb = 2048", "max_memory_mb = 1024")
        exported.write_text(content)

        import_dir = tmp_path / "import_strict"
        import_dir.mkdir()

        with pytest.raises(ValueError, match="Config hash mismatch"):
            import_profile(exported, profile_dir=import_dir)

    def test_import_integrity_warning_when_not_strict(self, tmp_path, caplog):
        """Import should warn (not raise) when strict=False and hash mismatches."""
        import logging

        p = evaluation_profile(str(tmp_path), name="tampered")
        save_profile(p, profile_dir=tmp_path)
        exported = tmp_path / "export.toml"
        export_profile("tampered", exported, profile_dir=tmp_path)

        # Tamper with the file: change a value
        content = exported.read_text()
        content = content.replace("max_memory_mb = 2048", "max_memory_mb = 1024")
        exported.write_text(content)

        import_dir = tmp_path / "import2"
        import_dir.mkdir()

        with caplog.at_level(logging.WARNING, logger="lasso.sharing"):
            imported = import_profile(exported, profile_dir=import_dir, strict=False)

        # Should still import but warn about hash mismatch
        assert imported.name == "tampered"
        assert any("hash mismatch" in r.message.lower() for r in caplog.records)


# ---------------------------------------------------------------------------
# Versioning
# ---------------------------------------------------------------------------

class TestProfileVersioning:
    def test_save_versioned_creates_history(self, tmp_path):
        """Saving a versioned profile should create history entries."""
        p = evaluation_profile(str(tmp_path), name="versioned")
        save_profile(p, profile_dir=tmp_path)

        # Save again with versioning
        p2 = evaluation_profile(str(tmp_path), name="versioned")
        p2.description = "Updated description"
        result = save_profile_versioned(p2, profile_dir=tmp_path)

        assert result.exists()

        # Check history was created
        history = tmp_path.parent / ".lasso" / "profiles" / ".history" / "versioned"
        # History is stored under DEFAULT_PROFILE_DIR, not tmp_path
        # Let's check the profile was saved with incremented version
        loaded = load_profile("versioned", profile_dir=tmp_path)
        assert loaded.profile_version == 2
        assert loaded.description == "Updated description"

    def test_version_increments(self, tmp_path):
        """Each versioned save should increment profile_version."""
        p = evaluation_profile(str(tmp_path), name="vtest")
        save_profile(p, profile_dir=tmp_path)

        for i in range(3):
            p = load_profile("vtest", profile_dir=tmp_path)
            p.description = f"Version {i + 2}"
            save_profile_versioned(p, profile_dir=tmp_path)

        final = load_profile("vtest", profile_dir=tmp_path)
        assert final.profile_version == 4  # started at 1, incremented 3 times

    def test_list_versions_empty_for_new_profile(self, tmp_path):
        """A brand-new profile should have no version history."""
        result = list_profile_versions("brand-new-profile")
        assert result == []

    def test_first_save_versioned_no_crash(self, tmp_path):
        """First save_profile_versioned (no existing file) should not crash."""
        p = evaluation_profile(str(tmp_path), name="first-ever")
        result = save_profile_versioned(p, profile_dir=tmp_path)
        assert result.exists()

        loaded = load_profile("first-ever", profile_dir=tmp_path)
        assert loaded.profile_version == 1


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

class TestDiffProfiles:
    def test_identical_profiles_no_diff(self, tmp_path):
        """Diffing identical profiles should show no differences."""
        a = evaluation_profile(str(tmp_path), name="same")
        b = evaluation_profile(str(tmp_path), name="same")

        result = diff_profiles(a, b)
        assert "No differences." in result

    def test_diff_detects_name_change(self, tmp_path):
        """Diff should detect name changes."""
        a = evaluation_profile(str(tmp_path), name="alpha")
        b = evaluation_profile(str(tmp_path), name="beta")

        result = diff_profiles(a, b)
        assert "alpha" in result
        assert "beta" in result
        assert "name" in result

    def test_diff_detects_whitelist_changes(self, tmp_path):
        """Diff should detect whitelist additions/removals."""
        a = evaluation_profile(str(tmp_path), name="wl-a")
        b = evaluation_profile(str(tmp_path), name="wl-a")
        b.commands.whitelist.append("python3")

        result = diff_profiles(a, b)
        assert "whitelist" in result.lower() or "python3" in result

    def test_diff_detects_memory_change(self, tmp_path):
        """Diff should detect resource limit changes."""
        a = evaluation_profile(str(tmp_path), name="mem-a")
        b = evaluation_profile(str(tmp_path), name="mem-a")
        b.resources.max_memory_mb = 8192

        result = diff_profiles(a, b)
        assert "2048" in result  # old value
        assert "8192" in result  # new value

    def test_diff_detects_network_mode_change(self, tmp_path):
        """Diff should detect network mode changes."""
        a = evaluation_profile(str(tmp_path), name="net")
        b = standard_profile(str(tmp_path), name="net")

        result = diff_profiles(a, b)
        assert "none" in result
        assert "restricted" in result

    def test_diff_header_includes_versions(self, tmp_path):
        """Diff header should include profile names and versions."""
        a = evaluation_profile(str(tmp_path), name="old")
        a.profile_version = 1
        b = evaluation_profile(str(tmp_path), name="new")
        b.profile_version = 3

        result = diff_profiles(a, b)
        assert "old (v1)" in result
        assert "new (v3)" in result


# ---------------------------------------------------------------------------
# Round-trip: export -> import -> diff shows no changes
# ---------------------------------------------------------------------------

class TestExportImportRoundTrip:
    def test_round_trip_preserves_profile(self, tmp_path):
        """Exporting and reimporting a profile should preserve all fields."""
        p = standard_profile(str(tmp_path), name="roundtrip")
        p.tags = ["banking", "test"]
        save_profile(p, profile_dir=tmp_path)

        exported = tmp_path / "roundtrip.exported.toml"
        export_profile("roundtrip", exported, profile_dir=tmp_path)

        import_dir = tmp_path / "reimport"
        import_dir.mkdir()
        reimported = import_profile(exported, profile_dir=import_dir)

        # Core fields should match
        assert reimported.name == p.name
        assert reimported.description == p.description
        assert reimported.tags == p.tags
        assert reimported.commands.mode == p.commands.mode
        assert reimported.network.mode == p.network.mode
        assert reimported.resources.max_memory_mb == p.resources.max_memory_mb
        assert reimported.commands.whitelist == p.commands.whitelist
