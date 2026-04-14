"""Tests for profile inheritance — extends field and resolve_profile."""

from __future__ import annotations

import os

import pytest
import tomli_w

from lasso.config.defaults import BUILTIN_PROFILES
from lasso.config.profile import (
    _deep_merge,
    _extract_overrides,
    _strip_none,
    resolve_profile,
)


def _make_profile_toml(data: dict) -> bytes:
    """Serialize a profile dict to TOML bytes."""
    return tomli_w.dumps(_strip_none(data)).encode()


def _minimal_data(name: str, working_dir: str = "/tmp/work", **overrides) -> dict:
    """Return a minimal valid profile dict with optional overrides."""
    base = {
        "name": name,
        "description": f"Test profile: {name}",
        "version": "1",
        "filesystem": {"working_dir": working_dir},
    }
    base.update(overrides)
    return base


class TestSimpleExtends:
    """Child extends a builtin; scalars are overridden, lists are merged."""

    def test_simple_extends_builtin(self, tmp_path):
        """A child profile extending 'offline' should inherit its settings."""
        child_data = _minimal_data(
            "team-profile",
            extends="strict",
            tags=["team", "custom"],
        )
        child_data["commands"] = {
            "whitelist": ["my-custom-tool"],
        }

        # Save child to tmp dir
        child_path = tmp_path / "team-profile.toml"
        child_path.write_bytes(_make_profile_toml(child_data))

        # Set profile dir so resolve_profile can find it
        os.environ["LASSO_PROFILE_DIR"] = str(tmp_path)
        try:
            resolved = resolve_profile("team-profile", working_dir="/tmp/work")
        finally:
            del os.environ["LASSO_PROFILE_DIR"]

        # Name comes from child
        assert resolved.name == "team-profile"

        # Tags should be merged (offline has ["strict", "isolated", "compliance"])
        assert "team" in resolved.tags
        assert "custom" in resolved.tags
        assert "strict" in resolved.tags

        # Whitelist should include both parent and child commands
        assert "my-custom-tool" in resolved.commands.whitelist
        assert "python3" in resolved.commands.whitelist  # from offline profile

        # extends should be cleared
        assert resolved.extends is None

    def test_scalar_override(self, tmp_path):
        """Child scalar values should override parent."""
        child_data = _minimal_data(
            "child-scalar",
            extends="evaluation",
            description="Child description",
        )
        child_data["resources"] = {"max_memory_mb": 16384}

        child_path = tmp_path / "child-scalar.toml"
        child_path.write_bytes(_make_profile_toml(child_data))

        os.environ["LASSO_PROFILE_DIR"] = str(tmp_path)
        try:
            resolved = resolve_profile("child-scalar", working_dir="/tmp/work")
        finally:
            del os.environ["LASSO_PROFILE_DIR"]

        assert resolved.description == "Child description"
        assert resolved.resources.max_memory_mb == 16384


class TestChainedExtends:
    """A extends B extends C — three-level inheritance chain."""

    def test_chained_extends(self, tmp_path):
        """Three-level chain: grandchild -> child -> builtin."""
        # Child extends offline (builtin)
        child_data = _minimal_data(
            "middle-profile",
            extends="strict",
            tags=["middle"],
        )
        child_data["commands"] = {"whitelist": ["middle-tool"]}
        (tmp_path / "middle-profile.toml").write_bytes(_make_profile_toml(child_data))

        # Grandchild extends child
        grandchild_data = _minimal_data(
            "top-profile",
            extends="middle-profile",
            tags=["top"],
        )
        grandchild_data["commands"] = {"whitelist": ["top-tool"]}
        (tmp_path / "top-profile.toml").write_bytes(_make_profile_toml(grandchild_data))

        os.environ["LASSO_PROFILE_DIR"] = str(tmp_path)
        try:
            resolved = resolve_profile("top-profile", working_dir="/tmp/work")
        finally:
            del os.environ["LASSO_PROFILE_DIR"]

        # Name from grandchild
        assert resolved.name == "top-profile"

        # Tags merged from all three levels
        assert "top" in resolved.tags
        assert "middle" in resolved.tags
        assert "strict" in resolved.tags  # from builtin

        # Commands merged from all levels
        assert "top-tool" in resolved.commands.whitelist
        assert "middle-tool" in resolved.commands.whitelist
        assert "python3" in resolved.commands.whitelist  # from offline


class TestCircularExtends:
    """Circular inheritance should raise ValueError."""

    def test_circular_extends_raises(self, tmp_path):
        """A extends B extends A should raise ValueError."""
        a_data = _minimal_data("profile-a", extends="profile-b")
        b_data = _minimal_data("profile-b", extends="profile-a")

        (tmp_path / "profile-a.toml").write_bytes(_make_profile_toml(a_data))
        (tmp_path / "profile-b.toml").write_bytes(_make_profile_toml(b_data))

        os.environ["LASSO_PROFILE_DIR"] = str(tmp_path)
        try:
            with pytest.raises(ValueError, match="Circular profile inheritance"):
                resolve_profile("profile-a", working_dir="/tmp/work")
        finally:
            del os.environ["LASSO_PROFILE_DIR"]

    def test_self_extends_raises(self, tmp_path):
        """A profile extending itself should raise ValueError."""
        a_data = _minimal_data("self-ref", extends="self-ref")
        (tmp_path / "self-ref.toml").write_bytes(_make_profile_toml(a_data))

        os.environ["LASSO_PROFILE_DIR"] = str(tmp_path)
        try:
            with pytest.raises(ValueError, match="Circular profile inheritance"):
                resolve_profile("self-ref", working_dir="/tmp/work")
        finally:
            del os.environ["LASSO_PROFILE_DIR"]


class TestExtendsNone:
    """Profile without extends should resolve to itself."""

    def test_extends_none_is_identity(self):
        """A builtin profile (no extends) resolves to itself unchanged."""
        resolved = resolve_profile("evaluation", working_dir="/tmp/work")
        direct = BUILTIN_PROFILES["evaluation"]("/tmp/work")

        assert resolved.name == direct.name
        assert resolved.commands.whitelist == direct.commands.whitelist
        assert resolved.network.mode == direct.network.mode
        assert resolved.extends is None

    def test_extends_empty_string_treated_as_none(self, tmp_path):
        """An empty extends field should be treated like no inheritance."""
        data = _minimal_data("no-ext")
        # Don't set extends at all
        (tmp_path / "no-ext.toml").write_bytes(_make_profile_toml(data))

        os.environ["LASSO_PROFILE_DIR"] = str(tmp_path)
        try:
            resolved = resolve_profile("no-ext", working_dir="/tmp/work")
        finally:
            del os.environ["LASSO_PROFILE_DIR"]

        assert resolved.name == "no-ext"
        assert resolved.extends is None


class TestListMergeDeduplication:
    """Merged lists should not contain duplicate entries."""

    def test_list_merge_deduplication(self, tmp_path):
        """Commands appearing in both parent and child should not be duplicated."""
        # offline profile has python3 in its whitelist
        child_data = _minimal_data(
            "dedup-test",
            extends="strict",
        )
        child_data["commands"] = {
            "whitelist": ["python3", "my-tool"],  # python3 also in parent
        }

        (tmp_path / "dedup-test.toml").write_bytes(_make_profile_toml(child_data))

        os.environ["LASSO_PROFILE_DIR"] = str(tmp_path)
        try:
            resolved = resolve_profile("dedup-test", working_dir="/tmp/work")
        finally:
            del os.environ["LASSO_PROFILE_DIR"]

        # python3 should appear exactly once
        assert resolved.commands.whitelist.count("python3") == 1
        assert "my-tool" in resolved.commands.whitelist


class TestDictDeepMerge:
    """blocked_args and extra_env from both profiles should be combined."""

    def test_dict_deep_merge(self, tmp_path):
        """blocked_args from parent and child are deep-merged."""
        child_data = _minimal_data(
            "dict-merge-test",
            extends="strict",
        )
        child_data["commands"] = {
            "blocked_args": {
                "npm": ["publish"],
                "pip": ["install --global"],  # pip also in parent
            },
        }

        (tmp_path / "dict-merge-test.toml").write_bytes(_make_profile_toml(child_data))

        os.environ["LASSO_PROFILE_DIR"] = str(tmp_path)
        try:
            resolved = resolve_profile("dict-merge-test", working_dir="/tmp/work")
        finally:
            del os.environ["LASSO_PROFILE_DIR"]

        # npm blocked_args from child
        assert "npm" in resolved.commands.blocked_args
        assert "publish" in resolved.commands.blocked_args["npm"]

        # pip should have both parent and child entries (lists are merged)
        assert "pip" in resolved.commands.blocked_args
        assert "install --global" in resolved.commands.blocked_args["pip"]
        assert "install --user" in resolved.commands.blocked_args["pip"]  # from offline

    def test_extra_env_deep_merge(self, tmp_path):
        """extra_env dicts are merged, child values win."""
        # Create a base profile with extra_env
        base_data = _minimal_data("base-env", extra_env={"FOO": "base", "BAR": "base"})
        (tmp_path / "base-env.toml").write_bytes(_make_profile_toml(base_data))

        child_data = _minimal_data(
            "child-env",
            extends="base-env",
            extra_env={"FOO": "child", "BAZ": "child"},
        )
        (tmp_path / "child-env.toml").write_bytes(_make_profile_toml(child_data))

        os.environ["LASSO_PROFILE_DIR"] = str(tmp_path)
        try:
            resolved = resolve_profile("child-env", working_dir="/tmp/work")
        finally:
            del os.environ["LASSO_PROFILE_DIR"]

        assert resolved.extra_env["FOO"] == "child"   # child wins
        assert resolved.extra_env["BAR"] == "base"     # from parent
        assert resolved.extra_env["BAZ"] == "child"    # from child


class TestNameNotInherited:
    """The name field should always come from the child profile."""

    def test_name_not_inherited(self, tmp_path):
        """Child name must never be overwritten by parent name."""
        child_data = _minimal_data(
            "my-team-profile",
            extends="standard",
        )
        (tmp_path / "my-team-profile.toml").write_bytes(_make_profile_toml(child_data))

        os.environ["LASSO_PROFILE_DIR"] = str(tmp_path)
        try:
            resolved = resolve_profile("my-team-profile", working_dir="/tmp/work")
        finally:
            del os.environ["LASSO_PROFILE_DIR"]

        assert resolved.name == "my-team-profile"
        assert resolved.name != "standard"


class TestDeepMergeFunction:
    """Unit tests for the _deep_merge helper."""

    def test_scalars_override(self):
        assert _deep_merge({"a": 1}, {"a": 2}) == {"a": 2}

    def test_new_keys_added(self):
        assert _deep_merge({"a": 1}, {"b": 2}) == {"a": 1, "b": 2}

    def test_nested_dicts_merged(self):
        result = _deep_merge(
            {"d": {"x": 1, "y": 2}},
            {"d": {"y": 3, "z": 4}},
        )
        assert result == {"d": {"x": 1, "y": 3, "z": 4}}

    def test_lists_appended_deduped(self):
        result = _deep_merge(
            {"items": [1, 2, 3]},
            {"items": [3, 4, 5]},
        )
        assert result == {"items": [1, 2, 3, 4, 5]}

    def test_empty_base(self):
        assert _deep_merge({}, {"a": 1}) == {"a": 1}

    def test_empty_override(self):
        assert _deep_merge({"a": 1}, {}) == {"a": 1}


class TestExtractOverrides:
    """Unit tests for the _extract_overrides helper."""

    def test_identical_returns_empty(self):
        d = {"a": 1, "b": "hello"}
        assert _extract_overrides(d, d) == {}

    def test_scalar_difference(self):
        assert _extract_overrides({"a": 2}, {"a": 1}) == {"a": 2}

    def test_nested_dict_difference(self):
        child = {"d": {"x": 1, "y": 99}}
        default = {"d": {"x": 1, "y": 2}}
        assert _extract_overrides(child, default) == {"d": {"y": 99}}

    def test_nested_dict_identical(self):
        d = {"d": {"x": 1, "y": 2}}
        assert _extract_overrides(d, d) == {}

    def test_new_key_included(self):
        child = {"a": 1, "b": 2}
        default = {"a": 1}
        assert _extract_overrides(child, default) == {"b": 2}


class TestChildDoesNotOverrideParentDefaults:
    """Bug #5 regression: child defaults must not clobber parent values."""

    def test_child_only_sets_name_inherits_parent_memory(self, tmp_path):
        """A child that only sets name + extends should inherit ALL parent settings."""
        # Create a custom parent with non-default memory (default is 4096).
        # Use a non-builtin name so _load_profile_by_name finds it on disk.
        parent_data = _minimal_data(
            "custom-parent",
            working_dir=str(tmp_path),
        )
        parent_data["resources"] = {"max_memory_mb": 16384}
        (tmp_path / "custom-parent.toml").write_bytes(_make_profile_toml(parent_data))

        # Child TOML only sets extends and name — nothing else
        child_toml = tmp_path / "child-inherit.toml"
        child_toml.write_bytes(
            _make_profile_toml({
                "name": "child-inherit",
                "extends": "custom-parent",
                "filesystem": {"working_dir": str(tmp_path)},
            })
        )

        os.environ["LASSO_PROFILE_DIR"] = str(tmp_path)
        try:
            resolved = resolve_profile("child-inherit", working_dir=str(tmp_path))
        finally:
            del os.environ["LASSO_PROFILE_DIR"]

        # The parent set 16384 — the child did NOT override it, so it must
        # still be 16384, NOT the Pydantic default of 4096.
        assert resolved.resources.max_memory_mb == 16384
        assert resolved.name == "child-inherit"

    def test_child_explicit_override_still_wins(self, tmp_path):
        """When the child explicitly sets a value, it should override the parent."""
        parent_data = _minimal_data(
            "custom-parent2",
            working_dir=str(tmp_path),
        )
        parent_data["resources"] = {"max_memory_mb": 16384}
        (tmp_path / "custom-parent2.toml").write_bytes(_make_profile_toml(parent_data))

        child_toml = tmp_path / "child-override.toml"
        child_toml.write_bytes(
            _make_profile_toml({
                "name": "child-override",
                "extends": "custom-parent2",
                "filesystem": {"working_dir": str(tmp_path)},
                "resources": {"max_memory_mb": 2048},
            })
        )

        os.environ["LASSO_PROFILE_DIR"] = str(tmp_path)
        try:
            resolved = resolve_profile("child-override", working_dir=str(tmp_path))
        finally:
            del os.environ["LASSO_PROFILE_DIR"]

        # Child explicitly set 2048, so it must win
        assert resolved.resources.max_memory_mb == 2048
