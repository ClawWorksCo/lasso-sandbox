"""Tests for operational configuration loading, merging, and env var overrides."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lasso.cli.main import app
from lasso.config.operational import (
    LassoConfig,
    _apply_env_overrides,
    _deep_merge,
    load_config,
)

runner = CliRunner()


# -----------------------------------------------------------------------
# Deep merge
# -----------------------------------------------------------------------


class TestDeepMerge:
    def test_empty_override(self):
        base = {"a": 1, "b": {"c": 2}}
        assert _deep_merge(base, {}) == base

    def test_empty_base(self):
        override = {"x": 10}
        assert _deep_merge({}, override) == {"x": 10}

    def test_flat_override(self):
        assert _deep_merge({"a": 1}, {"a": 2}) == {"a": 2}

    def test_nested_merge(self):
        base = {"section": {"a": 1, "b": 2}}
        override = {"section": {"b": 99, "c": 3}}
        result = _deep_merge(base, override)
        assert result == {"section": {"a": 1, "b": 99, "c": 3}}

    def test_override_adds_new_keys(self):
        result = _deep_merge({"a": 1}, {"a": 1, "b": 2})
        assert result == {"a": 1, "b": 2}

    def test_override_replaces_dict_with_scalar(self):
        result = _deep_merge({"a": {"nested": 1}}, {"a": "flat"})
        assert result == {"a": "flat"}

    def test_base_not_mutated(self):
        base = {"a": {"b": 1}}
        _deep_merge(base, {"a": {"b": 2}})
        assert base == {"a": {"b": 1}}


# -----------------------------------------------------------------------
# Default config
# -----------------------------------------------------------------------


class TestDefaultConfig:
    def test_loads_without_files(self, tmp_path):
        """Loading config from a dir with no config files returns defaults."""
        config = load_config(working_dir=str(tmp_path))
        assert config.defaults.isolation == "container"
        assert config.defaults.profile == "standard"
        assert config.defaults.agent is None
        assert config.dashboard.port == 8080
        assert config.dashboard.host == "127.0.0.1"
        assert config.dashboard.public is False
        assert config.audit.default_log_dir == "./audit"
        assert config.containers.base_image == "python:3.12-slim"

    def test_model_roundtrip(self):
        """Config can be serialized and deserialized."""
        config = LassoConfig()
        data = config.model_dump()
        restored = LassoConfig(**data)
        assert restored == config


# -----------------------------------------------------------------------
# User config
# -----------------------------------------------------------------------


class TestUserConfig:
    def test_user_config_loaded(self, tmp_path, monkeypatch):
        """~/.lasso/config.toml values are loaded."""
        user_lasso = tmp_path / ".lasso"
        user_lasso.mkdir()
        (user_lasso / "config.toml").write_text(
            '[dashboard]\nport = 9999\n[defaults]\nprofile = "strict"\n'
        )
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr("lasso.config.operational.get_lasso_dir", lambda: tmp_path / ".lasso")

        config = load_config(working_dir=str(tmp_path / "nonexistent"))
        assert config.dashboard.port == 9999
        assert config.defaults.profile == "strict"
        # Unset values stay at defaults
        assert config.dashboard.host == "127.0.0.1"

    def test_malformed_user_config_ignored(self, tmp_path, monkeypatch):
        """A broken user config file logs a warning but doesn't crash."""
        user_lasso = tmp_path / ".lasso"
        user_lasso.mkdir()
        (user_lasso / "config.toml").write_text("{{invalid toml!!")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr("lasso.config.operational.get_lasso_dir", lambda: tmp_path / ".lasso")

        config = load_config(working_dir=str(tmp_path / "nonexistent"))
        assert config == LassoConfig()


# -----------------------------------------------------------------------
# Project config
# -----------------------------------------------------------------------


class TestProjectConfig:
    def test_project_config_loaded(self, tmp_path, monkeypatch):
        """Project .lasso/config.toml is loaded."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "fakehome")
        monkeypatch.setattr("lasso.config.operational.get_lasso_dir", lambda: tmp_path / "fakehome" / ".lasso")

        project_lasso = tmp_path / ".lasso"
        project_lasso.mkdir()
        (project_lasso / "config.toml").write_text(
            '[dashboard]\nport = 9876\n'
        )

        config = load_config(working_dir=str(tmp_path))
        assert config.dashboard.port == 9876

    def test_project_overrides_user(self, tmp_path, monkeypatch):
        """Project config takes precedence over user config."""
        # User config
        user_home = tmp_path / "home"
        user_lasso = user_home / ".lasso"
        user_lasso.mkdir(parents=True)
        (user_lasso / "config.toml").write_text('[dashboard]\nport = 1111\nhost = "10.0.0.1"\n')
        monkeypatch.setattr(Path, "home", lambda: user_home)
        monkeypatch.setattr("lasso.config.operational.get_lasso_dir", lambda: user_lasso)

        # Project config
        project_dir = tmp_path / "project"
        project_lasso = project_dir / ".lasso"
        project_lasso.mkdir(parents=True)
        (project_lasso / "config.toml").write_text("[dashboard]\nport = 2222\n")

        config = load_config(working_dir=str(project_dir))
        assert config.dashboard.port == 2222  # project wins
        assert config.dashboard.host == "10.0.0.1"  # user value preserved

    def test_explicit_config_path(self, tmp_path, monkeypatch):
        """config_path argument is used instead of working_dir lookup."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "fakehome")
        monkeypatch.setattr("lasso.config.operational.get_lasso_dir", lambda: tmp_path / "fakehome" / ".lasso")

        custom = tmp_path / "custom-config.toml"
        custom.write_text('[dashboard]\nport = 5050\n')

        config = load_config(config_path=str(custom))
        assert config.dashboard.port == 5050


# -----------------------------------------------------------------------
# LASSO_CONFIG env var
# -----------------------------------------------------------------------


class TestLassoConfigEnv:
    def test_lasso_config_env_var(self, tmp_path, monkeypatch):
        """LASSO_CONFIG env var loads from a custom path."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "fakehome")
        monkeypatch.setattr("lasso.config.operational.get_lasso_dir", lambda: tmp_path / "fakehome" / ".lasso")

        env_config = tmp_path / "team.toml"
        env_config.write_text('[audit]\ndefault_log_dir = "/var/log/lasso"\n')
        monkeypatch.setenv("LASSO_CONFIG", str(env_config))

        config = load_config(working_dir=str(tmp_path))
        assert config.audit.default_log_dir == "/var/log/lasso"

    def test_lasso_config_overrides_project(self, tmp_path, monkeypatch):
        """LASSO_CONFIG has higher precedence than project config."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "fakehome")
        monkeypatch.setattr("lasso.config.operational.get_lasso_dir", lambda: tmp_path / "fakehome" / ".lasso")

        # Project config
        project_lasso = tmp_path / ".lasso"
        project_lasso.mkdir()
        (project_lasso / "config.toml").write_text("[dashboard]\nport = 200\n")

        # Env config
        env_config = tmp_path / "override.toml"
        env_config.write_text("[dashboard]\nport = 10\n")
        monkeypatch.setenv("LASSO_CONFIG", str(env_config))

        config = load_config(working_dir=str(tmp_path))
        assert config.dashboard.port == 10

    def test_nonexistent_lasso_config_ignored(self, tmp_path, monkeypatch):
        """LASSO_CONFIG pointing to a missing file is silently ignored."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "fakehome")
        monkeypatch.setattr("lasso.config.operational.get_lasso_dir", lambda: tmp_path / "fakehome" / ".lasso")
        monkeypatch.setenv("LASSO_CONFIG", "/tmp/does-not-exist-lasso.toml")

        config = load_config(working_dir=str(tmp_path))
        assert config == LassoConfig()


# -----------------------------------------------------------------------
# Environment variable overrides
# -----------------------------------------------------------------------


class TestEnvVarOverrides:
    def test_string_override(self, monkeypatch):
        monkeypatch.setenv("LASSO_DEFAULT_PROFILE", "strict")
        config = _apply_env_overrides(LassoConfig())
        assert config.defaults.profile == "strict"

    def test_int_override(self, monkeypatch):
        monkeypatch.setenv("LASSO_DASHBOARD_PORT", "3000")
        config = _apply_env_overrides(LassoConfig())
        assert config.dashboard.port == 3000

    def test_bool_true_variants(self, monkeypatch):
        for val in ("true", "True", "1", "yes"):
            monkeypatch.setenv("LASSO_DASHBOARD_PUBLIC", val)
            config = _apply_env_overrides(LassoConfig())
            assert config.dashboard.public is True, f"Failed for {val!r}"

    def test_bool_false_variants(self, monkeypatch):
        for val in ("false", "False", "0", "no", "anything"):
            monkeypatch.setenv("LASSO_DASHBOARD_PUBLIC", val)
            config = _apply_env_overrides(LassoConfig())
            assert config.dashboard.public is False, f"Failed for {val!r}"

    def test_invalid_int_ignored(self, monkeypatch):
        """Non-numeric value for an int field is ignored (keeps default)."""
        monkeypatch.setenv("LASSO_DASHBOARD_PORT", "not-a-number")
        config = _apply_env_overrides(LassoConfig())
        assert config.dashboard.port == 8080  # default preserved

    def test_env_overrides_file_config(self, tmp_path, monkeypatch):
        """Env vars beat config files."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "fakehome")
        monkeypatch.setattr("lasso.config.operational.get_lasso_dir", lambda: tmp_path / "fakehome" / ".lasso")

        project_lasso = tmp_path / ".lasso"
        project_lasso.mkdir()
        (project_lasso / "config.toml").write_text("[dashboard]\nport = 5555\n")
        monkeypatch.setenv("LASSO_DASHBOARD_PORT", "6666")

        config = load_config(working_dir=str(tmp_path))
        assert config.dashboard.port == 6666

    def test_agent_override(self, monkeypatch):
        monkeypatch.setenv("LASSO_DEFAULT_AGENT", "claude-code")
        config = _apply_env_overrides(LassoConfig())
        assert config.defaults.agent == "claude-code"

    def test_base_image_override(self, monkeypatch):
        monkeypatch.setenv("LASSO_BASE_IMAGE", "node:20-slim")
        config = _apply_env_overrides(LassoConfig())
        assert config.containers.base_image == "node:20-slim"

    def test_multiple_overrides(self, monkeypatch):
        monkeypatch.setenv("LASSO_DASHBOARD_PORT", "4000")
        monkeypatch.setenv("LASSO_DASHBOARD_HOST", "0.0.0.0")
        monkeypatch.setenv("LASSO_DASHBOARD_PUBLIC", "true")
        config = _apply_env_overrides(LassoConfig())
        assert config.dashboard.port == 4000
        assert config.dashboard.host == "0.0.0.0"
        assert config.dashboard.public is True


# -----------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------


class TestValidation:
    def test_invalid_isolation_rejected(self):
        with pytest.raises(Exception):
            LassoConfig(defaults={"isolation": "invalid"})

    def test_port_out_of_range(self):
        with pytest.raises(Exception):
            LassoConfig(dashboard={"port": 99999})

    def test_port_zero_rejected(self):
        with pytest.raises(Exception):
            LassoConfig(dashboard={"port": 0})


# -----------------------------------------------------------------------
# CLI commands
# -----------------------------------------------------------------------


class TestConfigCLI:
    def test_config_show(self, tmp_path):
        result = runner.invoke(app, ["config", "show", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "standard" in result.output

    def test_config_show_json(self, tmp_path):
        result = runner.invoke(app, ["config", "show", "--json", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["defaults"]["profile"] == "standard"
        assert data["dashboard"]["port"] == 8080

    def test_config_validate_no_files(self, tmp_path):
        result = runner.invoke(app, ["config", "validate", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "No config" in result.output

    def test_config_validate_valid(self, tmp_path):
        lasso_dir = tmp_path / ".lasso"
        lasso_dir.mkdir()
        (lasso_dir / "config.toml").write_text('[dashboard]\nport = 9090\n')
        result = runner.invoke(app, ["config", "validate", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "valid" in result.output.lower()

    def test_config_validate_invalid(self, tmp_path):
        lasso_dir = tmp_path / ".lasso"
        lasso_dir.mkdir()
        (lasso_dir / "config.toml").write_text("{{broken toml!!")
        result = runner.invoke(app, ["config", "validate", "--dir", str(tmp_path)])
        assert result.exit_code == 1
        assert "error" in result.output.lower()

    def test_config_init(self, tmp_path):
        result = runner.invoke(app, ["config", "init", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / ".lasso" / "config.toml").exists()

    def test_config_init_no_overwrite(self, tmp_path):
        lasso_dir = tmp_path / ".lasso"
        lasso_dir.mkdir()
        (lasso_dir / "config.toml").write_text("existing")
        result = runner.invoke(app, ["config", "init", "--dir", str(tmp_path)])
        assert result.exit_code == 1
        assert "already exists" in result.output.lower()

    def test_config_init_force(self, tmp_path):
        lasso_dir = tmp_path / ".lasso"
        lasso_dir.mkdir()
        (lasso_dir / "config.toml").write_text("existing")
        result = runner.invoke(app, ["config", "init", "--dir", str(tmp_path), "--force"])
        assert result.exit_code == 0

    def test_config_validate_json(self, tmp_path):
        result = runner.invoke(app, ["config", "validate", "--json", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "valid" in data
        assert "errors" in data
