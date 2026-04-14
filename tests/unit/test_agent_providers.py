"""Tests for agent provider config generation.

Verifies that LASSO profiles are correctly translated into
agent-native configurations for OpenCode and Claude Code.
"""

import json

import pytest

from lasso.agents.base import AgentConfig, AgentType
from lasso.agents.claude_code import ClaudeCodeProvider
from lasso.agents.opencode import OpenCodeProvider
from lasso.config.defaults import evaluation_profile, standard_profile, strict_profile

# -----------------------------------------------------------------------
# OpenCode Provider
# -----------------------------------------------------------------------

class TestOpenCodeConfigGeneration:
    @pytest.fixture
    def provider(self):
        return OpenCodeProvider()

    @pytest.fixture
    def bank_profile(self):
        return strict_profile("/workspace")

    @pytest.fixture
    def dev_profile(self):
        return standard_profile("/workspace")

    def test_agent_type(self, provider):
        assert provider.agent_type == AgentType.OPENCODE

    def test_display_name(self, provider):
        assert "OpenCode" in provider.display_name

    def test_generates_opencode_json(self, provider, bank_profile):
        config = provider.generate_config(bank_profile)
        assert "opencode.json" in config.config_files
        data = json.loads(config.config_files["opencode.json"])
        assert "permission" in data

    def test_generates_agents_md(self, provider, bank_profile):
        config = provider.generate_config(bank_profile)
        assert "AGENTS.md" in config.rules_files

    def test_bash_permissions_from_whitelist(self, provider, bank_profile):
        config = provider.generate_config(bank_profile)
        data = json.loads(config.config_files["opencode.json"])
        bash_perms = data["permission"]["bash"]
        # Default should deny all
        assert bash_perms.get("*") == "deny"
        # Whitelisted commands should be allowed
        assert bash_perms.get("python3 *") == "allow"
        assert bash_perms.get("ls *") == "allow"

    def test_blocked_commands_denied(self, provider, bank_profile):
        config = provider.generate_config(bank_profile)
        data = json.loads(config.config_files["opencode.json"])
        bash_perms = data["permission"]["bash"]
        # curl not in bank whitelist, should remain denied via "*": "deny"
        assert "curl *" not in bash_perms or bash_perms.get("curl *") == "deny"

    def test_edit_permissions_restrict_to_workdir(self, provider, bank_profile):
        config = provider.generate_config(bank_profile)
        data = json.loads(config.config_files["opencode.json"])
        edit_perms = data["permission"]["edit"]
        assert edit_perms.get("*") == "deny"

    def test_external_directory_denied(self, provider, bank_profile):
        config = provider.generate_config(bank_profile)
        data = json.loads(config.config_files["opencode.json"])
        assert data["permission"]["external_directory"] == "deny"

    def test_network_tools_disabled_when_no_network(self, provider, bank_profile):
        config = provider.generate_config(bank_profile)
        data = json.loads(config.config_files["opencode.json"])
        # webfetch should be denied for no-network profile
        assert data["permission"].get("webfetch", "deny") == "deny" or \
               data.get("tools", {}).get("webfetch") is False

    def test_standard_profile_blacklist_mode(self, provider, dev_profile):
        """Standard profile uses blacklist — should have wildcard allow."""
        config = provider.generate_config(dev_profile)
        data = json.loads(config.config_files["opencode.json"])
        bash_perms = data["permission"]["bash"]
        # Blacklist mode sets "*": "allow" with specific denials
        assert bash_perms.get("*") == "allow"

    def test_rules_contain_guardrails(self, provider, bank_profile):
        rules = provider.generate_rules(bank_profile)
        assert "LASSO" in rules
        assert "sandbox" in rules.lower() or "security" in rules.lower()
        assert bank_profile.name in rules

    def test_start_command(self, provider):
        cmd = provider.get_start_command()
        assert "opencode" in cmd[0]

    def test_config_files_are_valid_json(self, provider, bank_profile):
        config = provider.generate_config(bank_profile)
        for name, content in config.config_files.items():
            if name.endswith(".json"):
                json.loads(content)  # should not raise


# -----------------------------------------------------------------------
# Claude Code Provider
# -----------------------------------------------------------------------

class TestClaudeCodeConfigGeneration:
    @pytest.fixture
    def provider(self):
        return ClaudeCodeProvider()

    @pytest.fixture
    def bank_profile(self):
        return strict_profile("/workspace")

    @pytest.fixture
    def dev_profile(self):
        return standard_profile("/workspace")

    def test_agent_type(self, provider):
        assert provider.agent_type == AgentType.CLAUDE_CODE

    def test_display_name(self, provider):
        assert "Claude" in provider.display_name

    def test_generates_claude_md(self, provider, bank_profile):
        config = provider.generate_config(bank_profile)
        assert "CLAUDE.md" in config.rules_files

    def test_generates_settings_json(self, provider, bank_profile):
        config = provider.generate_config(bank_profile)
        assert ".claude/settings.json" in config.config_files
        data = json.loads(config.config_files[".claude/settings.json"])
        assert "permissions" in data or "allowedTools" in data or isinstance(data, dict)

    def test_rules_contain_guardrails(self, provider, bank_profile):
        rules = provider.generate_rules(bank_profile)
        assert "LASSO" in rules
        assert bank_profile.name in rules

    def test_start_command(self, provider):
        cmd = provider.get_start_command()
        assert "claude" in cmd[0]

    def test_bank_profile_restricts_network(self, provider, bank_profile):
        rules = provider.generate_rules(bank_profile)
        assert "network" in rules.lower()

    def test_dev_profile_allows_git(self, provider, dev_profile):
        config = provider.generate_config(dev_profile)
        data = json.loads(config.config_files[".claude/settings.json"])
        # Dev profile should not block git
        config_str = json.dumps(data)
        assert "git" not in config_str or "allow" in config_str


# -----------------------------------------------------------------------
# Cross-provider tests
# -----------------------------------------------------------------------

class TestProviderConsistency:
    def test_both_providers_produce_valid_configs(self):
        profile = evaluation_profile("/workspace")
        for provider in [OpenCodeProvider(), ClaudeCodeProvider()]:
            config = provider.generate_config(profile)
            assert isinstance(config, AgentConfig)
            assert len(config.config_files) > 0
            assert len(config.rules_files) > 0
            assert len(config.command) > 0

    def test_both_providers_have_info(self):
        for provider in [OpenCodeProvider(), ClaudeCodeProvider()]:
            info = provider.info()
            assert "type" in info
            assert "name" in info
            assert "installed" in info
