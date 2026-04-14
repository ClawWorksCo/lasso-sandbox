"""Property-based tests for the CommandGate using Hypothesis.

These tests verify invariants that must hold for ALL possible inputs,
not just hand-picked examples.  They complement the example-based tests
in test_commands.py and test_command_security.py.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from lasso.config.schema import CommandConfig, CommandMode
from lasso.core.commands import CommandGate, CommandVerdict

# ---------------------------------------------------------------------------
# Gate constructors (module-level to avoid Hypothesis fixture health check)
# ---------------------------------------------------------------------------

def _make_permissive_gate() -> CommandGate:
    """A blacklist-mode gate that allows most commands through.

    Uses blacklist mode so that arbitrary generated command names are not
    rejected by a whitelist check -- we want to exercise the deeper
    validation stages (null bytes, control chars, path traversal, etc.).
    """
    config = CommandConfig(
        mode=CommandMode.BLACKLIST,
        blacklist=["rm", "dd", "mkfs"],
        allow_shell_operators=False,
    )
    return CommandGate(config)


def _make_whitelist_gate() -> CommandGate:
    """A whitelist gate with a broad set of allowed commands."""
    config = CommandConfig(
        mode=CommandMode.WHITELIST,
        whitelist=[
            "ls", "cat", "python3", "git", "grep", "find", "echo",
            "head", "tail", "wc", "sort", "diff", "mkdir", "cp",
            "mv", "touch", "printf", "test",
        ],
        allow_shell_operators=False,
    )
    return CommandGate(config)


# Reusable gate instances (CommandGate.check is stateless)
PERMISSIVE = _make_permissive_gate()
WHITELIST = _make_whitelist_gate()


# ---------------------------------------------------------------------------
# Property: null bytes are ALWAYS rejected
# ---------------------------------------------------------------------------

class TestNullByteRejection:
    """Null bytes in any part of the command must be stripped/rejected."""

    @given(prefix=st.text(), suffix=st.text())
    @settings(max_examples=200)
    def test_null_byte_never_passes_through(self, prefix, suffix):
        """A command containing a null byte must never produce a verdict
        whose .command field still contains a null byte."""
        raw = prefix + "\x00" + suffix
        verdict = PERMISSIVE.check(raw)
        # The gate strips null bytes before processing, so the resulting
        # command field must never contain one.
        assert "\x00" not in verdict.command
        for arg in verdict.args:
            assert "\x00" not in arg


# ---------------------------------------------------------------------------
# Property: command substitution is ALWAYS rejected
# ---------------------------------------------------------------------------

class TestCommandSubstitutionRejection:
    """$() and backtick command substitution must always be blocked."""

    @given(prefix=st.text(min_size=0, max_size=100),
           inner=st.text(min_size=0, max_size=50),
           suffix=st.text(min_size=0, max_size=100))
    @settings(max_examples=200)
    def test_dollar_paren_always_blocked(self, prefix, inner, suffix):
        raw = prefix + "$(" + inner + ")" + suffix
        verdict = PERMISSIVE.check(raw)
        assert verdict.blocked

    @given(prefix=st.text(min_size=0, max_size=100),
           inner=st.text(min_size=0, max_size=50),
           suffix=st.text(min_size=0, max_size=100))
    @settings(max_examples=200)
    def test_backtick_always_blocked(self, prefix, inner, suffix):
        raw = prefix + "`" + inner + "`" + suffix
        verdict = PERMISSIVE.check(raw)
        assert verdict.blocked


# ---------------------------------------------------------------------------
# Property: path traversal is ALWAYS caught
# ---------------------------------------------------------------------------

class TestPathTraversalDetection:
    """../ in arguments must always be caught by the gate."""

    @given(cmd=st.sampled_from(["ls", "cat", "head", "echo"]),
           prefix=st.text(alphabet=st.characters(whitelist_categories=("L", "N"),
                                                  whitelist_characters="_-"),
                          min_size=0, max_size=20),
           suffix=st.text(alphabet=st.characters(whitelist_categories=("L", "N"),
                                                  whitelist_characters="_-/"),
                          min_size=0, max_size=20))
    @settings(max_examples=200)
    def test_dot_dot_slash_in_arg_always_blocked(self, cmd, prefix, suffix):
        """Any argument containing '../' must be blocked."""
        raw = f"{cmd} {prefix}../{suffix}"
        verdict = WHITELIST.check(raw)
        assert verdict.blocked, f"Expected blocked for: {raw!r}"


# ---------------------------------------------------------------------------
# Property: no command ever causes an unhandled exception
# ---------------------------------------------------------------------------

class TestNoCrashOnAnyInput:
    """The gate must never raise an exception -- it returns a verdict."""

    @given(raw=st.text(min_size=0, max_size=500))
    @settings(max_examples=200)
    def test_arbitrary_string_no_crash(self, raw):
        """check() must return a CommandVerdict for any input string."""
        verdict = PERMISSIVE.check(raw)
        assert isinstance(verdict, CommandVerdict)

    @given(parts=st.lists(st.text(min_size=0, max_size=100), min_size=0, max_size=10))
    @settings(max_examples=200)
    def test_joined_list_no_crash(self, parts):
        """Joining arbitrary text segments must not crash the gate."""
        raw = " ".join(parts)
        verdict = PERMISSIVE.check(raw)
        assert isinstance(verdict, CommandVerdict)

    @given(raw=st.text(min_size=0, max_size=500))
    @settings(max_examples=200)
    def test_pipeline_check_no_crash(self, raw):
        """check_pipeline() must return a list of verdicts for any input."""
        verdicts = PERMISSIVE.check_pipeline(raw)
        assert isinstance(verdicts, list)
        for v in verdicts:
            assert isinstance(v, CommandVerdict)


# ---------------------------------------------------------------------------
# Property: gate never modifies the input (allow or block, no transform)
# ---------------------------------------------------------------------------

class TestGateDoesNotTransform:
    """The gate must either allow or block -- it must not silently rewrite
    the command text that gets executed.  The verdict's command + args must
    correspond to what was parsed from the original input."""

    @given(cmd=st.sampled_from(["ls", "cat", "echo", "grep", "head"]),
           args=st.lists(
               st.text(alphabet=st.characters(whitelist_categories=("L", "N"),
                                               whitelist_characters="_-."),
                       min_size=1, max_size=30),
               min_size=0, max_size=5,
           ))
    @settings(max_examples=200)
    def test_verdict_preserves_parsed_command(self, cmd, args):
        """For clean inputs, the verdict command must equal the base command name."""
        raw = " ".join([cmd] + args)
        verdict = WHITELIST.check(raw)
        # Whether allowed or blocked, the command name should be what was parsed
        assert verdict.command == cmd


# ---------------------------------------------------------------------------
# Property: empty and very long strings handled gracefully
# ---------------------------------------------------------------------------

class TestEdgeCaseLengths:
    """Empty strings and very long strings must not crash the gate."""

    def test_empty_string(self):
        verdict = PERMISSIVE.check("")
        assert isinstance(verdict, CommandVerdict)
        assert verdict.blocked

    def test_whitespace_only(self):
        verdict = PERMISSIVE.check("   \t  ")
        assert isinstance(verdict, CommandVerdict)
        assert verdict.blocked

    @given(length=st.integers(min_value=1000, max_value=10000))
    @settings(max_examples=20)
    def test_very_long_command(self, length):
        raw = "a" * length
        verdict = PERMISSIVE.check(raw)
        assert isinstance(verdict, CommandVerdict)

    @given(length=st.integers(min_value=1000, max_value=10000))
    @settings(max_examples=20)
    def test_very_long_with_spaces(self, length):
        raw = "ls " + "x" * length
        verdict = PERMISSIVE.check(raw)
        assert isinstance(verdict, CommandVerdict)
