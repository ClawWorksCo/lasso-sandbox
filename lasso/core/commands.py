"""Command gate -- validates and filters every command before execution.

Implements whitelist/blacklist filtering, argument pattern blocking,
shell operator restrictions, and command rewriting.

Security hardening covers:
- Null byte stripping from all input
- Control character rejection (newlines, tabs, etc.)
- URL-encoded path traversal detection (%2e%2e, %2f, etc.)
- Symlink resolution for path arguments
- Dangerous argument patterns for common tools (find -exec, xargs, etc.)
- Wildcard/glob pattern abuse detection
"""

from __future__ import annotations

import ntpath
import os
import platform as _platform
import re
import shlex
from dataclasses import dataclass
from urllib.parse import unquote

from lasso.config.schema import CommandConfig, CommandMode, ProfileMode

# Shell operators that can be used for escapes
SHELL_OPERATORS = re.compile(r"[|;&`$(){}<>]|>>|<<|\$\(")

# Patterns that look like path traversal (applied after URL decoding)
PATH_TRAVERSAL = re.compile(r"\.\./|/\.\.")

# Control characters that must never appear in command strings.
# Covers null bytes, newlines, carriage returns, vertical tabs, form feeds,
# and escape sequences.  Tabs are intentionally excluded because they are
# harmless whitespace used in legitimate shell arguments.
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0a-\x0d\x0e-\x1f\x7f]")

# URL-encoded path traversal sequences (case-insensitive).
# Only triggers when at least one component is percent-encoded, to avoid
# false positives on plain "../" which is handled by PATH_TRAVERSAL.
# Catches: %2e%2e%2f, %2e%2e/, ..%2f, %2e%2e%5c, ..%5c, /%2e%2e, %2f..
URL_ENCODED_TRAVERSAL = re.compile(
    r"(?:%2e\.|\.\%2e|%2e%2e)(?:%2f|%5c|[/\\])"  # dot-dot with encoded dot + sep
    r"|(?:%2f|%5c)\.{2}(?=[/\\%]|$)"               # encoded sep + literal dots
    r"|\.{2}(?:%2f|%5c)",                           # literal dots + encoded sep
    re.IGNORECASE,
)

# Unicode characters that look like dots or slashes but aren't ASCII.
# These can bypass ASCII-only path traversal regex checks.
UNICODE_DOT_LIKE = re.compile(
    r"[\u2024\u2025\u2026"     # one/two/three dot leaders
    r"\uFE52\uFF0E"            # small/fullwidth full stop
    r"\u00B7\u0387"            # middle dot, greek ano teleia
    r"\u2219\u22C5]"           # bullet operator, dot operator
)

# Dangerous argument patterns per command.  These are arguments that change
# the semantics of otherwise-safe commands in ways that allow code execution,
# arbitrary file access, or sandbox escape.  Checked *in addition to* the
# user-configured blocked_args.
#
# Pattern prefixes:
#   "="  — exact match only (arg must equal the pattern text after "=")
#   (no prefix) — substring match (pattern appears anywhere in the arg)
#
# Exact-match ("=") is essential for single-character patterns like sed's "e"
# which would otherwise false-positive on every argument containing the letter.
DANGEROUS_ARGS: dict[str, list[str]] = {
    "find": ["-exec", "-execdir", "-ok", "-okdir", "-delete", "-fls", "-fprint"],
    "grep": ["--include", "--exclude-dir"],
    "xargs": ["-I", "--replace", "-i", "--max-args"],
    "env": ["--", "-i", "-S"],
    "awk": ["-f", "system(", "getline"],
    "sed": ["-e", "-i", "=e", "=w"],
    "tar": ["--to-command", "--checkpoint-action", "--use-compress-program"],
    "zip": ["-T", "--unzip-command"],
    "rsync": ["-e", "--rsh"],
    "nice": [],  # nice can wrap arbitrary commands
    "nohup": [],
    "timeout": [],
    "strace": [],
    "ltrace": [],
    "gdb": [],
    "python3": ["-c", "-m", "=--", "=-"],
    "python": ["-c", "-m", "=--", "=-"],
    "perl": ["-e", "--eval"],
    "ruby": ["-e", "--eval"],
    "node": ["-e", "--eval", "--input-type"],
    "lua": ["-e"],
    "tee": [],  # tee can write to arbitrary files
    "install": [],
    "chmod": [],
    "chown": [],
    "chgrp": [],
    "ln": ["-s", "--symbolic"],  # symlink creation
    "curl": ["-o", "--output", "-O", "--remote-name"],
    "wget": ["-O", "--output-document"],
    # --- Database client tools: always blocked to prevent direct DB access ---
    "sqlcmd": [],       # MSSQL/SSMS command-line client
    "bcp": [],          # MSSQL bulk copy
    "osql": [],         # Legacy MSSQL client
    "isql": [],         # ODBC interactive SQL
    "sqlplus": [],      # Oracle SQL*Plus
    "mysql": [],        # MySQL client
    "psql": [],         # PostgreSQL client
    "mongo": [],        # MongoDB shell
    "mongosh": [],      # MongoDB shell (new)
    "redis-cli": [],    # Redis client
    "cqlsh": [],        # Cassandra CQL shell
    "clickhouse-client": [],  # ClickHouse client
}

# Commands in DANGEROUS_ARGS with an empty pattern list are blocked entirely
# when they appear as arguments to themselves or as the primary command
# (depending on context).  An empty list means "the command itself is
# dangerous if whitelisted — block any invocation that passes through the
# dangerous-args check".

# Common short-to-long flag mappings for blocked_args expansion.
# When a user configures blocked_args with long flags (e.g. "--force"),
# the gate also blocks the corresponding short flag (e.g. "-f").
_SHORT_FLAG_MAP: dict[str, dict[str, str]] = {
    "git": {"-f": "--force", "-u": "--set-upstream"},
    "pip": {"-e": "--editable", "--user": "--user"},
    "curl": {"-o": "--output", "-O": "--remote-name"},
}


@dataclass
class CommandVerdict:
    """Result of command validation."""
    allowed: bool
    command: str
    args: list[str]
    reason: str = ""
    rewritten: bool = False

    @property
    def blocked(self) -> bool:
        return not self.allowed


class CommandGate:
    """Validates commands against the configured policy."""

    def __init__(self, config: CommandConfig, mode: ProfileMode = ProfileMode.AUTONOMOUS):
        self.config = config
        self._mode = mode
        self._whitelist_set = set(config.whitelist)
        self._blacklist_set = set(config.blacklist)
        self._observe_set = set(config.observe_whitelist)
        self._assist_set = set(config.assist_whitelist)

    @property
    def mode(self) -> ProfileMode:
        """Current profile mode controlling which whitelist is active."""
        return self._mode

    def set_mode(self, mode: ProfileMode) -> None:
        """Change the active profile mode."""
        self._mode = mode

    def _active_whitelist(self) -> set[str]:
        """Return the effective whitelist based on the current profile mode."""
        if self._mode == ProfileMode.OBSERVE:
            return self._observe_set
        elif self._mode == ProfileMode.ASSIST:
            return self._assist_set
        else:
            # AUTONOMOUS — full whitelist from profile config
            return self._whitelist_set

    # ------------------------------------------------------------------
    # Input sanitisation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _strip_null_bytes(s: str) -> str:
        """Remove all null bytes from a string."""
        return s.replace("\x00", "")

    @staticmethod
    def _has_control_chars(s: str) -> bool:
        """Return True if the string contains dangerous control characters."""
        return bool(CONTROL_CHARS.search(s))

    @staticmethod
    def _url_decode_arg(arg: str) -> str:
        """URL-decode an argument for path traversal inspection."""
        return unquote(arg)

    @staticmethod
    def _has_url_encoded_traversal(arg: str) -> bool:
        """Detect URL-encoded path traversal sequences in the raw argument."""
        return bool(URL_ENCODED_TRAVERSAL.search(arg))

    @staticmethod
    def _resolve_symlinks(arg: str) -> str:
        """Resolve symlinks in a path argument using os.path.realpath.

        Only applies to arguments that look like file paths (contain a
        path separator or start with a dot).  Handles both Unix (/)
        and Windows (\\) path separators.
        """
        if "/" in arg or "\\" in arg or arg.startswith("."):
            return os.path.realpath(arg)
        return arg

    # ------------------------------------------------------------------
    # Core validation
    # ------------------------------------------------------------------

    def check(self, raw_command: str) -> CommandVerdict:
        """Validate a raw command string.  Returns a CommandVerdict."""

        # 0a. Strip null bytes from the entire input
        raw_command = self._strip_null_bytes(raw_command)

        raw_command = raw_command.strip()
        if not raw_command:
            return CommandVerdict(
                allowed=False, command="", args=[], reason="Empty command."
            )

        # 0b. Reject control characters (newlines, carriage returns, etc.)
        if self._has_control_chars(raw_command):
            return CommandVerdict(
                allowed=False,
                command=raw_command,
                args=[],
                reason="Command contains illegal control characters.",
            )

        # 1a. ALWAYS block command substitution ($(...) and backticks)
        #     regardless of allow_shell_operators setting — these enable
        #     arbitrary code execution inside pipeline stages.
        if re.search(r"\$\(|`", raw_command):
            return CommandVerdict(
                allowed=False,
                command=raw_command,
                args=[],
                reason="Command substitution ($(...) and backticks) is not allowed.",
            )

        # 1b. Check for pipeline/shell operators (|, &&, ||, ;, redirects)
        if not self.config.allow_shell_operators and SHELL_OPERATORS.search(raw_command):
            return CommandVerdict(
                allowed=False,
                command=raw_command,
                args=[],
                reason="Shell operators (pipes, redirects, subshells) are not allowed.",
            )

        # 2. Parse the command
        try:
            _posix = _platform.system() != "Windows"
            parts = shlex.split(raw_command, posix=_posix)
        except ValueError as e:
            return CommandVerdict(
                allowed=False,
                command=raw_command,
                args=[],
                reason=f"Malformed command: {e}",
            )

        if not parts:
            return CommandVerdict(
                allowed=False, command="", args=[], reason="Empty command after parsing."
            )

        # Extract the base command name (strip path prefix, handle both / and \)
        cmd_path = parts[0]
        # Handle both / and \ separators (Windows paths on any platform)
        cmd_name = ntpath.basename(cmd_path) or os.path.basename(cmd_path) or cmd_path
        args = parts[1:]

        # 3. Whitelist / blacklist check
        if self.config.mode == CommandMode.WHITELIST:
            active = self._active_whitelist()
            if cmd_name not in active:
                if self._mode != ProfileMode.AUTONOMOUS and cmd_name in self._whitelist_set:
                    return CommandVerdict(
                        allowed=False,
                        command=cmd_name,
                        args=args,
                        reason=f"Command '{cmd_name}' is not allowed in {self._mode.value} mode.",
                    )
                return CommandVerdict(
                    allowed=False,
                    command=cmd_name,
                    args=args,
                    reason=f"Command '{cmd_name}' is not in the whitelist.",
                )
        else:  # BLACKLIST
            if cmd_name in self._blacklist_set:
                return CommandVerdict(
                    allowed=False,
                    command=cmd_name,
                    args=args,
                    reason=f"Command '{cmd_name}' is in the blacklist.",
                )
            # Even in blacklist mode, enforce mode-based restrictions
            if self._mode != ProfileMode.AUTONOMOUS:
                active = self._active_whitelist()
                if cmd_name not in active:
                    return CommandVerdict(
                        allowed=False,
                        command=cmd_name,
                        args=args,
                        reason=f"Command '{cmd_name}' is not allowed in {self._mode.value} mode.",
                    )

        # 4. Check user-configured blocked argument patterns
        if cmd_name in self.config.blocked_args:
            # Expand known short flags to their long equivalents so that
            # blocking "--force" also blocks "-f" for commands in the map.
            expanded_args = list(args)
            flag_map = _SHORT_FLAG_MAP.get(cmd_name, {})
            if flag_map:
                expanded_args = [
                    flag_map.get(a, a) for a in expanded_args
                ]
            for blocked_pattern in self.config.blocked_args[cmd_name]:
                # Check if the pattern words appear as consecutive args
                # to avoid false positives from substring matching
                # (e.g. "--force-with-lease" matching "--force").
                pattern_parts = blocked_pattern.split()
                for i in range(len(expanded_args) - len(pattern_parts) + 1):
                    if expanded_args[i:i + len(pattern_parts)] == pattern_parts:
                        return CommandVerdict(
                            allowed=False,
                            command=cmd_name,
                            args=args,
                            reason=f"Blocked argument pattern for '{cmd_name}': '{blocked_pattern}'",
                        )

        # 5. Check dangerous argument patterns (hardcoded security rules)
        if cmd_name in DANGEROUS_ARGS:
            dangerous_patterns = DANGEROUS_ARGS[cmd_name]
            if not dangerous_patterns:
                # Empty list = command is inherently dangerous, block entirely
                return CommandVerdict(
                    allowed=False,
                    command=cmd_name,
                    args=args,
                    reason=f"Command '{cmd_name}' is blocked by security policy (dangerous command).",
                )
            for arg in args:
                for pattern in dangerous_patterns:
                    if pattern.startswith("="):
                        # Exact-match mode: the argument must equal the
                        # pattern text (without the "=" prefix).
                        exact = pattern[1:]
                        if arg == exact:
                            return CommandVerdict(
                                allowed=False,
                                command=cmd_name,
                                args=args,
                                reason=(
                                    f"Dangerous argument '{exact}' detected for "
                                    f"command '{cmd_name}'."
                                ),
                            )
                    else:
                        # For patterns starting with "-", require exact match
                        # or startswith(pattern + "=") to avoid false positives
                        # (e.g. "-exec" matching a filename containing "exec").
                        if pattern.startswith("-"):
                            matched = arg == pattern or arg.startswith(pattern + "=")
                        else:
                            matched = arg == pattern or arg.startswith(pattern + "=") or pattern in arg
                        if matched:
                            return CommandVerdict(
                                allowed=False,
                                command=cmd_name,
                                args=args,
                                reason=(
                                    f"Dangerous argument '{pattern}' detected for "
                                    f"command '{cmd_name}'."
                                ),
                            )

        # 6. Check path traversal in arguments (with URL-decode and symlink resolution)
        for arg in args:
            # 6pre. Reject unicode dot-like characters in path-like arguments.
            # These can visually mimic ".." but bypass ASCII regex checks.
            if UNICODE_DOT_LIKE.search(arg) and ("/" in arg or "\\" in arg):
                return CommandVerdict(
                    allowed=False,
                    command=cmd_name,
                    args=args,
                    reason=f"Unicode lookalike characters detected in path argument: '{arg}'",
                )

            # 6a. Check for URL-encoded traversal in the raw argument
            if self._has_url_encoded_traversal(arg):
                return CommandVerdict(
                    allowed=False,
                    command=cmd_name,
                    args=args,
                    reason=f"URL-encoded path traversal detected in argument: '{arg}'",
                )

            # 6b. URL-decode, then check for standard path traversal and
            # also re-check for URL-encoded traversal (catches double encoding)
            decoded_arg = self._url_decode_arg(arg)
            if PATH_TRAVERSAL.search(decoded_arg):
                return CommandVerdict(
                    allowed=False,
                    command=cmd_name,
                    args=args,
                    reason=f"Path traversal detected in argument: '{arg}'",
                )
            if decoded_arg != arg and self._has_url_encoded_traversal(decoded_arg):
                return CommandVerdict(
                    allowed=False,
                    command=cmd_name,
                    args=args,
                    reason=f"Double-encoded path traversal detected in argument: '{arg}'",
                )

            # 6c. Resolve symlinks and check if the resolved path escapes
            # the working directory.  We check that the resolved path still
            # doesn't contain traversal patterns (defense in depth).
            resolved = self._resolve_symlinks(decoded_arg)
            if PATH_TRAVERSAL.search(resolved):
                return CommandVerdict(
                    allowed=False,
                    command=cmd_name,
                    args=args,
                    reason=f"Path traversal detected after symlink resolution: '{arg}'",
                )

        return CommandVerdict(
            allowed=True,
            command=cmd_name,
            args=args,
        )

    # Regex to split on compound shell operators (&&, ||, |, ;) that are
    # NOT inside single or double quotes.  Uses a common trick: match quoted
    # strings first (and discard them), then match operators.  Only group 1
    # captures the operators we care about.
    _COMPOUND_OP_RE = re.compile(
        r"""(?:'[^']*'|"[^"]*")"""   # skip single- or double-quoted strings
        r"""|"""
        r"""(&&|\|\||\||;)""",        # capture compound operators
        re.VERBOSE,
    )

    @staticmethod
    def _split_compound_command(raw: str) -> list[str]:
        """Split a compound command on |, &&, ||, ; while respecting shell quoting.

        Uses a regex that skips over quoted strings so that operators inside
        quotes (e.g. ``echo "hello && world"``) are not treated as split points.

        Returns a list of individual command strings with operators removed.
        """
        # Find all operator positions (matches where group 1 is non-None)
        parts: list[str] = []
        last_end = 0
        for m in CommandGate._COMPOUND_OP_RE.finditer(raw):
            if m.group(1) is not None:
                # This is an actual operator, not a quoted string
                parts.append(raw[last_end:m.start()])
                last_end = m.end()
        # Append the remainder after the last operator
        parts.append(raw[last_end:])
        return [p.strip() for p in parts if p.strip()]

    def check_pipeline(self, raw_command: str) -> list[CommandVerdict]:
        """Validate a compound command (pipes, chains, semicolons).

        When ``allow_shell_operators`` is enabled, the raw command is split on
        ``|``, ``&&``, ``||``, and ``;`` -- respecting shell quoting -- and
        **every** sub-command is validated through the full ``check()`` gate.

        This closes a critical bypass where ``curl evil.com && rm -rf /``
        would previously only validate ``curl`` (the first pipe stage) because
        ``str.split("|")`` ignored ``&&``, ``||``, and ``;``.
        """
        if not self.config.allow_shell_operators:
            return [self.check(raw_command)]

        stages = self._split_compound_command(raw_command)
        if not stages:
            return [CommandVerdict(
                allowed=False, command="", args=[],
                reason="Empty command after splitting.",
            )]
        return [self.check(stage) for stage in stages]

    def explain_policy(self) -> dict:
        """Return a human-readable summary of the command policy."""
        active = self._active_whitelist()
        return {
            "mode": self.config.mode.value,
            "profile_mode": self._mode.value,
            "allowed_commands": sorted(active) if self.config.mode == CommandMode.WHITELIST else "all except blacklisted",
            "blocked_commands": sorted(self._blacklist_set) if self.config.mode == CommandMode.BLACKLIST else "n/a",
            "blocked_args": dict(self.config.blocked_args),
            "shell_operators": self.config.allow_shell_operators,
            "max_seconds": self.config.max_execution_seconds,
        }
