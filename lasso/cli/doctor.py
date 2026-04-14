"""LASSO doctor — comprehensive system diagnostics.

Runs a battery of checks to verify that everything LASSO needs is present
and configured correctly, reporting pass/warn/fail for each check with
remediation hints.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from lasso.utils.paths import get_lasso_dir

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

STATUS_PASS = "PASS"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"


@dataclass
class CheckResult:
    """Result of a single diagnostic check."""

    name: str
    status: str  # PASS / WARN / FAIL
    message: str
    fix_hint: str = ""
    fixable: bool = False

    def to_dict(self) -> dict:
        d = {
            "name": self.name,
            "status": self.status,
            "message": self.message,
        }
        if self.fix_hint:
            d["fix_hint"] = self.fix_hint
        if self.fixable:
            d["fixable"] = True
        return d


@dataclass
class DoctorReport:
    """Aggregated report from all checks."""

    checks: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == STATUS_PASS)

    @property
    def warned(self) -> int:
        return sum(1 for c in self.checks if c.status == STATUS_WARN)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == STATUS_FAIL)

    def to_dict(self) -> dict:
        return {
            "summary": {
                "total": len(self.checks),
                "passed": self.passed,
                "warned": self.warned,
                "failed": self.failed,
            },
            "checks": [c.to_dict() for c in self.checks],
        }


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

LASSO_DIR = get_lasso_dir()

_PLATFORM = platform.system()


def _daemon_hint(cmd: str, action: str = "start") -> str:
    """Return a platform-appropriate hint for starting/restarting a container daemon."""
    if _PLATFORM == "Darwin":
        if cmd == "docker":
            return "Open Docker Desktop, or run: open -a Docker"
        return f"Start {cmd} via Homebrew: brew services {action} {cmd}"
    if _PLATFORM == "Windows":
        if cmd == "docker":
            return "Open Docker Desktop from the Start menu"
        return f"Start {cmd} from the Start menu or run: {cmd} machine start"
    # Linux
    return f"{action.capitalize()} the {cmd} daemon: sudo systemctl {action} {cmd}"


def _chmod_hint(path: str | Path, mode: str = "700") -> str:
    """Return a platform-appropriate hint for fixing file permissions."""
    if _PLATFORM == "Windows":
        return f"Check permissions on {path} via Properties > Security"
    return f"Fix permissions: chmod {mode} {path}"


def _check_python_version() -> CheckResult:
    """Check 1: Python >= 3.10."""
    ver = sys.version_info
    version_str = f"{ver.major}.{ver.minor}.{ver.micro}"
    if (ver.major, ver.minor) >= (3, 10):
        return CheckResult(
            name="Python version",
            status=STATUS_PASS,
            message=f"Python {version_str}",
        )
    return CheckResult(
        name="Python version",
        status=STATUS_FAIL,
        message=f"Python {version_str} (>= 3.10 required)",
        fix_hint="Install Python 3.10+ from https://www.python.org/downloads/",
    )


def _check_container_runtime() -> CheckResult:
    """Check 2: Docker or Podman installed and responsive."""
    for cmd in ("docker", "podman"):
        path = shutil.which(cmd)
        if path:
            try:
                result = subprocess.run(
                    [cmd, "version", "--format", "{{.Server.Version}}"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    version = result.stdout.strip() or "unknown"
                    return CheckResult(
                        name="Container runtime",
                        status=STATUS_PASS,
                        message=f"{cmd} {version}",
                    )
                # Go template may not be supported (e.g. some Podman versions).
                # Fall back to plain `cmd version` and parse the output.
                try:
                    fallback = subprocess.run(
                        [cmd, "version"],
                        capture_output=True, text=True, timeout=10,
                    )
                    if fallback.returncode == 0:
                        version = "unknown"
                        for line in fallback.stdout.splitlines():
                            if "version" in line.lower() and ":" in line:
                                version = line.split(":", 1)[1].strip()
                                break
                        return CheckResult(
                            name="Container runtime",
                            status=STATUS_PASS,
                            message=f"{cmd} {version}",
                        )
                except Exception:
                    pass
                # Command exists but server not responding
                return CheckResult(
                    name="Container runtime",
                    status=STATUS_FAIL,
                    message=f"{cmd} found but daemon not responding",
                    fix_hint=_daemon_hint(cmd, "start"),
                )
            except subprocess.TimeoutExpired:
                return CheckResult(
                    name="Container runtime",
                    status=STATUS_FAIL,
                    message=f"{cmd} timed out (daemon may be hung)",
                    fix_hint=_daemon_hint(cmd, "restart"),
                )
            except Exception as exc:
                return CheckResult(
                    name="Container runtime",
                    status=STATUS_FAIL,
                    message=f"{cmd} error: {exc}",
                    fix_hint=f"Reinstall {cmd} or check its configuration.",
                )

    return CheckResult(
        name="Container runtime",
        status=STATUS_FAIL,
        message="Neither Docker nor Podman found on PATH",
        fix_hint=(
            "Install Docker (https://docs.docker.com/get-docker/) "
            "or Podman (https://podman.io/getting-started/installation)"
        ),
    )


def _check_container_permissions() -> CheckResult:
    """Check 3: Can actually create containers (not just installed)."""
    for cmd in ("docker", "podman"):
        if not shutil.which(cmd):
            continue
        try:
            result = subprocess.run(
                [cmd, "run", "--rm", "hello-world"],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 0:
                return CheckResult(
                    name="Container permissions",
                    status=STATUS_PASS,
                    message=f"Can create containers via {cmd}",
                )
            stderr = result.stderr.strip()
            if "permission denied" in stderr.lower() or "denied" in stderr.lower():
                fix = (
                    f"Add your user to the {cmd} group: "
                    f"sudo usermod -aG {cmd} $USER && newgrp {cmd}"
                )
                return CheckResult(
                    name="Container permissions",
                    status=STATUS_FAIL,
                    message=f"Permission denied when creating container via {cmd}",
                    fix_hint=fix,
                )
            return CheckResult(
                name="Container permissions",
                status=STATUS_FAIL,
                message=f"Container creation failed: {stderr[:120]}",
                fix_hint=f"Check {cmd} daemon status and configuration.",
            )
        except subprocess.TimeoutExpired:
            return CheckResult(
                name="Container permissions",
                status=STATUS_WARN,
                message=f"Container creation timed out via {cmd} (may be pulling image)",
                fix_hint=f"Try running '{cmd} run --rm hello-world' manually.",
            )
        except Exception as exc:
            return CheckResult(
                name="Container permissions",
                status=STATUS_FAIL,
                message=f"Error testing container creation: {exc}",
                fix_hint=f"Check {cmd} installation.",
            )

    return CheckResult(
        name="Container permissions",
        status=STATUS_FAIL,
        message="No container runtime available to test",
        fix_hint="Install Docker or Podman first.",
    )


def _check_lasso_directory() -> CheckResult:
    """Check 4: ~/.lasso/ exists with correct permissions."""
    if not LASSO_DIR.exists():
        return CheckResult(
            name="LASSO directory",
            status=STATUS_WARN,
            message=f"{LASSO_DIR} does not exist",
            fix_hint=f"Will be created automatically, or run: mkdir -p {LASSO_DIR}",
            fixable=True,
        )

    if not LASSO_DIR.is_dir():
        return CheckResult(
            name="LASSO directory",
            status=STATUS_FAIL,
            message=f"{LASSO_DIR} exists but is not a directory",
            fix_hint=f"Remove the file and create the directory: rm {LASSO_DIR} && mkdir -p {LASSO_DIR}",
        )

    # Check permissions on Unix
    if platform.system() != "Windows":
        try:
            stat = LASSO_DIR.stat()
            mode = oct(stat.st_mode)[-3:]
            # Owner should have rwx; warn if group/other have write
            if int(mode[1]) >= 2 or int(mode[2]) >= 2:
                return CheckResult(
                    name="LASSO directory",
                    status=STATUS_WARN,
                    message=f"{LASSO_DIR} permissions {mode} (group/other writable)",
                    fix_hint=_chmod_hint(LASSO_DIR, "700"),
                )
        except OSError:
            pass

    return CheckResult(
        name="LASSO directory",
        status=STATUS_PASS,
        message=str(LASSO_DIR),
    )



def _check_signing_key_location() -> CheckResult:
    """Check 6: Warn if signing key is co-located with logs."""
    # Check the default location (inside the audit log directory)
    # A properly configured deployment has signing_key_path pointing
    # to an external location.
    default_key = LASSO_DIR / "audit" / ".audit_key"
    profiles_dir = LASSO_DIR / "profiles"

    # Scan saved profiles for signing_key_path settings
    external_key_found = False
    colocated_key_found = False

    if profiles_dir.exists():
        for toml_file in profiles_dir.glob("*.toml"):
            try:
                try:
                    import tomllib
                except ImportError:
                    import tomli as tomllib
                with open(toml_file, "rb") as f:
                    data = tomllib.load(f)
                audit = data.get("audit", {})
                key_path = audit.get("signing_key_path")
                log_dir = audit.get("log_dir", "./audit")
                if key_path:
                    # Check if key_path is outside the log_dir
                    try:
                        kp = Path(key_path).resolve()
                        ld = Path(log_dir).resolve()
                        if not kp.is_relative_to(ld):
                            external_key_found = True
                        else:
                            colocated_key_found = True
                    except Exception:
                        pass
            except Exception:
                continue

    if default_key.exists() and not external_key_found:
        return CheckResult(
            name="Signing key location",
            status=STATUS_WARN,
            message="Signing key is co-located with audit logs (default location)",
            fix_hint=(
                "For tamper-evidence, set signing_key_path in your profile "
                "to an external location (e.g., a mounted USB or separate volume)."
            ),
        )

    if external_key_found:
        return CheckResult(
            name="Signing key location",
            status=STATUS_PASS,
            message="Signing key configured at external location",
        )

    if colocated_key_found:
        return CheckResult(
            name="Signing key location",
            status=STATUS_WARN,
            message="Signing key is inside the audit log directory",
            fix_hint=(
                "Set signing_key_path in your profile audit config "
                "to a path outside the log directory."
            ),
        )

    # No signing key exists yet — that is fine, it will be auto-generated
    return CheckResult(
        name="Signing key location",
        status=STATUS_PASS,
        message="No signing key yet (will be auto-generated on first audit)",
    )


def _check_profile_validation() -> CheckResult:
    """Check 7: All saved profiles parse without errors."""
    from lasso.config.profile import list_profiles

    profiles = list_profiles()
    if not profiles:
        return CheckResult(
            name="Profile validation",
            status=STATUS_PASS,
            message="No saved profiles (builtins are always valid)",
        )

    errors = [p for p in profiles if "error" in p]
    valid = len(profiles) - len(errors)

    if errors:
        error_names = ", ".join(p["name"] for p in errors)
        return CheckResult(
            name="Profile validation",
            status=STATUS_FAIL,
            message=f"{len(errors)} profile(s) have errors: {error_names}",
            fix_hint=(
                "Fix or delete broken profiles: lasso profile delete <name>"
            ),
        )

    return CheckResult(
        name="Profile validation",
        status=STATUS_PASS,
        message=f"{valid} saved profile(s) valid",
    )


def _check_network_tools() -> CheckResult:
    """Check 8: iptables available for RESTRICTED network mode."""
    # Only relevant on Linux; on other platforms network policy relies
    # on the container runtime's built-in isolation.
    if platform.system() != "Linux":
        return CheckResult(
            name="Network tools (iptables)",
            status=STATUS_PASS,
            message=f"Not applicable on {platform.system()} (container runtime handles isolation)",
        )

    # Check if iptables is available on the host (needed for
    # generating rules applied inside the container namespace)
    iptables_path = shutil.which("iptables")
    if iptables_path:
        return CheckResult(
            name="Network tools (iptables)",
            status=STATUS_PASS,
            message=f"iptables found at {iptables_path}",
        )

    return CheckResult(
        name="Network tools (iptables)",
        status=STATUS_WARN,
        message="iptables not found on host",
        fix_hint=(
            "Install iptables for RESTRICTED network mode: "
            "sudo apt install iptables (Debian/Ubuntu) or "
            "sudo dnf install iptables (Fedora)"
        ),
    )


def _check_disk_space() -> CheckResult:
    """Check 9: Warn if < 1GB free in ~/.lasso/."""
    check_path = LASSO_DIR if LASSO_DIR.exists() else Path.home()
    try:
        usage = shutil.disk_usage(check_path)
        free_gb = usage.free / (1024 ** 3)
        if free_gb < 1.0:
            return CheckResult(
                name="Disk space",
                status=STATUS_WARN,
                message=f"{free_gb:.1f} GB free (< 1 GB)",
                fix_hint="Free up disk space. Audit logs and container images use storage.",
            )
        return CheckResult(
            name="Disk space",
            status=STATUS_PASS,
            message=f"{free_gb:.1f} GB free",
        )
    except OSError as exc:
        return CheckResult(
            name="Disk space",
            status=STATUS_WARN,
            message=f"Could not check disk space: {exc}",
        )


def _check_state_file() -> CheckResult:
    """Check 10: ~/.lasso/state.json readable/writable."""
    state_file = LASSO_DIR / "state.json"

    if not state_file.exists():
        # Not an error — state file is created on first sandbox creation
        if LASSO_DIR.exists():
            # Check if we can write to the directory
            try:
                test_file = LASSO_DIR / ".doctor_write_test"
                test_file.write_text("test")
                test_file.unlink()
                return CheckResult(
                    name="State file",
                    status=STATUS_PASS,
                    message="No state file yet (directory is writable)",
                )
            except OSError as exc:
                return CheckResult(
                    name="State file",
                    status=STATUS_FAIL,
                    message=f"Cannot write to {LASSO_DIR}: {exc}",
                    fix_hint=_chmod_hint(LASSO_DIR, "700"),
                )
        return CheckResult(
            name="State file",
            status=STATUS_PASS,
            message="No state file yet (created on first sandbox)",
        )

    # File exists — check it is readable and valid JSON
    try:
        data = json.loads(state_file.read_text())
        sandboxes = data.get("sandboxes", {})
        running = sum(1 for s in sandboxes.values() if s.get("state") == "running")
        return CheckResult(
            name="State file",
            status=STATUS_PASS,
            message=f"OK ({len(sandboxes)} sandbox records, {running} running)",
        )
    except json.JSONDecodeError:
        return CheckResult(
            name="State file",
            status=STATUS_WARN,
            message="State file exists but contains invalid JSON",
            fix_hint=f"Delete and let LASSO recreate it: rm {state_file}",
        )
    except OSError as exc:
        return CheckResult(
            name="State file",
            status=STATUS_FAIL,
            message=f"Cannot read state file: {exc}",
            fix_hint=_chmod_hint(state_file, "600"),
        )


# ---------------------------------------------------------------------------
# Team-mode checks (11-14)
# ---------------------------------------------------------------------------


def _check_profile_dir() -> CheckResult:
    """Check 11: LASSO_PROFILE_DIR is set and valid."""
    env_dir = os.environ.get("LASSO_PROFILE_DIR", "")
    if not env_dir:
        return CheckResult(
            name="Profile directory (LASSO_PROFILE_DIR)",
            status=STATUS_WARN,
            message="LASSO_PROFILE_DIR is not set",
            fix_hint="Set LASSO_PROFILE_DIR to a shared directory containing team profiles.",
        )

    # Validate each path in the (potentially multi-path) value
    invalid_parts = []
    valid_parts = []
    for part in env_dir.split(os.pathsep):
        part = part.strip()
        if not part:
            continue
        p = Path(part)
        if not p.exists():
            invalid_parts.append(part)
        elif not p.is_dir():
            invalid_parts.append(f"{part} (not a directory)")
        else:
            valid_parts.append(part)

    if invalid_parts:
        return CheckResult(
            name="Profile directory (LASSO_PROFILE_DIR)",
            status=STATUS_FAIL,
            message=f"Invalid paths: {', '.join(invalid_parts)}",
            fix_hint="Fix or create the directories listed in LASSO_PROFILE_DIR.",
        )

    profile_count = 0
    for part in valid_parts:
        profile_count += len(list(Path(part).glob("*.toml")))

    return CheckResult(
        name="Profile directory (LASSO_PROFILE_DIR)",
        status=STATUS_PASS,
        message=f"{len(valid_parts)} directory(ies), {profile_count} profile(s) found",
    )


def _check_extends_resolution() -> CheckResult:
    """Check 12: All extends references in profiles resolve."""
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib

    profiles_dir = LASSO_DIR / "profiles"
    env_dir = os.environ.get("LASSO_PROFILE_DIR", "")

    # Collect all TOML files from saved profiles and LASSO_PROFILE_DIR
    toml_files: list[Path] = []
    if profiles_dir.exists():
        toml_files.extend(profiles_dir.glob("*.toml"))
    if env_dir:
        for part in env_dir.split(os.pathsep):
            part = part.strip()
            if part:
                p = Path(part)
                if p.is_dir():
                    toml_files.extend(p.glob("*.toml"))

    if not toml_files:
        return CheckResult(
            name="Profile extends resolution",
            status=STATUS_PASS,
            message="No profiles to check",
        )

    broken: list[str] = []
    checked = 0

    for toml_file in toml_files:
        try:
            with open(toml_file, "rb") as f:
                data = tomllib.load(f)
            extends = data.get("extends")
            if not extends:
                continue
            checked += 1
            # Try to resolve the base profile
            from lasso.config.profile import resolve_profile
            try:
                resolve_profile(extends)
            except (FileNotFoundError, ValueError):
                broken.append(f"{toml_file.stem} -> {extends}")
        except Exception:
            continue

    if broken:
        return CheckResult(
            name="Profile extends resolution",
            status=STATUS_FAIL,
            message=f"{len(broken)} broken: {', '.join(broken)}",
            fix_hint="Fix or remove the 'extends' field in broken profiles.",
        )

    return CheckResult(
        name="Profile extends resolution",
        status=STATUS_PASS,
        message=f"{checked} extends reference(s) resolved OK"
        if checked else "No extends references found",
    )


def _check_version_pin() -> CheckResult:
    """Check 13: Pinned version matches running version."""
    from lasso.core.checkpoint import CheckpointStore

    store = CheckpointStore()
    pinned = store.get_pinned_version()

    if not pinned:
        return CheckResult(
            name="Version pin",
            status=STATUS_WARN,
            message="No version pinned",
            fix_hint="Pin a version with: lasso checkpoint pin <version>",
        )

    from lasso import __version__
    if pinned == __version__:
        return CheckResult(
            name="Version pin",
            status=STATUS_PASS,
            message=f"Running v{__version__} matches pinned v{pinned}",
        )

    return CheckResult(
        name="Version pin",
        status=STATUS_WARN,
        message=f"Running v{__version__} does not match pinned v{pinned}",
        fix_hint=(
            f"Update LASSO to v{pinned} or re-pin: "
            f"lasso checkpoint pin {__version__}"
        ),
    )


def _check_profile_locks() -> CheckResult:
    """Check 14: Locked profiles match their hashes."""
    from lasso.config.sharing import verify_profile_locks

    # Check in current directory and home .lasso
    results = verify_profile_locks(".")
    if not results:
        # Also check ~/.lasso
        home_lasso = str(LASSO_DIR)
        results = verify_profile_locks(home_lasso)

    if not results:
        return CheckResult(
            name="Profile locks",
            status=STATUS_PASS,
            message="No profile locks found (none to verify)",
        )

    mismatches = [r for r in results if not r.get("match", True)]
    if mismatches:
        names = ", ".join(r.get("name", "?") for r in mismatches)
        return CheckResult(
            name="Profile locks",
            status=STATUS_FAIL,
            message=f"{len(mismatches)} lock mismatch(es): {names}",
            fix_hint="Re-lock profiles with: lasso profile lock <name>",
        )

    return CheckResult(
        name="Profile locks",
        status=STATUS_PASS,
        message=f"{len(results)} locked profile(s) verified OK",
    )


# ---------------------------------------------------------------------------
# Auto-fix logic
# ---------------------------------------------------------------------------

def _auto_fix(report: DoctorReport, console: Console) -> int:
    """Attempt to fix issues that are marked fixable. Returns count of fixes applied."""
    fixes_applied = 0

    for check in report.checks:
        if check.status == STATUS_PASS or not check.fixable:
            continue

        if check.name == "LASSO directory" and not LASSO_DIR.exists():
            try:
                LASSO_DIR.mkdir(parents=True, exist_ok=True)
                if platform.system() != "Windows":
                    LASSO_DIR.chmod(0o700)
                console.print(f"  [green]FIXED[/green] Created {LASSO_DIR}")
                check.status = STATUS_PASS
                check.message = f"{LASSO_DIR} (auto-created)"
                fixes_applied += 1
            except OSError as exc:
                console.print(f"  [red]FAILED[/red] Could not create {LASSO_DIR}: {exc}")


    return fixes_applied


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_doctor(
    output_json: bool = False,
    fix: bool = False,
    team: bool = False,
    console: Console | None = None,
) -> DoctorReport:
    """Run all diagnostic checks and return a report.

    Args:
        output_json: Output structured JSON instead of a Rich table.
        fix: Attempt to auto-fix issues that support it.
        team: Run team-mode checks (profile dir, extends, version pin, locks).
        console: Rich console for output (uses default if None).

    Returns:
        DoctorReport with all check results.
    """
    if console is None:
        console = Console()

    # Collect all check results.  Container permission check is slow
    # (pulls an image), so run it only when the runtime is present.
    report = DoctorReport()

    if not output_json:
        console.print()

    checks = [
        _check_python_version,
        _check_container_runtime,
        _check_container_permissions,
        _check_lasso_directory,
        _check_signing_key_location,
        _check_profile_validation,
        _check_network_tools,
        _check_disk_space,
        _check_state_file,
    ]

    # Add team-mode checks when --team is passed or LASSO_PROFILE_DIR is set
    if team or os.environ.get("LASSO_PROFILE_DIR"):
        checks.extend([
            _check_profile_dir,
            _check_extends_resolution,
            _check_version_pin,
            _check_profile_locks,
        ])

    # Skip container permissions if runtime itself is not found
    skip_permissions = False

    for check_fn in checks:
        if skip_permissions and check_fn is _check_container_permissions:
            report.checks.append(CheckResult(
                name="Container permissions",
                status=STATUS_FAIL,
                message="Skipped (no container runtime)",
                fix_hint="Install Docker or Podman first.",
            ))
            continue

        if not output_json:
            console.print(f"  Checking {check_fn.__doc__ or check_fn.__name__}...", end="\r")

        result = check_fn()
        report.checks.append(result)

        # If runtime check failed, skip the permissions check
        if check_fn is _check_container_runtime and result.status == STATUS_FAIL:
            skip_permissions = True

    # --fix: attempt auto-fixes
    fixes_applied = 0
    if fix:
        if not output_json:
            console.print()
            console.print("[bold]Attempting auto-fixes...[/bold]")
        fixes_applied = _auto_fix(report, console)

    # Output
    if output_json:
        report_dict = report.to_dict()
        if fix:
            report_dict["fixes_applied"] = fixes_applied
        console.print_json(json.dumps(report_dict, indent=2))
        return report

    # Clear the "Checking..." line
    console.print(" " * 60, end="\r")

    # Rich table output
    console.print(Panel.fit(
        "[bold]LASSO System Diagnostics[/bold]",
        border_style="blue",
    ))

    table = Table(show_header=True)
    table.add_column("Status", width=6, justify="center")
    table.add_column("Check", min_width=22)
    table.add_column("Details", min_width=30)
    table.add_column("Fix", min_width=20)

    status_styles = {
        STATUS_PASS: "[green]PASS[/green]",
        STATUS_WARN: "[yellow]WARN[/yellow]",
        STATUS_FAIL: "[red]FAIL[/red]",
    }

    for check in report.checks:
        styled_status = status_styles.get(check.status, check.status)
        hint = check.fix_hint or ""
        if check.fixable and not fix:
            hint += " [dim](--fix)[/dim]" if hint else "[dim]--fix to auto-repair[/dim]"
        table.add_row(styled_status, check.name, check.message, hint)

    console.print(table)

    # Summary
    console.print()
    parts = [f"[green]{report.passed} passed[/green]"]
    if report.warned:
        parts.append(f"[yellow]{report.warned} warning(s)[/yellow]")
    if report.failed:
        parts.append(f"[red]{report.failed} failure(s)[/red]")
    console.print(f"  {', '.join(parts)} out of {len(report.checks)} checks")

    if fix and fixes_applied:
        console.print(f"  [green]{fixes_applied} issue(s) auto-fixed[/green]")

    if report.failed:
        console.print("\n  [red]Some checks failed.[/red] Fix the issues above and re-run: lasso doctor")
    elif report.warned:
        console.print("\n  [yellow]Warnings found.[/yellow] LASSO will work but review the hints above.")
    else:
        console.print("\n  [green]All checks passed. LASSO is ready.[/green]")

    console.print()
    return report
