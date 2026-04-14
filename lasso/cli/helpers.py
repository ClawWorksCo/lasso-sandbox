"""Shared helper functions for LASSO CLI commands."""

from __future__ import annotations

import json
import os
import platform
import shutil
import signal
from pathlib import Path

import typer

from lasso import __version__
from lasso.config.defaults import BUILTIN_PROFILES
from lasso.config.profile import (
    load_profile,
    load_profile_from_path,
    resolve_profile,
)
from lasso.config.schema import SandboxProfile
from lasso.utils.paths import get_lasso_dir

from .constants import (
    _BLOCKED_ENV_KEYS,
    _BLOCKED_ENV_PREFIXES,
    console,
    err_console,
)

# Lazy-initialized registry
_registry = None


def _ensure_lasso_dir() -> Path:
    """Ensure ~/.lasso/ and ~/.lasso/profiles/ directories exist.

    Returns the path to ~/.lasso/.
    """
    lasso_home = get_lasso_dir()
    lasso_home.mkdir(parents=True, exist_ok=True)
    (lasso_home / "profiles").mkdir(exist_ok=True)
    return lasso_home


def _get_registry(native: bool = False, quiet: bool = False):
    """Get or create the sandbox registry with auto-detected backend."""
    from lasso.core.sandbox import SandboxRegistry

    global _registry
    _ensure_lasso_dir()
    if _registry is None:
        backend = None
        if not native:
            from lasso.backends.detect import detect_backend
            backend = detect_backend()
            if backend and not quiet:
                info = backend.get_info()
                runtime = info.get("runtime", "container")
                ver = info.get("version", "")
                console.print(f"[dim]Backend: {runtime} {ver}[/dim]")
        if backend is None and not native:
            err_console.print("[red]Docker or Podman is required but not found.[/red]")
            err_console.print("[dim]Install Docker Desktop: https://docker.com/products/docker-desktop[/dim]")
            raise typer.Exit(1)
        _registry = SandboxRegistry(backend=backend)
    return _registry


def _resolve_profile(
    profile_name: str,
    working_dir: str,
    file: str | None = None,
    quiet: bool = False,
) -> SandboxProfile:
    """Resolve a profile from name, file, or .lasso/ directory."""
    # Check for --file flag
    if file:
        return load_profile_from_path(file)

    # Check for .lasso/profile.toml in working dir
    local_profile = Path(working_dir) / ".lasso" / "profile.toml"
    if profile_name == "auto" and local_profile.exists():
        if not quiet:
            console.print(f"[dim]Using local profile: {local_profile}[/dim]")
        return load_profile_from_path(local_profile)

    # Check for .lasso/profiles/<name>.toml in working dir (project-level profiles)
    project_profile = Path(working_dir) / ".lasso" / "profiles" / f"{profile_name}.toml"
    if project_profile.exists():
        if not quiet:
            console.print(f"[dim]Using project profile: {project_profile}[/dim]")
        return load_profile_from_path(project_profile)

    # Resolve profile with inheritance support (builtins, saved, LASSO_PROFILE_DIR)
    try:
        return resolve_profile(profile_name, working_dir=working_dir)
    except FileNotFoundError:
        err_console.print(f"[red]Error: Profile '{profile_name}' not found.[/red]")
        err_console.print(f"[dim]Builtins: {', '.join(BUILTIN_PROFILES.keys())}[/dim]")
        err_console.print("[dim]Run 'lasso profile list' to see available profiles.[/dim]")
        raise typer.Exit(1)
    except ValueError as e:
        err_console.print(f"[red]Error resolving profile '{profile_name}': {e}[/red]")
        raise typer.Exit(1)


def _detect_container_cli() -> str | None:
    """Detect the container CLI binary (docker or podman).

    Prefers docker if available; falls back to podman.
    Returns None if neither is found.
    """
    if shutil.which("docker"):
        return "docker"
    if shutil.which("podman"):
        return "podman"
    return None


def _exec_container_cli(args: list[str]) -> None:
    """Replace or spawn the container CLI (docker/podman) with proper args.

    On Unix, uses os.execvp to replace the current process.
    On Windows, uses subprocess.run since os.execvp is not available.
    """
    cli = _detect_container_cli()
    if cli is None:
        err_console.print("[red]Error: Neither docker nor podman found on PATH.[/red]")
        raise typer.Exit(1)
    full_args = [cli] + args

    if platform.system() == "Windows":
        import subprocess
        result = subprocess.run(full_args)
        raise typer.Exit(result.returncode)
    else:
        os.execvp(cli, full_args)


def _parse_mount(mount_str: str) -> dict[str, str]:
    """Parse a mount string into {source, target, mode}.

    Handles Windows drive letters (e.g. C:\\data:/container:ro) by recognising
    that the first colon after a single drive letter is part of the path,
    not a separator.
    """
    # Handle Windows drive letters: C:\path or C:/path
    if (len(mount_str) >= 2
            and mount_str[0].isalpha()
            and mount_str[1] == ':'
            and (len(mount_str) == 2 or mount_str[2] in ('\\', '/'))):
        # Windows absolute path — first colon is drive letter
        rest = mount_str[2:]
        # Find the next colon (separator between source and target)
        colon_idx = rest.find(':')
        if colon_idx == -1:
            return {"source": mount_str, "target": mount_str, "mode": "rw"}
        source = mount_str[:2] + rest[:colon_idx]
        remaining = rest[colon_idx + 1:]
    else:
        colon_idx = mount_str.find(':')
        if colon_idx == -1:
            return {"source": mount_str, "target": mount_str, "mode": "rw"}
        source = mount_str[:colon_idx]
        remaining = mount_str[colon_idx + 1:]

    # Parse target and optional mode from remaining
    parts = remaining.split(":", 1)
    target = parts[0]
    mode = parts[1] if len(parts) > 1 else "rw"

    if not target:
        return {"source": source, "target": source, "mode": mode}
    return {"source": source, "target": target, "mode": mode}


def _validate_agent(agent: str | None, profile: SandboxProfile) -> None:
    """Validate agent name and store in profile.extra_env. Exits on unknown agent."""
    if not agent:
        return
    from lasso.backends.image_builder import AGENT_BASE_IMAGES, AGENT_INSTALLS
    known_agents = set(AGENT_INSTALLS) | set(AGENT_BASE_IMAGES)
    if agent not in known_agents:
        err_console.print(f"[red]Error: Unknown agent '{agent}'.[/red]")
        err_console.print(f"[dim]Available agents: {', '.join(sorted(known_agents))}[/dim]")
        raise typer.Exit(1)
    profile.extra_env["LASSO_AGENT"] = agent


def _apply_mounts(profile: SandboxProfile, mount: list[str] | None) -> None:
    """Parse --mount flags and store as JSON in profile.extra_env."""
    if not mount:
        return
    extra_mounts = []
    for m in mount:
        parsed = _parse_mount(m)
        if not parsed["target"]:
            err_console.print(f"[red]Invalid mount format: {m}[/red]")
            err_console.print("[dim]Use: /host/path:/container/path or /host/path:/container/path:ro[/dim]")
            raise typer.Exit(1)
        extra_mounts.append(parsed)
    profile.extra_env["LASSO_EXTRA_MOUNTS"] = json.dumps(extra_mounts)


def _load_env_file(path: str) -> list[str]:
    """Parse a dotenv file and return a list of KEY=VALUE strings.

    Skips empty lines and comments (lines starting with #).
    Does not expand variables or handle quoting beyond stripping
    surrounding single/double quotes from values.
    """
    from pathlib import Path as _Path

    env_path = _Path(path)
    if not env_path.is_file():
        err_console.print(f"[red]Error: Env file not found: {path}[/red]")
        raise typer.Exit(1)

    entries: list[str] = []
    for lineno, raw_line in enumerate(env_path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            err_console.print(
                f"[red]Error: Invalid line {lineno} in env file (expected KEY=VALUE): {raw_line}[/red]"
            )
            raise typer.Exit(1)
        key, _, value = line.partition("=")
        key = key.strip()
        # Strip surrounding quotes from value
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        entries.append(f"{key}={value}")
    return entries


def _apply_extra_env(
    profile: SandboxProfile,
    env_vars: list[str] | None,
    pass_env: list[str] | None,
) -> None:
    """Merge --env and --pass-env values into profile.extra_env."""
    if env_vars:
        for item in env_vars:
            if "=" not in item:
                err_console.print(f"[red]Error: Invalid --env value (expected KEY=VALUE): {item}[/red]")
                raise typer.Exit(1)
            key, _, value = item.partition("=")
            if key.upper() in _BLOCKED_ENV_KEYS:
                err_console.print(f"[red]Cannot set '{key}' — blocked for security[/red]")
                raise typer.Exit(1)
            for prefix in _BLOCKED_ENV_PREFIXES:
                if key.upper().startswith(prefix):
                    err_console.print(f"[red]Cannot set '{key}' — blocked prefix '{prefix}'[/red]")
                    raise typer.Exit(1)
            profile.extra_env[key] = value
    if pass_env:
        for name in pass_env:
            if name.upper() in _BLOCKED_ENV_KEYS:
                err_console.print(f"[red]Cannot pass '{name}' — blocked for security[/red]")
                raise typer.Exit(1)
            for prefix in _BLOCKED_ENV_PREFIXES:
                if name.upper().startswith(prefix):
                    err_console.print(f"[red]Cannot pass '{name}' — blocked prefix '{prefix}'[/red]")
                    raise typer.Exit(1)
            value = os.environ.get(name)
            if value is None:
                err_console.print(f"[yellow]Warning: --pass-env '{name}' is not set in host environment, skipping.[/yellow]")
            else:
                profile.extra_env[name] = value


def _apply_auto_mount_flags(
    profile: SandboxProfile,
    *,
    ssh: bool = False,
    no_auto_mount: bool = False,
) -> None:
    """Apply --ssh and --no-auto-mount flags to the profile.

    Controls auto-mounting of ~/.ssh and ~/.gitconfig inside the sandbox.
    The actual mounting is done by converter.py's _auto_mount_credentials()
    and is enabled by default. This function sets the control env vars that
    converter.py reads.

    - ``--no-auto-mount``: sets LASSO_NO_AUTO_MOUNT=1 to suppress all
      auto-credential mounts (SSH + gitconfig).
    - ``--ssh``: forces SSH mount even when --no-auto-mount is set, by
      adding an explicit extra mount via LASSO_EXTRA_MOUNTS.
    """
    if no_auto_mount:
        profile.extra_env["LASSO_NO_AUTO_MOUNT"] = "1"

    # --ssh overrides --no-auto-mount by adding an explicit mount
    if ssh:
        ssh_dir = Path.home() / ".ssh"
        if ssh_dir.is_dir():
            import json as _json
            existing = _json.loads(profile.extra_env.get("LASSO_EXTRA_MOUNTS", "[]"))
            existing.append({
                "source": str(ssh_dir),
                "target": "/home/agent/.ssh",
                "mode": "ro",
            })
            profile.extra_env["LASSO_EXTRA_MOUNTS"] = _json.dumps(existing)
        else:
            err_console.print("[yellow]Warning: --ssh specified but ~/.ssh does not exist, skipping.[/yellow]")


def _compute_structured_diff(a: dict, b: dict, prefix: str = "") -> list[dict]:
    """Compute a structured diff between two dicts, returning a list of change records."""
    changes: list[dict] = []
    all_keys = sorted(set(a) | set(b))

    for key in all_keys:
        path = f"{prefix}.{key}" if prefix else key
        a_val = a.get(key)
        b_val = b.get(key)

        if key not in a:
            changes.append({"path": path, "type": "added", "value": b_val})
        elif key not in b:
            changes.append({"path": path, "type": "removed", "value": a_val})
        elif a_val != b_val:
            if isinstance(a_val, dict) and isinstance(b_val, dict):
                changes.extend(_compute_structured_diff(a_val, b_val, path))
            else:
                changes.append({"path": path, "type": "changed", "old": a_val, "new": b_val})

    return changes


def _collect_check_data() -> dict:
    """Collect all system check data into a dict."""
    data: dict = {
        "platform": {
            "system": platform.system(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
            "lasso": __version__,
        },
    }

    # Container runtime
    from lasso.backends.detect import detect_backend
    backend = detect_backend()
    if backend:
        info = backend.get_info()
        data["container_runtime"] = {
            "available": True,
            **info,
        }
    else:
        data["container_runtime"] = {"available": False}

    # AI Agents
    from lasso.agents.registry import list_agents
    data["agents"] = list_agents()

    # Checkpoint version info
    from lasso.core.checkpoint import CheckpointStore
    cp_store = CheckpointStore()
    latest = cp_store.latest_checkpoint()
    pinned = cp_store.get_pinned_version()
    update = cp_store.check_for_update(__version__)
    data["version"] = {
        "current": __version__,
        "pinned_version": pinned,
        "latest_checkpoint": latest.version if latest else None,
        "update_available": update.version if update else None,
    }

    return data


def _check_json():
    """Output check results as JSON."""
    data = _collect_check_data()
    console.print_json(json.dumps(data, indent=2))


def _run_security_audit(
    profile_name: str,
    generate_checklist: bool,
    sign_off_name: str | None,
    output_json: bool,
) -> None:
    """Run a security audit against a sandbox profile."""
    import tempfile
    from datetime import datetime, timezone

    from lasso.core.security_audit import (
        ReviewSignoff,
        SecurityAuditor,
        compute_profile_hash,
        save_signoff,
    )

    # Resolve the profile (builtin or saved)
    if profile_name in BUILTIN_PROFILES:
        audit_dir = tempfile.mkdtemp(prefix="lasso-audit-")
        profile = BUILTIN_PROFILES[profile_name](audit_dir)
    else:
        try:
            profile = load_profile(profile_name)
        except FileNotFoundError:
            err_console.print(f"[red]Error: Profile '{profile_name}' not found.[/red]")
            err_console.print(f"[dim]Builtins: {', '.join(BUILTIN_PROFILES.keys())}[/dim]")
            err_console.print("[dim]Run 'lasso profile list' to see available profiles.[/dim]")
            raise typer.Exit(1)

    auditor = SecurityAuditor(profile)

    # Generate checklist mode
    if generate_checklist:
        console.print(auditor.generate_checklist())
        return

    # Run all checks
    results = auditor.run_all_checks()
    summary = auditor.summary()

    # JSON output mode
    if output_json:
        json_data = {
            "profile": profile_name,
            "profile_hash": compute_profile_hash(profile)[:12],
            "summary": summary,
            "checks": [
                {
                    "id": c.id,
                    "name": c.name,
                    "severity": c.severity,
                    "passed": c.passed,
                    "details": c.details,
                }
                for c in results
            ],
        }
        console.print_json(json.dumps(json_data, indent=2))
        return

    # Rich table output
    from rich.panel import Panel
    from rich.table import Table

    profile_hash = compute_profile_hash(profile)[:12]
    console.print(Panel.fit(
        f"[bold]Security Audit: {profile_name}[/bold]  (hash: {profile_hash})",
        border_style="blue",
    ))

    severity_colors = {
        "critical": "red",
        "high": "yellow",
        "medium": "cyan",
        "low": "dim",
    }

    table = Table(show_header=True, title="Security Checks")
    table.add_column("Status", width=6, justify="center")
    table.add_column("Severity", width=10)
    table.add_column("Check", min_width=25)
    table.add_column("Details")

    for check in results:
        status = "[green]PASS[/green]" if check.passed else "[red]FAIL[/red]"
        color = severity_colors.get(check.severity, "white")
        severity = f"[{color}]{check.severity.upper()}[/{color}]"
        table.add_row(status, severity, check.name, check.details)

    console.print(table)

    # Summary line
    console.print()
    if summary["failed"] == 0:
        console.print(
            f"[green]All {summary['total']} checks passed.[/green]"
        )
    else:
        console.print(
            f"[red]{summary['failed']} of {summary['total']} checks failed.[/red]"
        )
        if summary.get("critical_failed", 0) > 0:
            console.print(
                f"[bold red]{summary['critical_failed']} CRITICAL failure(s) "
                f"-- profile is not safe for deployment.[/bold red]"
            )

    # Sign-off mode
    if sign_off_name:
        reviewers_path = Path("REVIEWERS.md")
        signoff = ReviewSignoff(
            reviewer=sign_off_name,
            date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            profile_hash=compute_profile_hash(profile),
            version=profile.version,
            checks_passed=summary["passed"],
            checks_total=summary["total"],
            approved=summary["failed"] == 0,
        )
        save_signoff(signoff, reviewers_path)
        console.print()
        approved_str = "[green]APPROVED[/green]" if signoff.approved else "[red]NOT APPROVED[/red]"
        console.print(
            f"Sign-off recorded: {sign_off_name} -- {approved_str}"
        )
        console.print(f"Written to: {reviewers_path.resolve()}")


def _dry_run_create(profile: SandboxProfile, working_dir: str) -> None:
    """Show what would be created without actually creating containers."""
    from rich.panel import Panel

    from lasso.backends.converter import profile_to_container_config

    container_config = profile_to_container_config(profile)

    # Network rules summary
    net_rules = []
    net_mode = profile.network.mode.value.lower()
    if net_mode == "none":
        net_rules.append("All network access blocked")
    elif net_mode == "restricted":
        if profile.network.allowed_domains:
            net_rules.append(f"Allowed domains: {', '.join(profile.network.allowed_domains)}")
        if profile.network.allowed_ports:
            net_rules.append(f"Allowed ports: {', '.join(str(p) for p in profile.network.allowed_ports)}")
        if profile.network.blocked_domains:
            net_rules.append(f"Blocked domains: {', '.join(profile.network.blocked_domains)}")
        if not net_rules:
            net_rules.append("Restricted mode (no specific host/port rules defined)")
    else:
        net_rules.append("Full network access")

    # Environment vars (redact values)
    env_display = []
    for key in sorted(container_config.environment.keys()):
        env_display.append(f"{key}=***")

    # Mounts
    mount_display = []
    for mount in container_config.bind_mounts:
        src = mount.get("source", "?")
        dest = mount.get("target", "?")
        mode = mount.get("mode", "rw")
        mount_display.append(f"{src} -> {dest} ({mode})")

    console.print(Panel.fit(
        f"[bold yellow]DRY RUN[/bold yellow] -- no containers created\n\n"
        f"[bold]Profile Summary[/bold]\n"
        f"  Name:        {profile.name}\n"
        f"  Mode:        {profile.mode.value}\n"
        f"  Working dir: {working_dir}\n"
        f"  Commands:    {profile.commands.mode.value} "
        f"({len(profile.commands.whitelist)} whitelisted)\n"
        f"  Network:     {profile.network.mode.value}\n"
        f"  Resources:   {profile.resources.max_memory_mb}MB RAM, "
        f"{profile.resources.max_cpu_percent}% CPU\n"
        f"  Isolation:   {getattr(profile, 'isolation', 'container')}\n"
        f"  Audit:       {'enabled' if profile.audit.enabled else 'disabled'}\n\n"
        f"[bold]Container Config[/bold]\n"
        f"  Image:       lasso-{profile.name}:latest\n"
        f"  Container:   {container_config.name}\n"
        f"  Read-only:   {container_config.read_only_root}\n"
        f"  Memory:      {container_config.mem_limit}\n"
        f"  Mounts:      {len(container_config.bind_mounts)}\n"
        + ("".join(f"    {m}\n" for m in mount_display) if mount_display else "")
        + f"  Env vars:    {len(container_config.environment)}\n"
        + ("".join(f"    {e}\n" for e in env_display) if env_display else "")
        + "\n[bold]Network Rules[/bold]\n"
        + "".join(f"  {r}\n" for r in net_rules)
        + "\n[bold yellow]DRY RUN -- no containers created[/bold yellow]",
        border_style="yellow",
        title="LASSO Dry Run",
    ))


def _init_from_config(
    from_config: str,
    working_dir: str,
    lasso_dir: Path,
    output_json: bool,
) -> None:
    """Bootstrap a project from a shared team config directory."""
    config_dir = Path(from_config).resolve()
    if not config_dir.is_dir():
        err_console.print(f"[red]Error: Config directory not found: {config_dir}[/red]")
        raise typer.Exit(1)

    lasso_dir.mkdir(parents=True, exist_ok=True)
    (lasso_dir / "audit").mkdir(exist_ok=True)

    created_files: list[str] = []

    # 1. Copy lasso-config.toml -> .lasso/config.toml
    config_toml = config_dir / "lasso-config.toml"
    if config_toml.exists():
        dest = lasso_dir / "config.toml"
        shutil.copy2(str(config_toml), str(dest))
        created_files.append(str(dest))

    # 2. Copy profiles/ -> .lasso/profiles/
    profiles_src = config_dir / "profiles"
    if profiles_src.is_dir():
        profiles_dest = lasso_dir / "profiles"
        profiles_dest.mkdir(parents=True, exist_ok=True)
        for toml_file in profiles_src.glob("*.toml"):
            dest_file = profiles_dest / toml_file.name
            shutil.copy2(str(toml_file), str(dest_file))
            created_files.append(str(dest_file))

    # 3. Copy templates/ -> .lasso/templates/
    templates_src = config_dir / "templates"
    if templates_src.is_dir():
        templates_dest = lasso_dir / "templates"
        if templates_dest.exists():
            shutil.rmtree(str(templates_dest))
        shutil.copytree(str(templates_src), str(templates_dest))
        for root, _dirs, files in os.walk(str(templates_dest)):
            for fname in files:
                created_files.append(os.path.join(root, fname))

    # 4. Basic bootstrap checks
    checks: list[dict] = []
    checks.append({
        "check": "config_dir_exists",
        "status": "pass",
        "detail": str(config_dir),
    })
    checks.append({
        "check": "profiles_copied",
        "status": "pass" if any("profiles" in f for f in created_files) else "skip",
        "detail": f"{sum(1 for f in created_files if 'profiles' in f)} profile(s)",
    })
    checks.append({
        "check": "config_copied",
        "status": "pass" if config_toml.exists() else "skip",
        "detail": "lasso-config.toml" if config_toml.exists() else "not found in source",
    })
    checks.append({
        "check": "templates_copied",
        "status": "pass" if templates_src.is_dir() else "skip",
        "detail": "templates/" if templates_src.is_dir() else "not found in source",
    })

    if output_json:
        console.print_json(json.dumps({
            "status": "bootstrapped",
            "source": str(config_dir),
            "working_dir": working_dir,
            "files": created_files,
            "checks": checks,
        }, indent=2))
    else:
        console.print(f"[bold green]Team config bootstrapped[/bold green] from {config_dir}\n")
        for f in created_files:
            console.print(f"  [dim]Created: {f}[/dim]")
        console.print()
        for c in checks:
            icon = "[green]PASS[/green]" if c["status"] == "pass" else "[yellow]SKIP[/yellow]"
            console.print(f"  {icon}  {c['check']}: {c['detail']}")
        console.print(f"\n[dim]Project dir: {working_dir}[/dim]")
        console.print(f"[dim]LASSO dir:   {lasso_dir}[/dim]")


def _show_changelog(pinned_version: str | None, output_json: bool = False) -> None:
    """Read CHANGELOG.md and show entries since the pinned version (or all)."""
    import re

    # Find CHANGELOG.md relative to the lasso package directory
    pkg_dir = Path(__file__).resolve().parent.parent  # lasso/cli/helpers.py -> lasso/
    changelog_candidates = [
        pkg_dir.parent / "CHANGELOG.md",         # repo root
        pkg_dir / "CHANGELOG.md",                 # inside package
    ]

    changelog_path = None
    for candidate in changelog_candidates:
        if candidate.exists():
            changelog_path = candidate
            break

    if changelog_path is None:
        err_console.print("[red]CHANGELOG.md not found.[/red]")
        raise typer.Exit(1)

    content = changelog_path.read_text(encoding="utf-8")

    # Parse changelog into sections by version header: ## [x.y.z]
    version_pattern = re.compile(r"^## \[([^\]]+)\]", re.MULTILINE)
    matches = list(version_pattern.finditer(content))

    if not matches:
        if output_json:
            console.print_json(json.dumps({"entries": [], "since": pinned_version}, indent=2))
        else:
            console.print("[dim]No versioned entries found in CHANGELOG.md.[/dim]")
        return

    entries: list[dict] = []
    for i, match in enumerate(matches):
        ver = match.group(1)
        start = match.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
        body = content[start:end].strip()
        entries.append({"version": ver, "body": body})

    # Filter to entries since pinned version
    if pinned_version:
        filtered = []
        for entry in entries:
            if entry["version"] == pinned_version:
                break
            filtered.append(entry)
        if not filtered:
            filtered = entries  # pinned version not found, show all
    else:
        filtered = entries

    if output_json:
        data = {
            "since": pinned_version,
            "entries": [{"version": e["version"], "body": e["body"]} for e in filtered],
        }
        console.print_json(json.dumps(data, indent=2))
        return

    if pinned_version:
        console.print(f"[bold]Changelog since v{pinned_version}:[/bold]\n")
    else:
        console.print("[bold]Full changelog:[/bold]\n")

    for entry in filtered:
        console.print(entry["body"])
        console.print()


def _shutdown_handler(signum, frame):
    """Handle SIGINT/SIGTERM by shutting down the registry gracefully."""
    global _registry
    if _registry is not None:
        try:
            _registry.shutdown()
        except Exception:
            pass  # Best-effort during signal handling
    raise SystemExit(0)


def _register_signal_handlers():
    """Register signal handlers for graceful shutdown.

    Handles SIGINT and SIGTERM on all platforms, plus SIGBREAK on Windows.
    """
    signal.signal(signal.SIGINT, _shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)

    # Windows sends SIGBREAK on Ctrl+Break and when the console window is closed
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, _shutdown_handler)
