"""LASSO CLI — the primary interface for managing sandboxes.

Usage:
    lasso up                             # zero-config start (auto-detect everything)
    lasso down                           # stop all running sandboxes
    lasso why "command"                  # explain why a command is allowed/blocked
    lasso doctor                         # comprehensive system diagnostics
    lasso check                          # verify system + container runtime
    lasso init [--profile NAME]          # bootstrap project with .lasso/
    lasso create <profile> [--dir PATH]  # create and start a sandbox
    lasso exec <id> -- <command>         # run command in sandbox
    lasso shell [profile] [--dir PATH]   # create sandbox + attach real terminal
    lasso attach <id> [--shell SHELL]    # attach PTY to running sandbox
    lasso status [id]                    # show sandbox status
    lasso stop <id|all>                  # stop sandbox(es)
    lasso profile list|show|save|delete  # manage profiles
    lasso audit view|verify|export       # audit log tools
    lasso dashboard                      # launch web UI

Aliases:
    lasso ps   → lasso status
    lasso rm   → lasso stop
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path

import typer
from rich.panel import Panel
from rich.table import Table

from lasso import __version__
from lasso.config.defaults import BUILTIN_PROFILES
from lasso.config.profile import save_profile
from lasso.config.schema import ProfileMode

# Import sub-app Typer instances
from .agents_cmds import agent_app
from .audit_cmds import audit_app
from .auth_cmds import auth_app
from .checkpoints import checkpoint_app
from .config_cmds import config_app
from .constants import console, err_console
from .helpers import (
    _apply_auto_mount_flags,
    _apply_extra_env,
    _apply_mounts,
    _check_json,
    _collect_check_data,
    _dry_run_create,
    _get_registry,
    _init_from_config,
    _load_env_file,
    _register_signal_handlers,
    _resolve_profile,
    _run_security_audit,
    _show_changelog,
    _validate_agent,
)
from .profiles import profile_app
from .sandbox_cmds import register_sandbox_commands


def _version_callback(value: bool):
    if value:
        print(f"lasso {__version__}")
        raise typer.Exit()


def _main_callback(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
):
    """LASSO -- Layered Agent Sandbox Security Orchestrator."""


app = typer.Typer(
    name="lasso",
    help="LASSO — Layered Agent Sandbox Security Orchestrator",
    no_args_is_help=True,
    rich_markup_mode="rich",
    callback=_main_callback,
)

# Register sub-apps
app.add_typer(profile_app, name="profile")
app.add_typer(audit_app, name="audit")
app.add_typer(agent_app, name="agent")
app.add_typer(auth_app, name="auth")
app.add_typer(checkpoint_app, name="checkpoint")
app.add_typer(config_app, name="config")

# Register sandbox lifecycle commands (up, shell, attach) from sandbox_cmds
register_sandbox_commands(app)


# -----------------------------------------------------------------------
# Doctor (comprehensive diagnostics)
# -----------------------------------------------------------------------

@app.command()
def doctor(
    output_json: bool = typer.Option(False, "--json", help="Output as JSON."),
    fix: bool = typer.Option(False, "--fix", help="Attempt to fix issues automatically."),
    team: bool = typer.Option(False, "--team", help="Run team-mode checks (profile dir, extends, version pin, locks)."),
):
    """Run comprehensive system diagnostics.

    Checks everything needed for LASSO to function correctly and
    reports issues with remediation hints.

    Checks include: Python version, container runtime, permissions,
    LASSO directory, API keys, signing key location, profile validation,
    network tools, disk space, and state file.

    With --team, also checks: LASSO_PROFILE_DIR validity, extends resolution,
    version pin consistency, and profile lock integrity. Team checks also run
    automatically when LASSO_PROFILE_DIR is set.

    Use --fix to auto-create ~/.lasso/ and generate an API key if missing.
    Use --json for structured output suitable for scripting.
    """
    from lasso.cli.doctor import run_doctor

    report = run_doctor(output_json=output_json, fix=fix, team=team, console=console)
    if report.failed:
        raise typer.Exit(1)


# -----------------------------------------------------------------------
# Prebuild preset images
# -----------------------------------------------------------------------

@app.command()
def prebuild(
    force: bool = typer.Option(False, "--force", "-f", help="Rebuild even if images exist."),
    ca_cert: str | None = typer.Option(None, "--ca-cert", help="Path to corporate CA certificate (PEM) for image builds."),
    agent: str | None = typer.Option(None, "--agent", "-a", help="Only build this agent's image (e.g. opencode, claude-code)."),
):
    """Pre-build all sandbox preset images for instant startup.

    Builds images for: base (no agent), Claude Code, OpenCode.
    First run downloads dependencies (~1-2 min per agent). After that,
    sandbox creation is near-instant.

    Run this once after installing LASSO, or after upgrading.

    Use --ca-cert to inject a corporate CA certificate into images so that
    tools like curl/pip/npm trust your proxy's TLS interception certificate.

    Use --agent to build only a specific agent's image instead of all presets.
    """
    from lasso.backends.image_builder import prebuild_presets

    registry = _get_registry()
    if not registry._backend:
        err_console.print("[red]Error: No container runtime (Docker/Podman) found.[/red]")
        raise typer.Exit(1)

    # Resolve CA cert: explicit flag > operational config > None
    ca_cert_path = ca_cert
    if not ca_cert_path:
        from lasso.config.operational import load_config
        op_config = load_config()
        ca_cert_path = op_config.containers.ca_cert_path

    # Build agent filter list from --agent flag
    agents_filter: list[str] | None = None
    if agent:
        from lasso.backends.image_builder import AGENT_BASE_IMAGES, AGENT_INSTALLS
        known = sorted(set(AGENT_INSTALLS) | set(AGENT_BASE_IMAGES) | {"base"})
        if agent not in known:
            err_console.print(f"[red]Error: Unknown agent '{agent}'. Known agents: {', '.join(known)}[/red]")
            raise typer.Exit(1)
        agents_filter = [agent]

    if agent:
        console.print(f"[bold]Pre-building image for agent: {agent}...[/bold]\n")
    else:
        console.print("[bold]Pre-building sandbox images...[/bold]\n")
    if ca_cert_path:
        console.print(f"[dim]CA certificate: {ca_cert_path}[/dim]")

    results = prebuild_presets(registry._backend, force=force, ca_cert_path=ca_cert_path, agents=agents_filter)

    table = Table(show_header=True, title="Preset Images")
    table.add_column("Preset", style="bold")
    table.add_column("Image Tag")
    table.add_column("Status")

    for name, tag in results.items():
        table.add_row(name, tag, "[green]Ready[/green]")

    console.print(table)
    console.print(f"\n[green]All {len(results)} preset images are ready.[/green]")
    console.print("[dim]Sandbox creation will now be near-instant.[/dim]")


# -----------------------------------------------------------------------
# System check
# -----------------------------------------------------------------------

@app.command()
def check(
    output_json: bool = typer.Option(False, "--json", help="Output results as JSON."),
    security_audit: bool = typer.Option(False, "--security-audit", "-s", help="Run security audit against a profile."),
    profile_name: str | None = typer.Option(None, "--profile", "-p", help="Profile to audit (default: standard)."),
    generate_checklist: bool = typer.Option(False, "--generate-checklist", help="Output Markdown checklist for manual review."),
    sign_off: str | None = typer.Option(None, "--sign-off", help="Record a reviewer sign-off (name of reviewer)."),
):
    """Check system capabilities and container runtime.

    Verifies that a container runtime (Docker or Podman) is available,
    lists detected AI agents, and checks platform-specific capabilities.

    With --security-audit, runs security checks against a sandbox profile.
    With --generate-checklist, outputs a Markdown checklist for human review.
    With --sign-off <name>, records a reviewer sign-off in REVIEWERS.md.
    """
    # Security audit mode
    if security_audit or generate_checklist or sign_off:
        _run_security_audit(
            profile_name=profile_name or "standard",
            generate_checklist=generate_checklist,
            sign_off_name=sign_off,
            output_json=output_json,
        )
        return

    if output_json:
        _check_json()
        return

    with console.status("[bold blue]Checking system capabilities..."):
        check_data = _collect_check_data()

    console.print(Panel.fit(
        "[bold]LASSO System Capability Check[/bold]",
        border_style="blue",
    ))

    # Platform info
    table = Table(show_header=True, title="System")
    table.add_column("Property", style="bold")
    table.add_column("Value")
    table.add_row("Platform", check_data["platform"]["system"])
    table.add_row("Architecture", check_data["platform"]["architecture"])
    table.add_row("Python", check_data["platform"]["python"])
    table.add_row("LASSO", check_data["platform"]["lasso"])

    # Version / checkpoint row
    ver_info = check_data.get("version", {})
    latest_cp = ver_info.get("latest_checkpoint")
    pinned = ver_info.get("pinned_version")
    if latest_cp:
        version_val = f"{__version__} (latest checkpoint: {latest_cp})"
        if ver_info.get("update_available"):
            version_val += " [yellow]update available[/yellow]"
    else:
        version_val = __version__
    if pinned:
        version_val += f" [cyan](pinned: {pinned})[/cyan]"
    table.add_row("Version", version_val)

    console.print(table)
    console.print()

    # Container runtime
    table = Table(show_header=True, title="Container Runtime")
    table.add_column("Property", style="bold")
    table.add_column("Status")

    rt = check_data["container_runtime"]
    if rt["available"]:
        table.add_row("Runtime", f"[green]{rt.get('runtime', 'unknown')}[/green]")
        table.add_row("Version", rt.get("version", "unknown"))
        table.add_row("OS", rt.get("os", "unknown"))
        table.add_row("Storage", rt.get("storage_driver", "unknown"))
        table.add_row("Status", "[green]Available[/green]")
    else:
        table.add_row("Runtime", "[red]Not found[/red]")
        table.add_row("Status", "[red]Unavailable[/red]")
        table.add_row("Action", "Install Docker or Podman, then run 'lasso check'.")

    console.print(table)

    # AI Agents
    console.print()
    at = Table(show_header=True, title="AI Agent Support")
    at.add_column("Agent", style="bold")
    at.add_column("Status")
    at.add_column("Version")
    at.add_column("Priority")
    for i, a in enumerate(check_data["agents"]):
        installed = "[green]Installed[/green]" if a["installed"] else "[dim]Not found[/dim]"
        ver = a.get("version") or "-"
        priority = "[bold cyan]Default[/bold cyan]" if i == 0 else str(i + 1)
        at.add_row(a["name"], installed, ver, priority)
    console.print(at)


# -----------------------------------------------------------------------
# Init
# -----------------------------------------------------------------------

@app.command()
def init(
    profile_name: str = typer.Option("standard", "--profile", "-p", help="Profile template."),
    working_dir: str = typer.Option(".", "--dir", "-d", help="Project directory."),
    agent: str | None = typer.Option(None, "--agent", "-a", help="Agent: claude-code, opencode, or auto."),
    templates: str | None = typer.Option(None, "--templates", help="Team template directory for agent configs."),
    no_overwrite: bool = typer.Option(False, "--no-overwrite", help="Skip files that already exist."),
    merge: bool = typer.Option(False, "--merge", help="Merge with existing agent configs instead of overwriting."),
    from_config: str | None = typer.Option(None, "--from-config", help="Path to team config directory to bootstrap from."),
    output_json: bool = typer.Option(False, "--json", help="Output created file paths as JSON."),
):
    """Initialize a project directory with LASSO sandbox config and agent configs.

    Creates a .lasso/ directory with a profile.toml and agent-specific config
    files. If no --agent is specified, auto-detects the best available agent.

    With --from-config, bootstraps from a shared team config directory:
    copies profiles/, lasso-config.toml, and templates/ into .lasso/.

    Example:
        lasso init --profile data-analysis --dir ./my-project
        lasso init --from-config /team/lasso-config --dir ./my-project
    """
    working_dir = str(Path(working_dir).resolve())
    lasso_dir = Path(working_dir) / ".lasso"

    # --from-config: team bootstrap mode
    if from_config:
        _init_from_config(from_config, working_dir, lasso_dir, output_json)
        return

    if (lasso_dir / "profile.toml").exists():
        err_console.print(f"[yellow]Already initialized:[/yellow] {lasso_dir}/profile.toml")
        err_console.print("[dim]Edit it directly or delete .lasso/ to reinitialize.[/dim]")
        raise typer.Exit(1)

    if profile_name not in BUILTIN_PROFILES:
        err_console.print(f"[red]Error: Unknown profile '{profile_name}'.[/red]")
        err_console.print(f"[dim]Available: {', '.join(BUILTIN_PROFILES.keys())}[/dim]")
        err_console.print("[dim]Run 'lasso profile list' to see all profiles.[/dim]")
        raise typer.Exit(1)

    with console.status("[bold blue]Initializing project..."):
        lasso_dir.mkdir(parents=True, exist_ok=True)
        (lasso_dir / "audit").mkdir(exist_ok=True)

        profile = BUILTIN_PROFILES[profile_name](working_dir)
        profile.audit.log_dir = str(lasso_dir / "audit")
        save_profile(profile, profile_dir=lasso_dir)

        # Rename to profile.toml
        src = lasso_dir / f"{profile.name}.toml"
        dest = lasso_dir / "profile.toml"
        if src.exists():
            src.rename(dest)

        # Generate agent-specific configs
        from lasso.agents.base import AgentType
        from lasso.agents.registry import detect_agent, get_provider, write_agent_config

        if agent and agent != "auto":
            try:
                provider = get_provider(AgentType(agent))
            except ValueError:
                err_console.print(f"[red]Error: Unknown agent '{agent}'.[/red]")
                err_console.print(
                    "[dim]Supported: claude-code, opencode[/dim]"
                )
                raise typer.Exit(1)
        else:
            provider = detect_agent()

        agent_name = "none"
        written_files: list = []
        if provider:
            agent_config = provider.generate_config(profile)
            written_files = write_agent_config(
                agent_config,
                working_dir,
                templates_dir=templates,
                no_overwrite=no_overwrite,
                merge=merge,
            )
            agent_name = provider.display_name

    for f in written_files:
        console.print(f"  [dim]Agent config: {f}[/dim]")

    if output_json:
        console.print_json(json.dumps({
            "status": "initialized",
            "profile": profile_name,
            "agent": agent_name,
            "config": str(dest),
            "working_dir": working_dir,
            "files": [str(dest)] + [str(f) for f in written_files],
        }, indent=2))
    else:
        console.print(Panel.fit(
            f"[bold green]LASSO initialized[/bold green]\n\n"
            f"  Profile:     {profile_name}\n"
            f"  Agent:       {agent_name}\n"
            f"  Config:      {dest}\n"
            f"  Audit dir:   {lasso_dir / 'audit'}\n"
            f"  Working dir: {working_dir}\n\n"
            f"  Commands:    {profile.commands.mode.value} "
            f"({len(profile.commands.whitelist)} tools)\n"
            f"  Network:     {profile.network.mode.value}\n"
            f"  Memory:      {profile.resources.max_memory_mb}MB\n\n"
            f"Next: [bold]lasso create auto --dir {working_dir}[/bold]",
            border_style="green",
            title="LASSO",
        ))


# -----------------------------------------------------------------------
# Up / Down — docker-compose-style shortcuts
# -----------------------------------------------------------------------

# up, shell, attach commands are registered from sandbox_cmds.py
# (see register_sandbox_commands call after app creation)


@app.command()
def down(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt."),
):
    """Stop all running sandboxes.

    Equivalent to 'lasso stop all --yes'.

    Examples:
        lasso down              # stop everything
        lasso down --yes        # skip confirmation
    """
    registry = _get_registry(quiet=True)
    sandboxes = registry.list_all()
    count = len([s for s in sandboxes if s["state"] == "running"])

    if count == 0:
        console.print("[dim]No running sandboxes.[/dim]")
        return

    if not yes:
        typer.confirm(f"Stop all {count} running sandbox(es)?", abort=True)

    stopped = registry.stop_all()
    console.print(f"[green]Stopped {stopped} sandbox(es).[/green]")


@app.command()
def why(
    command: str = typer.Argument(help="Command to check (quote if it contains spaces)."),
    profile_name: str = typer.Option("standard", "--profile", "-p", help="Profile to check against."),
    mode_str: str = typer.Option("autonomous", "--mode", "-m", help="Profile mode: observe, assist, autonomous."),
    working_dir: str = typer.Option(".", "--dir", "-d", help="Working directory for profile resolution."),
):
    """Explain why a command would be allowed or blocked.

    Runs the command through the security gate in dry-run mode and
    shows which validation stage produced the verdict.

    Examples:
        lasso why "pip install requests"
        lasso why "git push --force" --profile strict
        lasso why "rm -rf /" --mode observe
    """
    from lasso.core.commands import CommandGate

    working_dir = str(Path(working_dir).resolve())
    profile = _resolve_profile(profile_name, working_dir, quiet=True)

    try:
        target_mode = ProfileMode(mode_str)
    except ValueError:
        err_console.print(f"[red]Error: Invalid mode '{mode_str}'.[/red]")
        err_console.print("[dim]Valid modes: observe, assist, autonomous[/dim]")
        raise typer.Exit(1)

    gate = CommandGate(profile.commands, mode=target_mode)
    verdict = gate.check(command)

    if verdict.allowed:
        console.print(Panel.fit(
            f"[bold green]ALLOWED[/bold green]\n\n"
            f"  Command:  {verdict.command}\n"
            f"  Args:     {' '.join(verdict.args) if verdict.args else '(none)'}\n"
            f"  Profile:  {profile_name}\n"
            f"  Mode:     {target_mode.value}\n\n"
            f"  The command passed all validation stages:\n"
            f"    1. Input sanitization (control chars, null bytes)\n"
            f"    2. Shell operator check\n"
            f"    3. Whitelist/blacklist check\n"
            f"    4. Blocked argument patterns\n"
            f"    5. Dangerous argument detection\n"
            f"    6. Path traversal check\n"
            f"    7. Plugin hooks",
            border_style="green",
            title="Command Gate: ALLOWED",
        ))
    else:
        console.print(Panel.fit(
            f"[bold red]BLOCKED[/bold red]\n\n"
            f"  Command:  {verdict.command}\n"
            f"  Args:     {' '.join(verdict.args) if verdict.args else '(none)'}\n"
            f"  Profile:  {profile_name}\n"
            f"  Mode:     {target_mode.value}\n\n"
            f"  Reason:   {verdict.reason}",
            border_style="red",
            title="Command Gate: BLOCKED",
        ))

    # Show whitelist context for blocked commands
    if verdict.blocked and profile.commands.whitelist:
        active = gate._active_whitelist()
        if verdict.command and verdict.command not in active:
            # Show similar commands that ARE allowed
            similar = [c for c in sorted(active) if verdict.command[:3] in c]
            if similar:
                console.print(f"\n[dim]Similar allowed commands: {', '.join(similar[:5])}[/dim]")
            console.print(f"[dim]Total commands in {target_mode.value} whitelist: {len(active)}[/dim]")


# -----------------------------------------------------------------------
# Sandbox lifecycle
# -----------------------------------------------------------------------

@app.command()
def create(
    profile_name: str = typer.Argument("auto", help="Profile name (builtin, saved, or 'auto' to use .lasso/profile.toml)."),
    working_dir: str = typer.Option(".", "--dir", "-d", help="Working directory."),
    file: str | None = typer.Option(None, "--file", "-f", help="Load profile from TOML file."),
    native: bool = typer.Option(False, "--native", help="Use native mode (no container)."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Print only the sandbox ID."),
    mode_str: str | None = typer.Option(None, "--mode", "-m", help="Profile mode: observe, assist, or autonomous."),
    env_vars: list[str] | None = typer.Option(None, "--env", "-e", help="Pass environment variable (KEY=VALUE). Repeatable."),
    pass_env: list[str] | None = typer.Option(None, "--pass-env", help="Pass host env var into sandbox by name. Repeatable."),
    isolation: str | None = typer.Option(None, "--isolation", "-I", help="Isolation level: container (default), gvisor, or kata."),
    agent: str | None = typer.Option(None, "--agent", "-a", help="Pre-install AI agent: claude-code or opencode."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be created without actually creating containers."),
    mount: list[str] | None = typer.Option(None, "--mount", "-v", help="Mount extra directory. Format: /host/path:/container/path or /host/path:/container/path:ro"),
    session_volume: str | None = typer.Option(None, "--session-volume", help="Named Docker volume for agent state persistence."),
    docker: bool = typer.Option(False, "--docker", help="Enable Docker-from-Docker via socket proxy."),
    ssh: bool = typer.Option(False, "--ssh", help="Force-mount ~/.ssh read-only into sandbox."),
    no_auto_mount: bool = typer.Option(False, "--no-auto-mount", help="Disable auto-mounting SSH keys and git config."),
    env_file: str | None = typer.Option(None, "--env-file", help="Load environment variables from a dotenv file."),
):
    """Create a new sandbox from a profile.

    If profile is 'auto' (default), reads from .lasso/profile.toml in the
    working directory. Use 'lasso init' to set up a project first.
    Auto-mounts ~/.ssh and ~/.gitconfig (read-only) if they exist.
    Use --no-auto-mount to disable.

    Examples:
        lasso create                       # auto-resolve from .lasso/
        lasso create standard --dir .      # use builtin profile
        lasso create --file custom.toml    # use TOML file
        lasso create --quiet               # print only sandbox ID
        lasso create --mode autonomous     # start in autonomous mode
        lasso create --dry-run             # preview without creating
        lasso create --agent claude-code   # pre-install Claude Code CLI
        lasso create --mount /data/shared:/data:ro  # mount extra folder
        lasso create --no-auto-mount       # skip auto SSH/gitconfig mounts
    """
    working_dir = str(Path(working_dir).resolve())
    profile = _resolve_profile(profile_name, working_dir, file, quiet=quiet)

    # Override profile mode if --mode flag was provided
    if mode_str:
        try:
            profile.mode = ProfileMode(mode_str)
        except ValueError:
            err_console.print(f"[red]Error: Invalid mode '{mode_str}'.[/red]")
            err_console.print("[dim]Valid modes: observe, assist, autonomous[/dim]")
            raise typer.Exit(1)

    # Load env file entries (before --env so explicit overrides win)
    combined_env_vars = list(env_vars or [])
    if env_file:
        file_entries = _load_env_file(env_file)
        env_file_keys = {e.partition("=")[0] for e in file_entries}
        combined_env_vars = file_entries + combined_env_vars
        _apply_extra_env(profile, combined_env_vars, pass_env)
        # Mark env-file keys for audit redaction
        profile.extra_env["_LASSO_REDACT_KEYS"] = ",".join(sorted(env_file_keys))
    else:
        _apply_extra_env(profile, combined_env_vars, pass_env)

    # Store agent choice for image builder
    _validate_agent(agent, profile)

    # Override isolation level if --isolation flag was provided
    if isolation:
        if isolation not in ("container", "gvisor", "kata"):
            err_console.print(f"[red]Error: Invalid isolation level '{isolation}'.[/red]")
            err_console.print("[dim]Valid levels: container, gvisor, kata[/dim]")
            raise typer.Exit(1)
        profile.isolation = isolation

    # Parse --mount flags into extra mounts stored as JSON in extra_env
    _apply_mounts(profile, mount)

    # Apply session volume override
    if session_volume:
        profile.filesystem.session_volume = session_volume

    # Enable Docker-from-Docker via socket proxy
    if docker:
        profile.docker_from_docker = True

    # Auto-mount control flags
    _apply_auto_mount_flags(profile, ssh=ssh, no_auto_mount=no_auto_mount)

    # --dry-run: show what would be created without actually doing it
    if dry_run:
        _dry_run_create(profile, working_dir)
        return

    # Check for newer checkpoint after profile resolution
    if not quiet:
        from lasso.core.checkpoint import CheckpointStore
        _cp_store = CheckpointStore()
        _update = _cp_store.check_for_update(__version__)
        if _update:
            console.print(
                f"[yellow]LASSO v{_update.version} is available "
                f"(current: v{__version__}). "
                f"Run 'lasso checkpoint list' for details.[/yellow]"
            )

    registry = _get_registry(native=native, quiet=quiet)

    if quiet:
        sandbox = registry.create(profile)
        registry.start(sandbox)
        console.print(sandbox.id)
        return

    with console.status("[bold blue]Creating sandbox..."):
        sandbox = registry.create(profile)

    with console.status("[bold blue]Starting sandbox..."):
        registry.start(sandbox)

    console.print(Panel.fit(
        f"[bold green]Sandbox created and running[/bold green]\n\n"
        f"  ID:          [bold cyan]{sandbox.id}[/bold cyan]\n"
        f"  Name:        {profile.name}\n"
        f"  Mode:        {sandbox.mode.value}\n"
        f"  Working dir: {working_dir}\n"
        f"  Backend:     {sandbox.status()['backend']}\n"
        f"  Commands:    {profile.commands.mode.value}\n"
        f"  Network:     {profile.network.mode.value}\n"
        f"  Audit log:   {sandbox.audit.log_file}\n\n"
        f"Run commands: [bold]lasso exec {sandbox.id} -- ls[/bold]\n"
        f"Set mode:     [bold]lasso mode {sandbox.id} autonomous[/bold]\n"
        f"Shell:        [bold]lasso attach {sandbox.id}[/bold]",
        border_style="green",
        title="LASSO",
    ))


@app.command(name="exec")
def exec_cmd(
    sandbox_id: str = typer.Argument(help="Sandbox ID."),
    command: list[str] = typer.Argument(help="Command to execute."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Check if command would be allowed without executing."),
):
    """Execute a command inside a sandbox.

    Use '--' to separate lasso arguments from the sandbox command.

    Example:
        lasso exec abc123 -- ls -la
        lasso exec abc123 -- python3 script.py
        lasso exec abc123 --dry-run -- rm -rf /
    """
    registry = _get_registry()
    sandbox = registry.get(sandbox_id)
    if not sandbox:
        err_console.print(f"[red]Error: Sandbox '{sandbox_id}' not found.[/red]")
        err_console.print("[dim]Run 'lasso status' to see active sandboxes.[/dim]")
        raise typer.Exit(1)

    raw = shlex.join(command)

    # --dry-run: validate through command gate without executing
    if dry_run:
        from lasso.core.commands import CommandGate
        gate = CommandGate(sandbox.profile.commands, sandbox.mode)
        verdict = gate.check(raw)
        if verdict.allowed:
            console.print(f"[bold green]ALLOWED[/bold green]  {raw}")
            console.print(f"  [dim]Reason: {verdict.reason or 'Passes all command gate checks'}[/dim]")
        else:
            console.print(f"[bold red]BLOCKED[/bold red]  {raw}")
            console.print(f"  [dim]Reason: {verdict.reason}[/dim]")
            raise typer.Exit(1)
        console.print("\n[bold yellow]DRY RUN -- command not executed[/bold yellow]")
        return

    result = sandbox.exec(raw)

    if result.blocked:
        console.print(f"[red bold]BLOCKED[/red bold] {result.block_reason}")
        raise typer.Exit(1)

    if result.stdout:
        console.print(result.stdout, end="")
    if result.stderr:
        err_console.print(result.stderr, end="")
    if result.duration_ms > 0:
        console.print(f"[dim]({result.duration_ms}ms)[/dim]")

    raise typer.Exit(result.exit_code)


@app.command()
def status(
    sandbox_id: str | None = typer.Argument(None, help="Sandbox ID (omit for all)."),
    output_json: bool = typer.Option(False, "--json", help="Output raw JSON."),
):
    """Show sandbox status.

    Without arguments, lists all active sandboxes. Pass a sandbox ID to
    see detailed status for a single sandbox.
    """
    registry = _get_registry(quiet=output_json)

    if sandbox_id:
        sandbox = registry.get(sandbox_id)
        if not sandbox:
            err_console.print(f"[red]Error: Sandbox '{sandbox_id}' not found.[/red]")
            err_console.print("[dim]Run 'lasso status' to see active sandboxes.[/dim]")
            raise typer.Exit(1)
        console.print_json(json.dumps(sandbox.status(), indent=2))
    else:
        sandboxes = registry.list_all()

        if output_json:
            console.print_json(json.dumps(sandboxes, indent=2))
            return

        if not sandboxes:
            console.print("[dim]No sandboxes running.[/dim]")
            return

        table = Table(title="LASSO Sandboxes", show_header=True)
        table.add_column("ID", style="bold cyan")
        table.add_column("Name")
        table.add_column("State")
        table.add_column("Mode")
        table.add_column("Backend")
        table.add_column("Cmds")
        table.add_column("Net")
        table.add_column("Execs")
        table.add_column("Blocked")

        for s in sandboxes:
            state_color = {
                "running": "green", "stopped": "dim", "error": "red",
            }.get(s["state"], "yellow")
            mode_color = {
                "observe": "blue", "assist": "yellow", "autonomous": "red",
            }.get(s.get("mode", "observe"), "dim")
            table.add_row(
                s["id"], s["name"],
                f"[{state_color}]{s['state']}[/{state_color}]",
                f"[{mode_color}]{s.get('mode', 'observe')}[/{mode_color}]",
                s.get("backend", "native"),
                s["command_mode"], s["network_mode"],
                str(s["exec_count"]), str(s["blocked_count"]),
            )

        console.print(table)


# Alias: lasso ps → lasso status
@app.command(name="ps", hidden=True)
def ps_alias(
    sandbox_id: str | None = typer.Argument(None, help="Sandbox ID (omit for all)."),
    output_json: bool = typer.Option(False, "--json", help="Output raw JSON."),
):
    """Alias for 'status'. Show sandbox status."""
    status(sandbox_id=sandbox_id, output_json=output_json)


@app.command()
def stop(
    sandbox_id: str = typer.Argument(help="Sandbox ID, or 'all'."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt."),
):
    """Stop a sandbox (or all sandboxes with 'all').

    Use --yes to skip the confirmation prompt for 'stop all'.
    """
    registry = _get_registry()
    if sandbox_id == "all":
        sandboxes = registry.list_all()
        count = len([s for s in sandboxes if s["state"] == "running"])
        if not yes:
            if count == 0:
                console.print("[dim]No running sandboxes to stop.[/dim]")
                return
            typer.confirm(f"Stop all {count} running sandbox(es)?", abort=True)
        stopped = registry.stop_all()
        console.print(f"[green]Stopped {stopped} sandbox(es).[/green]")
    else:
        if registry.stop(sandbox_id):
            console.print(f"[green]Sandbox {sandbox_id} stopped.[/green]")
        else:
            err_console.print(f"[red]Error: Sandbox '{sandbox_id}' not found.[/red]")
            err_console.print("[dim]Run 'lasso status' to see active sandboxes.[/dim]")
            raise typer.Exit(1)


# Alias: lasso rm → lasso stop
@app.command(name="rm", hidden=True)
def rm_alias(
    sandbox_id: str = typer.Argument(help="Sandbox ID, or 'all'."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt."),
):
    """Alias for 'stop'. Stop a sandbox."""
    stop(sandbox_id=sandbox_id, yes=yes)


@app.command(name="mode")
def mode_cmd(
    sandbox_id: str = typer.Argument(help="Sandbox ID."),
    new_mode: str = typer.Argument(help="New mode: observe, assist, or autonomous."),
):
    """Change the profile mode of a running sandbox.

    Controls the level of command access:
      observe    - read-only commands only (ls, cat, grep, etc.)
      assist     - curated development commands (+ python3, git, pip, etc.)
      autonomous - full whitelist from the profile

    Example:
        lasso mode abc123 autonomous
    """
    try:
        target_mode = ProfileMode(new_mode)
    except ValueError:
        err_console.print(f"[red]Error: Invalid mode '{new_mode}'.[/red]")
        err_console.print("[dim]Valid modes: observe, assist, autonomous[/dim]")
        raise typer.Exit(1)

    registry = _get_registry()
    sandbox = registry.get(sandbox_id)
    if not sandbox:
        err_console.print(f"[red]Error: Sandbox '{sandbox_id}' not found.[/red]")
        err_console.print("[dim]Run 'lasso status' to see active sandboxes.[/dim]")
        raise typer.Exit(1)

    old_mode = sandbox.mode.value
    registry.set_mode(sandbox_id, target_mode)
    console.print(
        f"[green]Sandbox {sandbox_id} mode changed:[/green] "
        f"{old_mode} -> [bold]{target_mode.value}[/bold]"
    )


# -----------------------------------------------------------------------
# Terminal attach commands
# -----------------------------------------------------------------------


# -----------------------------------------------------------------------
# Dashboard
# -----------------------------------------------------------------------

@app.command()
def dashboard(
    port: int = typer.Option(8080, "--port", "-p", help="Dashboard port."),
    host: str = typer.Option("127.0.0.1", "--host", help="Dashboard host."),
):
    """Launch the LASSO web dashboard."""
    try:
        from lasso.dashboard.app import create_app
    except ImportError:
        err_console.print("[red]Error: Flask is not installed.[/red]")
        err_console.print("[dim]Install it with: pip install lasso-sandbox[dashboard][/dim]")
        raise typer.Exit(1)

    registry = _get_registry()
    backend = registry._backend

    web_app = create_app(registry=registry, backend=backend)
    console.print(Panel.fit(
        f"[bold]LASSO Dashboard[/bold]\n"
        f"http://{host}:{port}",
        border_style="blue",
    ))
    web_app.run(host=host, port=port, debug=False)


# -----------------------------------------------------------------------
# Shell completions
# -----------------------------------------------------------------------

@app.command()
def completions():
    """Show how to install shell completions for LASSO.

    Typer provides built-in shell completion support for bash, zsh,
    fish, and PowerShell.
    """
    console.print(Panel.fit(
        "[bold]Shell Completions[/bold]\n\n"
        "Install completions for your shell:\n\n"
        "  [bold cyan]lasso --install-completion[/bold cyan]    Install completion for current shell\n"
        "  [bold cyan]lasso --show-completion[/bold cyan]       Show completion script (for manual install)\n\n"
        "Supported shells: bash, zsh, fish, PowerShell\n\n"
        "After installing, restart your shell or source the config file.",
        border_style="blue",
        title="LASSO Shell Completions",
    ))


# -----------------------------------------------------------------------
# Quickstart — guided setup wizard
# -----------------------------------------------------------------------

@app.command()
def quickstart(
    working_dir: str = typer.Option(".", "--dir", "-d", help="Project directory."),
    agent: str | None = typer.Option(None, "--agent", "-a", help="AI agent: claude-code or opencode."),
    docker: bool = typer.Option(False, "--docker", help="Enable Docker-from-Docker."),
    ca_cert: str | None = typer.Option(None, "--ca-cert", help="Path to corporate CA certificate (PEM) for image builds."),
):
    """Guided setup: run doctor checks, detect agent, build images, and print next steps.

    Runs through the full setup pipeline so you can go from zero to a running
    sandbox in one command.  Steps that are already done (image cached, proxy
    running) are skipped automatically.

    Examples:
        lasso quickstart                         # auto-detect everything
        lasso quickstart --agent claude-code     # force a specific agent
        lasso quickstart --docker                # enable Docker-from-Docker
        lasso quickstart --dir ~/my-project      # set project directory
    """
    from lasso.cli.doctor import run_doctor

    working_dir = str(Path(working_dir).resolve())

    # Step 1: Doctor checks
    console.print("[bold]Step 1/4:[/bold] Running system diagnostics...")
    with console.status("[bold blue]Checking system..."):
        report = run_doctor(output_json=False, fix=True, console=console)

    if report.failed:
        err_console.print(
            "\n[red]System checks failed. Fix the issues above before continuing.[/red]"
        )
        raise typer.Exit(1)
    console.print("[green]System checks passed.[/green]\n")

    # Step 2: Auto-detect agent
    console.print("[bold]Step 2/4:[/bold] Detecting AI agent...")
    detected_agent = agent
    if not detected_agent:
        project_path = Path(working_dir)
        if (project_path / "CLAUDE.md").exists():
            detected_agent = "claude-code"
        elif (project_path / "opencode.json").exists():
            detected_agent = "opencode"

    if detected_agent:
        # Validate agent name
        from lasso.backends.image_builder import AGENT_BASE_IMAGES, AGENT_INSTALLS
        known_agents = set(AGENT_INSTALLS) | set(AGENT_BASE_IMAGES)
        if detected_agent not in known_agents:
            err_console.print(f"[red]Unknown agent '{detected_agent}'.[/red]")
            err_console.print(f"[dim]Available: {', '.join(sorted(known_agents))}[/dim]")
            raise typer.Exit(1)
        console.print(f"  Agent: [bold cyan]{detected_agent}[/bold cyan]")
    else:
        console.print("  Agent: [dim]none detected (will use shell)[/dim]")
    console.print()

    # Step 3: Prebuild images
    console.print("[bold]Step 3/4:[/bold] Building sandbox images...")
    try:
        registry = _get_registry(quiet=True)
    except SystemExit:
        err_console.print("[red]No container runtime found. Install Docker or Podman.[/red]")
        raise typer.Exit(1)

    backend = registry._backend
    if not backend:
        err_console.print("[red]No container runtime found.[/red]")
        raise typer.Exit(1)

    from lasso.backends.image_builder import PRESET_IMAGES, prebuild_presets

    # Resolve CA cert: explicit flag > operational config > None
    ca_cert_path = ca_cert
    if not ca_cert_path:
        from lasso.config.operational import load_config
        op_config = load_config()
        ca_cert_path = op_config.containers.ca_cert_path
    if ca_cert_path:
        console.print(f"  [dim]CA certificate: {ca_cert_path}[/dim]")

    # Check which images already exist
    needed = []
    for preset_name, tag in PRESET_IMAGES.items():
        if not backend.image_exists(tag):
            needed.append(preset_name)

    if needed:
        with console.status(f"[bold blue]Building {len(needed)} image(s)..."):
            prebuild_presets(backend, force=False, ca_cert_path=ca_cert_path)
        console.print(f"  Built {len(needed)} image(s).")
    else:
        console.print("  All images already cached. [green]Skipped.[/green]")
    console.print()

    # Step 4: Docker socket proxy (if --docker)
    console.print("[bold]Step 4/4:[/bold] Docker-from-Docker proxy...")
    if docker:
        from lasso.backends.docker_backend import DockerBackend
        if isinstance(backend, DockerBackend):
            with console.status("[bold blue]Starting socket proxy..."):
                backend._ensure_socket_proxy()
            console.print("  Socket proxy: [green]running[/green]")
        else:
            console.print("  [yellow]Docker-from-Docker requires the Docker backend.[/yellow]")
    else:
        console.print("  [dim]Skipped (use --docker to enable).[/dim]")
    console.print()

    # Summary
    docker_flag = " --docker" if docker else ""
    agent_flag = f" --agent {detected_agent}" if detected_agent else ""
    start_cmd = f"lasso up --dir {working_dir}{agent_flag}{docker_flag}"

    console.print(Panel.fit(
        f"[bold green]Setup complete![/bold green]\n\n"
        f"  Project dir: {working_dir}\n"
        f"  Agent:       {detected_agent or 'shell'}\n"
        f"  Docker-DfD:  {'enabled' if docker else 'disabled'}\n\n"
        f"Start your sandbox:\n"
        f"  [bold]{start_cmd}[/bold]",
        border_style="green",
        title="LASSO Quickstart",
    ))


# -----------------------------------------------------------------------
# Reset — clean up all LASSO resources
# -----------------------------------------------------------------------

@app.command()
def reset(
    prune: bool = typer.Option(False, "--prune", help="Also remove stopped containers."),
    hard: bool = typer.Option(False, "--hard", help="Also remove named volumes and images."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation."),
):
    """Stop all sandboxes and clean up LASSO resources.

    Without flags, stops all running sandboxes and the socket proxy.
    With --prune, also removes stopped LASSO containers.
    With --hard, also removes LASSO images and named volumes.

    Examples:
        lasso reset                # stop everything
        lasso reset --prune        # also remove stopped containers
        lasso reset --hard --yes   # full cleanup, no confirmation
    """
    import subprocess

    actions: list[str] = ["Stop all running sandboxes", "Stop socket proxy (if running)"]
    if prune:
        actions.append("Remove stopped LASSO containers")
    if hard:
        actions.append("Remove LASSO images and named volumes")

    if not yes:
        console.print("[bold]The following actions will be performed:[/bold]")
        for action in actions:
            console.print(f"  - {action}")
        console.print()
        typer.confirm("Continue?", abort=True)

    summary: list[str] = []

    # Step 1: Stop all running sandboxes (reuse down logic)
    try:
        registry = _get_registry(quiet=True)
        sandboxes = registry.list_all()
        running_count = len([s for s in sandboxes if s["state"] == "running"])
        if running_count > 0:
            stopped = registry.stop_all()
            summary.append(f"Stopped {stopped} sandbox(es)")
        else:
            summary.append("No running sandboxes")
    except SystemExit:
        summary.append("No container runtime (skipped sandbox stop)")

    # Step 2: Stop socket proxy
    cli_bin = None
    for cmd in ("docker", "podman"):
        import shutil as _shutil
        if _shutil.which(cmd):
            cli_bin = cmd
            break

    if cli_bin:
        proxy_name = "lasso-socket-proxy"
        proxy_network = "lasso-sandbox-net"
        try:
            result = subprocess.run(
                [cli_bin, "inspect", proxy_name],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                subprocess.run(
                    [cli_bin, "stop", proxy_name],
                    capture_output=True, timeout=15,
                )
                subprocess.run(
                    [cli_bin, "rm", "-f", proxy_name],
                    capture_output=True, timeout=10,
                )
                summary.append("Stopped and removed socket proxy")
            else:
                summary.append("Socket proxy not running")
        except (subprocess.TimeoutExpired, OSError):
            summary.append("Could not check socket proxy")

        # Remove proxy network
        try:
            subprocess.run(
                [cli_bin, "network", "rm", proxy_network],
                capture_output=True, timeout=10,
            )
        except (subprocess.TimeoutExpired, OSError):
            pass

        # Step 3: Prune stopped containers
        if prune:
            try:
                result = subprocess.run(
                    [cli_bin, "ps", "-a", "--filter", "label=managed-by=lasso",
                     "--format", "{{.ID}}"],
                    capture_output=True, text=True, timeout=10,
                )
                container_ids = [
                    cid.strip() for cid in result.stdout.strip().splitlines() if cid.strip()
                ]
                if container_ids:
                    subprocess.run(
                        [cli_bin, "rm", "-f"] + container_ids,
                        capture_output=True, timeout=30,
                    )
                    summary.append(f"Removed {len(container_ids)} stopped container(s)")
                else:
                    summary.append("No stopped LASSO containers")
            except (subprocess.TimeoutExpired, OSError):
                summary.append("Could not prune containers")

        # Step 4: Hard cleanup — volumes and images
        if hard:
            # Remove named volumes with "lasso" or "opencode" in name
            volumes_removed = 0
            try:
                result = subprocess.run(
                    [cli_bin, "volume", "ls", "--format", "{{.Name}}"],
                    capture_output=True, text=True, timeout=10,
                )
                for vol_name in result.stdout.strip().splitlines():
                    vol_name = vol_name.strip()
                    if not vol_name:
                        continue
                    vol_lower = vol_name.lower()
                    if "lasso" in vol_lower or "opencode" in vol_lower:
                        subprocess.run(
                            [cli_bin, "volume", "rm", "-f", vol_name],
                            capture_output=True, timeout=10,
                        )
                        volumes_removed += 1
            except (subprocess.TimeoutExpired, OSError):
                pass
            summary.append(f"Removed {volumes_removed} volume(s)")

            # Remove LASSO images
            images_removed = 0
            try:
                result = subprocess.run(
                    [cli_bin, "images", "--format", "{{.Repository}}:{{.Tag}}"],
                    capture_output=True, text=True, timeout=10,
                )
                for image_line in result.stdout.strip().splitlines():
                    image_line = image_line.strip()
                    if not image_line:
                        continue
                    if image_line.startswith("lasso-"):
                        subprocess.run(
                            [cli_bin, "rmi", "-f", image_line],
                            capture_output=True, timeout=30,
                        )
                        images_removed += 1
            except (subprocess.TimeoutExpired, OSError):
                pass
            summary.append(f"Removed {images_removed} image(s)")

    else:
        summary.append("No container runtime found (skipped proxy/prune/hard cleanup)")

    # Print summary
    console.print()
    console.print("[bold]Reset summary:[/bold]")
    for item in summary:
        console.print(f"  - {item}")
    console.print()
    console.print("[green]Reset complete.[/green]")


# -----------------------------------------------------------------------
# Version
# -----------------------------------------------------------------------

@app.command()
def version(
    output_json: bool = typer.Option(False, "--json", help="Output version info as JSON."),
    changelog: bool = typer.Option(False, "--changelog", help="Show changelog since pinned version."),
):
    """Print LASSO version, pinned version, and latest checkpoint."""
    from lasso.core.checkpoint import CheckpointStore

    store = CheckpointStore()
    pinned = store.get_pinned_version()
    latest = store.latest_checkpoint()
    update = store.check_for_update(__version__)

    if changelog:
        _show_changelog(pinned, output_json)
        return

    if output_json:
        data = {
            "current_version": __version__,
            "pinned_version": pinned,
            "latest_checkpoint": latest.to_dict() if latest else None,
            "update_available": update.to_dict() if update else None,
        }
        console.print_json(json.dumps(data, indent=2))
        return

    console.print(f"LASSO v{__version__}")
    if pinned:
        console.print(f"  Pinned to: [bold cyan]{pinned}[/bold cyan]")
    if latest:
        console.print(f"  Latest checkpoint: [bold]{latest.version}[/bold] ({latest.tag})")
    if update:
        console.print(
            f"  [yellow]Update available: v{update.version}[/yellow]"
            f" \u2014 run 'lasso checkpoint list' for details."
        )


# -----------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------

def main():
    _register_signal_handlers()
    app()
