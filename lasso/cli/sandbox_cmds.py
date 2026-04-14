"""Sandbox lifecycle commands: up, shell, attach.

These are the largest CLI commands and share patterns around terminal
environment setup, agent detection, and exec-into-container.  Extracted
from main.py to keep each module under ~1200 lines.
"""

from __future__ import annotations

import os
from pathlib import Path

import typer
from rich.panel import Panel

from lasso.config.schema import ProfileMode, SandboxState

from .constants import AGENT_CLI_COMMANDS, console, err_console
from .helpers import (
    _apply_auto_mount_flags,
    _apply_extra_env,
    _apply_mounts,
    _ensure_lasso_dir,
    _exec_container_cli,
    _get_registry,
    _load_env_file,
    _resolve_profile,
    _validate_agent,
)


def _terminal_env_args() -> tuple[int, int, list[str]]:
    """Return (cols, rows, cli_args) for passing terminal geometry and TERM.

    The returned *cli_args* list contains ``-e KEY=VALUE`` pairs suitable for
    ``docker exec`` / ``podman exec`` so that interactive TUI applications
    (OpenCode, htop, etc.) render correctly.

    Falls back to 120x40 when stdout is not a TTY (e.g. piped or on Windows
    without a real console).  TERM defaults to ``xterm-256color`` when the
    host environment does not set it.
    """
    try:
        cols, rows = os.get_terminal_size()
    except OSError:
        cols, rows = 120, 40

    term = os.environ.get("TERM", "xterm-256color")

    args = [
        "-e", f"COLUMNS={cols}",
        "-e", f"LINES={rows}",
        "-e", f"TERM={term}",
    ]
    return cols, rows, args


def register_sandbox_commands(app: typer.Typer) -> None:
    """Register up, shell, and attach commands on the given Typer app."""

    @app.command()
    def up(
        agent: str | None = typer.Option(None, "--agent", "-a", help="AI agent: claude-code or opencode."),
        working_dir: str = typer.Option(".", "--dir", "-d", help="Project directory."),
        env_vars: list[str] | None = typer.Option(None, "--env", "-e", help="Pass environment variable (KEY=VALUE). Repeatable."),
        pass_env: list[str] | None = typer.Option(None, "--pass-env", help="Pass host env var into sandbox by name. Repeatable."),
        mount: list[str] | None = typer.Option(None, "--mount", "-v", help="Mount extra directory. Format: /host/path:/container/path[:ro]"),
        session_volume: str | None = typer.Option(None, "--session-volume", help="Named Docker volume for agent state persistence."),
        docker: bool = typer.Option(False, "--docker", help="Enable Docker-from-Docker via socket proxy."),
        resume: bool = typer.Option(False, "--resume", help="Reconnect to existing sandbox if one matches."),
        ssh: bool = typer.Option(False, "--ssh", help="Force-mount ~/.ssh read-only into sandbox."),
        no_auto_mount: bool = typer.Option(False, "--no-auto-mount", help="Disable auto-mounting SSH keys and git config."),
        env_file: str | None = typer.Option(None, "--env-file", help="Load environment variables from a dotenv file."),
        agent_args: list[str] | None = typer.Option(None, "--agent-arg", help="Extra argument to pass to the agent binary. Repeatable."),
    ):
        """Start a sandbox. Zero config, one command.

        Detects your project, picks the right settings, and drops you in.
        Auto-mounts ~/.ssh and ~/.gitconfig (read-only) if they exist.
        Use --no-auto-mount to disable.

        Examples:
            lasso up                         # auto-detect everything
            lasso up --agent claude-code     # use Claude Code
            lasso up --dir ~/my-project      # specific directory
            lasso up --resume                # reconnect to existing sandbox
            lasso up --ssh                   # force SSH mount even if auto-mount is off
            lasso up --no-auto-mount         # skip auto SSH/gitconfig mounts
        """
        import time as _time

        working_dir_resolved = str(Path(working_dir).resolve())
        _ensure_lasso_dir()

        # Auto-detect agent from project files if not specified
        detected_agent = agent
        if not detected_agent:
            project_path = Path(working_dir_resolved)
            if (project_path / "CLAUDE.md").exists():
                detected_agent = "claude-code"
            elif (project_path / "opencode.json").exists():
                detected_agent = "opencode"

        agent_display = detected_agent or "shell"
        console.print(f"[dim]Agent: {agent_display}[/dim]")

        registry = _get_registry(quiet=False)

        # --resume: try to reconnect to an existing sandbox for this directory
        if resume:
            existing = registry.find_existing(working_dir_resolved, agent=detected_agent)
            if existing is not None:
                container_name = f"lasso-{existing.id}"

                if existing.state == SandboxState.RUNNING:
                    console.print(Panel.fit(
                        f"[bold green]Resuming LASSO Sandbox[/bold green]\n\n"
                        f"  ID:       {existing.id}\n"
                        f"  Agent:    {agent_display}\n"
                        f"  Profile:  {existing.profile.name}\n"
                        f"  Dir:      {working_dir_resolved}\n\n"
                        f"  Type [bold]exit[/bold] to leave (sandbox keeps running).\n"
                        f"  Stop:     [bold]lasso down[/bold]",
                        border_style="cyan",
                        title="LASSO (resumed)",
                    ))
                else:
                    # Stopped sandbox — try to restart
                    console.print(f"[dim]Found stopped sandbox {existing.id}, restarting...[/dim]")
                    with console.status("[bold blue]Restarting sandbox..."):
                        registry.start(existing)
                    console.print(Panel.fit(
                        f"[bold green]Restarted LASSO Sandbox[/bold green]\n\n"
                        f"  ID:       {existing.id}\n"
                        f"  Agent:    {agent_display}\n"
                        f"  Profile:  {existing.profile.name}\n"
                        f"  Dir:      {working_dir_resolved}\n\n"
                        f"  Type [bold]exit[/bold] to leave (sandbox keeps running).\n"
                        f"  Stop:     [bold]lasso down[/bold]",
                        border_style="cyan",
                        title="LASSO (restarted)",
                    ))

                # Drop into the resumed sandbox
                _cols, _rows, term_env = _terminal_env_args()

                if detected_agent and detected_agent in AGENT_CLI_COMMANDS:
                    # Build agent command with --continue for session resume
                    from lasso.agents.base import AgentType
                    from lasso.agents.registry import get_provider
                    try:
                        provider = get_provider(AgentType(detected_agent))
                    except (ValueError, KeyError):
                        provider = None
                    if provider:
                        agent_cmd_parts = provider.get_start_command(resume=True)
                    else:
                        agent_cmd_parts = [AGENT_CLI_COMMANDS[detected_agent][0]]
                    # Append any extra --agent-arg values
                    agent_cmd_parts += (agent_args or [])
                    _exec_container_cli([
                        "exec", "-it",
                        *term_env,
                        "-w", "/workspace",
                        container_name,
                    ] + agent_cmd_parts)
                else:
                    _exec_container_cli([
                        "exec", "-it",
                        *term_env,
                        "-w", "/workspace",
                        container_name,
                        "/bin/bash",
                    ])
                return

            # No existing sandbox found — fall through to create a new one
            console.print("[dim]No existing sandbox found for this directory, creating new...[/dim]")

        # Use standard profile
        profile = _resolve_profile("standard", working_dir_resolved, quiet=True)

        # Load env file entries (before --env so explicit overrides win)
        combined_env_vars = list(env_vars or [])
        env_file_keys: set[str] = set()
        if env_file:
            file_entries = _load_env_file(env_file)
            env_file_keys = {e.partition("=")[0] for e in file_entries}
            combined_env_vars = file_entries + combined_env_vars

        # Apply mount and env overrides
        _apply_extra_env(profile, combined_env_vars, pass_env)
        _apply_mounts(profile, mount)

        # Mark env-file keys for audit redaction
        if env_file_keys:
            profile.extra_env["_LASSO_REDACT_KEYS"] = ",".join(sorted(env_file_keys))

        # Apply session volume override (auto-set for agents if not specified)
        if session_volume:
            profile.filesystem.session_volume = session_volume
        elif detected_agent in ("opencode", "claude-code") and not profile.filesystem.session_volume:
            profile.filesystem.session_volume = f"lasso-session-{detected_agent}"

        # Enable Docker-from-Docker via socket proxy
        if docker:
            profile.docker_from_docker = True

        # Store agent choice for image builder
        if detected_agent:
            from lasso.backends.image_builder import AGENT_BASE_IMAGES, AGENT_INSTALLS
            known_agents = set(AGENT_INSTALLS) | set(AGENT_BASE_IMAGES)
            if detected_agent in known_agents:
                profile.extra_env["LASSO_AGENT"] = detected_agent

        # Auto-mount control flags
        _apply_auto_mount_flags(profile, ssh=ssh, no_auto_mount=no_auto_mount)

        t0 = _time.monotonic()

        with console.status("[bold blue]Creating sandbox..."):
            sandbox = registry.create(profile)

        with console.status("[bold blue]Starting sandbox..."):
            registry.start(sandbox)

        elapsed_ms = int((_time.monotonic() - t0) * 1000)
        container_name = f"lasso-{sandbox.id}"

        console.print(Panel.fit(
            f"[bold green]LASSO Sandbox Ready[/bold green]\n\n"
            f"  ID:       {sandbox.id}\n"
            f"  Agent:    {agent_display}\n"
            f"  Profile:  standard\n"
            f"  Dir:      {working_dir_resolved}\n"
            f"  Started:  {elapsed_ms}ms\n\n"
            f"  Type [bold]exit[/bold] to leave (sandbox keeps running).\n"
            f"  Stop:     [bold]lasso down[/bold]",
            border_style="green",
            title="LASSO",
        ))

        # Drop into agent or shell
        _cols, _rows, term_env = _terminal_env_args()

        if detected_agent and detected_agent in AGENT_CLI_COMMANDS:
            agent_cmd_parts = [AGENT_CLI_COMMANDS[detected_agent][0]] + (agent_args or [])
            _exec_container_cli([
                "exec", "-it",
                *term_env,
                "-w", "/workspace",
                container_name,
            ] + agent_cmd_parts)
        else:
            _exec_container_cli([
                "exec", "-it",
                *term_env,
                "-w", "/workspace",
                container_name,
                "/bin/bash",
            ])

    @app.command(name="shell")
    def shell_cmd(
        profile_name: str = typer.Argument("standard", help="Profile name."),
        working_dir: str = typer.Option(".", "--dir", "-d", help="Working directory to mount."),
        file: str | None = typer.Option(None, "--file", "-f", help="Load profile from TOML file."),
        shell: str = typer.Option("/bin/bash", "--shell", "-s", help="Shell to use inside the container."),
        native: bool = typer.Option(False, "--native", help="Use native mode (no container)."),
        mode_str: str | None = typer.Option(None, "--mode", "-m", help="Profile mode: observe, assist, or autonomous."),
        env_vars: list[str] | None = typer.Option(None, "--env", "-e", help="Pass environment variable (KEY=VALUE). Repeatable."),
        pass_env: list[str] | None = typer.Option(None, "--pass-env", help="Pass host env var into sandbox by name. Repeatable."),
        agent: str | None = typer.Option(None, "--agent", "-a", help="Pre-install AI agent: claude-code or opencode."),
        mount: list[str] | None = typer.Option(None, "--mount", "-v", help="Mount extra directory. Format: /host/path:/container/path or /host/path:/container/path:ro"),
        session_volume: str | None = typer.Option(None, "--session-volume", help="Named Docker volume for agent state persistence."),
        docker: bool = typer.Option(False, "--docker", help="Enable Docker-from-Docker via socket proxy."),
        ssh: bool = typer.Option(False, "--ssh", help="Force-mount ~/.ssh read-only into sandbox."),
        no_auto_mount: bool = typer.Option(False, "--no-auto-mount", help="Disable auto-mounting SSH keys and git config."),
        env_file: str | None = typer.Option(None, "--env-file", help="Load environment variables from a dotenv file."),
    ):
        """Create a sandbox and drop into an interactive terminal.

        This is the recommended way to work inside a sandbox. Creates the
        sandbox, starts it, and gives you a real PTY shell via docker exec -it.
        The sandbox keeps running after you exit -- stop it with 'lasso stop'.
        Auto-mounts ~/.ssh and ~/.gitconfig (read-only) if they exist.
        Use --no-auto-mount to disable.

        Examples:
            lasso shell                             # standard profile, current dir
            lasso shell standard --dir .            # explicit profile and dir
            lasso shell strict --dir /path/to/code  # strict profile
            lasso shell --mode autonomous           # autonomous mode
            lasso shell --agent claude-code         # pre-install Claude Code CLI
            lasso shell --mount /data/shared:/data:ro  # mount extra folder
            lasso shell --no-auto-mount             # skip auto SSH/gitconfig mounts
        """
        working_dir_resolved = str(Path(working_dir).resolve())
        profile = _resolve_profile(profile_name, working_dir_resolved, file)

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
            profile.extra_env["_LASSO_REDACT_KEYS"] = ",".join(sorted(env_file_keys))
        else:
            _apply_extra_env(profile, combined_env_vars, pass_env)

        # Store agent choice for image builder
        _validate_agent(agent, profile)

        # Parse --mount flags into extra mounts stored as JSON in extra_env
        _apply_mounts(profile, mount)

        # Apply session volume override (auto-set for agents if not specified)
        if session_volume:
            profile.filesystem.session_volume = session_volume
        elif agent in ("opencode", "claude-code") and not profile.filesystem.session_volume:
            profile.filesystem.session_volume = f"lasso-session-{agent}"

        # Enable Docker-from-Docker via socket proxy
        if docker:
            profile.docker_from_docker = True

        # Auto-mount control flags
        _apply_auto_mount_flags(profile, ssh=ssh, no_auto_mount=no_auto_mount)

        if native:
            err_console.print("[red]Error: 'lasso shell' requires a container backend (cannot use --native).[/red]")
            err_console.print("[dim]Use 'lasso create --native' for native mode.[/dim]")
            raise typer.Exit(1)

        registry = _get_registry(native=False)

        with console.status("[bold blue]Creating sandbox..."):
            sandbox = registry.create(profile)

        with console.status("[bold blue]Starting sandbox..."):
            registry.start(sandbox)

        container_name = f"lasso-{sandbox.id}"

        console.print(Panel.fit(
            f"[bold green]LASSO Sandbox Ready[/bold green]\n\n"
            f"  ID:       {sandbox.id}\n"
            f"  Profile:  {profile.name}\n"
            f"  Mode:     {profile.mode.value}\n"
            f"  Network:  {profile.network.mode.value}\n"
            f"  Dir:      {working_dir_resolved}\n\n"
            f"  Type [bold]exit[/bold] to leave (sandbox keeps running).\n"
            f"  Stop later: [bold]lasso stop {sandbox.id}[/bold]",
            border_style="green",
            title="LASSO Sandbox",
        ))

        # Log the session attachment to the audit trail
        sandbox.audit.log_lifecycle("session_attached", {
            "agent": agent or "shell",
            "container": container_name,
            "note": "Interactive PTY session -- individual commands run by the "
                    "agent are not logged by LASSO (the agent runs directly "
                    "inside the container). See the agent's own history for "
                    "command details.",
        })

        # Determine what to launch inside the container
        # Get terminal size for proper TUI rendering
        _cols, _rows, term_env = _terminal_env_args()

        if agent and agent in AGENT_CLI_COMMANDS:
            # Launch the agent CLI directly
            agent_cmd = AGENT_CLI_COMMANDS[agent][0]
            _exec_container_cli([
                "exec", "-it",
                *term_env,
                "-w", "/workspace",
                container_name,
                agent_cmd,
            ])
        else:
            # Drop into a shell
            _exec_container_cli([
                "exec", "-it",
                *term_env,
                "-w", "/workspace",
                container_name,
                shell,
            ])

    @app.command()
    def attach(
        sandbox_id: str = typer.Argument(help="Sandbox ID to attach to."),
        shell: str = typer.Option("/bin/bash", "--shell", "-s", help="Shell to use inside the container."),
    ):
        """Attach an interactive terminal (PTY) to a running sandbox.

        Opens a real shell inside the sandbox container using docker exec -it.
        Use this to run AI coding agents (claude, opencode) inside
        the sandbox.

        The sandbox keeps running after you exit the shell.

        Examples:
            lasso attach abc123
            lasso attach abc123 --shell /bin/sh
        """
        registry = _get_registry()
        sb = registry.get(sandbox_id)
        if not sb:
            err_console.print(f"[red]Error: Sandbox '{sandbox_id}' not found.[/red]")
            err_console.print("[dim]Run 'lasso status' to see active sandboxes.[/dim]")
            raise typer.Exit(1)

        if sb.state != SandboxState.RUNNING:
            err_console.print(f"[red]Error: Sandbox is {sb.state.value}, not running.[/red]")
            raise typer.Exit(1)

        container_name = f"lasso-{sandbox_id}"

        console.print(Panel.fit(
            f"[bold green]Entering LASSO Sandbox[/bold green]\n\n"
            f"  ID:       {sandbox_id}\n"
            f"  Profile:  {sb.profile.name}\n"
            f"  Mode:     {sb.mode.value}\n"
            f"  Network:  {sb.profile.network.mode.value}\n\n"
            f"  Type [bold]exit[/bold] to leave (sandbox keeps running).\n"
            f"  Run AI agents: [bold]claude[/bold], [bold]opencode[/bold], etc.",
            border_style="green",
            title="LASSO Sandbox",
        ))

        # Log the session attachment
        sb.audit.log_lifecycle("session_attached", {
            "container": container_name,
            "shell": shell,
        })

        # Get terminal size for proper TUI rendering
        _cols, _rows, term_env = _terminal_env_args()

        # Replace this process with container exec -it for a real PTY.
        _exec_container_cli([
            "exec", "-it",
            *term_env,
            "-w", "/workspace",
            container_name,
            shell,
        ])
