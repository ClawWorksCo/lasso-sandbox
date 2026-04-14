"""Agent management CLI commands (lasso agent ...)."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.table import Table

from .constants import console, err_console
from .helpers import _resolve_profile

agent_app = typer.Typer(help="Manage AI agent configurations.", no_args_is_help=True)


@agent_app.command(name="list")
def agent_list(
    output_json: bool = typer.Option(False, "--json", help="Output as JSON array."),
):
    """List supported AI agents and their status."""
    from lasso.agents.registry import list_agents
    agents = list_agents()

    if output_json:
        console.print_json(json.dumps(agents, indent=2))
        return

    table = Table(title="AI Agent Providers", show_header=True)
    table.add_column("Agent", style="bold")
    table.add_column("Type")
    table.add_column("Installed")
    table.add_column("Version")
    table.add_column("Priority")

    for i, a in enumerate(agents):
        installed = "[green]Yes[/green]" if a["installed"] else "[dim]No[/dim]"
        ver = a.get("version") or "-"
        priority = "[bold cyan]Default[/bold cyan]" if i == 0 else str(i + 1)
        table.add_row(a["name"], a["type"], installed, ver, priority)

    console.print(table)
    console.print("\n[dim]OpenCode is the default agent. Override with --agent flag.[/dim]")
    console.print("[dim]Supported: claude-code, opencode[/dim]")


@agent_app.command(name="config")
def agent_config(
    agent_type: str = typer.Argument(help="Agent: claude-code or opencode."),
    profile_name: str = typer.Option("standard", "--profile", "-p", help="Profile."),
    working_dir: str = typer.Option(".", "--dir", "-d", help="Working directory."),
    write: bool = typer.Option(False, "--write", "-w", help="Write config files to disk."),
    templates: str | None = typer.Option(None, "--templates", help="Team template directory for agent configs."),
    no_overwrite: bool = typer.Option(False, "--no-overwrite", help="Skip files that already exist."),
    merge: bool = typer.Option(False, "--merge", help="Merge with existing agent configs instead of overwriting."),
    from_config: str | None = typer.Option(None, "--from-config", help="Path to team config directory to bootstrap from."),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON."),
):
    """Preview or write agent-specific config from a LASSO profile."""
    from rich.panel import Panel

    from lasso.agents.base import AgentType as AT
    from lasso.agents.registry import get_provider, write_agent_config

    working_dir = str(Path(working_dir).resolve())

    try:
        provider = get_provider(AT(agent_type))
    except ValueError:
        err_console.print(f"[red]Error: Unknown agent '{agent_type}'.[/red]")
        err_console.print(
            "[dim]Supported: claude-code, opencode[/dim]"
        )
        raise typer.Exit(1)

    profile = _resolve_profile(profile_name, working_dir)
    config = provider.generate_config(profile)

    if write:
        written = write_agent_config(
            config,
            working_dir,
            templates_dir=templates,
            no_overwrite=no_overwrite,
            merge=merge,
        )
        for f in written:
            console.print(f"[green]Wrote:[/green] {f}")
    else:
        console.print(f"[bold]Agent config preview for {provider.display_name}[/bold]\n")
        for name, content in config.config_files.items():
            console.print(Panel(content, title=name, border_style="blue"))
        for name, content in config.rules_files.items():
            console.print(Panel(content, title=name, border_style="green"))
        console.print(f"\n[dim]Use --write to save these files to {working_dir}[/dim]")


@agent_app.command(name="guardrails")
def agent_guardrails_cmd(
    agent: str = typer.Argument(help="Agent type (claude-code or opencode)."),
    profile_name: str = typer.Option("standard", "--profile", "-p", help="Profile."),
    working_dir: str = typer.Option(".", "--dir", "-d", help="Working directory (for profile resolution)."),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON."),
    existing: str | None = typer.Option(None, "--existing", help="Comma-separated list of existing team denials to merge."),
):
    """Export agent guardrails matching a profile's security policy.

    Shows the blocked commands, network restrictions, and isolation level
    derived from a LASSO profile. Use --existing to merge in your team's
    existing denial list so you get a unified view.

    Examples:
        lasso agent guardrails claude-code --profile strict
        lasso agent guardrails opencode --json
        lasso agent guardrails claude-code --existing "curl,wget,nc"
    """
    from lasso.agents.guardrails_export import export_agent_guardrails

    working_dir = str(Path(working_dir).resolve())
    profile = _resolve_profile(profile_name, working_dir)

    existing_denials = None
    if existing:
        existing_denials = [d.strip() for d in existing.split(",") if d.strip()]

    guardrails = export_agent_guardrails(agent, profile, existing_denials)

    if output_json:
        console.print_json(json.dumps(guardrails, indent=2))
        return

    console.print(f"[bold]Agent Guardrails: {agent}[/bold] (profile: {profile_name})\n")

    table = Table(show_header=True, title="Blocked Commands")
    table.add_column("Command / Pattern", style="red")
    for cmd in guardrails["blocked_commands"]:
        table.add_row(cmd)
    console.print(table)

    console.print(f"\n  Command mode:    [bold]{guardrails['command_mode']}[/bold]")
    console.print(f"  Network mode:    [bold]{guardrails['network_mode']}[/bold]")
    console.print(f"  Isolation:       [bold]{guardrails['isolation_level']}[/bold]")
    console.print(f"  Profile mode:    [bold]{guardrails['mode']}[/bold]")

    if guardrails["blocked_ports"]:
        ports = ", ".join(str(p) for p in guardrails["blocked_ports"])
        console.print(f"  Blocked ports:   [dim]{ports}[/dim]")

    if guardrails["allowed_domains"]:
        domains = ", ".join(guardrails["allowed_domains"])
        console.print(f"  Allowed domains: [dim]{domains}[/dim]")

    if guardrails.get("whitelisted_commands"):
        console.print(f"\n  Whitelisted:     {len(guardrails['whitelisted_commands'])} commands")

    console.print("\n[dim]Use --json for machine-readable output.[/dim]")
