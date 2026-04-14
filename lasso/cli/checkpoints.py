"""Checkpoint management CLI commands (lasso checkpoint ...)."""

from __future__ import annotations

import json

import typer
from rich.panel import Panel
from rich.table import Table

from .constants import console

checkpoint_app = typer.Typer(help="Manage release checkpoints.", no_args_is_help=True)


@checkpoint_app.command(name="list")
def checkpoint_list(
    output_json: bool = typer.Option(False, "--json", help="Output as JSON."),
):
    """List all registered checkpoints."""
    from lasso.core.checkpoint import CheckpointStore

    store = CheckpointStore()
    checkpoints = store.load_manifest()

    if output_json:
        console.print_json(json.dumps(
            [c.to_dict() for c in checkpoints], indent=2,
        ))
        return

    if not checkpoints:
        console.print("[dim]No checkpoints registered.[/dim]")
        console.print("Run 'lasso checkpoint create <tag> --notes \"...\"' to register one.")
        return

    table = Table(show_header=True, title="LASSO Checkpoints")
    table.add_column("Tag", style="bold")
    table.add_column("Version")
    table.add_column("Released")
    table.add_column("Notes")
    table.add_column("Reviewers")

    for c in sorted(checkpoints, key=lambda x: x.released_at, reverse=True):
        released = c.released_at[:10] if c.released_at else "-"
        reviewers = ", ".join(c.reviewed_by) if c.reviewed_by else "-"
        table.add_row(c.tag, c.version, released, c.notes or "-", reviewers)

    console.print(table)

    pinned = store.get_pinned_version()
    if pinned:
        console.print(f"\n[bold cyan]Pinned to: {pinned}[/bold cyan]")


@checkpoint_app.command(name="create")
def checkpoint_create(
    tag: str = typer.Argument(help="Checkpoint tag (e.g. 'v0.2.0-rc1')."),
    notes: str = typer.Option("", "--notes", "-n", help="Release notes."),
    reviewer: list[str] = typer.Option([], "--reviewer", "-r", help="Reviewer name (repeatable)."),
):
    """Register a new checkpoint (admin operation).

    Example:
        lasso checkpoint create v0.2.0 --notes "Stable release" --reviewer Alice
    """
    from lasso.core.checkpoint import CheckpointStore

    # Derive version from tag by stripping leading 'v'
    version = tag.lstrip("v")

    store = CheckpointStore()
    cp = store.register_checkpoint(
        tag=tag,
        version=version,
        notes=notes,
        reviewed_by=reviewer,
    )

    console.print(Panel.fit(
        f"[bold green]Checkpoint registered[/bold green]\n\n"
        f"  Tag:       {cp.tag}\n"
        f"  Version:   {cp.version}\n"
        f"  SHA-256:   {cp.sha256[:16]}...\n"
        f"  Released:  {cp.released_at}\n"
        f"  Notes:     {cp.notes or '-'}\n"
        f"  Reviewers: {', '.join(cp.reviewed_by) or '-'}",
        border_style="green",
        title="LASSO Checkpoint",
    ))


@checkpoint_app.command(name="pin")
def checkpoint_pin(
    version_str: str = typer.Argument(help="Version to pin to (e.g. '0.2.0')."),
):
    """Pin LASSO to a specific checkpoint version.

    When pinned, LASSO will warn if the running version does not match
    the pinned version.

    Example:
        lasso checkpoint pin 0.2.0
    """
    from lasso.core.checkpoint import CheckpointStore

    store = CheckpointStore()
    store.pin_version(version_str)
    console.print(f"[bold green]Pinned to version {version_str}[/bold green]")
