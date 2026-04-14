"""Audit log CLI commands (lasso audit ...)."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import typer
from rich.panel import Panel
from rich.table import Table

from .constants import console, err_console

audit_app = typer.Typer(help="View and verify audit logs.", no_args_is_help=True)


@audit_app.command(name="view")
def audit_view(
    log_file: str = typer.Argument(help="Path to audit log (.jsonl)."),
    tail: int = typer.Option(50, "--tail", "-n", help="Show last N entries."),
    event_type: str | None = typer.Option(None, "--type", "-t", help="Filter by event type."),
    raw: bool = typer.Option(False, "--json", help="Output raw JSON."),
):
    """View audit log entries."""
    from lasso.core.audit_verify import read_audit_entries

    entries = read_audit_entries(log_file, tail=tail, event_type=event_type)
    if not entries:
        console.print("[dim]No entries found.[/dim]")
        return

    if raw:
        for e in entries:
            console.print_json(json.dumps(e))
        return

    table = Table(title=f"Audit Log ({len(entries)} entries)", show_header=True)
    table.add_column("Time", style="dim", width=19)
    table.add_column("Type", width=10)
    table.add_column("Action", max_width=30)
    table.add_column("Outcome", width=8)
    table.add_column("Detail", max_width=40)
    table.add_column("Sig", width=8)

    for e in entries:
        ts = e.get("ts", "")[:19]
        etype = e.get("type", "")
        action = e.get("action", "")
        outcome = e.get("outcome", "")
        detail = ""
        if e.get("detail"):
            d = e["detail"]
            if "reason" in d:
                detail = d["reason"][:40]
            elif "exit_code" in d:
                detail = f"exit={d['exit_code']}"
        sig = e.get("sig", "")[:8] if e.get("sig") else "none"

        oc = {"success": "green", "blocked": "red", "error": "yellow"}.get(outcome, "white")
        table.add_row(ts, etype, action, f"[{oc}]{outcome}[/{oc}]", detail, sig)

    console.print(table)


@audit_app.command(name="verify")
def audit_verify_cmd(
    log_file: str = typer.Argument(help="Path to audit log (.jsonl)."),
    key_file: str | None = typer.Option(None, "--key", "-k", help="Path to signing key."),
):
    """Verify audit log integrity (HMAC chain)."""
    from lasso.core.audit_verify import verify_audit_log

    result = verify_audit_log(log_file, key_path=key_file)

    if result.valid:
        console.print(Panel.fit(
            f"[bold green]INTEGRITY VERIFIED[/bold green]\n\n"
            f"  Entries:  {result.total_entries}\n"
            f"  Verified: {result.verified_entries}\n"
            f"  Chain:    Unbroken\n\n"
            f"  All HMAC signatures match. No tampering detected.",
            border_style="green",
            title="Audit Verification",
        ))
    else:
        console.print(Panel.fit(
            f"[bold red]VERIFICATION FAILED[/bold red]\n\n"
            f"  Entries:     {result.total_entries}\n"
            f"  Verified:    {result.verified_entries}\n"
            f"  First break: line {result.first_break_at}\n"
            f"  Errors:      {len(result.errors)}",
            border_style="red",
            title="Audit Verification",
        ))
        for err in result.errors[:10]:
            err_console.print(f"  [red]{err}[/red]")
        if len(result.errors) > 10:
            err_console.print(f"  ... and {len(result.errors) - 10} more")
        raise typer.Exit(1)


@audit_app.command(name="export")
def audit_export(
    log_file: str = typer.Argument(help="Path to audit log (.jsonl)."),
    output_format: str = typer.Option("json", "--format", "-f", help="Export format: json, csv."),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file (stdout if omitted)."),
):
    """Export audit log to JSON or CSV for compliance review."""
    from lasso.core.audit_verify import read_audit_entries

    entries = read_audit_entries(log_file)
    if not entries:
        err_console.print("[dim]No entries to export.[/dim]")
        return

    if output_format == "json":
        data = json.dumps(entries, indent=2)
        if output:
            Path(output).write_text(data)
            console.print(f"[green]Exported {len(entries)} entries to {output}[/green]")
        else:
            console.print(data)

    elif output_format == "csv":
        buf = io.StringIO()
        fieldnames = ["event_id", "ts", "sandbox_id", "type", "actor", "action",
                       "target", "outcome", "sig"]
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for e in entries:
            writer.writerow(e)

        if output:
            Path(output).write_text(buf.getvalue())
            console.print(f"[green]Exported {len(entries)} entries to {output}[/green]")
        else:
            console.print(buf.getvalue())
    else:
        err_console.print(f"[red]Error: Unknown format '{output_format}'.[/red]")
        err_console.print("[dim]Valid formats: json, csv[/dim]")
        raise typer.Exit(1)
